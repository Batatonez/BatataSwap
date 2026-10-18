"""Montagem do servidor: borda externa, OAuth próprio e transporte oficial MCP."""

import time
from contextlib import asynccontextmanager
from pathlib import Path

import anyio.to_thread
import uvicorn
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.staticfiles import StaticFiles

from batataswap import __version__, db, logs
from batataswap.auth import oauth
from batataswap.auth.ratelimit import Budget, ScryptSlot
from batataswap.auth.routes import OAuthDeps, bearer_context, bearer_error_response, oauth_routes
from batataswap.config import ConfigError
from batataswap.crypto import Keyring, load_master_key
from batataswap.edge import EdgeMiddleware, RoutePolicy
from batataswap.memory import Actor
from batataswap.panel_api import panel_routes
from batataswap.tools import register_tools, request_actor


def _grant_atual():
    """Id público do grant da requisição; None sem actor (erro antes da autenticação)."""
    actor = request_actor.get(None)
    return actor.grant_public_id if actor is not None else None


def create_app(config, keyring, *, db_path, fetcher=None, clock=None, extra_routes=()):
    """Cria ASGI sem iniciar rede. extra_routes precedem as reservas dos painéis futuros."""

    # Pior caso de escape: cada byte "\" vira 2 caracteres em content e 2 em structuredContent,
    # então o contexto ocupa 4x context_bytes na resposta; 1600 cobre o resto do envelope.
    if config.limits.context_bytes * 4 + 1600 > config.limits.tool_response_chars:
        raise ConfigError("limits.tool_response_chars: insuficiente para limits.context_bytes.")

    def connect():
        return db.connect(Path(db_path))

    options = {"clock": clock or time.time, "on_event": logs.emit}
    if fetcher is not None:
        options["fetcher"] = fetcher
    deps = OAuthDeps(config, keyring, connect, Budget(), ScryptSlot(), **options)

    async def prompts(ctx, params):
        return types.ListPromptsResult(prompts=[])

    async def resources(ctx, params):
        return types.ListResourcesResult(resources=[])

    server = Server(
        "BatataSwap", version=__version__, on_list_prompts=prompts, on_list_resources=resources
    )

    class LoggedRegistration:
        def add_request_handler(self, name, params_type, handler):
            if name == "tools/call":
                original = handler

                async def handler(ctx, params):
                    start = time.monotonic()
                    response = await original(ctx, params)
                    logs.tool(
                        params.name,
                        response,
                        (time.monotonic() - start) * 1000,
                        grant=_grant_atual(),
                    )
                    return response

            server.add_request_handler(name, params_type, handler)

    raw_dispatch = register_tools(LoggedRegistration(), deps)

    async def dispatch(name, arguments):
        start = time.monotonic()
        response = await raw_dispatch(name, arguments)
        logs.tool(
            name,
            response,
            (time.monotonic() - start) * 1000,
            grant=_grant_atual(),
        )
        return response

    transport = server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        max_request_body_size=config.limits.mcp_body_bytes,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[config.authority, config.authority + ":443"],
            allowed_origins=[],
        ),
    )
    transport_handler = next(route.endpoint for route in transport.routes if route.path == "/mcp")

    class MCPHandler:
        async def __call__(self, scope, receive, send):
            try:
                context = await bearer_context(deps, scope, "mcp")
            except oauth.BearerError as error:
                await bearer_error_response(error)(scope, receive, send)
                return
            token = request_actor.set(
                Actor(context.grant_id, context.grant_public_id, context.label)
            )
            try:
                await transport_handler(scope, receive, send)
            finally:
                request_actor.reset(token)

    async def health(request):
        return JSONResponse({"ok": True, "versao": __version__})

    async def unavailable(request):
        return JSONResponse({"erro": "Não encontrado."}, status_code=404)

    class StaticHandler:
        def __init__(self):
            self.files = StaticFiles(directory=Path(__file__).parent / "auth" / "static")

        async def __call__(self, scope, receive, send):
            child = dict(scope)
            child["path"] = "/" + scope["path_params"]["path"]
            child["root_path"] = ""
            await self.files(child, receive, send)

    routes = [
        *oauth_routes(deps),
        Route("/mcp", MCPHandler(), methods=["POST"]),
        Route("/saude", health, methods=["GET"]),
        Route("/static/{path:path}", StaticHandler(), methods=["GET"]),
        *extra_routes,
        *panel_routes(deps),
        # Reservas negam acesso e mantêm a política completa verificável antes da T11/T18.
        Route("/api/painel/{path:path}", unavailable, methods=["GET", "POST"]),
        Route("/painel/{path:path}", unavailable, methods=["GET", "POST"]),
    ]
    policy = RoutePolicy.default()
    policy.check_against(routes)

    @asynccontextmanager
    async def lifespan(app):
        def migrate():
            conn = connect()
            try:
                db.migrate(conn)
            finally:
                conn.close()

        await anyio.to_thread.run_sync(migrate)
        async with transport.router.lifespan_context(transport):
            yield

    inner = Starlette(routes=routes, lifespan=lifespan)
    inner.router.redirect_slashes = False
    inner.state.oauth_deps = deps
    inner.state.mcp_server = server
    inner.state.dispatch_tool = dispatch
    app = EdgeMiddleware(inner, config=config, routes=policy, on_event=logs.emit)
    app.state = inner.state
    app.router = inner.router
    return app


def serve(config):
    """T12: banco deve existir (init); chave vem da credencial systemd, nunca do banco."""
    path = config.data_dir / "batataswap.db"
    db.connect(path).close()
    app = create_app(config, Keyring(load_master_key()), db_path=path)
    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.port,
        server_header=False,
        proxy_headers=False,
        forwarded_allow_ips="",
        access_log=False,
        limit_concurrency=64,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=15,
        h11_max_incomplete_event_size=16384,
    )
