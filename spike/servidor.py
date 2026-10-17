"""Spike descartável: observação de transporte, sem memória nem autorização real."""

import asyncio
import json
import os
from datetime import UTC, datetime
from urllib.parse import urlsplit

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.datastructures import Headers, QueryParams
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

MAX_BODY = 64 * 1024


def create_app():
    body_timeout = float(os.environ.get("SPIKE_BODY_TIMEOUT", "10"))
    origin = os.environ.get("SPIKE_PUBLIC_ORIGIN", "")
    parsed = urlsplit(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("SPIKE_PUBLIC_ORIGIN é obrigatória e deve ser uma origem sem barra final.")

    server = MCPServer("Spike descartável do BatataSwap", log_level="CRITICAL")

    @server.tool(structured_output=False)
    async def ping() -> str:
        """Responde pong com a data e hora UTC."""
        return f"pong {datetime.now(UTC).isoformat()}"

    mcp_app = server.streamable_http_app(
        streamable_http_path="/aberto/mcp",
        stateless_http=True,
        json_response=True,
        max_request_body_size=MAX_BODY,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async def resource_metadata(request):
        return JSONResponse(
            {
                "resource": f"{origin}/protegido/mcp",
                "authorization_servers": [origin],
                "scopes_supported": ["memoria"],
                "bearer_methods_supported": ["header"],
            }
        )

    async def authorization_metadata(request):
        return JSONResponse(
            {
                "issuer": origin,
                "authorization_endpoint": f"{origin}/oauth/authorize",
                "token_endpoint": f"{origin}/oauth/token",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "client_id_metadata_document_supported": True,
                "scopes_supported": ["memoria", "offline_access"],
                "authorization_response_iss_parameter_supported": True,
            }
        )

    async def authorize(request):
        return HTMLResponse(
            '<!doctype html><html lang="pt-BR"><meta charset="utf-8">'
            "<title>Spike do BatataSwap</title><p>Spike do BatataSwap: autorização "
            "desativada de propósito. Pode fechar esta janela.</p></html>"
        )

    async def token(request):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    app = Starlette(
        routes=[
            *mcp_app.routes,
            Route("/.well-known/oauth-protected-resource/protegido/mcp", resource_metadata),
            Route("/.well-known/oauth-authorization-server", authorization_metadata),
            Route("/oauth/authorize", authorize),
            Route("/oauth/token", token, methods=["POST"]),
        ],
        lifespan=mcp_app.router.lifespan_context,
    )
    app.router.redirect_slashes = False

    async def observed_app(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        record = {"method": scope["method"], "path": scope["path"]}
        for name in (
            "host",
            "origin",
            "user-agent",
            "mcp-protocol-version",
            "accept",
            "content-type",
        ):
            record[name] = headers.get(name)
        for name in ("mcp-session-id", "authorization"):
            record[name] = "sim" if name in headers else "não"
        if scope["path"] == "/oauth/authorize" and scope["method"] == "GET":
            query = QueryParams(scope.get("query_string", b""))
            for name in (
                "client_id",
                "redirect_uri",
                "scope",
                "resource",
                "response_type",
                "code_challenge_method",
            ):
                record[name] = query.get(name)
            for name in ("state", "code_challenge"):
                record[name] = "sim" if name in query else "não"

        async def observed_send(message):
            if message["type"] == "http.response.start":
                record["status"] = message["status"]
            await send(message)

        try:
            if scope["path"] == "/protegido/mcp":
                response = JSONResponse(
                    {"erro": "Autorização necessária."},
                    status_code=401,
                    headers={
                        "WWW-Authenticate": 'Bearer resource_metadata="'
                        f'{origin}/.well-known/oauth-protected-resource/protegido/mcp"'
                    },
                )
                await response(scope, receive, observed_send)
                return
            if scope["path"] != "/aberto/mcp":
                await app(scope, receive, observed_send)
                return

            body = bytearray()
            try:
                async with asyncio.timeout(body_timeout):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        body.extend(message.get("body", b""))
                        if len(body) > MAX_BODY:
                            await JSONResponse({"erro": "Corpo acima de 64 KiB."}, 413)(
                                scope, receive, observed_send
                            )
                            return
                        if not message.get("more_body", False):
                            break
            except TimeoutError:
                await JSONResponse({"erro": "Prazo de leitura do corpo excedido."}, 408)(
                    scope, receive, observed_send
                )
                return
            if scope["path"] == "/aberto/mcp" and scope["method"] == "POST":
                try:
                    payload = json.loads(body)
                except (ValueError, UnicodeDecodeError):
                    payload = None
                if isinstance(payload, dict):
                    record["jsonrpc_method"] = payload.get("method")
                    params = payload.get("params")
                    if payload.get("method") == "initialize" and isinstance(params, dict):
                        record["protocolVersion"] = params.get("protocolVersion")
                        record["clientInfo"] = params.get("clientInfo")

            delivered = False

            async def replay_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await app(scope, replay_receive, observed_send)
        finally:
            record.setdefault("status", 499)
            print("SPIKE " + json.dumps(record, ensure_ascii=False), flush=True)

    observed_app.router = app.router
    return observed_app


if __name__ == "__main__":
    uvicorn.run(
        create_app(),
        host="127.0.0.1",
        port=int(os.environ.get("SPIKE_PORT", "8780")),
        access_log=False,
        proxy_headers=False,
        limit_concurrency=20,
        timeout_keep_alive=5,
        h11_max_incomplete_event_size=16384,
    )
