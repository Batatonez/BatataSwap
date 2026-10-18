# ruff: noqa: F811
"""Integração do app inteiro e versões reais do transporte MCP."""

import asyncio
from dataclasses import replace

import httpx
from starlette.responses import HTMLResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from batataswap import __version__
from batataswap.app import create_app, serve
from tests.test_oauth import (  # noqa: F401
    NOW,
    ORIGIN,
    PAINEL_CALLBACK,
    FakeFetcher,
    claude_tokens,
    env,
    exchange,
    make_code,
    painel_params,
    pkce,
)


def app_for(environment, **kwargs):
    return create_app(
        environment.config,
        environment.keyring,
        db_path=environment.path,
        clock=lambda: NOW,
        fetcher=FakeFetcher(),
        **kwargs,
    )


def rpc(client, token, method, params=None, version="2026-07-28"):
    params = dict(params or {})
    if version == "2026-07-28":
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    return client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": version,
            "MCP-Method": method,
            "Accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )


def test_full_app(env):
    token = claude_tokens(env).access_token
    app = app_for(env)
    app.routes.check_against(app.router.routes)
    with TestClient(app, base_url=ORIGIN) as client:
        assert client.get("/saude").json() == {"ok": True, "versao": __version__}
        missing = client.post("/mcp")
        assert missing.status_code == 401
        assert missing.headers["www-authenticate"] == (
            f'Bearer resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource/mcp"'
        )
        assert client.get("/mcp").status_code == 405
        assert client.delete("/mcp").status_code == 405
        for method in ("server/discover", "tools/list", "prompts/list", "resources/list"):
            response = rpc(client, token, method)
            assert response.status_code == 200, response.text
            assert "result" in response.json(), response.text
            if method in {"prompts/list", "resources/list"}:
                assert response.json()["result"][method.split("/")[0]] == []
        response = rpc(
            client,
            token,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
            version="2025-11-25",
        )
        assert response.json()["result"]["protocolVersion"] == "2025-11-25"
        assert rpc(client, token, "tools/list", version="2025-11-25").status_code == 200
        assert client.get("/static/oauth.css").status_code == 200


def test_panel_token_rejected(env):
    verifier, challenge = pkce()
    code, _ = make_code(env, painel_params(challenge), label="painel")
    tokens = exchange(
        env,
        code,
        verifier,
        client_id="painel-vercel",
        redirect_uri=PAINEL_CALLBACK,
        resource=ORIGIN + "/api/painel",
    )
    with TestClient(app_for(env), base_url=ORIGIN) as client:
        assert rpc(client, tokens.access_token, "tools/list").status_code in {401, 403}


def test_html_referrer_and_extra_routes(env):
    async def html(request):
        return HTMLResponse("<p>Teste</p>")

    app = app_for(env, extra_routes=[Route("/painel/teste", html)])
    with TestClient(app, base_url=ORIGIN) as client:
        response = client.get("/oauth/authorize")
        assert response.headers["referrer-policy"] == "same-origin"
        assert client.get("/saude").headers["referrer-policy"] == "no-referrer"


def test_migrations_at_startup(env):
    # Uma base vazia existente é migrada antes de atender qualquer requisição.
    from batataswap import db

    path = env.path.parent / "empty.db"
    db.connect(path, create=True).close()
    app = create_app(env.config, env.keyring, db_path=path)
    with TestClient(app, base_url=ORIGIN) as client:
        assert client.get("/saude").status_code == 200
    conn = db.connect(path)
    try:
        assert conn.execute("SELECT count(*) FROM projects").fetchone()[0] == 0
    finally:
        conn.close()


def test_serve_options(env, monkeypatch):
    calls = []
    monkeypatch.setattr("batataswap.app.load_master_key", lambda: bytes(32))
    monkeypatch.setattr("batataswap.app.uvicorn.run", lambda *a, **kw: calls.append(kw))
    serve(replace(env.config, data_dir=env.path.parent))
    assert calls == [
        {
            "host": env.config.bind_host,
            "port": env.config.port,
            "server_header": False,
            "proxy_headers": False,
            "forwarded_allow_ips": "",
            "access_log": False,
            "limit_concurrency": 64,
            "timeout_keep_alive": 5,
        }
    ]


def test_httpx_asgi_transport(env):
    async def run():
        app = app_for(env)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client,
        ):
            assert (await client.get("/saude")).json()["ok"]

    asyncio.run(run())
