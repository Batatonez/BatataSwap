# ruff: noqa: F811
"""Integração do app inteiro e versões reais do transporte MCP."""

import asyncio
from dataclasses import replace

import httpx
import pytest
from starlette.responses import HTMLResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from batataswap import __version__, db
from batataswap.app import create_app, serve
from batataswap.transport import DeadlineH11Protocol
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
            **({"Mcp-Name": params["name"]} if method == "tools/call" else {}),
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
        response = rpc(client, tokens.access_token, "tools/list")
        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]


def test_saude_cors_aberto_sem_credenciais(env):
    app = app_for(env)
    with TestClient(app, base_url=ORIGIN) as client:
        for origem in ("https://batataswap.vercel.app", "https://mal.example"):
            r = client.get("/saude", headers={"Origin": origem})
            assert r.status_code == 200
            assert r.json() == {"ok": True, "versao": __version__}
            assert r.headers["access-control-allow-origin"] == "*"
            assert "access-control-allow-credentials" not in r.headers
        r = client.options(
            "/saude",
            headers={
                "Origin": "https://mal.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.status_code == 204
        assert r.headers["access-control-allow-origin"] == "*"
        assert "access-control-allow-credentials" not in r.headers
        # /oauth/token continua só para a origem exata da Vercel (não configurada aqui).
        r = client.post(
            "/oauth/token",
            headers={"Origin": "https://mal.example"},
            data={"grant_type": "x"},
        )
        assert "access-control-allow-origin" not in r.headers
        assert "access-control-allow-credentials" not in r.headers


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
    db.connect(env.path.parent / "batataswap.db", create=True).close()
    serve(replace(env.config, data_dir=env.path.parent))
    assert calls == [
        {
            "host": env.config.bind_host,
            "port": env.config.port,
            "server_header": False,
            "proxy_headers": False,
            "forwarded_allow_ips": "",
            "access_log": False,
            "limit_concurrency": 512,
            "http": DeadlineH11Protocol,
            "ws": "none",
            "timeout_keep_alive": 5,
            "timeout_graceful_shutdown": 15,
            "h11_max_incomplete_event_size": 16384,
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


def test_config_response_budget(env):
    from batataswap.config import ConfigError

    with pytest.raises(ConfigError):
        create_app(
            replace(env.config, limits=replace(env.config.limits, tool_response_chars=4096)),
            env.keyring,
            db_path=env.path,
        )


def test_serve_missing_database(env, monkeypatch):
    monkeypatch.setattr("batataswap.app.load_master_key", lambda: bytes(32))
    with pytest.raises(db.DatabaseError):
        serve(replace(env.config, data_dir=env.path.parent / "missing"))


def test_rpc_calls_versions_and_name(env):
    token = claude_tokens(env).access_token
    with TestClient(app_for(env), base_url=ORIGIN) as client:
        for version in ("2026-07-28", "2025-11-25"):
            response = rpc(
                client, token, "tools/call", {"name": "listar_projetos", "arguments": {}}, version
            )
            assert response.status_code == 200, response.text
            assert not response.json()["result"].get("isError")
        response = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "MCP-Protocol-Version": "2026-07-28",
                "MCP-Method": "tools/call",
                "Mcp-Name": "buscar",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "listar_projetos", "arguments": {}},
            },
        )
        assert response.status_code == 400


def test_panel_routes_integrated(env):
    from batataswap.auth.owner import verify_totp_only
    from tests.test_oauth import VERCEL

    verifier, challenge = pkce()
    code, _ = make_code(env, painel_params(challenge), label="painel")
    panel = exchange(
        env,
        code,
        verifier,
        client_id="painel-vercel",
        redirect_uri=PAINEL_CALLBACK,
        resource=ORIGIN + "/api/painel",
    )
    mcp = claude_tokens(env).access_token
    app = app_for(env)
    headers = {"Authorization": f"Bearer {panel.access_token}", "Origin": VERCEL}
    with TestClient(app, base_url=ORIGIN) as client:
        for path in ("conexoes", "atividade"):
            response = client.get("/api/painel/" + path, headers=headers)
            assert response.status_code == 200
            assert response.headers["access-control-allow-origin"] == VERCEL
            assert response.headers["cache-control"] == "no-store"
            assert (
                client.get(
                    "/api/painel/" + path,
                    headers={"Authorization": f"Bearer {mcp}", "Origin": VERCEL},
                ).status_code
                == 401
            )
        assert (
            client.post(
                "/api/painel/revogar",
                headers={"Authorization": f"Bearer {mcp}", "Origin": VERCEL},
                json={"rotulo": "conta-1", "totp": "000000"},
            ).status_code
            == 401
        )
        for _ in range(5):
            assert (
                client.post(
                    "/api/painel/revogar",
                    headers=headers,
                    json={"rotulo": "conta-1", "totp": "000000"},
                ).status_code
                == 403
            )
        assert (
            client.post(
                "/api/painel/revogar", headers=headers, json={"rotulo": "conta-1", "totp": "000000"}
            ).status_code
            == 429
        )
        assert (
            verify_totp_only(
                env.conn, env.keyring, app.state.oauth_deps.budget, "000000", None, NOW
            ).status
            == "invalido"
        )  # o painel tem orçamento próprio: o do login global continua livre


def test_mcp_edge_guards(env, monkeypatch):
    token = claude_tokens(env).access_token
    app = app_for(env)
    with TestClient(app, base_url=ORIGIN) as client:
        response = client.post("/mcp", headers={"Authorization": "Bearer invalido"})
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer resource_metadata=")
        response = client.post("/mcp", headers={"Authorization": "Bearer bsw_at_" + "A" * 43})
        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]
        assert client.post("/mcp", content=b"x" * 8193).status_code == 401
        assert (
            client.post(
                "/oauth/token",
                content=b"x" * 8193,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ).status_code
            == 413
        )
        headers = {"Authorization": f"Bearer {token}"}
        assert (
            client.post("/mcp", headers=headers, content=b"x" * (256 * 1024 + 1)).status_code == 413
        )
        assert (
            client.post("/mcp", headers={**headers, "Origin": "https://claude.ai"}).status_code
            == 403
        )
        assert client.get("/static/%2e%2e/x").status_code == 400
        response = rpc(client, token, "tools/list")
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        app.state.oauth_deps.clock = lambda: NOW + 10 * 365 * 86400
        assert rpc(client, token, "tools/list").status_code == 401
        app.state.oauth_deps.clock = lambda: NOW
        env.conn.execute("UPDATE oauth_grants SET revoked_at=?", (NOW,))
        assert rpc(client, token, "tools/list").status_code == 401
