import asyncio
import json
from datetime import datetime

import httpx
import pytest
from servidor import create_app

ORIGIN = "https://exemplo.ts.net"
ACCEPT = {"Accept": "application/json, text/event-stream"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


pytestmark = pytest.mark.anyio


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.setenv("SPIKE_PUBLIC_ORIGIN", ORIGIN)
    app = create_app()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client,
    ):
        yield client


async def test_mcp(client, capsys):
    async def rpc(method, params=None, headers=None):
        return await client.post(
            "/aberto/mcp",
            headers={**ACCEPT, **(headers or {})},
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        )

    response = await rpc(
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "teste-spike", "version": "1"},
        },
    )
    assert response.status_code == 200
    version = response.json()["result"]["protocolVersion"]
    headers = {"MCP-Protocol-Version": version}
    response = await rpc("tools/list", headers=headers)
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["ping"]
    assert tools[0]["inputSchema"].get("properties", {}) == {}
    response = await rpc("tools/call", {"name": "ping", "arguments": {}}, headers)
    assert response.status_code == 200
    result = response.json()["result"]
    assert not result.get("isError", False)
    text = result["content"][0]["text"]
    assert text.startswith("pong ")
    assert datetime.fromisoformat(text[5:]).utcoffset().total_seconds() == 0
    logs = [json.loads(line[6:]) for line in capsys.readouterr().out.splitlines()]
    assert logs[0]["jsonrpc_method"] == "initialize"
    assert logs[0]["protocolVersion"] == "2025-11-25"
    assert logs[0]["clientInfo"] == {"name": "teste-spike", "version": "1"}


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def test_protected(client, method):
    response = await client.request(method, "/protegido/mcp")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == (
        f'Bearer resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource/protegido/mcp"'
    )


async def test_metadata(client):
    assert (await client.get("/.well-known/oauth-protected-resource/protegido/mcp")).json() == {
        "resource": f"{ORIGIN}/protegido/mcp",
        "authorization_servers": [ORIGIN],
        "scopes_supported": ["memoria"],
        "bearer_methods_supported": ["header"],
    }
    assert (await client.get("/.well-known/oauth-authorization-server")).json() == {
        "issuer": ORIGIN,
        "authorization_endpoint": f"{ORIGIN}/oauth/authorize",
        "token_endpoint": f"{ORIGIN}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": True,
        "scopes_supported": ["memoria", "offline_access"],
        "authorization_response_iss_parameter_supported": True,
    }


async def test_authorize(client, capsys):
    fields = {
        "client_id": "https://cliente.example/cimd",
        "redirect_uri": "https://claude.ai/cb",
        "scope": "memoria offline_access",
        "resource": f"{ORIGIN}/protegido/mcp",
        "response_type": "code",
        "code_challenge_method": "S256",
    }
    response = await client.get(
        "/oauth/authorize",
        params={
            **fields,
            "state": "estado-secreto",
            "code_challenge": "desafio-secreto",
            "code": "codigo-secreto",
        },
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Location" not in response.headers
    assert "autorização desativada de propósito" in response.text
    output = capsys.readouterr().out
    record = json.loads(output.removeprefix("SPIKE "))
    assert all(record[key] == value for key, value in fields.items())
    assert record["state"] == record["code_challenge"] == "sim"
    for secret in ("estado-secreto", "desafio-secreto", "codigo-secreto"):
        assert secret not in output


async def test_no_credentials_in_log(client, capsys):
    response = await client.post(
        "/oauth/token",
        headers={
            "Authorization": "Bearer segredo123",
            "Cookie": "cookie-secreto",
            "Host": "host-observado.example",
            "Origin": "https://origem.example",
        },
        content="token-secreto",
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_grant"}
    output = capsys.readouterr().out
    assert all(secret not in output for secret in ("segredo123", "cookie-secreto", "token-secreto"))
    record = json.loads(output.removeprefix("SPIKE "))
    assert record["authorization"] == "sim"
    assert record["host"] == "host-observado.example"
    assert record["origin"] == "https://origem.example"


async def test_body_limit(client):
    assert (await client.post("/aberto/mcp", content=b"x" * (65536 + 1))).status_code == 413
    assert (await client.post("/oauth/token", content=b"x" * 65536)).status_code == 400


async def test_unknown(client):
    assert (await client.get("/desconhecido")).status_code == 404
    assert (await client.get("/aberto/mcp/")).status_code == 404


async def test_origin_required(monkeypatch):
    monkeypatch.delenv("SPIKE_PUBLIC_ORIGIN", raising=False)
    with pytest.raises(ValueError, match="SPIKE_PUBLIC_ORIGIN"):
        create_app()


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("POST", "/protegido/mcp", 401),
        ("POST", "/oauth/token", 400),
        ("POST", "/desconhecido", 404),
        ("GET", "/.well-known/oauth-protected-resource/protegido/mcp", 200),
        ("GET", "/.well-known/oauth-authorization-server", 200),
        ("GET", "/oauth/authorize", 200),
    ],
)
async def test_response_without_reading_body(monkeypatch, method, path, status):
    monkeypatch.setenv("SPIKE_PUBLIC_ORIGIN", ORIGIN)
    app = create_app()
    messages = []

    async def receive():
        pytest.fail("A rota não deve consumir o corpo.")

    async def send(message):
        messages.append(message)

    await app(
        {"type": "http", "method": method, "path": path, "headers": [], "query_string": b""},
        receive,
        send,
    )
    assert messages[0]["status"] == status


async def test_body_timeout(monkeypatch, capsys):
    monkeypatch.setenv("SPIKE_PUBLIC_ORIGIN", ORIGIN)
    monkeypatch.setenv("SPIKE_BODY_TIMEOUT", "0.05")
    app = create_app()
    messages = []

    async def receive():
        await asyncio.sleep(0.02)
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def send(message):
        messages.append(message)

    await app(
        {"type": "http", "method": "POST", "path": "/aberto/mcp", "headers": []},
        receive,
        send,
    )
    assert messages[0]["status"] == 408
    record = json.loads(capsys.readouterr().out.removeprefix("SPIKE "))
    assert record["status"] == 408
