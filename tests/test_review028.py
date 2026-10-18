# ruff: noqa: F811
"""T16, 3ª passada: Bearer sem tag fora do banco, corpo lento sem vaga e flush da agregação."""

import asyncio
import json
import time

import pytest
from starlette.testclient import TestClient

from batataswap import app as app_module
from batataswap import crypto, logs
from batataswap.auth import oauth, routes
from batataswap.crypto import token_hash
from tests.test_app import app_for
from tests.test_edge import HOST, make
from tests.test_oauth import NOW, ORIGIN, claude_tokens, env, refresh  # noqa: F401

# ---------------------------------------------------------------------------
# I1 — access token sem tag nunca chega ao banco
# ---------------------------------------------------------------------------


def _untagged():
    return crypto.new_token(oauth.ACCESS_PREFIX)


def test_untagged_bearer_never_touches_db(env, monkeypatch):
    calls = []
    original = routes._db

    async def counting_db(deps, fn, *args, **kwargs):
        calls.append(getattr(fn, "__name__", "?"))
        return await original(deps, fn, *args, **kwargs)

    app = app_for(env)
    with TestClient(app, base_url=ORIGIN) as client:
        monkeypatch.setattr(routes, "_db", counting_db)
        for _ in range(200):
            response = client.post("/mcp", headers={"Authorization": f"Bearer {_untagged()}"})
            assert response.status_code == 401
            assert response.headers["www-authenticate"] == (
                f'Bearer error="invalid_token", resource_metadata="{ORIGIN}'
                '/.well-known/oauth-protected-resource/mcp"'
            )
        assert calls == []
        # Sanidade: o mesmo caminho com token válido consulta o banco e passa da borda.
        token = claude_tokens(env).access_token
        response = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert response.status_code != 401
        assert calls


def test_untagged_bearer_context_zero_connections(env):
    connections = 0

    def connect():
        nonlocal connections
        connections += 1
        raise AssertionError("não deve abrir banco")

    deps = routes.OAuthDeps(env.config, env.keyring, connect, routes.Budget(), routes.ScryptSlot())

    async def run():
        for which in ("mcp", "painel"):
            for _ in range(100):
                with pytest.raises(oauth.BearerError) as caught:
                    await routes.bearer_context(deps, {"state": {"bearer": _untagged()}}, which)
                assert caught.value.status == 401
                assert 'error="invalid_token"' in caught.value.www_authenticate

    asyncio.run(run())
    assert connections == 0


def test_refresh_issues_tagged_token_and_legacy_row_refused(env):
    tokens = claude_tokens(env)
    renewed = refresh(env, tokens.refresh_token, NOW + 5)
    for token in (tokens.access_token, renewed.access_token):
        assert oauth.access_tag_ok(env.keyring, token)
        oauth.precheck_access(env.keyring, token, ORIGIN + "/mcp")
    assert oauth.validate_bearer(env.conn, renewed.access_token, ORIGIN + "/mcp", "memoria", NOW)
    # Linha antiga sem tag no banco: nem o validador do banco aceita mais esse formato.
    legacy = renewed.access_token.split(".")[0]
    env.conn.execute(
        "UPDATE oauth_tokens SET token_hash=? WHERE token_hash=?",
        (token_hash(legacy), token_hash(renewed.access_token)),
    )
    with pytest.raises(oauth.BearerError):
        oauth.precheck_access(env.keyring, legacy, ORIGIN + "/mcp")
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, legacy, ORIGIN + "/mcp", "memoria", NOW)
    with pytest.raises(oauth.BearerError):
        oauth.check_access_active(env.conn, legacy, ORIGIN + "/mcp", NOW)


def test_revoke_untagged_or_forged_access_skips_db(env):
    statements = []
    env.conn.set_trace_callback(statements.append)
    try:
        for token in (_untagged(), _untagged() + "." + "A" * 22):
            oauth.revoke_token(env.conn, env.config, {"token": [token]}, NOW, env.keyring)
    finally:
        env.conn.set_trace_callback(None)
    assert statements == []
    tokens = claude_tokens(env)
    oauth.revoke_token(env.conn, env.config, {"token": [tokens.access_token]}, NOW, env.keyring)
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW)


# ---------------------------------------------------------------------------
# I2 — corpos incompletos não seguram a admissão de corpo pronto
# ---------------------------------------------------------------------------


def _scope(path="/oauth/token", length=2):
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "headers": [(b"host", HOST.encode()), (b"content-length", str(length).encode())],
        "query_string": b"",
    }


async def _request(edge, slow):
    messages = []

    async def receive():
        if slow:
            await asyncio.Event().wait()  # nunca termina o corpo
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message):
        messages.append(message)

    await edge(_scope(), receive, send)
    return next(m for m in messages if m["type"] == "http.response.start")


def test_staggered_slow_waves_do_not_starve_ready_body():
    events = []
    edge, toy = make(events=events)

    async def run():
        slow = []
        ready = None
        for wave in range(3):
            slow += [asyncio.create_task(_request(edge, True)) for _ in range(8)]
            await asyncio.sleep(0.15)
            assert edge._body_slots["token"]._value == 8  # ler o corpo não ocupa vaga
            if wave == 1:
                ready = asyncio.create_task(_request(edge, False))
        started = time.monotonic()
        response = await asyncio.wait_for(ready, 1)
        assert response["status"] == 200
        assert time.monotonic() - started < 0.5
        assert toy.calls == 1
        slow_responses = await asyncio.wait_for(asyncio.gather(*slow), 3)
        assert {r["status"] for r in slow_responses} == {408}
        assert all((b"connection", b"close") in r["headers"] for r in slow_responses)
        assert edge._body_slots["token"]._value == 8
        assert toy.calls == 1

    asyncio.run(run())
    assert ("sem_vaga_corpo", 503) not in events
    assert events.count(("corpo_timeout", 408)) == 24


def test_anonymous_deadline_counts_from_edge_entry():
    edge, toy = make()
    edge.body_total_timeout = 0.2
    deadlines = []
    original = edge._read_body

    async def spy(scope, receive, send, rule, limit, cors_origin, deadline=None):
        deadlines.append(deadline)
        await asyncio.sleep(0.15)  # tempo gasto antes da leitura conta no prazo
        return await original(scope, receive, send, rule, limit, cors_origin, deadline)

    edge._read_body = spy

    async def run():
        messages = []

        async def receive():
            await asyncio.sleep(0.1)
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(message):
            messages.append(message)

        entered = asyncio.get_running_loop().time()
        await edge(_scope(), receive, send)
        assert deadlines[0] is not None and deadlines[0] - entered <= 0.2 + 0.01
        return messages[0]["status"]

    assert asyncio.run(run()) == 408
    assert toy.calls == 0


def test_pool_slot_held_during_handler_only():
    edge, toy = make()
    inside = asyncio.Event()
    leave = asyncio.Event()
    seen = []
    original = toy.__call__

    async def handler(scope, receive, send):
        seen.append(edge._body_slots["token"]._value)
        inside.set()
        await leave.wait()
        await original(scope, receive, send)

    edge.app = handler

    async def run():
        task = asyncio.create_task(_request(edge, False))
        await asyncio.wait_for(inside.wait(), 1)
        assert edge._body_slots["token"]._value == 7
        leave.set()
        assert (await task)["status"] == 200
        assert edge._body_slots["token"]._value == 8

    asyncio.run(run())
    assert seen == [7]


# ---------------------------------------------------------------------------
# S1 — agregação publica o fim da rajada sem precisar de evento novo
# ---------------------------------------------------------------------------


def _lines(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]


def test_flush_publishes_pending_counts(monkeypatch, capsys):
    monkeypatch.setattr(logs, "_counts", {})
    now = [0.0]
    monkeypatch.setattr(logs.time, "monotonic", lambda: now[0])
    for _ in range(50):
        logs.emit("corpo_timeout", 408)
    for _ in range(3):
        logs.emit("repassado", 200)
    logs.emit("repassado", 400)
    first = _lines(capsys)
    assert [(r["evento"], r["status"]) for r in first] == [
        ("corpo_timeout", 408),
        ("repassado", 200),
        ("repassado", 400),
    ]
    now[0] = 5
    logs.flush()
    assert _lines(capsys) == []  # janela ainda aberta
    now[0] = 10
    logs.flush()
    flushed = {(r["evento"], r["status"]): r["contador"] for r in _lines(capsys)}
    assert flushed == {("corpo_timeout", 408): 49, ("repassado", 200): 2}
    logs.flush()
    assert _lines(capsys) == []  # nada pendente: não repete


def test_flush_force_and_secret_free(monkeypatch, capsys):
    monkeypatch.setattr(logs, "_counts", {})
    for _ in range(4):
        logs.emit("token_recusado", 400)
    capsys.readouterr()
    logs.flush(force=True)
    (record,) = _lines(capsys)
    assert record["evento"] == "token_recusado" and record["contador"] == 3
    assert set(record) <= {"evento", "status", "ms", "grant", "tamanho", "nivel", "contador"}


def test_app_flushes_periodically_and_on_shutdown(env, monkeypatch, capsys):
    monkeypatch.setattr(logs, "_counts", {})
    monkeypatch.setattr(logs, "AGGREGATE_WINDOW", 0.2)
    monkeypatch.setattr(app_module, "LOG_FLUSH_EVERY", 0.05)
    app = app_for(env)
    with TestClient(app, base_url=ORIGIN) as client:
        for _ in range(3):
            assert client.get("/nada").status_code == 404
        capsys.readouterr()
        deadline = time.monotonic() + 2
        periodic = []
        while time.monotonic() < deadline and not periodic:
            time.sleep(0.05)
            periodic = [r for r in _lines(capsys) if r["evento"] == "rota_inexistente"]
        assert periodic and periodic[0]["contador"] == 2
        monkeypatch.setattr(logs, "AGGREGATE_WINDOW", 3600)
        for _ in range(3):
            assert client.get("/nada").status_code == 404
        capsys.readouterr()
    shutdown = [r for r in _lines(capsys) if r["evento"] == "rota_inexistente"]
    assert shutdown and shutdown[0]["contador"] == 3
