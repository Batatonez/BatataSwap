"""T16, 4ª passada: a vaga do pool não fica presa no envio da resposta (prazo de envio)."""

import asyncio
import contextlib
import json

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from batataswap import edge as edge_module
from batataswap import logs
from tests.test_edge import HOST, TOKEN, make


def _scope(path="/oauth/token", length=2, extra=()):
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "headers": [(b"host", HOST.encode()), (b"content-length", str(length).encode()), *extra],
        "query_string": b"",
    }


async def _receive():
    return {"type": "http.request", "body": b"{}", "more_body": False}


async def _stuck_send(message):
    await asyncio.Event().wait()  # cliente que nunca lê a resposta


def test_default_send_timeout_is_a_constant():
    edge, _ = make()
    assert edge_module.SEND_TIMEOUT == 5
    assert edge.send_timeout == edge_module.SEND_TIMEOUT
    assert "envio_timeout" in edge_module.EVENTS
    assert "envio_timeout" in logs.EVENTS


def test_stuck_responses_do_not_hold_pool_slots():
    events = []
    edge, toy = make(events=events)
    edge.send_timeout = 0.5

    async def run():
        stuck = [asyncio.create_task(edge(_scope(), _receive, _stuck_send)) for _ in range(8)]
        await asyncio.sleep(0.1)
        assert toy.calls == 8
        # Os 8 estão presos no envio, mas nenhum segura vaga.
        assert edge._body_slots["token"]._value == 8

        messages = []

        async def send(message):
            messages.append(message)

        await asyncio.wait_for(edge(_scope(), _receive, send), 1)
        assert toy.calls == 9
        assert messages[0]["type"] == "http.response.start"
        assert messages[0]["status"] == 200

        results = await asyncio.wait_for(asyncio.gather(*stuck, return_exceptions=True), 2)
        assert all(isinstance(r, RuntimeError) for r in results)
        assert all("segredo" not in str(r) for r in results)
        assert edge._body_slots["token"]._value == 8

    asyncio.run(run())
    assert ("sem_vaga_corpo", 503) not in events
    assert events.count(("envio_timeout", 200)) == 8
    assert ("erro_interno", 500) not in events


def test_slot_released_when_response_starts():
    edge, _ = make()
    started = asyncio.Event()
    leave = asyncio.Event()
    seen = []

    async def handler(scope, receive, send):
        seen.append(edge._body_slots["token"]._value)
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        seen.append(edge._body_slots["token"]._value)
        started.set()
        await leave.wait()
        await send({"type": "http.response.body", "body": b"ok"})

    edge.app = handler

    async def run():
        async def send(message):
            pass

        task = asyncio.create_task(edge(_scope(), _receive, send))
        await asyncio.wait_for(started.wait(), 1)
        assert edge._body_slots["token"]._value == 8
        leave.set()
        await task
        assert edge._body_slots["token"]._value == 8  # soltar duas vezes não passa de 8

    asyncio.run(run())
    assert seen == [7, 8]


def test_swallowed_send_timeout_still_aborts():
    events = []
    edge, _ = make(events=events)
    edge.send_timeout = 0.1
    sends_after = []

    async def handler(scope, receive, send):
        await receive()
        with contextlib.suppress(Exception):  # app que engole o erro do envio
            await send({"type": "http.response.start", "status": 200, "headers": []})
        try:
            await send({"type": "http.response.body", "body": b"ok"})
        except Exception:  # noqa: BLE001
            sends_after.append("recusado")

    edge.app = handler

    async def run():
        with pytest.raises(RuntimeError):
            await asyncio.wait_for(edge(_scope(), _receive, _stuck_send), 1)
        assert edge._body_slots["token"]._value == 8

    asyncio.run(run())
    assert sends_after == ["recusado"]  # depois de estourar, nenhum envio é tentado
    assert events.count(("envio_timeout", 200)) == 1


def test_starlette_app_send_timeout_aborts():
    events = []
    edge, _ = make(events=events)
    edge.send_timeout = 0.1

    async def token(request):
        await request.body()
        return JSONResponse({"ok": True})

    edge.app = Starlette(routes=[Route("/oauth/token", token, methods=["POST"])])

    async def run():
        with pytest.raises(RuntimeError):
            await asyncio.wait_for(edge(_scope(), _receive, _stuck_send), 1)
        assert edge._body_slots["token"]._value == 8

    asyncio.run(run())
    assert ("envio_timeout", 200) in events
    assert ("erro_interno", 500) not in events


def test_bearer_route_has_no_send_deadline():
    edge, _ = make()
    edge.send_timeout = 0.05
    messages = []

    async def slow_send(message):
        await asyncio.sleep(0.1)
        messages.append(message)

    scope = _scope("/mcp", extra=[(b"authorization", f"Bearer {TOKEN}".encode())])
    asyncio.run(edge(scope, _receive, slow_send))
    assert messages[0]["status"] == 200
    assert json.loads(messages[1]["body"])["body"] == 2


def test_envio_timeout_is_aggregated(monkeypatch, capsys):
    monkeypatch.setattr(logs, "_counts", {})
    for _ in range(5):
        logs.emit("envio_timeout", 200)
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    assert [(r["evento"], r["status"]) for r in lines] == [("envio_timeout", 200)]
    logs.flush(force=True)
    (record,) = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    assert record["contador"] == 4
