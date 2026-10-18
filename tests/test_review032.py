"""T16, 5ª passada: prazo de escrita no nível da conexão, com o ciclo REAL do uvicorn.

O transporte é simulado: ``close()`` com a escrita pausada não chama ``connection_lost`` (o
buffer nunca esvazia, como num cliente que não lê); ``abort()`` chama, como o asyncio.
"""

import asyncio
import inspect

import pytest
import uvicorn
from uvicorn.protocols.http.flow_control import FlowControl
from uvicorn.protocols.http.h11_impl import H11Protocol, RequestResponseCycle
from uvicorn.server import ServerState

from batataswap import logs, transport
from batataswap.transport import DeadlineFlowControl, DeadlineH11Protocol
from tests.test_edge import HOST, make

DRAIN = 0.3


class FakeTransport:
    def __init__(self, loop, pause_on_first_write=False):
        self.loop = loop
        self.protocol = None
        self.written = []
        self.closing = False
        self.aborted_at = None
        self.pause_on_first_write = pause_on_first_write

    def get_extra_info(self, name, default=None):
        return {"sockname": ("127.0.0.1", 8000), "peername": ("127.0.0.1", 50000)}.get(
            name, default
        )

    def write(self, data):
        self.written.append(data)
        if self.pause_on_first_write and len(self.written) == 1:
            self.protocol.pause_writing()  # buffer cheio logo depois dos headers

    def close(self):
        # Fechar com buffer cheio espera esvaziar: com cliente parado, nunca acontece.
        self.closing = True

    def abort(self):
        if self.aborted_at is None:
            self.aborted_at = self.loop.time()
            self.closing = True
            self.loop.call_soon(self.protocol.connection_lost, None)

    def is_closing(self):
        return self.closing

    def pause_reading(self):
        pass

    def resume_reading(self):
        pass


def _request(path="/oauth/token", body=b"{}", extra=b""):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: {len(body)}\r\n".encode()
        + extra
        + b"\r\n"
        + body
    )


async def _connect(app, *, pause_on_first_write=False):
    loop = asyncio.get_running_loop()
    config = uvicorn.Config(
        app,
        http=DeadlineH11Protocol,
        ws="none",
        lifespan="off",
        proxy_headers=False,
        server_header=False,
        access_log=False,
        log_level="critical",
    )
    config.load()
    state = ServerState()
    protocol = DeadlineH11Protocol(config=config, server_state=state, app_state={}, _loop=loop)
    fake = FakeTransport(loop, pause_on_first_write)
    fake.protocol = protocol
    protocol.connection_made(fake)
    return protocol, fake, state


@pytest.fixture
def emitted(monkeypatch):
    monkeypatch.setattr(transport, "WRITE_DRAIN_TIMEOUT", DRAIN)
    events = []
    monkeypatch.setattr(logs, "emit", lambda evento, *a, **kw: events.append(evento))
    return events


def _task(state):
    (task,) = state.tasks  # pego logo, antes de terminar e sair do conjunto
    return task


async def _finish(task, timeout=3):
    await asyncio.wait_for(asyncio.shield(task), timeout)
    assert task.exception() is None
    return task


def _check_aborted(fake, paused_at):
    assert fake.aborted_at is not None
    assert fake.aborted_at - paused_at >= DRAIN - 0.05


# -- acoplamento com o uvicorn ----------------------------------------------------------------


def test_uvicorn_names_still_match():
    """Falha se uma versão nova do uvicorn mudar o que ``transport.py`` usa."""
    for name in ("connection_made", "connection_lost", "pause_writing", "resume_writing"):
        assert callable(getattr(H11Protocol, name, None)), name
    for name in ("drain", "pause_writing", "resume_writing"):
        assert callable(getattr(FlowControl, name, None)), name
    assert "self.flow = FlowControl(transport)" in inspect.getsource(H11Protocol.connection_made)
    assert "self.flow.resume_writing()" in inspect.getsource(H11Protocol.connection_lost)
    assert "self.flow.pause_writing()" in inspect.getsource(H11Protocol.pause_writing)
    send = inspect.getsource(RequestResponseCycle.send)
    assert "if self.flow.write_paused and not self.disconnected:" in send
    assert "await self.flow.drain()" in send
    assert "if self.disconnected:" in send
    assert "flow=self.flow" in inspect.getsource(H11Protocol.handle_events)
    cycle_attrs = inspect.getsource(RequestResponseCycle.__init__)
    for attr in ("self.disconnected", "self.keep_alive", "self.message_event", "self.flow"):
        assert attr in cycle_attrs, attr


def test_constant_and_event():
    assert transport.WRITE_DRAIN_TIMEOUT == 10
    assert "escrita_timeout" in logs.EVENTS
    assert "escrita_timeout" in logs._AGGREGATED


def test_connection_uses_deadline_flow():
    async def run():
        protocol, _, _ = await _connect(make()[0])
        assert isinstance(protocol.flow, DeadlineFlowControl)

    asyncio.run(run())


# -- critérios de aceite -----------------------------------------------------------------------


@pytest.mark.parametrize("send_timeout", [0.1, 5])
def test_token_paused_before_headers(emitted, send_timeout):
    """Com o SEND_TIMEOUT da borda antes (0.1) ou depois (5) do prazo de escrita."""
    edge, toy = make()
    edge.send_timeout = send_timeout

    async def run():
        loop = asyncio.get_running_loop()
        protocol, fake, state = await _connect(edge)
        protocol.data_received(_request())
        task = _task(state)
        protocol.pause_writing()
        paused_at = loop.time()
        await _finish(task)
        _check_aborted(fake, paused_at)
        assert fake.written == []  # nada chegou a ser escrito
        assert edge._body_slots["token"]._value == 8
        assert toy.calls == 1
        assert not protocol.flow.write_paused

    asyncio.run(run())
    assert emitted.count("escrita_timeout") == 1


def test_token_paused_after_headers(emitted):
    edge, _ = make()

    async def run():
        loop = asyncio.get_running_loop()
        protocol, fake, state = await _connect(edge, pause_on_first_write=True)
        protocol.data_received(_request())
        task = _task(state)
        await asyncio.sleep(0.05)
        assert len(fake.written) == 1 and fake.written[0].startswith(b"HTTP/1.1 200")
        paused_at = loop.time() - 0.05
        await _finish(task)
        _check_aborted(fake, paused_at)
        assert len(fake.written) == 1  # o corpo nunca foi escrito
        assert edge._body_slots["token"]._value == 8

    asyncio.run(run())
    assert emitted.count("escrita_timeout") == 1


def test_mcp_401_from_edge_paused(emitted):
    events = []
    edge, toy = make(events=events)

    async def run():
        loop = asyncio.get_running_loop()
        protocol, fake, state = await _connect(edge)
        protocol.data_received(_request("/mcp"))
        task = _task(state)
        protocol.pause_writing()
        paused_at = loop.time()
        await _finish(task)
        _check_aborted(fake, paused_at)
        assert toy.calls == 0

    asyncio.run(run())
    assert ("credencial_ausente", 401) in events
    assert emitted.count("escrita_timeout") == 1


def test_handler_exception_paused_releases_slot(emitted):
    events = []
    edge, toy = make("boom", events=events)

    async def run():
        loop = asyncio.get_running_loop()
        protocol, fake, state = await _connect(edge)
        protocol.data_received(_request())
        task = _task(state)
        protocol.pause_writing()
        paused_at = loop.time()
        await asyncio.sleep(DRAIN / 3)
        # O 500 está preso no envio, mas a vaga já voltou.
        assert toy.calls == 1
        assert fake.aborted_at is None
        assert edge._body_slots["token"]._value == 8
        await _finish(task)
        _check_aborted(fake, paused_at)
        assert edge._body_slots["token"]._value == 8

    asyncio.run(run())
    assert ("erro_interno", 500) in events
    assert emitted.count("escrita_timeout") == 1


def test_reading_client_is_not_affected(emitted):
    edge, _ = make()

    async def run():
        protocol, fake, state = await _connect(edge, pause_on_first_write=True)
        protocol.data_received(_request())
        task = _task(state)
        await asyncio.sleep(DRAIN / 3)
        protocol.resume_writing()  # o cliente leu: o buffer esvaziou antes do prazo
        await _finish(task)
        await asyncio.sleep(DRAIN)
        assert fake.aborted_at is None
        assert b"".join(fake.written).startswith(b"HTTP/1.1 200")
        assert protocol.cycle.response_complete
        assert not protocol.cycle.disconnected
        assert edge._body_slots["token"]._value == 8

    asyncio.run(run())
    assert "escrita_timeout" not in emitted


def test_lost_connection_cancels_deadline(emitted):
    async def run():
        protocol, fake, _ = await _connect(make()[0])
        protocol.pause_writing()
        protocol.connection_lost(None)  # cliente saiu: a pausa acaba sem abortar
        await asyncio.sleep(DRAIN * 1.5)
        assert fake.aborted_at is None

    asyncio.run(run())
    assert emitted == []
