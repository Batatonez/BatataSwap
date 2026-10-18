"""Prazo de escrita no nível da conexão (§8, T16).

Um cliente que não lê a resposta enche o buffer de envio; o uvicorn então pausa a escrita e
toda chamada ``send`` fica em ``FlowControl.drain()`` sem prazo. Isso vale para qualquer
resposta: do app, da borda, o 500 de fallback do próprio uvicorn e o SSE do ``/mcp``. A borda
não consegue resolver sozinha, porque o 500 do uvicorn é enviado fora dela.

Aqui a escrita pausada ganha prazo: se a conexão ficar com a escrita pausada por mais de
``WRITE_DRAIN_TIMEOUT`` segundos seguidos, o transporte é abortado (``abort()``, que descarta o
buffer e fecha na hora) e o ciclo atual é marcado como desconectado. Daí em diante o uvicorn
trata a conexão como se o cliente tivesse saído: ``send`` vira no-op, ``receive`` devolve
``http.disconnect`` e a tarefa termina. O prazo é contado desde a pausa, e não por chamada de
``drain()``, para que um segundo envio (ex.: o 500 depois de uma exceção) não reinicie o
relógio, e para valer mesmo quando ninguém está esperando no ``drain()``.

Por que não levantar exceção no ``drain()``: se quem está esperando é o
``send_500_response`` do uvicorn (já dentro do ``except`` do ``run_asgi``), a exceção escaparia
da tarefa sem ninguém para recolher. Marcar o ciclo como desconectado usa o caminho que o
próprio uvicorn já tem para cliente que caiu.

Acoplamento com o uvicorn, conferido na versão 0.54.0 (``requirements.lock``):
- ``H11Protocol.connection_made`` cria ``self.flow = FlowControl(transport)``; o
  ``RequestResponseCycle`` recebe esse mesmo objeto em ``handle_events``;
- ``H11Protocol.pause_writing``/``resume_writing`` repassam para ``self.flow``;
- ``RequestResponseCycle.send`` só chama ``flow.drain()`` se ``flow.write_paused`` e
  ``not self.disconnected``, e retorna sem escrever quando ``self.disconnected``;
- ``H11Protocol.connection_lost`` chama ``self.flow.resume_writing()``.
``tests/test_review032.py`` falha se esses nomes mudarem.
"""

import asyncio
from collections.abc import Callable

from uvicorn.protocols.http.flow_control import FlowControl
from uvicorn.protocols.http.h11_impl import H11Protocol

from batataswap import logs

# Segundos seguidos com a escrita pausada antes de abortar a conexão. Um cliente legítimo que
# lê a resposta não fica tanto tempo com o buffer cheio.
WRITE_DRAIN_TIMEOUT = 10


class DeadlineFlowControl(FlowControl):
    """``FlowControl`` cuja pausa de escrita expira em ``WRITE_DRAIN_TIMEOUT`` segundos."""

    def __init__(
        self,
        transport: asyncio.Transport,
        loop: asyncio.AbstractEventLoop,
        on_expire: Callable[[], None],
    ) -> None:
        super().__init__(transport)
        self._loop = loop
        self._on_expire = on_expire
        self._timer: asyncio.TimerHandle | None = None
        self.expired = False

    def pause_writing(self) -> None:
        if not self.write_paused and not self.expired:
            # Lido na hora, para os testes poderem reduzir o prazo.
            self._timer = self._loop.call_later(WRITE_DRAIN_TIMEOUT, self._expire)
        super().pause_writing()

    def resume_writing(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        super().resume_writing()

    def _expire(self) -> None:
        self._timer = None
        if not self.write_paused or self.expired:
            return
        self.expired = True
        try:
            self._on_expire()
        finally:
            # Acorda quem estiver no drain(); o ciclo já está marcado como desconectado.
            super().resume_writing()


class DeadlineH11Protocol(H11Protocol):
    """``H11Protocol`` com prazo de escrita. Use em ``uvicorn.run(..., http=...)``."""

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        self.flow = DeadlineFlowControl(transport, self.loop, self._write_expired)

    def _write_expired(self) -> None:
        cycle = self.cycle
        if cycle is not None and not cycle.response_complete:
            cycle.disconnected = True
            cycle.keep_alive = False
            cycle.message_event.set()
        self.transport.abort()
        logs.emit("escrita_timeout")
