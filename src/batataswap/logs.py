"""Eventos fechados: nunca serializa argumentos nem exceções."""

import contextlib
import json
import re
import socket
import threading
import time

EVENTS = frozenset(
    [
        "login_ok",
        "login_falhou",
        "login_trancado",
        "grant_criado",
        "grant_revogado",
        "token_emitido",
        "refresh_reuso",
        "refresh_reuso_tolerado",
        "sem_vaga_corpo",
        "codigo_reuso",
        "ferramenta",
        "limite",
        "backup_ok",
        "backup_falhou",
        "restore_teste_ok",
        "restore_teste_falhou",
        "restore_feito",
        "authorize_limite",
        "authorize_recusado",
        "transacao_criada",
        "transacao_invalida",
        "consentimento_cancelado",
        "token_recusado",
        "token_revogado",
        "caminho_invalido",
        "corpo_grande",
        "corpo_timeout",
        "envio_timeout",
        "escrita_timeout",
        "credencial_ausente",
        "erro_interno",
        "host_duplicado",
        "host_invalido",
        "metodo_nao_permitido",
        "origem_recusada",
        "preflight_aceito",
        "preflight_recusado",
        "repassado",
        "requisicao_invalida",
        "rota_inexistente",
        "token_na_query",
        "websocket_recusado",
    ]
)
TOOLS = frozenset(
    [
        "salvar_contexto",
        "buscar_contexto",
        "listar_projetos",
        "registrar_preferencia",
        "listar_preferencias",
        "buscar",
        "apagar",
        "anexar_mensagens",
        "ler_conversa",
    ]
)


ADMIN = False


# Eventos que um visitante anônimo consegue disparar em rajada. Por (evento, status), cada
# janela de AGGREGATE_WINDOW segundos publica a primeira linha na hora e o resto vira contador,
# publicado pelo próximo evento igual depois da janela ou pelo ``flush`` periódico/no shutdown.
_AGGREGATED = {
    "credencial_ausente",
    "requisicao_invalida",
    "sem_vaga_corpo",
    "rota_inexistente",
    "corpo_timeout",
    "envio_timeout",
    "escrita_timeout",
    "token_recusado",
    "repassado",
}
AGGREGATE_WINDOW = 10
_counts = {}
_counts_lock = threading.Lock()


def flush(*, force=False):
    """Publica os contadores pendentes cuja janela já fechou (todos, com ``force``).

    O app chama periodicamente e no encerramento, para o fim de uma rajada não sumir.
    """
    pending = []
    with _counts_lock:
        now = time.monotonic()
        for key, (last, count) in list(_counts.items()):
            if count and (force or now - last >= AGGREGATE_WINDOW):
                _counts[key] = (now, 0)
                pending.append((key, count))
    for (evento, status), count in pending:
        _write(evento, status, contador=count)


def emit(evento, status=None, *, ms=None, grant=None, tamanho=None, nivel="info", ferramenta=None):
    if type(evento) is not str or evento not in EVENTS:
        return
    count = None
    if evento in _AGGREGATED:
        key = (evento, status if type(status) is int else None)
        with _counts_lock:
            now = time.monotonic()
            last, count = _counts.get(key, (float("-inf"), 0))
            count += 1
            if now - last < AGGREGATE_WINDOW:
                _counts[key] = (last, count)
                return
            _counts[key] = (now, 0)
    _write(
        evento,
        status,
        ms=ms,
        grant=grant,
        tamanho=tamanho,
        nivel=nivel,
        ferramenta=ferramenta,
        contador=count,
    )


def _write(
    evento,
    status,
    *,
    ms=None,
    grant=None,
    tamanho=None,
    nivel="info",
    ferramenta=None,
    contador=None,
):
    record = dict.fromkeys(("evento", "status", "ms", "grant", "tamanho", "nivel"))
    record["evento"] = evento
    if type(contador) is int and contador > 0:
        record["contador"] = contador
    if type(status) is int and 0 <= status <= 599:
        record["status"] = status
    if type(ms) in (int, float) and 0 <= ms < 1e12:
        record["ms"] = ms
    if type(grant) is str and re.fullmatch(r"grant_[a-z2-7]{16}", grant):
        record["grant"] = grant
    if type(tamanho) is int and 0 <= tamanho < 2**63:
        record["tamanho"] = tamanho
    record["nivel"] = nivel if type(nivel) is str and nivel in {"info", "err"} else "info"
    if type(ferramenta) is str and ferramenta in TOOLS:
        record["ferramenta"] = ferramenta
    line = json.dumps(record, allow_nan=False)
    if record["nivel"] != "err":
        print(line, flush=True)
    # stdout mantém JSON puro; a entrada nativa adicional sinaliza prioridade ao journal.
    if record["nivel"] == "err" or ADMIN:
        with (
            contextlib.suppress(OSError),
            socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as journal,
        ):
            journal.sendto(
                (
                    f"PRIORITY={3 if record['nivel'] == 'err' else 6}\n"
                    f"SYSLOG_IDENTIFIER={'batataswap-admin' if ADMIN else 'batataswap'}\n"
                    f"MESSAGE={line}\n"
                ).encode(),
                "/run/systemd/journal/socket",
            )


def tool(name, response, elapsed, grant=None):
    # Só nomes definidos no código podem entrar no registro.
    if type(name) is str and name in TOOLS:
        from batataswap.tools import response_size

        emit(
            "ferramenta",
            400 if response.is_error else 200,
            ms=elapsed,
            tamanho=response_size(response),
            ferramenta=name,
            grant=grant,
        )
