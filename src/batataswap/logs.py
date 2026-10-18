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


_AGGREGATED = {"credencial_ausente", "requisicao_invalida", "sem_vaga_corpo", "rota_inexistente"}
_counts = {}
_counts_lock = threading.Lock()


def emit(evento, status=None, *, ms=None, grant=None, tamanho=None, nivel="info", ferramenta=None):
    if type(evento) is not str or evento not in EVENTS:
        return
    count = None
    if evento in _AGGREGATED:
        with _counts_lock:
            now = time.monotonic()
            last, count = _counts.get(evento, (float("-inf"), 0))
            count += 1
            if now - last < 10:
                _counts[evento] = (last, count)
                return
            _counts[evento] = (now, 0)
    record = dict.fromkeys(("evento", "status", "ms", "grant", "tamanho", "nivel"))
    record["evento"] = evento
    if count is not None:
        record["contador"] = count
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
