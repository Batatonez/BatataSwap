"""Client ID Metadata Document (CIMD) em lista fechada (ARQUITETURA §4.4).

Só busca ``client_id`` que esteja exatamente em ``allowed_cimd_client_ids``. A busca é HTTPS
na porta 443, sem seguir redirect, até 64 KiB e com prazo total de 5 s. URLs auxiliares do
documento (``logo_uri``, ``jwks_uri``, ``client_uri``…) nunca são buscadas. Expirou o cache e
a busca falhou: falha fechada (nenhum login novo).

A busca é síncrona e bloqueante: quem chama roda isto fora do event loop.
O ``fetcher`` é injetável para os testes não usarem rede.
"""

import contextlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from batataswap.config import Config
from batataswap.db import write_transaction

MAX_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5.0
MIN_CACHE_SECONDS = 5 * 60
MAX_CACHE_SECONDS = 24 * 3600
CLAUDE_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
STATIC_CACHE_SECONDS = 10 * 365 * 24 * 3600
PAINEL_CLIENT_NAME = "Painel BatataSwap"
_CLIENT_NAME_MAX = 100


class CIMDError(Exception):
    """Cliente desconhecido, documento inválido ou busca falhou. Mensagem sem dado externo."""


@dataclass(frozen=True)
class FetchResult:
    status: int
    headers: Mapping[str, str]  # nomes em minúsculas
    body: bytes = field(repr=False)


# fetcher(url, max_bytes, timeout) -> FetchResult; levanta CIMDError em timeout, rede ou excesso.
Fetcher = Callable[[str, int, float], FetchResult]


@dataclass(frozen=True)
class ClientInfo:
    row_id: int
    client_id: str
    kind: str  # "cimd" ou "static"
    client_name: str
    redirect_uri: str  # o redirect da matriz §4.1 (já conferido contra o documento)


_TIMEOUT_MESSAGE = "tempo esgotado ao buscar o documento do cliente"


def _fetch(client, url: str, max_bytes: int, deadline: float) -> FetchResult:
    def check_clock():
        if time.monotonic() >= deadline:
            raise CIMDError(_TIMEOUT_MESSAGE)

    check_clock()
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    with client.stream("GET", url, headers=headers) as response:
        check_clock()
        # Sem compressão: o teto de 64 KiB vale para os bytes que realmente chegam.
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise CIMDError("documento do cliente com codificação inesperada")
        declared = response.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            raise CIMDError("documento do cliente grande demais")
        chunks = []
        size = 0
        for chunk in response.iter_raw():
            check_clock()
            size += len(chunk)
            if size > max_bytes:
                raise CIMDError("documento do cliente grande demais")
            chunks.append(chunk)
        check_clock()
        headers = {k.lower(): v for k, v in response.headers.items()}
        return FetchResult(response.status_code, headers, b"".join(chunks))


def httpx_fetcher(url: str, max_bytes: int = MAX_BYTES, timeout: float = TIMEOUT_SECONDS):
    """Busca real com ``httpx2`` (o httpx que vem com o SDK ``mcp`` 2.x, já no lock).

    ``trust_env=False``: sem proxy nem netrc vindos do ambiente. ``follow_redirects=False``:
    um 3xx volta como está e é recusado na validação.

    O prazo é global (conexão + headers + corpo): a busca roda numa thread própria e quem
    chama espera no máximo ``timeout``. Estourou, o cliente é fechado (o que interrompe a
    leitura em andamento) e a thread morre sozinha, presa também aos prazos por fase do httpx
    e à checagem de relógio antes e depois de cada pedaço do corpo.
    """
    import httpx2  # import tardio: só a busca real precisa do cliente HTTP

    deadline = time.monotonic() + timeout
    box: dict = {}
    try:
        client = httpx2.Client(
            follow_redirects=False, trust_env=False, timeout=httpx2.Timeout(timeout)
        )
    except Exception:  # noqa: BLE001
        raise CIMDError("não foi possível buscar o documento do cliente") from None

    def run():
        try:
            box["result"] = _fetch(client, url, max_bytes, deadline)
        except CIMDError as error:
            box["error"] = error
        except Exception:  # noqa: BLE001 (rede, TLS, timeout: tudo vira o mesmo erro)
            box["error"] = CIMDError("não foi possível buscar o documento do cliente")
        finally:
            with contextlib.suppress(Exception):
                client.close()

    worker = threading.Thread(target=run, name="cimd-fetch", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    if worker.is_alive():
        with contextlib.suppress(Exception):
            client.close()
        raise CIMDError(_TIMEOUT_MESSAGE)
    if "error" in box:
        raise CIMDError(str(box["error"])) from None
    return box["result"]


def _cache_seconds(headers: Mapping[str, str], now: float) -> int:
    seconds = None
    for part in headers.get("cache-control", "").split(","):
        name, _, value = part.strip().partition("=")
        if name.lower() == "max-age" and value.strip().isdigit():
            seconds = int(value.strip())
        elif name.lower() in ("no-store", "no-cache"):
            seconds = 0
    if seconds is None and headers.get("expires"):
        try:
            seconds = int(parsedate_to_datetime(headers["expires"]).timestamp() - now)
        except (TypeError, ValueError, OverflowError):
            seconds = 0
    if seconds is None:
        seconds = 0
    return max(MIN_CACHE_SECONDS, min(MAX_CACHE_SECONDS, seconds))


def validate_document(url: str, result: FetchResult, redirect_uri: str) -> dict:
    """Confere o documento buscado e devolve só os metadados públicos que usamos."""
    if result.status != 200:
        raise CIMDError("documento do cliente indisponível")
    if len(result.body) > MAX_BYTES:
        raise CIMDError("documento do cliente grande demais")
    try:
        document = json.loads(result.body.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        raise CIMDError("documento do cliente não é JSON válido") from None
    if not isinstance(document, dict):
        raise CIMDError("documento do cliente não é um objeto JSON")
    if not isinstance(document.get("client_id"), str) or document["client_id"] != url:
        raise CIMDError("client_id do documento não confere")
    redirects = document.get("redirect_uris")
    if (
        not isinstance(redirects, list)
        or not all(isinstance(r, str) for r in redirects)
        or redirect_uri not in redirects
    ):
        raise CIMDError("documento do cliente sem o redirect esperado")
    if document.get("token_endpoint_auth_method", "none") != "none":
        raise CIMDError("cliente precisa ser público (sem segredo)")
    name = document.get("client_name")
    if not isinstance(name, str) or not name.strip():
        raise CIMDError("documento do cliente sem client_name")
    clean = "".join(ch for ch in name if ch.isprintable()).strip()[:_CLIENT_NAME_MAX]
    if not clean:
        raise CIMDError("documento do cliente sem client_name")
    return {"client_id": url, "client_name": clean, "redirect_uris": [redirect_uri]}


def _upsert(conn: sqlite3.Connection, client_id, kind, metadata, now, cache_until) -> int:
    with write_transaction(conn):
        conn.execute(
            "INSERT INTO oauth_clients(client_id,kind,metadata_json,fetched_at,cache_until) "
            "VALUES (?,?,?,?,?) ON CONFLICT(client_id) DO UPDATE SET kind=excluded.kind, "
            "metadata_json=excluded.metadata_json, fetched_at=excluded.fetched_at, "
            "cache_until=excluded.cache_until",
            (client_id, kind, json.dumps(metadata, ensure_ascii=False), int(now), cache_until),
        )
        return conn.execute(
            "SELECT id FROM oauth_clients WHERE client_id=?", (client_id,)
        ).fetchone()[0]


def is_known_client(config: Config, client_id: object) -> bool:
    """Lista fechada: CIMD da config ou o client estático do painel (se houver Vercel)."""
    if not isinstance(client_id, str):
        return False
    if client_id == config.painel_client_id:
        return config.painel_redirect_uri is not None
    return client_id in config.allowed_cimd_client_ids


def resolve_client(
    conn: sqlite3.Connection, config: Config, client_id: str, fetcher: Fetcher, now: float
) -> ClientInfo:
    """Identifica o cliente pela matriz §4.1. Fora da lista → ``CIMDError`` sem tocar na rede."""
    if not is_known_client(config, client_id):
        raise CIMDError("cliente não autorizado")
    if client_id == config.painel_client_id:
        redirect = config.painel_redirect_uri
        metadata = {
            "client_id": client_id,
            "client_name": PAINEL_CLIENT_NAME,
            "redirect_uris": [redirect],
        }
        row = conn.execute(
            "SELECT id, kind, metadata_json FROM oauth_clients WHERE client_id=?", (client_id,)
        ).fetchone()
        if row is None or row[1] != "static" or json.loads(row[2]) != metadata:
            row_id = _upsert(
                conn, client_id, "static", metadata, now, int(now) + STATIC_CACHE_SECONDS
            )
        else:
            row_id = row[0]
        return ClientInfo(row_id, client_id, "static", PAINEL_CLIENT_NAME, redirect)

    url = urlsplit(client_id)
    if url.scheme != "https" or url.port is not None or url.query or url.fragment:
        raise CIMDError("cliente não autorizado")
    row = conn.execute(
        "SELECT id, kind, metadata_json, cache_until FROM oauth_clients WHERE client_id=?",
        (client_id,),
    ).fetchone()
    if row is not None and row[1] == "cimd" and row[3] > now:
        metadata = json.loads(row[2])
        if CLAUDE_REDIRECT_URI in metadata.get("redirect_uris", []):
            return ClientInfo(
                row[0], client_id, "cimd", metadata["client_name"], CLAUDE_REDIRECT_URI
            )
    result = fetcher(client_id, MAX_BYTES, TIMEOUT_SECONDS)
    if not isinstance(result, FetchResult):
        raise CIMDError("não foi possível buscar o documento do cliente")
    metadata = validate_document(client_id, result, CLAUDE_REDIRECT_URI)
    cache_until = int(now) + _cache_seconds(result.headers, now)
    row_id = _upsert(conn, client_id, "cimd", metadata, now, cache_until)
    return ClientInfo(row_id, client_id, "cimd", metadata["client_name"], CLAUDE_REDIRECT_URI)
