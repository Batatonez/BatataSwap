"""CIMD em lista fechada (§4.4), sem rede: fetcher falso e MockTransport do httpx2."""

import json
import secrets
import time

import httpx2
import pytest

from batataswap import db
from batataswap.auth import cimd
from batataswap.auth.cimd import CLAUDE_REDIRECT_URI, CIMDError, FetchResult, resolve_client
from batataswap.config import CLAUDE_CIMD_CLIENT_ID, Config
from tests.test_oauth import FakeFetcher, claude_document

ORIGIN = "https://batatarp.exemplo.ts.net"
NOW = 1_800_000_000


@pytest.fixture
def conn(tmp_path):
    tmp_path.chmod(0o700)
    connection = db.connect(tmp_path / "c.db", create=True)
    db.migrate(connection)
    yield connection
    connection.close()


@pytest.fixture
def config():
    return Config(public_origin=ORIGIN, vercel_origin="https://batataswap.vercel.app")


def test_resolve_claude_and_cache(conn, config):
    fetcher = FakeFetcher(headers={"cache-control": "public, max-age=600"})
    info = resolve_client(conn, config, CLAUDE_CIMD_CLIENT_ID, fetcher, NOW)
    assert (info.kind, info.client_name, info.redirect_uri) == (
        "cimd",
        "Claude",
        CLAUDE_REDIRECT_URI,
    )
    assert fetcher.calls == [(CLAUDE_CIMD_CLIENT_ID, 64 * 1024, 5.0)]
    stored = json.loads(conn.execute("SELECT metadata_json FROM oauth_clients").fetchone()[0])
    assert stored == {
        "client_id": CLAUDE_CIMD_CLIENT_ID,
        "client_name": "Claude",
        "redirect_uris": [CLAUDE_REDIRECT_URI],
    }  # só o necessário; logo_uri nunca é guardado nem buscado
    resolve_client(conn, config, CLAUDE_CIMD_CLIENT_ID, fetcher, NOW + 599)
    assert len(fetcher.calls) == 1
    resolve_client(conn, config, CLAUDE_CIMD_CLIENT_ID, fetcher, NOW + 600)
    assert len(fetcher.calls) == 2
    # Venceu e a busca falhou: falha fechada, mesmo com cache antigo no banco.
    broken = FakeFetcher(error=CIMDError("tempo esgotado"))
    with pytest.raises(CIMDError):
        resolve_client(conn, config, CLAUDE_CIMD_CLIENT_ID, broken, NOW + 600 + 3600)


@pytest.mark.parametrize(
    "headers, seconds",
    [
        ({}, 300),
        ({"cache-control": "max-age=10"}, 300),
        ({"cache-control": "no-store"}, 300),
        ({"cache-control": "max-age=999999"}, 86400),
        ({"cache-control": "max-age=7200"}, 7200),
        ({"expires": "Fri, 22 Jan 2027 08:00:00 GMT"}, 86400),
        ({"expires": "lixo"}, 300),
    ],
)
def test_cache_bounds(headers, seconds):
    assert cimd._cache_seconds(headers, NOW) == seconds


def test_unknown_client_never_fetches(conn, config):
    fetcher = FakeFetcher()
    for client_id in (
        "https://evil.example/cimd",
        "https://claude.ai/oauth/claude-code-client-metadata",
        CLAUDE_CIMD_CLIENT_ID + "/",
        "",
        None,
    ):
        with pytest.raises(CIMDError):
            resolve_client(conn, config, client_id, fetcher, NOW)
    assert fetcher.calls == []


def test_non_443_port_refused(conn):
    config = Config(public_origin=ORIGIN, allowed_cimd_client_ids=["https://claude.ai:8443/m"])
    fetcher = FakeFetcher()
    with pytest.raises(CIMDError):
        resolve_client(conn, config, "https://claude.ai:8443/m", fetcher, NOW)
    assert fetcher.calls == []


@pytest.mark.parametrize(
    "fetcher",
    [
        FakeFetcher(body=claude_document(client_id="https://claude.ai/outro")),
        FakeFetcher(body=claude_document(client_id=None)),
        FakeFetcher(body=claude_document(redirect_uris=None)),
        FakeFetcher(body=claude_document(redirect_uris=["http://claude.ai/api/mcp/auth_callback"])),
        FakeFetcher(body=claude_document(redirect_uris=CLAUDE_REDIRECT_URI)),
        FakeFetcher(body=claude_document(token_endpoint_auth_method="client_secret_basic")),
        FakeFetcher(body=claude_document(client_name=None)),
        FakeFetcher(body=claude_document(client_name=" \n")),
        FakeFetcher(body=b"[1, 2]"),
        FakeFetcher(body=b"nao e json"),
        FakeFetcher(body=b"\xff\xfe"),
        FakeFetcher(body=b" " * (64 * 1024 + 1)),
        FakeFetcher(status=302, headers={"location": "https://evil.example/cimd"}),
        FakeFetcher(status=500),
        FakeFetcher(error=CIMDError("tempo esgotado")),
    ],
)
def test_invalid_documents(conn, config, fetcher):
    with pytest.raises(CIMDError) as caught:
        resolve_client(conn, config, CLAUDE_CIMD_CLIENT_ID, fetcher, NOW)
    assert "evil" not in str(caught.value)
    assert conn.execute("SELECT count(*) FROM oauth_clients").fetchone()[0] == 0


def test_client_name_sanitized(conn, config):
    fetcher = FakeFetcher(body=claude_document(client_name="Cla\u202eude\x00" + "x" * 300))
    info = resolve_client(conn, config, CLAUDE_CIMD_CLIENT_ID, fetcher, NOW)
    assert "\u202e" not in info.client_name and "\x00" not in info.client_name
    assert len(info.client_name) <= 100


def test_painel_static_client(conn, config):
    info = resolve_client(conn, config, "painel-vercel", FakeFetcher(), NOW)
    assert info.kind == "static"
    assert info.redirect_uri == "https://batataswap.vercel.app/callback"
    again = resolve_client(conn, config, "painel-vercel", FakeFetcher(), NOW + 5)
    assert again.row_id == info.row_id
    with pytest.raises(CIMDError):
        resolve_client(conn, Config(public_origin=ORIGIN), "painel-vercel", FakeFetcher(), NOW)


# ---------------------------------------------------------------------------
# Fetcher real (httpx2) com transporte falso
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_http(monkeypatch):
    state = {"handler": None, "kwargs": None, "requests": []}
    real = httpx2.Client

    def factory(**kwargs):
        state["kwargs"] = kwargs

        def handler(request):
            state["requests"].append(request)
            return state["handler"](request)

        return real(transport=httpx2.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx2, "Client", factory)
    return state


def test_httpx_fetcher_ok(mock_http):
    mock_http["handler"] = lambda r: httpx2.Response(
        200, stream=httpx2.ByteStream(claude_document()), headers={"cache-control": "max-age=60"}
    )
    result = cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID)
    assert isinstance(result, FetchResult) and result.status == 200
    assert result.headers["cache-control"] == "max-age=60"
    assert mock_http["kwargs"]["follow_redirects"] is False
    assert mock_http["kwargs"]["trust_env"] is False
    request = mock_http["requests"][0]
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"


def test_httpx_fetcher_does_not_follow_redirect(mock_http):
    mock_http["handler"] = lambda r: httpx2.Response(
        302, headers={"location": "https://evil.example/"}, stream=httpx2.ByteStream(b"")
    )
    result = cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID)
    assert result.status == 302 and len(mock_http["requests"]) == 1
    with pytest.raises(CIMDError):
        cimd.validate_document(CLAUDE_CIMD_CLIENT_ID, result, CLAUDE_REDIRECT_URI)


def test_httpx_fetcher_too_big(mock_http):
    mock_http["handler"] = lambda r: httpx2.Response(
        200, stream=httpx2.ByteStream(b"x" * (64 * 1024 + 1))
    )
    with pytest.raises(CIMDError):
        cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID)


def test_httpx_fetcher_compressed_refused(mock_http):
    mock_http["handler"] = lambda r: httpx2.Response(
        200, content=b"x", headers={"content-encoding": "gzip"}
    )
    with pytest.raises(CIMDError):
        cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID)


def test_httpx_fetcher_timeout_and_network(mock_http):
    secret = secrets.token_hex(8)

    def timeout(request):
        raise httpx2.ReadTimeout("lento " + secret, request=request)

    mock_http["handler"] = timeout
    with pytest.raises(CIMDError) as caught:
        cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID)
    assert secret not in str(caught.value) and caught.value.__cause__ is None

    def down(request):
        raise httpx2.ConnectError("sem rede", request=request)

    mock_http["handler"] = down
    with pytest.raises(CIMDError):
        cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID)


# ---------------------------------------------------------------------------
# Prazo global (revisão I2): atraso na conexão/headers ou no corpo não passa do timeout
# ---------------------------------------------------------------------------


class _SlowBody(httpx2.SyncByteStream):
    def __init__(self, pieces, delay):
        self.pieces = pieces
        self.delay = delay

    def __iter__(self):
        for piece in self.pieces:
            time.sleep(self.delay)
            yield piece


def _timed(call):
    started = time.monotonic()
    with pytest.raises(CIMDError) as caught:
        call()
    return time.monotonic() - started, caught.value


def test_httpx_fetcher_deadline_on_connect_or_headers(mock_http):
    def slow(request):
        time.sleep(1.5)  # conexão ou headers demorando
        return httpx2.Response(200, stream=httpx2.ByteStream(claude_document()))

    mock_http["handler"] = slow
    elapsed, error = _timed(lambda: cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID, timeout=0.3))
    assert elapsed < 1.0 and "tempo esgotado" in str(error)


def test_httpx_fetcher_deadline_on_slow_body(mock_http):
    mock_http["handler"] = lambda r: httpx2.Response(200, stream=_SlowBody([b"{"] * 20, 0.1))
    elapsed, error = _timed(lambda: cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID, timeout=0.35))
    assert elapsed < 1.0 and "tempo esgotado" in str(error)


def test_httpx_fetcher_deadline_on_stalled_body(mock_http):
    mock_http["handler"] = lambda r: httpx2.Response(200, stream=_SlowBody([b"{", b"}"], 1.5))
    elapsed, _ = _timed(lambda: cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID, timeout=0.3))
    assert elapsed < 1.0


def test_httpx_fetcher_default_timeout_is_global(mock_http):
    mock_http["handler"] = lambda r: httpx2.Response(200, stream=httpx2.ByteStream(b"{}"))
    cimd.httpx_fetcher(CLAUDE_CIMD_CLIENT_ID)
    timeout = mock_http["kwargs"]["timeout"]
    assert isinstance(timeout, httpx2.Timeout)
    assert timeout.connect == timeout.read == timeout.write == timeout.pool == 5.0
