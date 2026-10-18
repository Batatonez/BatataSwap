import asyncio
import secrets
from types import SimpleNamespace

import pytest

from batataswap import crypto, logs, memory
from batataswap.auth import oauth
from batataswap.auth.routes import bearer_context
from batataswap.cli import terminal_text
from tests.test_edge import call, make


@pytest.mark.parametrize("char", ["\x1b", "\r", "\x00", "\x7f", "\x9b"])
def test_text_rejects_terminal_controls(char):
    with pytest.raises(memory.InvalidInput):
        memory.check_text("texto" + char, "texto", 100)


def test_terminal_escape_and_text_newlines():
    assert terminal_text("\x1b\r\n\t\x9b\u202e") == (r"\u001B\u000D\u000A\u0009\u009B\u202E")
    assert memory.check_text("linha\n\t\u202e", "texto", 100) == "linha\n\t\u202e"


def test_invalid_access_tags_never_connect():
    keyring = crypto.Keyring(secrets.token_bytes(32))
    connections = 0

    def connect():
        nonlocal connections
        connections += 1
        raise AssertionError("não deve abrir banco")

    deps = SimpleNamespace(
        keyring=keyring, config=SimpleNamespace(mcp_resource="https://x/mcp"), connect=connect
    )

    async def run():
        for _ in range(200):
            token = crypto.new_token("bsw_at_") + "." + "A" * 22
            with pytest.raises(oauth.BearerError):
                await bearer_context(deps, {"state": {"bearer": token}}, "mcp")

    asyncio.run(run())
    assert connections == 0


def test_edge_token_requires_length_and_no_chunked():
    edge, toy = make()
    assert call(edge, "POST", "/oauth/token", auto_content_length=False).status == 400
    assert call(edge, "POST", "/oauth/token", [("transfer-encoding", "chunked")]).status == 400
    assert (
        call(
            edge,
            "POST",
            "/oauth/token",
            [("content-length", "0"), ("transfer-encoding", "chunked")],
        ).status
        == 400
    )
    assert toy.calls == 0


def test_get_body_rejected():
    edge, toy = make()
    assert call(edge, chunks=(b"x",)).status == 400
    assert call(edge, "HEAD", headers=[("content-length", "1")]).status == 400
    assert toy.calls == 0


def test_edge_logs_aggregate(monkeypatch, capsys):
    monkeypatch.setattr(logs, "_counts", {})
    now = [0.0]
    monkeypatch.setattr(logs.time, "monotonic", lambda: now[0])
    for _ in range(200):
        logs.emit("credencial_ausente", 401)
    assert capsys.readouterr().out.count("\n") == 1
    now[0] = 10
    logs.emit("credencial_ausente", 401)
    assert '"contador": 200' in capsys.readouterr().out
