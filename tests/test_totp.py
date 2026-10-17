from urllib.parse import parse_qs, urlsplit

import pytest

from batataswap.auth.totp import (
    _code_at,
    code_at,
    generate_secret,
    provisioning_uri,
    qr_text,
    verify,
)


# RFC 6238, apêndice B, coluna SHA1, segredo ASCII oficial de 20 bytes.
@pytest.mark.parametrize(
    "now,expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc6238_sha1(now, expected):
    assert _code_at(b"12345678901234567890", now // 30, digits=8) == expected


def test_window_and_replay():
    secret = generate_secret()
    assert len(secret) == 20
    for step in (99, 100, 101):
        code = code_at(secret, step)
        assert verify(secret, code[:3] + " " + code[3:], 3000, 98) == step
        assert verify(secret, code, 3000, step) is None
    assert verify(secret, code_at(secret, 97), 3000, 0) is None
    for code in ("１２３４５６", "12345", "1234567", "123-456", None):
        assert verify(secret, code, 3000, 0) is None


def test_uri_and_terminal():
    uri = provisioning_uri(b"12345678901234567890", account="davi teste")
    assert urlsplit(uri).scheme == "otpauth"
    assert parse_qs(urlsplit(uri).query)["digits"] == ["6"]
    assert "%20" in uri
    assert qr_text(uri)
