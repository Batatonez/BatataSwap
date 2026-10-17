"""TOTP RFC 6238 SHA-1, com proteção contra replay pelo step consumido."""

import base64
import hashlib
import hmac
import io
import secrets
import struct
from urllib.parse import quote, urlencode

import segno


def generate_secret() -> bytes:
    return secrets.token_bytes(20)


def _code_at(secret: bytes, step: int, digits: int = 6) -> str:
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(number % 10**digits).zfill(digits)


def code_at(secret: bytes, step: int) -> str:
    return _code_at(secret, step)


def verify(secret: bytes, code: str, now: float, last_step: int) -> int | None:
    if not isinstance(code, str) or len(code) > 64:
        return None
    cleaned = "".join(code.split())
    if len(cleaned) != 6 or any(c not in "0123456789" for c in cleaned):
        return None
    step = int(now // 30)
    accepted = None
    for candidate in range(max(0, step - 1), step + 2):
        matches = hmac.compare_digest(code_at(secret, candidate), cleaned)
        if matches and candidate > last_step:
            accepted = candidate
    return accepted


def provisioning_uri(secret: bytes, account: str = "davi", issuer: str = "BatataSwap") -> str:
    label = quote(f"{issuer}:{account}", safe="")
    query = urlencode(
        {
            "secret": base64.b32encode(secret).decode().rstrip("="),
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def qr_text(uri: str) -> str:
    output = io.StringIO()
    segno.make(uri, micro=False).terminal(out=output, compact=True)
    return output.getvalue()
