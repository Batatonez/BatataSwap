"""Senhas scrypt com formato restrito e lista local verificada."""

import base64
import hashlib
import hmac
import secrets
import unicodedata
from importlib.resources import files

COMMON_PASSWORDS_SHA256 = "76727f6eb25eda1d4faf612f9dcad8927e6d9ea446d2bdb4073a82735e1326c2"


def _common_passwords():
    payload = files("batataswap.auth").joinpath("data/common_passwords.txt").read_bytes()
    if hashlib.sha256(payload).hexdigest() != COMMON_PASSWORDS_SHA256:
        raise RuntimeError("Lista de senhas comuns alterada.")
    return frozenset(line.strip().casefold() for line in payload.decode().splitlines())


def validate_new_password(pw: str) -> str:
    """Valida e devolve a senha em NFC; não remove espaços da senha armazenada."""
    if not isinstance(pw, str):
        raise TypeError("Senha inválida.")
    pw = unicodedata.normalize("NFC", pw)
    if not 12 <= len(pw) <= 1024:
        raise ValueError("A senha deve ter entre 12 e 1024 caracteres.")
    if pw.strip().casefold() in _common_passwords():
        raise ValueError("Escolha uma senha menos comum.")
    try:
        pw.encode("utf-8")
    except UnicodeError:
        raise ValueError("Senha inválida.") from None
    return pw


def _derive(pw, salt, log_n):
    return hashlib.scrypt(
        unicodedata.normalize("NFC", pw).encode("utf-8"),
        salt=salt,
        n=2**log_n,
        r=8,
        p=1,
        dklen=32,
        maxmem=256 * 1024**2,
    )


def hash_password(pw: str, *, log_n: int = 17) -> str:
    """Produção usa 17; valores menores existem apenas para testes."""
    pw = validate_new_password(pw)
    if type(log_n) is not int or not 10 <= log_n <= 17:
        raise ValueError("Parâmetros de senha inválidos.")
    salt = secrets.token_bytes(16)
    digest = _derive(pw, salt, log_n)
    return (
        f"scrypt${log_n}$8$1${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
    )


def verify_password(pw: str, encoded: str) -> bool:
    try:
        if not isinstance(pw, str) or not 1 <= len(pw) <= 1024:
            return False
        if not isinstance(encoded, str) or len(encoded) > 128:
            return False
        kind, log_n, r, p, salt_text, digest_text = encoded.split("$")
        if kind != "scrypt" or log_n not in {str(i) for i in range(10, 18)}:
            return False
        if r != "8" or p != "1":
            return False
        salt = base64.b64decode(salt_text, validate=True)
        digest = base64.b64decode(digest_text, validate=True)
        if len(salt) != 16 or len(digest) != 32:
            return False
        if base64.b64encode(salt).decode() != salt_text:
            return False
        if base64.b64encode(digest).decode() != digest_text:
            return False
        return hmac.compare_digest(_derive(pw, salt, int(log_n)), digest)
    except (ValueError, TypeError, UnicodeError):
        return False
