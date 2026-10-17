import hashlib
import unicodedata

import pytest

from batataswap.auth import passwords

PASSWORD = "uma frase longa e incomum 726!"


def test_hash_roundtrip():
    encoded = passwords.hash_password(PASSWORD, log_n=10)
    assert encoded.startswith("scrypt$10$8$1$")
    assert passwords.verify_password(PASSWORD, encoded)
    assert not passwords.verify_password("outra senha", encoded)
    assert passwords.hash_password(PASSWORD, log_n=10) != encoded


def test_production_parameters(monkeypatch):
    calls = []
    real = hashlib.scrypt

    def capture(*args, **kwargs):
        calls.append(kwargs.copy())
        kwargs["n"] = 1024
        return real(*args, **kwargs)

    monkeypatch.setattr(passwords.hashlib, "scrypt", capture)
    passwords.hash_password(PASSWORD)
    assert calls[0]["n"] == 2**17
    assert (calls[0]["r"], calls[0]["p"], calls[0]["dklen"]) == (8, 1, 32)
    assert len(calls[0]["salt"]) == 16
    assert calls[0]["maxmem"] > 128 * 2**17 * 8


@pytest.mark.parametrize(
    "value",
    ["", "secret", None, "x" * 2048, "scrypt$99$8$1$AA==$AA==", "scrypt$17$999999$1$AA==$AA=="],
)
def test_bad_format(value):
    assert not passwords.verify_password(PASSWORD, value)


def test_tampering():
    value = passwords.hash_password(PASSWORD, log_n=10)
    for changed in (value + "$", value.replace("$8$", "$08$"), value[:-2] + "!!"):
        assert not passwords.verify_password(PASSWORD, changed)


@pytest.mark.parametrize("value", ["short", "x" * 1025, "Password123456", " BATATAFRITA123 "])
def test_invalid_new_password(value):
    with pytest.raises(ValueError) as caught:
        passwords.validate_new_password(value)
    assert value not in str(caught.value)


def test_nfc_and_integrity(monkeypatch):
    value = "uma frase com café e 726!"
    decomposed = unicodedata.normalize("NFD", value)
    assert passwords.validate_new_password(decomposed) == value
    assert passwords.verify_password(decomposed, passwords.hash_password(value, log_n=10))
    monkeypatch.setattr(passwords, "COMMON_PASSWORDS_SHA256", "0" * 64)
    with pytest.raises(RuntimeError, match="alterada"):
        passwords.validate_new_password(PASSWORD)
