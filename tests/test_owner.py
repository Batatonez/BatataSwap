import secrets
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from batataswap import db
from batataswap.auth import owner, passwords
from batataswap.auth.ratelimit import Budget, ScryptSlot
from batataswap.auth.totp import code_at, generate_secret
from batataswap.crypto import Keyring, aad_owner_totp, token_hash

PASSWORD = "uma frase longa e incomum 726!"
NOW = 1800000000


@pytest.fixture
def setup(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    path = tmp_path / "owner.db"
    conn = db.connect(path, create=True)
    db.migrate(conn)
    keyring = Keyring(secrets.token_bytes(32))
    secret = generate_secret()
    monkeypatch.setattr(owner, "hash_password", lambda pw: passwords.hash_password(pw, log_n=10))
    owner.create_owner(conn, keyring, PASSWORD, secret)
    yield conn, path, keyring, secret
    conn.close()


def test_owner_and_login(setup):
    conn, _, keyring, secret = setup
    with pytest.raises(ValueError, match="já cadastrado"):
        owner.create_owner(conn, keyring, PASSWORD, secret)
    encrypted = conn.execute("SELECT totp_secret_ct FROM owner").fetchone()[0]
    assert encrypted != secret
    assert keyring.open("totp", encrypted, aad_owner_totp()) == secret
    budget, slot = Budget(), ScryptSlot()
    code = code_at(secret, NOW // 30)
    for pw, otp in (("errada", code), (PASSWORD, "invalido")):
        result = owner.check_login(conn, keyring, budget, slot, pw, otp, now=NOW)
        assert result.message == owner.INVALID
    result = owner.check_login(
        conn,
        keyring,
        budget,
        slot,
        PASSWORD,
        code,
        now=NOW,
        remember_device=True,
    )
    assert result.ok and result.device_token
    assert result.device_token not in repr(result)
    row = conn.execute("SELECT token_hash, expires_at FROM known_devices").fetchone()
    assert row == (token_hash(result.device_token), NOW + 180 * 86400)
    assert not owner.verify_totp_only(conn, keyring, budget, code, now=NOW).ok
    assert owner.verify_totp_only(
        conn,
        keyring,
        budget,
        code_at(secret, NOW // 30 + 1),
        now=NOW + 30,
    ).ok


def test_device_budget_expired_revoked_and_shared(setup):
    conn, _, keyring, secret = setup
    budget, slot = Budget(max_failures=1), ScryptSlot()
    token = owner.check_login(
        conn,
        keyring,
        budget,
        slot,
        PASSWORD,
        code_at(secret, NOW // 30),
        now=NOW,
        remember_device=True,
    ).device_token
    owner.verify_totp_only(conn, keyring, budget, "bad", now=NOW)
    assert (
        owner.check_login(conn, keyring, budget, slot, PASSWORD, "bad", now=NOW).status
        == "trancado"
    )
    assert owner.check_login(
        conn,
        keyring,
        budget,
        slot,
        PASSWORD,
        code_at(secret, NOW // 30 + 1),
        token,
        now=NOW + 30,
    ).ok
    for sql in (
        "UPDATE known_devices SET expires_at=0",
        "UPDATE known_devices SET expires_at=9999999999,revoked_at=1",
    ):
        conn.execute(sql)
        assert (
            owner.check_login(
                conn,
                keyring,
                budget,
                slot,
                PASSWORD,
                "bad",
                token,
                now=NOW,
            ).status
            == "trancado"
        )
    assert (
        owner.check_login(
            conn,
            keyring,
            budget,
            slot,
            PASSWORD,
            "bad",
            "forjado",
            now=NOW,
        ).status
        == "trancado"
    )


def test_atomic_consumption(setup, monkeypatch):
    _, path, keyring, secret = setup
    barrier = Barrier(2)
    budget = Budget()
    original_verify = owner.verify

    def synchronized_verify(*args):
        step = original_verify(*args)
        barrier.wait(timeout=5)
        return step

    monkeypatch.setattr(owner, "verify", synchronized_verify)

    def attempt(_):
        conn = db.connect(path)
        try:
            return owner.verify_totp_only(
                conn,
                keyring,
                budget,
                code_at(secret, NOW // 30),
                now=NOW,
            ).ok
        finally:
            conn.close()

    with ThreadPoolExecutor(2) as pool:
        assert sum(pool.map(attempt, range(2))) == 1


def test_slot_busy(setup):
    conn, _, keyring, _ = setup
    slot = ScryptSlot(timeout=0)
    assert slot.acquire()
    try:
        assert (
            owner.check_login(
                conn,
                keyring,
                Budget(),
                slot,
                PASSWORD,
                "123456",
                now=NOW,
            ).status
            == "ocupado"
        )
    finally:
        slot.release()
