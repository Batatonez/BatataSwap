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
    owner.create_owner(conn, keyring, PASSWORD, secret, code_at(secret, NOW // 30 - 2), NOW - 60)
    yield conn, path, keyring, secret
    conn.close()


def test_owner_and_login(setup):
    conn, _, keyring, secret = setup
    with pytest.raises(ValueError, match="já cadastrado"):
        owner.create_owner(
            conn, keyring, PASSWORD, secret, code_at(secret, NOW // 30 - 2), NOW - 60
        )
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


def test_init_confirmation(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    conn = db.connect(tmp_path / "init.db", create=True)
    db.migrate(conn)
    keyring = Keyring(secrets.token_bytes(32))
    secret = generate_secret()
    monkeypatch.setattr(owner, "hash_password", lambda pw: passwords.hash_password(pw, log_n=10))
    try:
        with pytest.raises(ValueError, match="TOTP"):
            owner.create_owner(conn, keyring, PASSWORD, secret, "bad", NOW)
        assert conn.execute("SELECT count(*) FROM owner").fetchone()[0] == 0
        owner.create_owner(conn, keyring, PASSWORD, secret, code_at(secret, NOW // 30), NOW)
        assert conn.execute("SELECT totp_last_step FROM owner").fetchone()[0] == NOW // 30
        assert not owner.verify_totp_only(
            conn, keyring, Budget(), code_at(secret, NOW // 30), now=NOW
        ).ok
    finally:
        conn.close()


def test_unlock_across_processes(setup):
    conn, path, keyring, _ = setup
    other = db.connect(path)
    budgets = [Budget(max_failures=1), Budget(max_failures=1)]
    try:
        for connection, budget in zip((conn, other), budgets):
            budget.fail("global")
            budget.fail("device:test")
        owner.unlock(other, NOW)
        for connection, budget in zip((conn, other), budgets):
            result = owner.verify_totp_only(connection, keyring, budget, "bad", now=NOW)
            assert result.status == "invalido"
            assert budget.check("device:test") == 0
            assert (
                owner.verify_totp_only(connection, keyring, budget, "bad", now=NOW).status
                == "trancado"
            )
        owner.unlock(conn, NOW + 1)
        for connection, budget in zip((conn, other), budgets):
            assert (
                owner.check_login(
                    connection, keyring, budget, ScryptSlot(), "bad", "bad", now=NOW
                ).status
                == "invalido"
            )
    finally:
        other.close()


@pytest.mark.parametrize("login", [False, True])
def test_only_one_evaluated(setup, monkeypatch, login):
    _, path, keyring, _ = setup
    budget = Budget(max_failures=1)
    calls = []

    def invalid(*args):
        calls.append(1)
        return False if login else None

    monkeypatch.setattr(owner, "verify_password" if login else "verify", invalid)
    slot = ScryptSlot()

    def attempt(_):
        conn = db.connect(path)
        try:
            if login:
                return owner.check_login(conn, keyring, budget, slot, PASSWORD, "bad", now=NOW)
            return owner.verify_totp_only(conn, keyring, budget, "bad", now=NOW)
        finally:
            conn.close()

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert len(calls) == 1
    assert sum(r.status == "invalido" for r in results) == 1


@pytest.mark.parametrize("code", ["1234567", "abcdef"])
def test_invalid_code_consumes_budget(setup, code):
    conn, _, keyring, _ = setup
    step = conn.execute("SELECT totp_last_step FROM owner").fetchone()[0]
    budget = Budget(max_failures=1)
    assert not owner.check_login(conn, keyring, budget, ScryptSlot(), PASSWORD, code, now=NOW).ok
    assert budget.check("global") > 0
    assert conn.execute("SELECT totp_last_step FROM owner").fetchone()[0] == step


def test_known_device_totp_and_surrogate(setup):
    conn, _, keyring, _ = setup
    token = "dev_known"
    conn.execute(
        "INSERT INTO known_devices VALUES (?,?,?,NULL)", (token_hash(token), NOW, NOW + 100)
    )
    budget = Budget(max_failures=1)
    budget.fail("global")
    assert owner.verify_totp_only(conn, keyring, budget, "bad", token, NOW).status == "invalido"
    assert budget.check("device:" + token_hash(token).hex()) > 0
    assert owner.verify_totp_only(conn, keyring, budget, "bad", "\ud800", NOW).status == "trancado"


def test_device_limit_and_cleanup(setup):
    conn, _, keyring, secret = setup
    tokens = []
    for i in range(11):
        now = NOW + 30 * i
        result = owner.check_login(
            conn,
            keyring,
            Budget(),
            ScryptSlot(),
            PASSWORD,
            code_at(secret, now // 30),
            now=now,
            remember_device=True,
        )
        assert result.ok
        tokens.append(result.device_token)
    assert (
        conn.execute("SELECT count(*) FROM known_devices WHERE revoked_at IS NULL").fetchone()[0]
        == 10
    )
    assert (
        conn.execute(
            "SELECT revoked_at FROM known_devices WHERE token_hash=?", (token_hash(tokens[0]),)
        ).fetchone()[0]
        is not None
    )
    assert owner.cleanup_known_devices(conn, NOW + 300) == 1
    assert owner.cleanup_known_devices(conn, NOW + owner.DEVICE_LIFETIME + 301) == 10


def test_missing_owner_uses_dummy_hash(setup, monkeypatch):
    conn, _, keyring, _ = setup
    conn.execute("DELETE FROM owner")
    calls = []
    monkeypatch.setattr(owner, "verify_password", lambda pw, hashed: calls.append(hashed) or True)
    assert not owner.check_login(
        conn, keyring, Budget(), ScryptSlot(), PASSWORD, "123456", now=NOW
    ).ok
    assert calls == [owner.DUMMY_HASH]
