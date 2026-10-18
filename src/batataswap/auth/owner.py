"""Núcleo síncrono de init e autenticação; rotas usam anyio.to_thread.run_sync(check_login, ...)."""

import sqlite3
import time
from dataclasses import dataclass, field

from batataswap.crypto import CryptoError, aad_owner_totp, new_token, token_hash
from batataswap.db import write_transaction

from .passwords import hash_password, verify_password
from .totp import verify

INVALID = "senha ou código inválido"
LOCKED = "Muitas tentativas. Tente de novo em alguns minutos."
DUMMY_HASH = "scrypt$17$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
DEVICE_LIFETIME = 180 * 24 * 3600


@dataclass(frozen=True)
class LoginResult:
    status: str
    message: str = ""
    retry_after: int = 0
    device_token: str | None = field(default=None, repr=False)

    @property
    def ok(self):
        return self.status == "ok"


def create_owner(conn, keyring, password, totp_secret, confirm_code, now):
    """Confirma o TOTP em memória antes de persistir o dono."""
    if conn.execute("SELECT 1 FROM owner WHERE id=1").fetchone():
        raise ValueError("Dono já cadastrado.")
    if not isinstance(totp_secret, bytes) or len(totp_secret) != 20:
        raise ValueError("Segredo TOTP inválido.")
    step = verify(totp_secret, confirm_code, now, -1)
    if step is None:
        raise ValueError("Código TOTP inválido.")
    password_hash = hash_password(password)
    secret_ct = keyring.seal("totp", totp_secret, aad_owner_totp())
    try:
        with write_transaction(conn):
            conn.execute(
                "INSERT INTO owner(id,password_hash,totp_secret_ct,totp_last_step,updated_at) "
                "VALUES (1,?,?,?,?)",
                (password_hash, secret_ct, step, int(now)),
            )
    except sqlite3.IntegrityError:
        raise ValueError("Dono já cadastrado.") from None


def _budget_key(conn, device_token, now):
    if isinstance(device_token, str) and 1 <= len(device_token) <= 256:
        try:
            digest = token_hash(device_token)
        except UnicodeError:
            return "global"
        if conn.execute(
            "SELECT 1 FROM known_devices WHERE token_hash=? AND expires_at>? "
            "AND revoked_at IS NULL",
            (digest, now),
        ).fetchone():
            return "device:" + digest.hex()
    return "global"


def _finish(conn, keyring, reservation, row, code, now, remember_device=False):
    step = None
    if row:
        try:
            secret = keyring.open("totp", row[1], aad_owner_totp())
            step = verify(secret, code, now, row[2])
        except CryptoError:
            pass
    device = None
    if step is not None:
        with write_transaction(conn):
            consumed = (
                conn.execute(
                    "UPDATE owner SET totp_last_step=? WHERE id=1 AND totp_last_step < ?",
                    (step, step),
                ).rowcount
                == 1
            )
            if consumed and remember_device:
                device = new_token("dev_")
                conn.execute(
                    "INSERT INTO known_devices(token_hash,created_at,expires_at) VALUES (?,?,?)",
                    (token_hash(device), int(now), int(now) + DEVICE_LIFETIME),
                )
                conn.execute(
                    "UPDATE known_devices SET revoked_at=? WHERE token_hash IN "
                    "(SELECT token_hash FROM known_devices WHERE revoked_at IS NULL "
                    "AND expires_at>? ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET 10)",
                    (int(now), now),
                )
        if consumed:
            reservation.success()
            return LoginResult("ok", device_token=device)
    return LoginResult("invalido", INVALID)


def check_login(
    conn,
    keyring,
    budget,
    slot,
    password,
    code,
    device_token=None,
    now=None,
    *,
    remember_device=False,
) -> LoginResult:
    now = time.time() if now is None else now
    _apply_unlock(conn, budget)
    key = _budget_key(conn, device_token, now)
    if not slot.acquire():
        return LoginResult("ocupado", "Tente novamente em instantes.")
    try:
        reservation = budget.begin(key)
        if isinstance(reservation, int):
            return LoginResult("trancado", LOCKED, reservation)
        row = conn.execute(
            "SELECT password_hash,totp_secret_ct,totp_last_step FROM owner WHERE id=1"
        ).fetchone()
        valid = verify_password(password, row[0] if row else DUMMY_HASH) and bool(row)
        if not valid:
            return LoginResult("invalido", INVALID)
        return _finish(conn, keyring, reservation, row, code, now, remember_device)
    finally:
        slot.release()


def verify_totp_only(
    conn, keyring, budget, code, device_token=None, now=None, *, budget_key=None
) -> LoginResult:
    now = time.time() if now is None else now
    _apply_unlock(conn, budget)
    key = budget_key if budget_key is not None else _budget_key(conn, device_token, now)
    reservation = budget.begin(key)
    if isinstance(reservation, int):
        return LoginResult("trancado", LOCKED, reservation)
    row = conn.execute(
        "SELECT password_hash,totp_secret_ct,totp_last_step FROM owner WHERE id=1"
    ).fetchone()
    return _finish(conn, keyring, reservation, row, code, now)


def _apply_unlock(conn, budget):
    row = conn.execute("SELECT value FROM meta WHERE key='unlock_requested_at'").fetchone()
    if row:
        budget.apply_unlock(float(row[0]))


def unlock(conn, now):
    with write_transaction(conn):
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES ('unlock_requested_at',?)",
            (str(now),),
        )


def cleanup_known_devices(conn, now):
    with write_transaction(conn):
        return conn.execute(
            "DELETE FROM known_devices WHERE expires_at<=? OR revoked_at IS NOT NULL", (now,)
        ).rowcount
