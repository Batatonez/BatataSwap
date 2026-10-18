from contextlib import closing

import pytest

from batataswap import backup, crypto, db


def test_decrypt_invalid_totp(tmp_path):
    with closing(db.connect(tmp_path / "db", create=True)) as conn:
        db.migrate(conn)
        conn.execute(
            "INSERT INTO owner VALUES (1,?,?,?,?)",
            ("hash", b"invalido", 0, 0),
        )
        with pytest.raises(crypto.CryptoError):
            backup.decrypt_all(conn, crypto.Keyring(b"k" * 32))
