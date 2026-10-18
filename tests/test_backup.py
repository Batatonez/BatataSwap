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


@pytest.fixture
def snapshot(tmp_path):
    from datetime import UTC, datetime

    path = tmp_path / "live.db"
    directory = tmp_path / "backups"
    keyring = crypto.Keyring(b"k" * 32)
    now = int(datetime(2026, 10, 18, tzinfo=UTC).timestamp())
    with closing(db.connect(path, create=True)) as conn:
        db.migrate(conn)
        conn.execute("INSERT INTO meta VALUES ('marker','original')")
        source = backup.backup(conn, directory, now)
    return path, directory, keyring, now, source


def test_permissions_and_retention(snapshot):
    from datetime import UTC, datetime, timedelta

    _path, directory, _keyring, now, source = snapshot
    assert source.stat().st_mode & 0o777 == 0o600
    assert source.with_suffix(".json").stat().st_mode & 0o777 == 0o600
    today = datetime.fromtimestamp(now, UTC).date()
    dates = [today - timedelta(days=age) for age in range(70)]
    for date in dates:
        (directory / f"{date}.db").touch()
        (directory / f"{date}.json").touch()
    backup.retain(directory, now)
    weekly = {}
    for date in sorted(dates):
        if 14 <= (today - date).days < 56:
            weekly[date.isocalendar()[:2]] = date
    expected = {date for date in dates if (today - date).days < 14} | set(weekly.values())
    assert {p.stem for p in directory.glob("*.db")} == {str(date) for date in expected}
    assert {p.stem for p in directory.glob("*.json")} == {str(date) for date in expected}


@pytest.mark.parametrize("mode", ["outside", "symlink", "parent", "manifest"])
def test_restore_rejects_paths(snapshot, tmp_path, mode):
    path, directory, keyring, now, source = snapshot
    if mode == "outside":
        candidate = tmp_path / "outside.db"
        candidate.write_bytes(source.read_bytes())
    elif mode == "symlink":
        candidate = directory / "link.db"
        candidate.symlink_to(source)
    elif mode == "parent":
        candidate = directory / ".." / "backups" / source.name
    else:
        metadata = source.with_suffix(".json")
        data = metadata.read_bytes()
        metadata.unlink()
        other = tmp_path / "metadata"
        other.write_bytes(data)
        metadata.symlink_to(other)
        candidate = source
    with pytest.raises(ValueError):
        backup.restore(candidate, path, directory, keyring, now)


@pytest.mark.parametrize("mode", ["missing", "orphan", "existing"])
def test_restore_sidecars(snapshot, tmp_path, mode):
    from pathlib import Path

    path, directory, keyring, now, source = snapshot
    # Um WAL real contém metadados diferentes dos da cópia restaurada.
    other = tmp_path / "other.db"
    live = db.connect(other, create=True)
    try:
        db.migrate(live)
        live.execute("PRAGMA wal_autocheckpoint=0")
        live.execute("INSERT INTO meta VALUES ('marker','velho')")
        sidecars = {suffix: Path(str(other) + suffix).read_bytes() for suffix in ("-wal", "-shm")}
        if mode != "existing":
            path.unlink()
        if mode != "missing":
            for suffix, data in sidecars.items():
                Path(str(path) + suffix).write_bytes(data)
                Path(str(path) + suffix).chmod(0o600)
        backup.restore(source, path, directory, keyring, now)
    finally:
        live.close()
    with closing(db.connect(path)) as conn:
        assert conn.execute("SELECT value FROM meta WHERE key='marker'").fetchone() == ("original",)
        assert conn.execute("SELECT value FROM meta WHERE key='restore_epoch'").fetchone() == ("1",)
    folders = list(tmp_path.glob("antes-do-restore-*"))
    if mode == "missing":
        assert not folders
    else:
        assert folders
        assert (folders[0] / (path.name + "-wal")).exists()
        assert (folders[0] / (path.name + "-shm")).exists()
        assert (folders[0] / path.name).exists() == (mode == "existing")


def test_restore_refuses_open_connection(snapshot):
    import sqlite3

    path, directory, keyring, now, source = snapshot
    with closing(db.connect(path)) as conn:
        conn.execute("SELECT * FROM meta").fetchall()
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            backup.restore(source, path, directory, keyring, now)
        assert not list(path.parent.glob("antes-do-restore-*"))


@pytest.mark.parametrize("mode", ["count", "aad", "key"])
def test_restore_test_detects_corruption(snapshot, mode):
    import json

    path, directory, keyring, now, source = snapshot
    with closing(db.connect(path)) as conn:
        ciphertext = keyring.seal(
            "totp", b"t" * 20, b"wrong-aad" if mode == "aad" else crypto.aad_owner_totp()
        )
        conn.execute("INSERT INTO owner VALUES (1,?,?,?,?)", ("hash", ciphertext, 0, 0))
        backup.backup(conn, directory, now)
    if mode == "count":
        metadata = source.with_suffix(".json")
        manifest = json.loads(metadata.read_text())
        manifest["contagens"]["owner"] = 99
        metadata.write_text(json.dumps(manifest))
    if mode == "key":
        keyring = crypto.Keyring(b"x" * 32)
    with pytest.raises((ValueError, crypto.CryptoError)):
        backup.restore_test(directory, keyring)
