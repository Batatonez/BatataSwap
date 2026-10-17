import os
import sqlite3

import pytest

from batataswap.db import DatabaseError, connect, migrate, write_transaction


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "private" / "swap.db"
    conn = connect(path, create=True)
    migrate(conn)
    yield conn, path
    conn.close()


def test_schema_and_idempotence(database):
    conn, _ = database
    expected = {
        "owner",
        "projects",
        "contexts",
        "preferences",
        "conversations",
        "message_batches",
        "messages",
        "oauth_clients",
        "oauth_transactions",
        "oauth_grants",
        "oauth_codes",
        "oauth_tokens",
        "known_devices",
        "panel_sessions",
        "pending_deletions",
        "daily_usage",
        "audit",
        "meta",
        "schema_migrations",
    }
    rows = conn.execute("SELECT name, sql FROM sqlite_schema WHERE type = 'table'").fetchall()
    assert {name for name, _ in rows} == expected
    assert all(sql.rstrip().endswith("STRICT") for _, sql in rows)
    before = conn.execute("SELECT * FROM schema_migrations").fetchall()
    schema = conn.execute("SELECT * FROM sqlite_schema").fetchall()
    migrate(conn)
    assert conn.execute("SELECT * FROM schema_migrations").fetchall() == before
    assert conn.execute("SELECT * FROM sqlite_schema").fetchall() == schema


def test_pragmas_and_permissions(database):
    conn, path = database
    for name, expected in [
        ("journal_mode", "wal"),
        ("foreign_keys", 1),
        ("secure_delete", 1),
        ("busy_timeout", 5000),
        ("synchronous", 2),
    ]:
        assert conn.execute(f"PRAGMA {name}").fetchone()[0] == expected
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


def test_symlink_and_public_directory_rejected(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(DatabaseError):
        connect(link / "swap.db", create=True)
    if os.name == "posix":
        private.chmod(0o755)
        with pytest.raises(DatabaseError):
            connect(private / "swap.db", create=True)


@pytest.mark.parametrize("name_ct,purged_at", [(b"cipher", 1), (None, None)])
def test_project_checks(database, name_ct, purged_at):
    conn, _ = database
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO projects(public_id,name_mac,name_ct,created_at,purged_at) "
            "VALUES (?,?,?,?,?)",
            ("proj_test", b"mac", name_ct, 0, purged_at),
        )


def test_active_label(database):
    conn, _ = database
    conn.execute(
        "INSERT INTO oauth_clients VALUES (?,?,?,?,?,?)", (1, "client", "static", "{}", 0, 0)
    )
    sql = (
        "INSERT INTO oauth_grants(public_id,client_row_id,label,resource,scope,created_at,"
        "expires_at) VALUES (?,?,?,?,?,?,?)"
    )
    conn.execute(sql, ("grant_1", 1, "conta-1", "resource", "memoria", 0, 10))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(sql, ("grant_2", 1, "conta-1", "resource", "memoria", 0, 10))
    conn.execute("UPDATE oauth_grants SET revoked_at = ? WHERE id = ?", (1, 1))
    conn.execute(sql, ("grant_2", 1, "conta-1", "resource", "memoria", 0, 10))


def test_transaction_rollback_and_commit(database):
    conn, _ = database
    with pytest.raises(RuntimeError), write_transaction(conn):
        conn.execute("INSERT INTO meta VALUES (?, ?)", ("test", "value"))
        raise RuntimeError("falha")
    assert conn.execute("SELECT count(*) FROM meta").fetchone()[0] == 0
    with write_transaction(conn):
        conn.execute("INSERT INTO meta VALUES (?, ?)", ("test", "value"))
    assert conn.execute("SELECT count(*) FROM meta").fetchone()[0] == 1


def test_future_schema_rejected(database):
    conn, _ = database
    conn.execute("INSERT INTO schema_migrations VALUES (?, ?, ?)", (9999, "futura", 0))
    with pytest.raises(DatabaseError):
        migrate(conn)


def test_migration_rollback_and_invalid_name(database, tmp_path, monkeypatch):
    from batataswap import db

    conn, _ = database
    directory = tmp_path / "migrations"
    directory.mkdir()
    # Inclui a migração conhecida para manter a compatibilidade com o banco existente.
    original = db.resources.files("batataswap.migrations")
    (directory / "0001_inicial.sql").write_text(original.joinpath("0001_inicial.sql").read_text())
    second = directory / "0002_failure.sql"
    second.write_text("CREATE TABLE temporary_table(id INTEGER) STRICT; INVALID SQL;")
    monkeypatch.setattr(db.resources, "files", lambda package: directory)
    with pytest.raises(DatabaseError):
        migrate(conn)
    assert not conn.execute(
        "SELECT 1 FROM sqlite_schema WHERE name = ?", ("temporary_table",)
    ).fetchone()
    assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 1
    (directory / "invalid.sql").write_text("SELECT 1;")
    with pytest.raises(DatabaseError, match="Nome de migração inválido"):
        migrate(conn)
