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
        ("trusted_schema", 0),
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
    conn.execute("INSERT INTO schema_migrations VALUES (?, ?, ?, ?)", (9999, "futura", "hash", 0))
    with pytest.raises(DatabaseError):
        migrate(conn)


def test_migration_rollback_and_invalid_name(database, tmp_path, monkeypatch):
    from batataswap import db

    conn, _ = database
    directory = tmp_path / "migrations"
    directory.mkdir()
    # Inclui as migrações conhecidas para manter a compatibilidade com o banco existente.
    original = db.resources.files("batataswap.migrations")
    for entry in original.iterdir():
        if entry.name.endswith(".sql"):
            (directory / entry.name).write_bytes(entry.read_bytes())
    failing = directory / "0004_failure.sql"
    failing.write_text("CREATE TABLE temporary_table(id INTEGER) STRICT; INVALID SQL;")
    monkeypatch.setattr(db.resources, "files", lambda package: directory)
    with pytest.raises(DatabaseError):
        migrate(conn)
    assert not conn.execute(
        "SELECT 1 FROM sqlite_schema WHERE name = ?", ("temporary_table",)
    ).fetchone()
    assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 3
    (directory / "invalid.sql").write_text("SELECT 1;")
    with pytest.raises(DatabaseError, match="Nome de migração inválido"):
        migrate(conn)


def test_statement_parser():
    from batataswap.db import _statements

    conn = sqlite3.connect(":memory:")
    sql = "CREATE TABLE sample(value TEXT); -- comentário ;\nINSERT INTO sample VALUES ('a;b');"
    for statement in _statements(sql + " /* comentário ; */ -- fim ;"):
        conn.execute(statement)
    assert conn.execute("SELECT value FROM sample").fetchone() == ("a;b",)
    with pytest.raises(DatabaseError, match="incompleta"):
        list(_statements(sql + " INSERT INTO sample"))
    with pytest.raises(DatabaseError, match="incompleta"):
        list(_statements(sql + " /* comentário aberto"))
    conn.close()


def test_foreign_key(database):
    conn, _ = database
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        conn.execute(
            "INSERT INTO contexts(public_id,project_id,version,created_at,source_label,"
            "content_ct,content_size) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("ctx_missing", 999, 1, 0, "cli", b"cipher", 1),
        )


def test_missing_public_file_and_file_symlink(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    path = directory / "swap.db"
    with pytest.raises(DatabaseError, match="banco não existe; rode init") as error:
        connect(path)
    assert str(tmp_path) not in str(error.value)
    path.touch(mode=0o600)
    link = directory / "link.db"
    link.symlink_to(path)
    with pytest.raises(DatabaseError, match="simbólicos"):
        connect(link)
    if os.name == "posix":
        path.chmod(0o644)
        with pytest.raises(DatabaseError):
            connect(path)


@pytest.mark.skipif(os.name != "posix", reason="Propriedade POSIX")
@pytest.mark.parametrize("target", ["directory", "database", "-wal", "-shm"])
def test_wrong_owner(tmp_path, monkeypatch, target):
    from pathlib import Path

    path = tmp_path / "private" / "swap.db"
    conn = connect(path, create=True)
    conn.close()
    for suffix in ("-wal", "-shm"):
        Path(str(path) + suffix).touch(mode=0o600)
    wrong = (
        path.parent
        if target == "directory"
        else (path if target == "database" else Path(str(path) + target))
    )
    original = Path.lstat

    def lstat(self, *args, **kwargs):
        info = original(self, *args, **kwargs)
        if self == wrong:
            values = list(info)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(DatabaseError, match="rode como o usuário do serviço"):
        connect(path)


@pytest.mark.parametrize(
    "table,column",
    [
        ("projects", "name_ct"),
        ("contexts", "content_ct"),
        ("preferences", "text_ct"),
        ("conversations", "name_ct"),
        ("messages", "text_ct"),
    ],
)
def test_trash_and_purge_checks(database, table, column):
    conn, _ = database
    conn.execute("INSERT INTO projects VALUES (1,'proj',X'01',X'01',0,NULL,NULL,NULL)")
    conn.execute("INSERT INTO contexts VALUES (1,'ctx',1,1,0,NULL,'cli',X'01',1,NULL,NULL,NULL)")
    conn.execute(
        "INSERT INTO preferences VALUES (1,'pref',NULL,1,0,NULL,'cli',X'01',1,NULL,NULL,NULL)"
    )
    conn.execute("INSERT INTO conversations VALUES (1,'conv',X'01',X'01',1,0,0,0,NULL,NULL,NULL)")
    conn.execute("INSERT INTO oauth_clients VALUES (1,'client','static','{}',0,0)")
    conn.execute("INSERT INTO oauth_grants VALUES (1,'grant',1,'cli','r','s',0,10,NULL,NULL)")
    conn.execute("INSERT INTO message_batches VALUES (1,'batch',1,1,0,NULL,X'01',1,1)")
    conn.execute("INSERT INTO messages VALUES (1,'msg',1,1,1,'usuario',0,X'01',1,NULL,NULL,NULL)")
    # Nomes de tabela/coluna vêm exclusivamente da parametrização fixa deste teste.
    for assignment in ("trashed_at=1", "trash_root='del'", "purged_at=1", f"{column}=NULL"):
        with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
            conn.execute(f"UPDATE {table} SET {assignment} WHERE id=1")
    conn.execute(f"UPDATE {table} SET trashed_at=1,trash_root='del' WHERE id=1")
    conn.execute(f"UPDATE {table} SET purged_at=1,{column}=NULL WHERE id=1")
    conn.execute(f"UPDATE {table} SET trashed_at=NULL,trash_root=NULL WHERE id=1")


def test_indexes(database):
    conn, _ = database
    indexes = dict(conn.execute("SELECT name,sql FROM sqlite_schema WHERE type='index'"))
    assert "contexts_project_version" not in indexes
    assert "messages_conversation_seq" not in indexes
    for name, expression in [
        ("oauth_tokens_code", "oauth_tokens(code_hash)"),
        ("conversations_project", "conversations(project_id)"),
        *[
            (f"{t}_trash_root", f"{t}(trash_root) WHERE trash_root IS NOT NULL")
            for t in ("contexts", "conversations", "messages")
        ],
    ]:
        assert expression in indexes[name]


def test_migration_hash_order_duplicates(database, tmp_path, monkeypatch):
    import hashlib

    from batataswap import db

    conn, _ = database
    directory = tmp_path / "migrations"
    directory.mkdir()
    payload = db.resources.files("batataswap.migrations").joinpath("0001_inicial.sql").read_bytes()
    initial = directory / "0001_inicial.sql"
    initial.write_bytes(payload)
    assert conn.execute("SELECT sha256 FROM schema_migrations").fetchone()[0] == (
        hashlib.sha256(payload).hexdigest()
    )
    monkeypatch.setattr(db.resources, "files", lambda package: directory)
    initial.write_bytes(payload + b"\n-- alterada")
    with pytest.raises(DatabaseError, match="alterada"):
        migrate(conn)
    initial.write_bytes(payload)
    (directory / "0001_duplicate.sql").write_text("SELECT 1;")
    with pytest.raises(DatabaseError, match="duplicadas"):
        migrate(conn)
    # Um conjunto independente permite testar uma lacuna anterior à versão aplicada.
    other = tmp_path / "other"
    other.mkdir()
    (other / "0002_second.sql").write_text("CREATE TABLE sample(id INTEGER) STRICT; /* fim */")
    monkeypatch.setattr(db.resources, "files", lambda package: other)
    fresh = connect(tmp_path / "fresh" / "swap.db", create=True)
    try:
        migrate(fresh)
        (other / "0001_first.sql").write_text("SELECT 1;")
        with pytest.raises(DatabaseError, match="pendente anterior"):
            migrate(fresh)
        assert fresh.execute("SELECT version FROM schema_migrations").fetchall() == [(2,)]
    finally:
        fresh.close()


def test_security_migration_discards_legacy_batch_keys(tmp_path, monkeypatch):
    from batataswap import db

    original_files = db.resources.files
    source = original_files("batataswap.migrations")
    old = tmp_path / "old_migrations"
    old.mkdir()
    for entry in source.iterdir():
        if entry.name.endswith(".sql") and entry.name[:4] in {"0001", "0002"}:
            (old / entry.name).write_bytes(entry.read_bytes())
    monkeypatch.setattr(db.resources, "files", lambda package: old)
    path = tmp_path / "private" / "legacy.db"
    conn = connect(path, create=True)
    try:
        migrate(conn)
        conn.execute("INSERT INTO oauth_clients VALUES (1,'c','static','{}',0,0)")
        conn.execute(
            "INSERT INTO oauth_grants(id,public_id,client_row_id,label,resource,scope,created_at,expires_at) VALUES (1,'grant_x',1,'conta-1','r','s',0,9999999999)"
        )
        conn.execute(
            "INSERT INTO conversations(id,public_id,name_mac,name_ct,created_at,updated_at) VALUES (1,'conv_x',X'01',X'02',0,0)"
        )
        conn.execute(
            "INSERT INTO message_batches VALUES (1,'lote_x',1,1,0,'CHAVE-ANTIGA-SECRETA',X'01',1,1)"
        )
        conn.execute(
            "INSERT INTO messages(id,public_id,conversation_id,batch_id,seq,claimed_author,created_at,text_ct,text_size) VALUES (1,'msg_x',1,1,1,'claude',0,X'02',1)"
        )
        monkeypatch.setattr(db.resources, "files", original_files)
        migrate(conn)
        assert conn.execute("SELECT client_batch_key FROM message_batches").fetchone() == (None,)
        assert conn.execute("SELECT count(*) FROM messages").fetchone() == (1,)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        assert b"CHAVE-ANTIGA-SECRETA" not in path.read_bytes()
    finally:
        conn.close()
