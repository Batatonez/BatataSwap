"""Cópias verificadas e recuperação administrativa, sem conteúdo em logs."""

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from batataswap import conversations, crypto, db, memory

TABLES = (
    "owner",
    "projects",
    "contexts",
    "preferences",
    "conversations",
    "message_batches",
    "messages",
    "oauth_clients",
    "oauth_grants",
    "oauth_tokens",
    "oauth_codes",
    "oauth_transactions",
    "known_devices",
    "panel_sessions",
    "pending_deletions",
    "daily_usage",
    "audit",
    "meta",
    "schema_migrations",
)


def counts(conn):
    return {table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in TABLES}


def integrity(conn):
    if conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("Cópia com integridade inválida.")
    if conn.execute("PRAGMA foreign_key_check").fetchall():
        raise ValueError("Cópia com referências inválidas.")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def decrypt_all(conn, keyring):
    for (ct,) in conn.execute("SELECT totp_secret_ct FROM owner"):
        keyring.open("totp", ct, crypto.aad_owner_totp())
    for pub, ct in conn.execute("SELECT public_id,name_ct FROM projects WHERE name_ct IS NOT NULL"):
        memory._project_name(keyring, pub, ct)
    for row in conn.execute(
        "SELECT p.public_id,c.public_id,c.version,c.created_at,c.source_label,g.public_id,"
        "c.content_ct FROM contexts c JOIN projects p ON p.id=c.project_id "
        "LEFT JOIN oauth_grants g ON g.id=c.grant_id WHERE c.content_ct IS NOT NULL"
    ):
        memory._decode_context(keyring, row[0], row[1:])
    for row in conn.execute(
        "SELECT p.public_id,p.version,p.created_at,p.source_label,g.public_id,p.text_ct "
        "FROM preferences p LEFT JOIN oauth_grants g ON g.id=p.grant_id "
        "WHERE p.text_ct IS NOT NULL"
    ):
        memory._decode_preference(keyring, row)
    for pub, ct in conn.execute(
        "SELECT public_id,name_ct FROM conversations WHERE name_ct IS NOT NULL"
    ):
        conversations.conversation_name(keyring, pub, ct)
    for row in conn.execute(
        "SELECT c.public_id,m.seq,b.public_id,g.public_id,m.claimed_author,m.created_at,"
        "m.text_ct FROM messages m JOIN conversations c ON c.id=m.conversation_id "
        "JOIN message_batches b ON b.id=m.batch_id JOIN oauth_grants g ON g.id=b.grant_id "
        "WHERE m.text_ct IS NOT NULL"
    ):
        conversations.open_message(keyring, *row)


def private_write(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def backup(conn, directory, now):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = datetime.fromtimestamp(now, UTC).date().isoformat()
    target = directory / f"{name}.db"
    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        stage = Path(temporary) / "copy.db"
        private_write(stage, b"")
        with closing(sqlite3.connect(stage)) as copy:
            conn.backup(copy)
            integrity(copy)
            manifest = {"sha256": digest(stage), "contagens": counts(copy)}
        metadata = Path(temporary) / "copy.json"
        private_write(metadata, json.dumps(manifest).encode())
        os.replace(stage, target)
        os.replace(metadata, target.with_suffix(".json"))
    retain(directory, now)
    return target


def retain(directory, now):
    today = datetime.fromtimestamp(now, UTC).date()
    dated = []
    for path in directory.glob("????-??-??.db"):
        try:
            date = datetime.strptime(path.stem, "%Y-%m-%d").date()
        except ValueError:
            continue
        dated.append((date, path))
    weekly = {}
    for date, path in sorted(dated):
        if 14 <= (today - date).days < 56:
            weekly[date.isocalendar()[:2]] = path
    for date, path in dated:
        age = (today - date).days
        if age >= 56 or (age >= 14 and path not in weekly.values()):
            path.unlink()
            path.with_suffix(".json").unlink(missing_ok=True)


def verified_copy(source, destination, keyring=None):
    if source.is_symlink() or not source.is_file():
        raise ValueError("Backup inválido.")
    metadata = source.with_suffix(".json")
    if metadata.is_symlink():
        raise ValueError("Manifesto inválido.")
    manifest = json.loads(metadata.read_text())
    private_write(destination, b"")
    shutil.copyfile(source, destination)
    if digest(destination) != manifest["sha256"]:
        raise ValueError("Hash do backup não confere.")
    with closing(db.connect(destination)) as conn:
        integrity(conn)
        if counts(conn) != manifest["contagens"]:
            raise ValueError("Contagens do backup não conferem.")
        db.migrate(conn)
        if keyring is not None:
            decrypt_all(conn, keyring)


def restore_test(directory, keyring):
    sources = sorted(directory.glob("????-??-??.db"))
    if not sources:
        raise ValueError("Nenhum backup disponível.")
    with tempfile.TemporaryDirectory() as temporary:
        verified_copy(sources[-1], Path(temporary) / "test.db", keyring)


def revoke_all(conn, now):
    with db.write_transaction(conn):
        conn.execute("UPDATE oauth_grants SET revoked_at=? WHERE revoked_at IS NULL", (now,))
        conn.execute("UPDATE oauth_tokens SET revoked_at=? WHERE revoked_at IS NULL", (now,))
        for table in (
            "oauth_transactions",
            "oauth_codes",
            "known_devices",
            "panel_sessions",
            "pending_deletions",
        ):
            conn.execute(f"DELETE FROM {table}")


def restore(source, target, directory, keyring, now):
    if (
        ".." in source.parts
        or source.is_symlink()
        or not source.resolve().is_relative_to(directory.resolve())
    ):
        raise ValueError("Restore aceita somente arquivo dentro da pasta de backups.")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as temporary:
        stage = Path(temporary) / "restore.db"
        verified_copy(source, stage, keyring)
        with closing(db.connect(stage)) as copy:
            revoke_all(copy, now)
            with db.write_transaction(copy):
                copy.execute(
                    "INSERT INTO meta(key,value) VALUES ('restore_epoch','1') "
                    "ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1"
                )
                copy.execute("UPDATE owner SET totp_last_step=max(totp_last_step,?)", (now // 30,))
            copy.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        current = None
        try:
            if target.exists():
                current = db.connect(target)
                current.execute("PRAGMA busy_timeout=0")
                current.execute("PRAGMA locking_mode=EXCLUSIVE")
                current.execute("BEGIN EXCLUSIVE")
                current.execute("SELECT count(*) FROM sqlite_master").fetchone()
            if any(Path(str(target) + suffix).exists() for suffix in ("", "-wal", "-shm")):
                folder = target.parent / datetime.fromtimestamp(now, UTC).strftime(
                    "antes-do-restore-%Y%m%d-%H%M%S"
                )
                folder.mkdir(mode=0o700)
                for suffix in ("", "-wal", "-shm"):
                    path = Path(str(target) + suffix)
                    if path.exists():
                        os.replace(path, folder / path.name)
            os.replace(stage, target)
        finally:
            if current is not None:
                current.close()
