"""Conexões privadas e migrações transacionais do SQLite."""

import os
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from importlib import resources
from pathlib import Path


class DatabaseError(RuntimeError):
    """Falha segura de preparação do banco."""


def _private(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or (os.name == "posix" and info.st_mode & 0o077):
        raise DatabaseError(
            "Banco e diretório devem ser privados e não podem ser links simbólicos."
        )


def connect(db_path: Path, *, create: bool = False) -> sqlite3.Connection:
    db_path = Path(db_path).absolute()
    # Verifica também ancestrais: não atravessar links na resolução do caminho.
    if any(p.is_symlink() for p in (db_path, *db_path.parents)):
        raise DatabaseError("O caminho do banco não pode conter links simbólicos.")
    if create:
        db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private(db_path.parent, directory=True)
    if create:
        try:
            fd = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    _private(db_path, directory=False)
    conn = sqlite3.connect(db_path.as_uri() + "?mode=rw", uri=True, isolation_level=None)
    try:
        for name, value in (
            ("journal_mode", "WAL"),
            ("foreign_keys", "ON"),
            ("secure_delete", "ON"),
            ("busy_timeout", "5000"),
            ("synchronous", "FULL"),
        ):
            # Nomes e valores são constantes internas, nunca dados de entrada.
            conn.execute(f"PRAGMA {name}={value}")
        for name, expected in (
            ("journal_mode", "wal"),
            ("foreign_keys", 1),
            ("secure_delete", 1),
            ("busy_timeout", 5000),
            ("synchronous", 2),
        ):
            if conn.execute(f"PRAGMA {name}").fetchone()[0] != expected:
                raise DatabaseError("Não foi possível ativar as proteções do SQLite.")
    except BaseException:
        conn.close()
        raise
    return conn


@contextmanager
def write_transaction(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def _statements(sql: str):
    statement = ""
    for char in sql:
        statement += char
        if char == ";" and sqlite3.complete_statement(statement):
            yield statement
            statement = ""
    if statement.strip() and any(
        line.strip() and not line.lstrip().startswith("--") for line in statement.splitlines()
    ):
        raise DatabaseError("Migração contém instrução SQL incompleta.")


def migrate(conn: sqlite3.Connection) -> None:
    migrations = []
    for entry in resources.files("batataswap.migrations").iterdir():
        if not entry.name.endswith(".sql"):
            continue
        if not re.fullmatch(r"\d{4}_[a-z0-9_]+\.sql", entry.name):
            raise DatabaseError("Nome de migração inválido.")
        migrations.append((int(entry.name[:4]), entry.name, entry))
    migrations.sort(key=lambda item: item[:2])
    versions = [version for version, _, _ in migrations]
    if len(set(versions)) != len(versions):
        raise DatabaseError("Versões de migração duplicadas.")
    with write_transaction(conn):
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT"
        )
        applied = dict(conn.execute("SELECT version, name FROM schema_migrations"))
        known = {version: name for version, name, _ in migrations}
        if any(version not in known or known[version] != name for version, name in applied.items()):
            raise DatabaseError("Banco contém versão de esquema desconhecida ou incompatível.")
    for version, name, entry in migrations:
        with write_transaction(conn):
            # Reconfere sob o bloqueio para suportar dois migradores concorrentes.
            if conn.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
            ).fetchone():
                continue
            try:
                for statement in _statements(entry.read_text(encoding="utf-8")):
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, int(time.time())),
                )
            except sqlite3.Error:
                raise DatabaseError("Não foi possível aplicar a migração do banco.") from None
