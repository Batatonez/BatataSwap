"""Núcleo de regras de negócio da memória (ARQUITETURA §5, §5.1, §7.1, §7.4, §7.5).

Funções puras sobre uma conexão SQLite, um ``Keyring`` e ``Limits``. Sem MCP e sem HTTP: a
camada de ferramentas (T10) chama estas funções.

Regras que valem aqui:

- toda escrita roda numa ``write_transaction`` (tudo ou nada);
- conteúdo nunca é atualizado: cada ``salvar`` cria uma versão nova;
- as mensagens de erro nunca carregam conteúdo salvo nem nome de projeto ou conversa;
- nada aqui loga nada.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from batataswap import crypto
from batataswap.config import Limits
from batataswap.crypto import CryptoError, Keyring
from batataswap.db import write_transaction

# ---------------------------------------------------------------------------
# Erros (mensagens em pt-BR, sem conteúdo)
# ---------------------------------------------------------------------------


class MemoryServiceError(Exception):
    """Base dos erros desta camada. ``code`` é estável para a camada de ferramentas."""

    code = "erro"


class InvalidInput(MemoryServiceError):
    code = "entrada_invalida"


class LimitExceeded(MemoryServiceError):
    code = "limite_excedido"


class NotFound(MemoryServiceError):
    code = "nao_encontrado"


class InvalidCursor(MemoryServiceError):
    code = "cursor_invalido"


class InvalidConfirmation(MemoryServiceError):
    code = "confirmacao_invalida"


class TrashError(MemoryServiceError):
    code = "lixeira"


class InvalidActor(MemoryServiceError):
    code = "ator_invalido"


class DataCorrupted(MemoryServiceError):
    code = "dado_ilegivel"


class BatchConflict(MemoryServiceError):
    code = "conflito_de_lote"


class SequenceConflict(MemoryServiceError):
    code = "conflito_de_sequencia"

    def __init__(self, message: str, current_seq: int) -> None:
        super().__init__(message)
        self.current_seq = current_seq


# ---------------------------------------------------------------------------
# Ator, JSON canônico, nomes
# ---------------------------------------------------------------------------

CURSOR_TTL_SECONDS = 3600
DELETE_CODE_TTL_SECONDS = 300
TRASH_RETENTION_SECONDS = 30 * 24 * 3600
LIST_MAX = 100


@dataclass(frozen=True)
class Actor:
    """Quem está pedindo a operação (grant do Claude, ``cli`` ou ``painel``)."""

    grant_id: int | None
    grant_public_id: str | None
    source_label: str

    def __post_init__(self) -> None:
        if (self.grant_id is None) != (self.grant_public_id is None):
            raise InvalidActor("Ator inválido: grant incompleto.")
        if not isinstance(self.source_label, str) or not self.source_label:
            raise InvalidActor("Ator inválido: rótulo ausente.")

    @property
    def origin(self) -> str:
        """Origem do AAD: public_id do grant ou o marcador ``cli``/``painel``."""
        if self.grant_public_id:
            return self.grant_public_id
        if self.source_label in crypto.ORIGIN_MARKERS:
            return self.source_label
        raise InvalidActor("Ator inválido: sem grant e sem marcador de origem.")

    @property
    def cursor_scope(self) -> str:
        return self.grant_public_id or self.source_label

    @property
    def is_local_admin(self) -> bool:
        return self.grant_id is None and self.source_label in crypto.ORIGIN_MARKERS


def canonical_json(obj: Any) -> bytes:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    except UnicodeEncodeError:
        raise InvalidInput("Texto com caracteres inválidos (UTF-8).") from None


def iso(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def check_name(name: object, what: str) -> str:
    """Valida nome de projeto/conversa: 1–80 caracteres (NFC), letras, números, espaço e ``-_.``."""
    if not isinstance(name, str):
        raise InvalidInput(f"O nome do {what} precisa ser texto.")
    text = unicodedata.normalize("NFC", name).strip(" ")
    if not 1 <= len(text) <= 80:
        raise InvalidInput(f"O nome do {what} precisa ter de 1 a 80 caracteres.")
    if not all(ch.isalnum() or ch in " -_." for ch in text):
        raise InvalidInput(
            f"O nome do {what} só pode ter letras, números, espaço e os símbolos - _ ."
        )
    return text


def name_key(keyring: Keyring, purpose: str, name: str) -> bytes:
    return keyring.mac(purpose, crypto.normalize_name(name).encode("utf-8"))  # type: ignore[arg-type]


def check_text(value: object, what: str, max_chars: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise InvalidInput(f"{what}: precisa ser texto.")
    if any((ord(c) < 32 or 127 <= ord(c) <= 159) and c not in "\n\t" for c in value):
        raise InvalidInput(f"{what}: caracteres de controle inválidos.")
    if not value and not allow_empty:
        raise InvalidInput(f"{what}: não pode ser vazio.")
    if len(value) > max_chars:
        raise LimitExceeded(f"{what}: passou do limite de {max_chars} caracteres.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidInput(f"{what}: caracteres inválidos (UTF-8).") from None
    return value


def _check_limit(value: int | None, default: int, high: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= high:
        raise InvalidInput(f"O limite precisa ser um número de 1 a {high}.")
    return value


def _open(keyring: Keyring, blob: bytes | None, aad: bytes) -> bytes:
    if blob is None:
        raise DataCorrupted("Registro sem conteúdo (expurgado).")
    try:
        return keyring.open("conteudo", blob, aad)
    except CryptoError:
        raise DataCorrupted("Não foi possível ler um registro (dado cifrado inválido).") from None


def _seal(keyring: Keyring, plain: bytes, aad: bytes) -> bytes:
    return keyring.seal("conteudo", plain, aad)


# ---------------------------------------------------------------------------
# Cursores (§7.1): opacos, assinados, presos ao ator e à consulta, validade de 1 h
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_cursor(
    keyring: Keyring, kind: str, actor: Actor, tag: str, data: dict[str, Any], now: int
) -> str:
    payload = canonical_json(
        {"k": kind, "a": actor.cursor_scope, "t": tag, "e": now + CURSOR_TTL_SECONDS, "d": data}
    )
    return _b64(payload) + "." + _b64(keyring.mac("cursor", payload))


def decode_cursor(
    keyring: Keyring, kind: str, actor: Actor, tag: str, token: object, now: int
) -> dict[str, Any]:
    bad = InvalidCursor("Cursor inválido. Refaça a consulta sem cursor.")
    if not isinstance(token, str) or not 0 < len(token) <= 2048 or token.count(".") != 1:
        raise bad
    try:
        payload_text, sig_text = token.split(".")
        payload, sig = _unb64(payload_text), _unb64(sig_text)
        valid = keyring.verify_mac("cursor", payload, sig)
        obj = json.loads(payload) if valid else None
    except (ValueError, TypeError):
        raise bad from None
    if not isinstance(obj, dict) or not isinstance(obj.get("d"), dict):
        raise bad
    if obj.get("k") != kind or obj.get("a") != actor.cursor_scope or obj.get("t") != tag:
        raise bad
    expires = obj.get("e")
    if isinstance(expires, bool) or not isinstance(expires, int):
        raise bad
    if expires < now:
        raise InvalidCursor("Cursor expirado. Refaça a consulta sem cursor.")
    return obj["d"]


def _after_from_cursor(
    keyring: Keyring, kind: str, actor: Actor, tag: str, cursor: str | None, now: int
) -> int:
    if cursor is None:
        return 0
    data = decode_cursor(keyring, kind, actor, tag, cursor, now)
    after = data.get("after")
    if isinstance(after, bool) or not isinstance(after, int) or after < 0:
        raise InvalidCursor("Cursor inválido. Refaça a consulta sem cursor.")
    return after


# ---------------------------------------------------------------------------
# Limites diários e total (§7.4)
# ---------------------------------------------------------------------------


def stored_bytes(conn: sqlite3.Connection) -> int:
    """Bytes de conteúdo guardados (vivo + lixeira; expurgado não conta)."""
    total = 0
    for table, column in (
        ("contexts", "content_size"),
        ("preferences", "text_size"),
        ("messages", "text_size"),
    ):
        # Nomes de tabela e coluna são constantes internas.
        row = conn.execute(
            f"SELECT COALESCE(SUM({column}), 0) FROM {table} WHERE purged_at IS NULL"
        ).fetchone()
        total += row[0]
    return total


def database_bytes(conn: sqlite3.Connection) -> int:
    """Estimativa do tamanho do banco inteiro: páginas do arquivo principal + arquivo -wal."""
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    total = pages * page_size
    for row in conn.execute("PRAGMA database_list"):
        if row[1] == "main" and row[2]:
            try:
                total += os.stat(row[2] + "-wal").st_size
            except OSError:
                pass
    return total


def charge_write(conn: sqlite3.Connection, limits: Limits, now: int, size: int) -> None:
    """Confere os limites diário e total e registra a escrita. Chamar dentro da transação."""
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    row = conn.execute("SELECT writes, bytes FROM daily_usage WHERE day = ?", (day,)).fetchone()
    writes, written = row if row else (0, 0)
    if writes + 1 > limits.daily_writes:
        raise LimitExceeded(f"Limite diário de {limits.daily_writes} escritas atingido.")
    if written + size > limits.daily_bytes:
        raise LimitExceeded("Limite diário de bytes gravados atingido.")
    if database_bytes(conn) + size > limits.database_bytes:
        raise LimitExceeded(
            "O banco chegou ao tamanho máximo. Exporte e limpe memórias antes de salvar mais."
        )
    if stored_bytes(conn) + size > limits.stored_bytes:
        raise LimitExceeded(
            "O total guardado chegou ao limite. Exporte e limpe memórias antes de salvar mais."
        )
    conn.execute(
        "INSERT INTO daily_usage(day, writes, bytes) VALUES (?, 1, ?) "
        "ON CONFLICT(day) DO UPDATE SET writes = writes + 1, bytes = bytes + excluded.bytes",
        (day, size),
    )


def audit(
    conn: sqlite3.Connection, now: int, event: str, grant_id: int | None, target: str | None
) -> None:
    conn.execute(
        "INSERT INTO audit(at, event, grant_id, target) VALUES (?, ?, ?, ?)",
        (now, event, grant_id, target),
    )


# ---------------------------------------------------------------------------
# Projetos
# ---------------------------------------------------------------------------


def get_or_create_project(
    conn: sqlite3.Connection, keyring: Keyring, name: str, now: int
) -> tuple[int, str]:
    """Devolve ``(id, public_id)``; cria se preciso. Dentro de transação. Recusa projeto na lixeira."""
    mac = name_key(keyring, "projeto", name)
    row = conn.execute(
        "SELECT id, public_id, trashed_at FROM projects WHERE name_mac = ?", (mac,)
    ).fetchone()
    if row:
        if row[2] is not None:
            raise TrashError("O projeto está na lixeira. Restaure-o antes de salvar nele.")
        return row[0], row[1]
    public_id = crypto.new_public_id("proj_")
    ct = _seal(keyring, name.encode("utf-8"), crypto.aad_project_name(public_id))
    cur = conn.execute(
        "INSERT INTO projects(public_id, name_mac, name_ct, created_at) VALUES (?, ?, ?, ?)",
        (public_id, mac, ct, now),
    )
    return cur.lastrowid, public_id


def _project_name(keyring: Keyring, public_id: str, ct: bytes | None) -> str | None:
    if ct is None:
        return None
    return _open(keyring, ct, crypto.aad_project_name(public_id)).decode("utf-8")


# ---------------------------------------------------------------------------
# Contextos
# ---------------------------------------------------------------------------


def _validate_list(limits: Limits, value: object, what: str) -> list[str]:
    if not isinstance(value, list):
        raise InvalidInput(f"{what}: precisa ser uma lista de textos.")
    if len(value) > limits.context_list_items:
        raise LimitExceeded(f"{what}: no máximo {limits.context_list_items} itens.")
    return [check_text(v, f"{what} (item)", limits.context_list_item_chars) for v in value]


def save_context(
    conn: sqlite3.Connection,
    keyring: Keyring,
    limits: Limits,
    actor: Actor,
    projeto: str,
    resumo: str,
    decisoes: list[str],
    pendencias: list[str],
    preferencias: list[str],
    *,
    now: int,
) -> dict[str, Any]:
    """Salva uma NOVA versão do contexto do projeto (cria o projeto se precisar)."""
    name = check_name(projeto, "projeto")
    content = {
        "resumo": check_text(resumo, "resumo", limits.summary_chars),
        "decisoes": _validate_list(limits, decisoes, "decisões"),
        "pendencias": _validate_list(limits, pendencias, "pendências"),
        "preferencias": _validate_list(limits, preferencias, "preferências"),
    }
    plain = canonical_json(content)
    if len(plain) > limits.context_bytes:
        raise LimitExceeded(f"O contexto passou do limite de {limits.context_bytes} bytes.")
    origin = actor.origin
    with write_transaction(conn):
        charge_write(conn, limits, now, len(plain))
        project_id, project_public = get_or_create_project(conn, keyring, name, now)
        version = conn.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM contexts WHERE project_id = ?",
            (project_id,),
        ).fetchone()[0]
        public_id = crypto.new_public_id("ctx_")
        aad = crypto.aad_context(project_public, version, origin, actor.source_label, now)
        conn.execute(
            "INSERT INTO contexts(public_id, project_id, version, created_at, grant_id, "
            "source_label, content_ct, content_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                public_id,
                project_id,
                version,
                now,
                actor.grant_id,
                actor.source_label,
                _seal(keyring, plain, aad),
                len(plain),
            ),
        )
        from batataswap.tools import check_record_readable

        check_record_readable(
            limits, {"tipo": "contexto", **get_context(conn, keyring, name, version)}
        )
    return {
        "id": public_id,
        "projeto_id": project_public,
        "versao": version,
        "salvo_em": iso(now),
        "enviado_por": actor.source_label,
    }


def _context_origin(grant_public: str | None, source_label: str) -> str:
    return grant_public or source_label


def _decode_context(keyring: Keyring, project_public: str, row: tuple) -> dict[str, Any]:
    # row: public_id, version, created_at, source_label, grant_public, content_ct
    public_id, version, created_at, label, grant_public, ct = row
    aad = crypto.aad_context(
        project_public, version, _context_origin(grant_public, label), label, created_at
    )
    try:
        data = json.loads(_open(keyring, ct, aad))
    except ValueError:
        raise DataCorrupted("Não foi possível ler um registro (conteúdo malformado).") from None
    return {
        "id": public_id,
        "versao": version,
        "salvo_em": iso(created_at),
        "enviado_por": label,
        "resumo": data.get("resumo", ""),
        "decisoes": data.get("decisoes", []),
        "pendencias": data.get("pendencias", []),
        "preferencias": data.get("preferencias", []),
    }


_CTX_COLUMNS = "c.public_id, c.version, c.created_at, c.source_label, g.public_id, c.content_ct"


def get_context(
    conn: sqlite3.Connection, keyring: Keyring, projeto: str, versao: int | None = None
) -> dict[str, Any]:
    """Última versão viva do projeto (ou a pedida), decifrada."""
    name = check_name(projeto, "projeto")
    if versao is not None and (
        isinstance(versao, bool) or not isinstance(versao, int) or versao < 1
    ):
        raise InvalidInput("A versão precisa ser um número inteiro maior que zero.")
    proj = conn.execute(
        "SELECT id, public_id, name_ct FROM projects "
        "WHERE name_mac = ? AND trashed_at IS NULL AND purged_at IS NULL",
        (name_key(keyring, "projeto", name),),
    ).fetchone()
    if not proj:
        raise NotFound("Projeto não encontrado.")
    base = (
        f"SELECT {_CTX_COLUMNS} FROM contexts c LEFT JOIN oauth_grants g ON g.id = c.grant_id "
        "WHERE c.project_id = ? AND c.trashed_at IS NULL AND c.purged_at IS NULL"
    )
    if versao is None:
        row = conn.execute(base + " ORDER BY c.version DESC LIMIT 1", (proj[0],)).fetchone()
    else:
        row = conn.execute(base + " AND c.version = ?", (proj[0], versao)).fetchone()
    if not row:
        raise NotFound("Versão do contexto não encontrada.")
    result = _decode_context(keyring, proj[1], row)
    result["projeto"] = _project_name(keyring, proj[1], proj[2])
    result["projeto_id"] = proj[1]
    return result


def list_projects(
    conn: sqlite3.Connection,
    keyring: Keyring,
    actor: Actor,
    cursor: str | None = None,
    limit: int | None = None,
    *,
    now: int,
) -> dict[str, Any]:
    """Projetos vivos em ordem estável (criação, id), com a última versão viva de cada um."""
    limit = _check_limit(limit, 20, LIST_MAX)
    after = _after_from_cursor(keyring, "projetos", actor, "", cursor, now)
    rows = conn.execute(
        "SELECT id, public_id, name_ct FROM projects "
        "WHERE id > ? AND trashed_at IS NULL AND purged_at IS NULL ORDER BY id LIMIT ?",
        (after, limit + 1),
    ).fetchall()
    items = []
    for project_id, public_id, name_ct in rows[:limit]:
        last = conn.execute(
            "SELECT public_id, version, created_at, source_label FROM contexts "
            "WHERE project_id = ? AND trashed_at IS NULL AND purged_at IS NULL "
            "ORDER BY version DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        items.append(
            {
                "id": public_id,
                "projeto": _project_name(keyring, public_id, name_ct),
                "ultima_versao": last[1] if last else None,
                "contexto_id": last[0] if last else None,
                "salvo_em": iso(last[2]) if last else None,
                "enviado_por": last[3] if last else None,
            }
        )
    next_cursor = None
    if len(rows) > limit:
        next_cursor = encode_cursor(
            keyring, "projetos", actor, "", {"after": rows[limit - 1][0]}, now
        )
    return {"projetos": items, "proximo_cursor": next_cursor}


# ---------------------------------------------------------------------------
# Preferências
# ---------------------------------------------------------------------------


def add_preference(
    conn: sqlite3.Connection,
    keyring: Keyring,
    limits: Limits,
    actor: Actor,
    texto: str,
    *,
    now: int,
    supersedes: str | None = None,
) -> dict[str, Any]:
    """Registra uma preferência geral. ``supersedes`` (public_id) cria a edição de uma antiga."""
    text = check_text(texto, "preferência", limits.preference_chars)
    plain = text.encode("utf-8")
    origin = actor.origin
    with write_transaction(conn):
        charge_write(conn, limits, now, len(plain))
        supersedes_id, version = None, 1
        if supersedes is not None:
            old = conn.execute(
                "SELECT id, version FROM preferences WHERE public_id = ? "
                "AND trashed_at IS NULL AND purged_at IS NULL",
                (supersedes,),
            ).fetchone()
            if not old:
                raise NotFound("Preferência a substituir não encontrada.")
            supersedes_id, version = old[0], old[1] + 1
        public_id = crypto.new_public_id("pref_")
        from batataswap.tools import check_record_readable

        check_record_readable(
            limits,
            {
                "tipo": "preferencia",
                "id": public_id,
                "versao": version,
                "salvo_em": iso(now),
                "enviado_por": actor.source_label,
                "texto": text,
            },
        )
        aad = crypto.aad_preference(public_id, version, origin, actor.source_label, now)
        conn.execute(
            "INSERT INTO preferences(public_id, supersedes_id, version, created_at, grant_id, "
            "source_label, text_ct, text_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                public_id,
                supersedes_id,
                version,
                now,
                actor.grant_id,
                actor.source_label,
                _seal(keyring, plain, aad),
                len(plain),
            ),
        )
    return {
        "id": public_id,
        "versao": version,
        "salvo_em": iso(now),
        "enviado_por": actor.source_label,
    }


def _decode_preference(keyring: Keyring, row: tuple) -> dict[str, Any]:
    # row: public_id, version, created_at, source_label, grant_public, text_ct
    public_id, version, created_at, label, grant_public, ct = row
    aad = crypto.aad_preference(
        public_id, version, _context_origin(grant_public, label), label, created_at
    )
    return {
        "id": public_id,
        "versao": version,
        "salvo_em": iso(created_at),
        "enviado_por": label,
        "texto": _open(keyring, ct, aad).decode("utf-8"),
    }


def list_preferences(
    conn: sqlite3.Connection,
    keyring: Keyring,
    actor: Actor,
    cursor: str | None = None,
    limit: int | None = None,
    *,
    now: int,
) -> dict[str, Any]:
    """Preferências vivas (as substituídas por uma edição viva ficam de fora), ordem estável."""
    limit = _check_limit(limit, 20, LIST_MAX)
    after = _after_from_cursor(keyring, "preferencias", actor, "", cursor, now)
    rows = conn.execute(
        "SELECT p.id, p.public_id, p.version, p.created_at, p.source_label, g.public_id, "
        "p.text_ct FROM preferences p LEFT JOIN oauth_grants g ON g.id = p.grant_id "
        "WHERE p.id > ? AND p.trashed_at IS NULL AND p.purged_at IS NULL "
        "AND NOT EXISTS (SELECT 1 FROM preferences n WHERE n.supersedes_id = p.id "
        "AND n.trashed_at IS NULL AND n.purged_at IS NULL) ORDER BY p.id LIMIT ?",
        (after, limit + 1),
    ).fetchall()
    items = [_decode_preference(keyring, row[1:]) for row in rows[:limit]]
    next_cursor = None
    if len(rows) > limit:
        next_cursor = encode_cursor(
            keyring, "preferencias", actor, "", {"after": rows[limit - 1][0]}, now
        )
    return {"preferencias": items, "proximo_cursor": next_cursor}


# ---------------------------------------------------------------------------
# Busca (§7.1, §7.4)
# ---------------------------------------------------------------------------

_SNIPPET_CHARS = 200
_SEARCH_KEYS = ("c", "p", "m")


def _snippet(parts: list[str], needle: str) -> str:
    for part in parts:
        if needle in crypto.normalize_name(part):
            return part[:_SNIPPET_CHARS]
    return (parts[0] if parts else "")[:_SNIPPET_CHARS]


_SEARCH_TABLES = {"c": "contexts", "p": "preferences", "m": "messages"}


def _search_rows(conn: sqlite3.Connection, key: str, low: int, high: int) -> list[tuple]:
    """Linhas vivas com ``low < id <= high`` (faixa limitada: o trabalho de SQL é previsível)."""
    if key == "c":
        return conn.execute(
            "SELECT c.id, c.public_id, c.version, c.created_at, c.source_label, g.public_id, "
            "c.content_ct, p.public_id, p.name_ct FROM contexts c "
            "JOIN projects p ON p.id = c.project_id "
            "LEFT JOIN oauth_grants g ON g.id = c.grant_id "
            "WHERE c.id > ? AND c.id <= ? AND c.trashed_at IS NULL AND c.purged_at IS NULL "
            "AND p.trashed_at IS NULL AND p.purged_at IS NULL ORDER BY c.id",
            (low, high),
        ).fetchall()
    if key == "p":
        return conn.execute(
            "SELECT p.id, p.public_id, p.version, p.created_at, p.source_label, g.public_id, "
            "p.text_ct FROM preferences p LEFT JOIN oauth_grants g ON g.id = p.grant_id "
            "WHERE p.id > ? AND p.id <= ? AND p.trashed_at IS NULL AND p.purged_at IS NULL "
            "ORDER BY p.id",
            (low, high),
        ).fetchall()
    return conn.execute(
        "SELECT m.id, m.public_id, m.seq, m.claimed_author, m.created_at, m.text_ct, "
        "b.public_id, g.public_id, g.label, cv.public_id, cv.name_ct FROM messages m "
        "JOIN conversations cv ON cv.id = m.conversation_id "
        "JOIN message_batches b ON b.id = m.batch_id JOIN oauth_grants g ON g.id = b.grant_id "
        "WHERE m.id > ? AND m.id <= ? AND m.trashed_at IS NULL AND m.purged_at IS NULL "
        "AND cv.trashed_at IS NULL AND cv.purged_at IS NULL ORDER BY m.id",
        (low, high),
    ).fetchall()


def _examine(keyring: Keyring, key: str, row: tuple, needle: str) -> dict[str, Any] | None:
    from batataswap import conversations  # import tardio: conversations importa este módulo

    try:
        if key == "c":
            _rid, public_id, version, created_at, label, grant_public, ct, proj_pub, proj_ct = row
            decoded = _decode_context(
                keyring, proj_pub, (public_id, version, created_at, label, grant_public, ct)
            )
            parts = [decoded["resumo"], *decoded["decisoes"], *decoded["pendencias"]]
            parts += decoded["preferencias"]
            if needle not in crypto.normalize_name("\n".join(parts)):
                return None
            return {
                "tipo": "contexto",
                "id": public_id,
                "projeto": _project_name(keyring, proj_pub, proj_ct),
                "versao": version,
                "salvo_em": iso(created_at),
                "enviado_por": label,
                "trecho": _snippet(parts, needle),
            }
        if key == "p":
            decoded = _decode_preference(keyring, row[1:])
            if needle not in crypto.normalize_name(decoded["texto"]):
                return None
            return {
                "tipo": "preferencia",
                "id": decoded["id"],
                "salvo_em": decoded["salvo_em"],
                "enviado_por": decoded["enviado_por"],
                "trecho": decoded["texto"][:_SNIPPET_CHARS],
            }
        (
            _,
            public_id,
            seq,
            author,
            created_at,
            ct,
            batch_pub,
            grant_pub,
            label,
            conv_pub,
            conv_ct,
        ) = row
        text = conversations.open_message(
            keyring, conv_pub, seq, batch_pub, grant_pub, author, created_at, ct
        )
        if needle not in crypto.normalize_name(text):
            return None
        return {
            "tipo": "mensagem",
            "id": public_id,
            "conversa": conversations.conversation_name(keyring, conv_pub, conv_ct),
            "seq": seq,
            "autor_alegado": author,
            "enviado_por": label,
            "salvo_em": iso(created_at),
            "trecho": text[:_SNIPPET_CHARS],
        }
    except DataCorrupted:
        return None  # linha ilegível é examinada e pulada; nunca aborta a busca


def search(
    conn: sqlite3.Connection,
    keyring: Keyring,
    limits: Limits,
    actor: Actor,
    texto: str,
    limite: int | None = None,
    cursor: str | None = None,
    *,
    now: int,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Busca simples (sem caixa e sem acento) em contextos, preferências e mensagens.

    Lê em blocos de ``limits.search_block_rows`` linhas por tabela. Para em ``limite`` achados
    ou quando passa ``limits.search_seconds`` (aviso ``parcial``). O ``proximo_cursor`` guarda a
    ÚLTIMA LINHA EXAMINADA de cada tabela, então uma busca cortada pelo tempo sem achar nada
    continua de onde parou. Sempre examina ao menos uma linha por chamada.
    """
    text = check_text(texto, "texto da busca", 200)
    if len(text) < 2:
        raise InvalidInput("O texto da busca precisa ter de 2 a 200 caracteres.")
    needle = crypto.normalize_name(text)
    if not needle:
        raise InvalidInput("O texto da busca precisa ter de 2 a 200 caracteres.")
    limite = _check_limit(limite, limits.search_results, limits.search_results)
    tag = keyring.mac("cursor", b"q|" + needle.encode("utf-8")).hex()
    state: dict[str, list] = {k: [0, False] for k in _SEARCH_KEYS}
    if cursor is not None:
        data = decode_cursor(keyring, "busca", actor, tag, cursor, now)
        for k in _SEARCH_KEYS:
            item = data.get(k)
            if (
                not isinstance(item, list)
                or len(item) != 2
                or isinstance(item[0], bool)
                or not isinstance(item[0], int)
                or item[0] < 0
                or not isinstance(item[1], bool)
            ):
                raise InvalidCursor("Cursor inválido. Refaça a consulta sem cursor.")
            state[k] = [item[0], item[1]]

    results: list[dict[str, Any]] = []
    partial = False
    stop = False
    started = clock()
    blocks = 0
    for key in _SEARCH_KEYS:
        if stop:
            break
        max_id = conn.execute(f"SELECT COALESCE(MAX(id), 0) FROM {_SEARCH_TABLES[key]}").fetchone()[
            0
        ]
        while not stop and not state[key][1]:
            # O relógio é conferido antes de cada bloco (menos do primeiro: sempre há progresso).
            if blocks and clock() - started >= limits.search_seconds:
                stop, partial = True, True
                break
            low = state[key][0]
            if low >= max_id:
                state[key][1] = True
                break
            high = min(low + limits.search_block_rows, max_id)
            rows = _search_rows(conn, key, low, high)
            blocks += 1
            for row in rows:
                state[key][0] = row[0]
                hit = _examine(keyring, key, row, needle)
                if hit is not None:
                    results.append(hit)
                if len(results) >= limite:
                    stop = True
                    break
                if clock() - started >= limits.search_seconds:
                    stop, partial = True, True
                    break
            if not stop:
                state[key][0] = high  # faixa inteira examinada
    next_cursor = None
    if not all(state[k][1] for k in _SEARCH_KEYS):
        next_cursor = encode_cursor(keyring, "busca", actor, tag, dict(state), now)
    return {"resultados": results, "parcial": partial, "proximo_cursor": next_cursor}


# ---------------------------------------------------------------------------
# Apagar em 2 passos, lixeira, restaurar, expurgar (§5.1)
# ---------------------------------------------------------------------------

_PREFIX_TABLE = {
    "proj_": ("projects", "projeto"),
    "ctx_": ("contexts", "contexto"),
    "pref_": ("preferences", "preferencia"),
    "conv_": ("conversations", "conversa"),
    "msg_": ("messages", "mensagem"),
}
_ALL_TABLES = ("projects", "contexts", "preferences", "conversations", "messages")


def _parse_id(public_id: object) -> tuple[str, str]:
    """Valida o public_id e devolve ``(tabela, tipo)``. Só constantes vão para o SQL."""
    if not isinstance(public_id, str) or len(public_id) > 40:
        raise InvalidInput("Identificador inválido.")
    prefix = public_id.split("_", 1)[0] + "_"
    entry = _PREFIX_TABLE.get(prefix)
    suffix = public_id[len(prefix) :]
    if (
        entry is None
        or len(suffix) != 16
        or not all(ch in "abcdefghijklmnopqrstuvwxyz234567" for ch in suffix)
    ):
        raise InvalidInput("Identificador inválido.")
    return entry


def _find(conn: sqlite3.Connection, table: str, public_id: str) -> tuple | None:
    return conn.execute(
        f"SELECT id, trashed_at, purged_at FROM {table} WHERE public_id = ?",
        (public_id,),
    ).fetchone()


def _describe(
    conn: sqlite3.Connection, keyring: Keyring, table: str, kind: str, row_id: int, public_id: str
) -> dict[str, Any]:
    """Descrição do alvo para o usuário confirmar: tipo, nome, versão, data. Sem conteúdo."""
    out: dict[str, Any] = {"id": public_id, "tipo": kind}
    if table == "projects":
        r = conn.execute(
            "SELECT public_id, name_ct, created_at FROM projects WHERE id = ?", (row_id,)
        ).fetchone()
        out["nome"] = _project_name(keyring, r[0], r[1])
        out["criado_em"] = iso(r[2])
    elif table == "contexts":
        r = conn.execute(
            "SELECT c.version, c.created_at, p.public_id, p.name_ct FROM contexts c "
            "JOIN projects p ON p.id = c.project_id WHERE c.id = ?",
            (row_id,),
        ).fetchone()
        out.update(versao=r[0], criado_em=iso(r[1]), projeto=_project_name(keyring, r[2], r[3]))
    elif table == "preferences":
        r = conn.execute(
            "SELECT version, created_at FROM preferences WHERE id = ?", (row_id,)
        ).fetchone()
        out.update(versao=r[0], criado_em=iso(r[1]))
    elif table == "conversations":
        r = conn.execute(
            "SELECT public_id, name_ct, created_at FROM conversations WHERE id = ?", (row_id,)
        ).fetchone()
        out["nome"] = _project_name_conv(keyring, r[0], r[1])
        out["criado_em"] = iso(r[2])
    else:
        r = conn.execute(
            "SELECT m.seq, m.created_at, cv.public_id, cv.name_ct FROM messages m "
            "JOIN conversations cv ON cv.id = m.conversation_id WHERE m.id = ?",
            (row_id,),
        ).fetchone()
        out.update(seq=r[0], criado_em=iso(r[1]), conversa=_project_name_conv(keyring, r[2], r[3]))
    return out


def _project_name_conv(keyring: Keyring, public_id: str, ct: bytes | None) -> str | None:
    if ct is None:
        return None
    return _open(keyring, ct, crypto.aad_conversation_name(public_id)).decode("utf-8")


def request_delete(
    conn: sqlite3.Connection, keyring: Keyring, actor: Actor, public_id: str, *, now: int
) -> dict[str, Any]:
    """1º passo: descreve o alvo e devolve um código de uso único (5 min, preso ao grant e ao alvo)."""
    if actor.grant_id is None:
        raise InvalidActor("Apagar em dois passos exige um grant. CLI e painel usam expurgar.")
    table, kind = _parse_id(public_id)
    with write_transaction(conn):
        row = _find(conn, table, public_id)
        if not row or row[1] is not None or row[2] is not None:
            raise NotFound("Registro não encontrado ou já apagado.")
        pending = conn.execute(
            "SELECT count(*) FROM pending_deletions WHERE grant_id=? "
            "AND expires_at>? AND used_at IS NULL",
            (actor.grant_id, now),
        ).fetchone()[0]
        hourly = conn.execute(
            "SELECT count(*) FROM audit WHERE event='apagar_pedido' AND grant_id=? AND at>?",
            (actor.grant_id, now - 3600),
        ).fetchone()[0]
        if pending >= 20 or hourly >= 60:
            raise LimitExceeded(
                "Limite de pedidos de apagar: 20 pendentes e 60 por hora por grant."
            )
        code = secrets.token_urlsafe(9)
        conn.execute("DELETE FROM pending_deletions WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO pending_deletions(confirm_hash, target, grant_id, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (crypto.token_hash(code), public_id, actor.grant_id, now + DELETE_CODE_TTL_SECONDS),
        )
        audit(conn, now, "apagar_pedido", actor.grant_id, public_id)
        target = _describe(conn, keyring, table, kind, row[0], public_id)
    return {"alvo": target, "codigo": code, "expira_em": iso(now + DELETE_CODE_TTL_SECONDS)}


def _trash_rows(conn: sqlite3.Connection, table: str, row_id: int, root: str, now: int) -> int:
    """Manda para a lixeira o item e seus filhos que ainda não estavam nela (nem expurgados)."""

    def mark(tbl: str, where: str, params: tuple) -> int:
        cur = conn.execute(
            f"UPDATE {tbl} SET trashed_at = ?, trash_root = ? WHERE {where} "
            "AND trashed_at IS NULL AND purged_at IS NULL",
            (now, root, *params),
        )
        return cur.rowcount

    def mark_conversations(where: str, params: tuple) -> int:
        ids = [
            r[0]
            for r in conn.execute(
                f"SELECT id FROM conversations WHERE {where} "
                "AND trashed_at IS NULL AND purged_at IS NULL",
                params,
            )
        ]
        count = 0
        for cid in ids:
            count += mark("conversations", "id = ?", (cid,))
            count += mark("messages", "conversation_id = ?", (cid,))
        return count

    if table == "projects":
        return (
            mark("projects", "id = ?", (row_id,))
            + mark("contexts", "project_id = ?", (row_id,))
            + mark_conversations("project_id = ?", (row_id,))
        )
    if table == "conversations":
        return mark("conversations", "id = ?", (row_id,)) + mark(
            "messages", "conversation_id = ?", (row_id,)
        )
    return mark(table, "id = ?", (row_id,))


def confirm_delete(
    conn: sqlite3.Connection, actor: Actor, public_id: str, codigo: str, *, now: int
) -> dict[str, Any]:
    """2º passo: consome o código (atômico) e manda o alvo e seus filhos para a lixeira."""
    if actor.grant_id is None:
        raise InvalidActor("Apagar em dois passos exige um grant. CLI e painel usam expurgar.")
    table, kind = _parse_id(public_id)
    bad = InvalidConfirmation("Código de confirmação inválido, expirado ou já usado.")
    if not isinstance(codigo, str) or not 0 < len(codigo.strip()) <= 100:
        raise bad
    with write_transaction(conn):
        cur = conn.execute(
            "UPDATE pending_deletions SET used_at = ? WHERE confirm_hash = ? AND target = ? "
            "AND grant_id = ? AND used_at IS NULL AND expires_at > ?",
            (now, crypto.token_hash(codigo.strip()), public_id, actor.grant_id, now),
        )
        if cur.rowcount != 1:
            raise bad
        row = _find(conn, table, public_id)
        if not row or row[1] is not None or row[2] is not None:
            raise NotFound("Registro não encontrado ou já apagado.")
        root = crypto.new_public_id("del_")
        count = _trash_rows(conn, table, row[0], root, now)
        audit(conn, now, "apagar_lixeira", actor.grant_id, public_id)
    return {"id": public_id, "tipo": kind, "lixeira_id": root, "itens": count}


def _require_local_admin(actor: Actor) -> None:
    if not actor.is_local_admin:
        raise InvalidActor("Esta operação é só da CLI ou do painel.")


def _live_parent_error(conn: sqlite3.Connection, table: str, row_id: int) -> None:
    """Recusa restaurar filho cujo pai está na lixeira (ou expurgado)."""
    if table == "contexts":
        parent = conn.execute(
            "SELECT p.trashed_at, p.purged_at, 'projeto' FROM contexts c "
            "JOIN projects p ON p.id = c.project_id WHERE c.id = ?",
            (row_id,),
        ).fetchone()
    elif table == "conversations":
        parent = conn.execute(
            "SELECT p.trashed_at, p.purged_at, 'projeto' FROM conversations c "
            "JOIN projects p ON p.id = c.project_id WHERE c.id = ?",
            (row_id,),
        ).fetchone()
    elif table == "messages":
        parent = conn.execute(
            "SELECT cv.trashed_at, cv.purged_at, 'conversa' FROM messages m "
            "JOIN conversations cv ON cv.id = m.conversation_id WHERE m.id = ?",
            (row_id,),
        ).fetchone()
    else:
        parent = None
    if parent and parent[1] is not None:
        raise TrashError(f"Não dá para restaurar: o {parent[2]} já foi expurgado.")
    if parent and parent[0] is not None:
        raise TrashError(f"Restaure o {parent[2]} primeiro.")


def list_trash(conn: sqlite3.Connection, actor: Actor) -> list[dict[str, Any]]:
    """Metadados administrativos da lixeira, sem nomes nem conteúdo."""
    _require_local_admin(actor)
    sources = {
        "projects": "(SELECT coalesce(g.public_id,c.source_label) FROM contexts c "
        "LEFT JOIN oauth_grants g ON g.id=c.grant_id WHERE c.project_id=t.id "
        "ORDER BY c.id DESC LIMIT 1)",
        "contexts": "coalesce((SELECT public_id FROM oauth_grants WHERE id=t.grant_id),t.source_label)",
        "preferences": "coalesce((SELECT public_id FROM oauth_grants WHERE id=t.grant_id),t.source_label)",
        "conversations": "(SELECT g.public_id FROM message_batches b JOIN oauth_grants g "
        "ON g.id=b.grant_id WHERE b.conversation_id=t.id ORDER BY b.id DESC LIMIT 1)",
        "messages": "(SELECT g.public_id FROM message_batches b JOIN oauth_grants g "
        "ON g.id=b.grant_id WHERE b.id=t.batch_id)",
    }
    items = []
    for table, source in sources.items():
        for public_id, deleted, origin in conn.execute(
            f"SELECT t.public_id,t.trashed_at,{source} FROM {table} t "
            "WHERE t.trashed_at IS NOT NULL AND t.purged_at IS NULL ORDER BY t.id"
        ):
            items.append(
                {
                    "id": public_id,
                    "tipo": _parse_id(public_id)[1],
                    "apagado_em": iso(deleted),
                    "origem": origin,
                }
            )
    return items


def restore(conn: sqlite3.Connection, actor: Actor, public_id: str, *, now: int) -> dict[str, Any]:
    """Restaura o item e só o que foi para a lixeira junto com ele (mesmo ``trash_root``)."""
    _require_local_admin(actor)
    table, kind = _parse_id(public_id)
    with write_transaction(conn):
        row = conn.execute(
            f"SELECT id, trash_root, purged_at, trashed_at FROM {table} "
            "WHERE public_id = ? AND trashed_at IS NOT NULL",
            (public_id,),
        ).fetchone()
        if not row or row[2] is not None:
            raise NotFound("Registro não encontrado na lixeira.")
        if row[3] <= now - TRASH_RETENTION_SECONDS:
            raise TrashError("O prazo de restauração de 30 dias expirou.")
        _live_parent_error(conn, table, row[0])
        count = 0
        for tbl in _ALL_TABLES:
            cur = conn.execute(
                f"UPDATE {tbl} SET trashed_at = NULL, trash_root = NULL "
                "WHERE trash_root = ? AND purged_at IS NULL",
                (row[1],),
            )
            count += cur.rowcount
        audit(conn, now, "restaurar", None, public_id)
    return {"id": public_id, "tipo": kind, "restaurados": count}


def _purge_rows(conn: sqlite3.Connection, table: str, row_id: int, now: int) -> int:
    """Expurga em cascata (inclusive filhos já na lixeira). Idempotente."""
    count = 0
    if table == "projects":
        for (cid,) in conn.execute(
            "SELECT id FROM conversations WHERE project_id = ?", (row_id,)
        ).fetchall():
            count += _purge_rows(conn, "conversations", cid, now)
        count += conn.execute(
            "UPDATE contexts SET content_ct = NULL, purged_at = ? "
            "WHERE project_id = ? AND purged_at IS NULL",
            (now, row_id),
        ).rowcount
    elif table == "conversations":
        count += conn.execute(
            "UPDATE messages SET text_ct = NULL, purged_at = ? "
            "WHERE conversation_id = ? AND purged_at IS NULL",
            (now, row_id),
        ).rowcount
    if table in ("projects", "conversations"):
        count += conn.execute(
            f"UPDATE {table} SET name_ct = NULL, name_mac = ?, purged_at = ? "
            "WHERE id = ? AND purged_at IS NULL",
            (secrets.token_bytes(32), now, row_id),
        ).rowcount
    elif table == "contexts":
        count += conn.execute(
            "UPDATE contexts SET content_ct = NULL, purged_at = ? "
            "WHERE id = ? AND purged_at IS NULL",
            (now, row_id),
        ).rowcount
    else:
        column = "text_ct"
        count += conn.execute(
            f"UPDATE {table} SET {column} = NULL, purged_at = ? WHERE id = ? AND purged_at IS NULL",
            (now, row_id),
        ).rowcount
    return count


def _checkpoint(conn: sqlite3.Connection, now: int) -> str:
    """``wal_checkpoint(TRUNCATE)`` conferido. Ocupado → marca ``checkpoint_pendente`` em meta."""
    row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if row is not None and row[0] == 0:
        conn.execute("DELETE FROM meta WHERE key = 'checkpoint_pendente'")
        return "ok"
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('checkpoint_pendente', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(now),),
    )
    return "pendente"


def retry_checkpoint(conn: sqlite3.Connection, *, now: int) -> str:
    """Refaz o checkpoint se algum expurgo o deixou pendente. Devolve ``ok`` ou ``pendente``."""
    pending = conn.execute("SELECT 1 FROM meta WHERE key = 'checkpoint_pendente'").fetchone()
    if not pending:
        return "ok"
    return _checkpoint(conn, now)


def purge(conn: sqlite3.Connection, actor: Actor, public_id: str, *, now: int) -> dict[str, Any]:
    """Expurgo (só CLI/painel): conteúdo e nomes viram NULL, ``name_mac`` vira aleatório."""
    _require_local_admin(actor)
    table, kind = _parse_id(public_id)
    with write_transaction(conn):
        row = _find(conn, table, public_id)
        if not row:
            raise NotFound("Registro não encontrado.")
        count = _purge_rows(conn, table, row[0], now)
        audit(conn, now, "expurgar", None, public_id)
    physical = _checkpoint(conn, now)
    return {"id": public_id, "tipo": kind, "expurgados": count, "limpeza_fisica": physical}


def sweep_trash(conn: sqlite3.Connection, *, now: int) -> int:
    """Faxina: expurga o que está na lixeira há mais de 30 dias. Devolve quantas linhas."""
    cutoff = now - TRASH_RETENTION_SECONDS
    total = 0
    with write_transaction(conn):
        for table in ("projects", "conversations", "contexts", "preferences", "messages"):
            ids = [
                r[0]
                for r in conn.execute(
                    f"SELECT id FROM {table} WHERE trashed_at IS NOT NULL "
                    "AND trashed_at <= ? AND purged_at IS NULL",
                    (cutoff,),
                )
            ]
            for row_id in ids:
                total += _purge_rows(conn, table, row_id, now)
        if total:
            audit(conn, now, "faxina_lixeira", None, None)
    if total:
        _checkpoint(conn, now)
    else:
        retry_checkpoint(conn, now=now)
    return total


# ---------------------------------------------------------------------------
# Export (§7.5)
# ---------------------------------------------------------------------------


def _skeleton(trashed_at: int | None, trash_root: str | None, purged_at: int | None) -> dict:
    return {
        "na_lixeira": trashed_at is not None,
        "lixeira_em": iso(trashed_at) if trashed_at is not None else None,
        "lixeira_id": trash_root,
        "expurgado_em": iso(purged_at) if purged_at is not None else None,
    }


def export_all(conn: sqlite3.Connection, keyring: Keyring) -> dict[str, Any]:
    """Tudo decifrado (vivo, lixeira e esqueletos expurgados). O resultado está em TEXTO PURO.

    Roda numa única transação de leitura (um só instante do banco). Recusa se a conexão já
    tem uma transação aberta.
    """
    if conn.in_transaction:
        raise InvalidInput(
            "Há uma transação aberta nesta conexão; o export precisa de um snapshot."
        )
    conn.execute("BEGIN")
    try:
        return _export_snapshot(conn, keyring)
    finally:
        if conn.in_transaction:
            conn.execute("ROLLBACK")


def _export_snapshot(conn: sqlite3.Connection, keyring: Keyring) -> dict[str, Any]:
    from batataswap import conversations  # import tardio

    projects = []
    for pid, pub, name_ct, created, tr_at, tr_root, pg_at in conn.execute(
        "SELECT id, public_id, name_ct, created_at, trashed_at, trash_root, purged_at "
        "FROM projects ORDER BY id"
    ).fetchall():
        contexts = []
        for row in conn.execute(
            "SELECT c.public_id, c.version, c.created_at, c.source_label, g.public_id, "
            "c.content_ct, c.content_size, c.trashed_at, c.trash_root, c.purged_at "
            "FROM contexts c LEFT JOIN oauth_grants g ON g.id = c.grant_id "
            "WHERE c.project_id = ? ORDER BY c.version",
            (pid,),
        ).fetchall():
            item: dict[str, Any] = {
                "id": row[0],
                "versao": row[1],
                "salvo_em": iso(row[2]),
                "enviado_por": row[3],
                "origem": row[4] or row[3],
                "tamanho": row[6],
                **_skeleton(row[7], row[8], row[9]),
            }
            if row[9] is None:
                try:
                    item.update(_decode_context(keyring, pub, row[:6]))
                except DataCorrupted:
                    item["erro"] = "dado ilegível"
            contexts.append(item)
        try:
            name = _project_name(keyring, pub, name_ct)
        except DataCorrupted:
            name = None
        projects.append(
            {
                "id": pub,
                "nome": name,
                "criado_em": iso(created),
                **_skeleton(tr_at, tr_root, pg_at),
                "contextos": contexts,
            }
        )
    preferences = []
    for row in conn.execute(
        "SELECT p.public_id, p.version, p.created_at, p.source_label, g.public_id, p.text_ct, "
        "p.text_size, p.trashed_at, p.trash_root, p.purged_at, s.public_id "
        "FROM preferences p LEFT JOIN oauth_grants g ON g.id = p.grant_id "
        "LEFT JOIN preferences s ON s.id = p.supersedes_id ORDER BY p.id"
    ).fetchall():
        item = {
            "id": row[0],
            "versao": row[1],
            "salvo_em": iso(row[2]),
            "enviado_por": row[3],
            "origem": row[4] or row[3],
            "substitui": row[10],
            "tamanho": row[6],
            **_skeleton(row[7], row[8], row[9]),
        }
        if row[9] is None:
            try:
                item["texto"] = _decode_preference(keyring, row[:6])["texto"]
            except DataCorrupted:
                item["erro"] = "dado ilegível"
        preferences.append(item)
    return {
        "formato": "batataswap-export-1",
        "aviso": "Este arquivo está em texto puro (sem cifra). Guarde com cuidado.",
        "projetos": projects,
        "preferencias": preferences,
        "conversas": conversations.export_conversations(conn, keyring),
    }
