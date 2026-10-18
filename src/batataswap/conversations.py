"""Conversas e mensagens (ARQUITETURA §7.2): sincronia do fio entre as contas.

Quem enviou é verificado (grant do lote); quem falou é só ALEGADO pelo modelo. Gravação sempre
tudo ou nada. Nada aqui loga ou coloca conteúdo em mensagem de erro.
"""

from __future__ import annotations

import hmac
import sqlite3
import unicodedata
from typing import Any

from batataswap import crypto
from batataswap.config import Limits
from batataswap.crypto import Keyring
from batataswap.db import write_transaction
from batataswap.memory import (
    LIST_MAX,
    Actor,
    BatchConflict,
    DataCorrupted,
    InvalidInput,
    LimitExceeded,
    NotFound,
    SequenceConflict,
    TrashError,
    _after_from_cursor,
    _check_limit,
    _open,
    _project_name,
    _seal,
    _skeleton,
    canonical_json,
    charge_write,
    check_name,
    check_text,
    encode_cursor,
    get_or_create_project,
    iso,
    name_key,
)

AUTHORS = ("usuario", "claude")
BATCH_KEY_MAX = 100


def conversation_name(keyring: Keyring, public_id: str, ct: bytes | None) -> str | None:
    if ct is None:
        return None
    return _open(keyring, ct, crypto.aad_conversation_name(public_id)).decode("utf-8")


def open_message(
    keyring: Keyring,
    conv_public_id: str,
    seq: int,
    batch_public_id: str,
    grant_public_id: str,
    author: str,
    created_at: int,
    ct: bytes | None,
) -> str:
    aad = crypto.aad_message(
        conv_public_id, seq, batch_public_id, grant_public_id, author, created_at
    )
    return _open(keyring, ct, aad).decode("utf-8")


def _validate_messages(limits: Limits, mensagens: object) -> list[dict[str, str]]:
    if not isinstance(mensagens, list) or not mensagens:
        raise InvalidInput("Envie pelo menos 1 mensagem (lista de {autor, texto}).")
    if len(mensagens) > limits.messages_per_call:
        raise LimitExceeded(
            f"No máximo {limits.messages_per_call} mensagens por chamada "
            f"(você mandou {len(mensagens)}). Nada foi gravado; mande lotes menores."
        )
    clean = []
    for i, msg in enumerate(mensagens, 1):
        if not isinstance(msg, dict) or set(msg) != {"autor", "texto"}:
            raise InvalidInput(f"Mensagem {i}: use exatamente os campos autor e texto.")
        if msg["autor"] not in AUTHORS:
            raise InvalidInput(f"Mensagem {i}: autor precisa ser 'usuario' ou 'claude'.")
        try:
            text = check_text(msg["texto"], f"Mensagem {i}", limits.message_chars)
        except LimitExceeded:
            raise LimitExceeded(
                f"Mensagem {i}: passou do limite de {limits.message_chars} caracteres. "
                "Nada foi gravado."
            ) from None
        clean.append({"autor": msg["autor"], "texto": text})
    return clean


def _fit_count(sizes: list[int], budget: int) -> int:
    used = 0
    for n, size in enumerate(sizes):
        used += size
        if used > budget:
            return n
    return len(sizes)


def append_messages(
    conn: sqlite3.Connection,
    keyring: Keyring,
    limits: Limits,
    actor: Actor,
    conversa: str,
    mensagens: list[dict[str, str]],
    projeto: str | None = None,
    lote: str | None = None,
    continua_de: int | None = None,
    *,
    now: int,
) -> dict[str, Any]:
    """Anexa um lote de mensagens, tudo ou nada. Veja §7.2 para idempotência e ``continua_de``."""
    if actor.grant_id is None or actor.grant_public_id is None:
        raise InvalidInput("Anexar mensagens exige um grant (conta conectada).")
    conv_name = check_name(conversa, "conversa")
    project_name = check_name(projeto, "projeto") if projeto is not None else None
    messages = _validate_messages(limits, mensagens)
    if lote is not None:
        lote = check_text(lote, "lote", BATCH_KEY_MAX)
        if any(unicodedata.category(ch)[0] == "C" for ch in lote):
            raise InvalidInput("lote: caracteres de controle não são permitidos.")
    if continua_de is not None and (
        isinstance(continua_de, bool) or not isinstance(continua_de, int) or continua_de < 0
    ):
        raise InvalidInput("continua_de precisa ser um número inteiro (seq) maior ou igual a 0.")
    canonical = canonical_json(messages)
    if len(canonical) > limits.message_batch_bytes:
        sizes = [len(canonical_json(m)) + 1 for m in messages]
        fit = _fit_count(sizes, limits.message_batch_bytes - 2)
        raise LimitExceeded(
            f"O lote passou de {limits.message_batch_bytes // 1024} KiB. "
            f"Cabem {fit} mensagens por chamada. Nada foi gravado; mande lotes menores."
        )
    payload_mac = keyring.mac("lote", canonical)
    sizes = [len(m["texto"].encode("utf-8")) for m in messages]
    total_size = sum(sizes)
    mac = name_key(keyring, "conversa", conv_name)

    with write_transaction(conn):
        conv = conn.execute(
            "SELECT id, public_id, project_id, total_bytes, trashed_at FROM conversations "
            "WHERE name_mac = ?",
            (mac,),
        ).fetchone()
        if conv and conv[4] is not None:
            raise TrashError("A conversa está na lixeira. Restaure-a antes de anexar.")

        # Idempotência vem ANTES do continua_de.
        if conv and lote is not None:
            prev = conn.execute(
                "SELECT payload_mac, first_seq, last_seq FROM message_batches "
                "WHERE conversation_id = ? AND grant_id = ? AND client_batch_key = ?",
                (conv[0], actor.grant_id, lote),
            ).fetchone()
            if prev:
                if hmac.compare_digest(prev[0], payload_mac):
                    return {
                        "first_seq": prev[1],
                        "last_seq": prev[2],
                        "conversa_id": conv[1],
                        "repetido": True,
                    }
                raise BatchConflict(
                    "Esta chave de lote já foi usada com mensagens diferentes. "
                    "Use outra chave para um lote novo."
                )

        current = 0
        if conv:
            current = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM messages WHERE conversation_id = ?",
                (conv[0],),
            ).fetchone()[0]
        if continua_de is not None and continua_de != current:
            raise SequenceConflict(
                f"A conversa já está na mensagem {current} (você disse {continua_de}). "
                "Leia a conversa e mande só o que falta.",
                current,
            )

        # Limites: tudo ou nada.
        already = conv[3] if conv else 0
        if already + total_size > limits.conversation_bytes:
            fit = _fit_count(sizes, limits.conversation_bytes - already)
            raise LimitExceeded(
                f"A conversa passaria de {limits.conversation_bytes // (1024 * 1024)} MiB. "
                f"Cabem {fit} destas mensagens. Nada foi gravado; comece uma conversa nova."
            )
        charge_write(conn, limits, now, total_size)

        if conv:
            conv_id, conv_public, project_id = conv[0], conv[1], conv[2]
        else:
            conv_public = crypto.new_public_id("conv_")
            project_id = None
        if project_name is not None:
            wanted_id, _ = get_or_create_project(conn, keyring, project_name, now)
            if project_id is not None and project_id != wanted_id:
                raise InvalidInput("Esta conversa já pertence a outro projeto.")
            project_id = wanted_id
        if not conv:
            name_ct = _seal(
                keyring, conv_name.encode("utf-8"), crypto.aad_conversation_name(conv_public)
            )
            conv_id = conn.execute(
                "INSERT INTO conversations(public_id, name_mac, name_ct, project_id, created_at, "
                "updated_at, total_bytes) VALUES (?, ?, ?, ?, ?, ?, 0)",
                (conv_public, mac, name_ct, project_id, now, now),
            ).lastrowid
        first_seq = current + 1
        last_seq = current + len(messages)
        batch_public = crypto.new_public_id("lote_")
        batch_id = conn.execute(
            "INSERT INTO message_batches(public_id, conversation_id, grant_id, created_at, "
            "client_batch_key, payload_mac, first_seq, last_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                batch_public,
                conv_id,
                actor.grant_id,
                now,
                lote,
                payload_mac,
                first_seq,
                last_seq,
            ),
        ).lastrowid
        for offset, (msg, size) in enumerate(zip(messages, sizes, strict=True)):
            seq = first_seq + offset
            aad = crypto.aad_message(
                conv_public, seq, batch_public, actor.grant_public_id, msg["autor"], now
            )
            conn.execute(
                "INSERT INTO messages(public_id, conversation_id, batch_id, seq, claimed_author, "
                "created_at, text_ct, text_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    crypto.new_public_id("msg_"),
                    conv_id,
                    batch_id,
                    seq,
                    msg["autor"],
                    now,
                    _seal(keyring, msg["texto"].encode("utf-8"), aad),
                    size,
                ),
            )
        conn.execute(
            "UPDATE conversations SET updated_at = ?, total_bytes = total_bytes + ?, "
            "project_id = ? WHERE id = ?",
            (now, total_size, project_id, conv_id),
        )
    return {
        "first_seq": first_seq,
        "last_seq": last_seq,
        "conversa_id": conv_public,
        "repetido": False,
    }


def sender_name(label: str) -> str:
    """``conta-N`` vira ``Claude N``; outros rótulos ficam como estão."""
    if label.startswith("conta-") and label[6:].isdigit():
        return f"Claude {label[6:]}"
    return label


def format_line(author: str, sender_label: str, text: str) -> str:
    who = sender_name(sender_label)
    if author == "claude":
        return f"{who}: {text}"
    return f"Usuário (registrado por {who}): {text}"


def read_conversation(
    conn: sqlite3.Connection,
    keyring: Keyring,
    conversa: str,
    ultimas: int | None = 50,
    antes_de: int | None = None,
) -> dict[str, Any]:
    """Últimas mensagens vivas (ordem crescente), marcadas ``verificada: False``.

    Paginação por ``antes_de`` (seq): ``proximo_antes_de`` é o menor seq devolvido quando há
    mensagens mais antigas.
    """
    name = check_name(conversa, "conversa")
    ultimas = _check_limit(ultimas, 50, 200)
    if antes_de is not None and (
        isinstance(antes_de, bool) or not isinstance(antes_de, int) or antes_de < 1
    ):
        raise InvalidInput("antes_de precisa ser um número inteiro (seq) maior que zero.")
    conv = conn.execute(
        "SELECT id, public_id, name_ct, project_id FROM conversations "
        "WHERE name_mac = ? AND trashed_at IS NULL AND purged_at IS NULL",
        (name_key(keyring, "conversa", name),),
    ).fetchone()
    if not conv:
        raise NotFound("Conversa não encontrada.")
    rows = conn.execute(
        "SELECT m.seq, m.claimed_author, m.created_at, m.text_ct, b.public_id, g.public_id, "
        "g.label FROM messages m JOIN message_batches b ON b.id = m.batch_id "
        "JOIN oauth_grants g ON g.id = b.grant_id "
        "WHERE m.conversation_id = ? AND m.trashed_at IS NULL AND m.purged_at IS NULL "
        "AND m.seq < ? ORDER BY m.seq DESC LIMIT ?",
        (conv[0], antes_de if antes_de is not None else 2**62, ultimas + 1),
    ).fetchall()
    items = []
    for seq, author, created_at, ct, batch_pub, grant_pub, label in reversed(rows[:ultimas]):
        text = open_message(keyring, conv[1], seq, batch_pub, grant_pub, author, created_at, ct)
        items.append(
            {
                "seq": seq,
                "autor_alegado": author,
                "enviado_por": label,
                "texto": text,
                "created_at": iso(created_at),
                "linha": format_line(author, label, text),
            }
        )
    return {
        "conversa": conversation_name(keyring, conv[1], conv[2]),
        "conversa_id": conv[1],
        "verificada": False,
        "itens": items,
        "proximo_antes_de": items[0]["seq"] if items and len(rows) > ultimas else None,
    }


def list_conversations(
    conn: sqlite3.Connection,
    keyring: Keyring,
    actor: Actor,
    projeto: str | None = None,
    cursor: str | None = None,
    limit: int | None = None,
    *,
    now: int,
) -> dict[str, Any]:
    """Conversas vivas em ordem estável (id), opcionalmente de um projeto, com cursor."""
    limit = _check_limit(limit, 20, LIST_MAX)
    project_id = None
    tag = ""
    if projeto is not None:
        name = check_name(projeto, "projeto")
        row = conn.execute(
            "SELECT id, public_id FROM projects "
            "WHERE name_mac = ? AND trashed_at IS NULL AND purged_at IS NULL",
            (name_key(keyring, "projeto", name),),
        ).fetchone()
        if not row:
            raise NotFound("Projeto não encontrado.")
        project_id, tag = row[0], row[1]
    after = _after_from_cursor(keyring, "conversas", actor, tag, cursor, now)
    sql = (
        "SELECT cv.id, cv.public_id, cv.name_ct, cv.updated_at, cv.total_bytes, "
        "p.public_id, p.name_ct, (SELECT COALESCE(MAX(seq), 0) FROM messages m "
        "WHERE m.conversation_id = cv.id AND m.trashed_at IS NULL AND m.purged_at IS NULL) "
        ", (SELECT g.label FROM messages m "
        "JOIN message_batches b ON b.id=m.batch_id "
        "JOIN oauth_grants g ON g.id=b.grant_id "
        "WHERE m.conversation_id=cv.id AND m.trashed_at IS NULL AND m.purged_at IS NULL "
        "ORDER BY m.seq DESC LIMIT 1) "
        "FROM conversations cv LEFT JOIN projects p ON p.id = cv.project_id "
        "WHERE cv.id > ? AND cv.trashed_at IS NULL AND cv.purged_at IS NULL "
        "AND (p.id IS NULL OR (p.trashed_at IS NULL AND p.purged_at IS NULL))"
    )
    params: list[Any] = [after]
    if project_id is not None:
        sql += " AND cv.project_id = ?"
        params.append(project_id)
    rows = conn.execute(sql + " ORDER BY cv.id LIMIT ?", (*params, limit + 1)).fetchall()
    items = [
        {
            "id": r[1],
            "conversa": conversation_name(keyring, r[1], r[2]),
            "projeto": _project_name(keyring, r[5], r[6]) if r[5] else None,
            "atualizada_em": iso(r[3]),
            "ultima_seq": r[7],
            "enviado_por": r[8],
        }
        for r in rows[:limit]
    ]
    next_cursor = None
    if len(rows) > limit:
        next_cursor = encode_cursor(
            keyring, "conversas", actor, tag, {"after": rows[limit - 1][0]}, now
        )
    return {"conversas": items, "proximo_cursor": next_cursor}


def export_conversations(conn: sqlite3.Connection, keyring: Keyring) -> list[dict[str, Any]]:
    """Conversas, lotes e mensagens decifrados (inclui lixeira e esqueletos expurgados)."""
    out = []
    for cid, pub, name_ct, proj_pub, created, updated, total, tr_at, tr_root, pg_at in conn.execute(
        "SELECT cv.id, cv.public_id, cv.name_ct, p.public_id, cv.created_at, cv.updated_at, "
        "cv.total_bytes, cv.trashed_at, cv.trash_root, cv.purged_at FROM conversations cv "
        "LEFT JOIN projects p ON p.id = cv.project_id ORDER BY cv.id"
    ).fetchall():
        try:
            name = conversation_name(keyring, pub, name_ct)
        except DataCorrupted:
            name = None
        batches = [
            {
                "id": r[0],
                "enviado_por": r[1],
                "origem": r[6],
                "criado_em": iso(r[2]),
                "chave": r[3],
                "first_seq": r[4],
                "last_seq": r[5],
            }
            for r in conn.execute(
                "SELECT b.public_id, g.label, b.created_at, b.client_batch_key, b.first_seq, "
                "b.last_seq, g.public_id FROM message_batches b JOIN oauth_grants g ON g.id = b.grant_id "
                "WHERE b.conversation_id = ? ORDER BY b.id",
                (cid,),
            )
        ]
        messages = []
        for row in conn.execute(
            "SELECT m.public_id, m.seq, m.claimed_author, m.created_at, m.text_ct, m.text_size, "
            "m.trashed_at, m.trash_root, m.purged_at, b.public_id, g.public_id, g.label "
            "FROM messages m JOIN message_batches b ON b.id = m.batch_id "
            "JOIN oauth_grants g ON g.id = b.grant_id WHERE m.conversation_id = ? ORDER BY m.seq",
            (cid,),
        ).fetchall():
            item: dict[str, Any] = {
                "id": row[0],
                "seq": row[1],
                "autor_alegado": row[2],
                "enviado_por": row[11],
                "origem": row[10],
                "lote": row[9],
                "salvo_em": iso(row[3]),
                "tamanho": row[5],
                **_skeleton(row[6], row[7], row[8]),
            }
            if row[8] is None:
                try:
                    text = open_message(
                        keyring, pub, row[1], row[9], row[10], row[2], row[3], row[4]
                    )
                    item["texto"] = text
                    item["linha"] = format_line(row[2], row[11], text)
                except DataCorrupted:
                    item["erro"] = "dado ilegível"
            messages.append(item)
        out.append(
            {
                "id": pub,
                "nome": name,
                "projeto_id": proj_pub,
                "criada_em": iso(created),
                "atualizada_em": iso(updated),
                "total_bytes": total,
                **_skeleton(tr_at, tr_root, pg_at),
                "lotes": batches,
                "mensagens": messages,
            }
        )
    return out
