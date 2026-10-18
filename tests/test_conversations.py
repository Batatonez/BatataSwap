# ruff: noqa: F811
import pytest

from batataswap import conversations as cv
from batataswap import memory
from batataswap.config import Limits
from batataswap.memory import Actor
from tests.test_memory import (  # noqa: F401
    CLI,
    SECRET,
    T0,
    _trash,
    a1,
    a2,
    conn,
    keyring,
    limits,
    run_threads,
)


def msgs(*pairs):
    return [{"autor": a, "texto": t} for a, t in pairs]


def append(conn, keyring, limits, actor, mensagens, conversa="Fio 1", now=T0, **kw):
    return cv.append_messages(conn, keyring, limits, actor, conversa, mensagens, now=now, **kw)


def test_append_and_read_format(conn, keyring, limits, a1, a2):
    r1 = append(conn, keyring, limits, a1, msgs(("claude", "olá"), ("usuario", "oi")))
    assert (r1["first_seq"], r1["last_seq"]) == (1, 2)
    r2 = append(conn, keyring, limits, a2, msgs(("usuario", "retomar"), ("claude", "certo")))
    assert (r2["first_seq"], r2["last_seq"]) == (3, 4)
    out = cv.read_conversation(conn, keyring, "fio 1")
    assert out["verificada"] is False and out["conversa"] == "Fio 1"
    assert [i["linha"] for i in out["itens"]] == [
        "Claude 1: olá",
        "Usuário (registrado por Claude 1): oi",
        "Usuário (registrado por Claude 2): retomar",
        "Claude 2: certo",
    ]
    first = out["itens"][0]
    assert first["autor_alegado"] == "claude" and first["enviado_por"] == "conta-1"
    assert first["seq"] == 1 and first["texto"] == "olá"


def test_other_labels_stay_as_is(conn, keyring, limits):
    c = conn.execute(
        "INSERT INTO oauth_grants(public_id, client_row_id, label, resource, scope, created_at, "
        "expires_at) VALUES ('grant_cccccccccccccccc', 1, 'tablet', 'r', 's', 0, 99)"
    )
    actor = Actor(c.lastrowid, "grant_cccccccccccccccc", "tablet")
    append(conn, keyring, limits, actor, msgs(("claude", "a"), ("usuario", "b")))
    lines = [i["linha"] for i in cv.read_conversation(conn, keyring, "Fio 1")["itens"]]
    assert lines == ["tablet: a", "Usuário (registrado por tablet): b"]


def test_identical_messages_not_deduped(conn, keyring, limits, a1):
    append(conn, keyring, limits, a1, msgs(("usuario", "ok"), ("usuario", "ok")))
    append(conn, keyring, limits, a1, msgs(("usuario", "ok")))
    assert len(cv.read_conversation(conn, keyring, "Fio 1")["itens"]) == 3


def test_pagination_antes_de(conn, keyring, limits, a1):
    append(conn, keyring, limits, a1, msgs(*[("claude", f"m{i}") for i in range(5)]))
    page = cv.read_conversation(conn, keyring, "Fio 1", ultimas=2)
    assert [i["seq"] for i in page["itens"]] == [4, 5] and page["proximo_antes_de"] == 4
    older = cv.read_conversation(conn, keyring, "Fio 1", 2, antes_de=4)
    assert [i["seq"] for i in older["itens"]] == [2, 3] and older["proximo_antes_de"] == 2
    last = cv.read_conversation(conn, keyring, "Fio 1", 2, antes_de=2)
    assert [i["seq"] for i in last["itens"]] == [1] and last["proximo_antes_de"] is None
    with pytest.raises(memory.NotFound):
        cv.read_conversation(conn, keyring, "Não Existe")


def test_message_validation_all_or_nothing(conn, keyring, a1):
    lim = Limits(messages_per_call=3, message_chars=5)
    bad_cases = [
        [],
        "texto",
        msgs(("claude", "a"), ("usuario", "b"), ("claude", "c"), ("usuario", "d")),
        msgs(("claude", "ok"), ("claude", "123456")),
        msgs(("humano", "x")),
        [{"autor": "claude", "texto": "x", "extra": 1}],
        [{"autor": "claude", "texto": 5}],
        [{"autor": "claude", "texto": ""}],
        ["x"],
    ]
    for bad in bad_cases:
        with pytest.raises(memory.MemoryServiceError):
            append(conn, keyring, lim, a1, bad)
    assert conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM daily_usage").fetchone()[0] == 0


def test_batch_bytes_limit_says_how_many_fit(conn, keyring, a1):
    lim = Limits(
        message_batch_bytes=300,
        mcp_body_bytes=1000,
        unauthenticated_mcp_body_bytes=500,
        message_chars=200,
    )
    m = msgs(*[("claude", "x" * 100)] * 4)
    with pytest.raises(memory.LimitExceeded) as exc:
        append(conn, keyring, lim, a1, m)
    assert "Cabem 2" in str(exc.value) and "Nada foi gravado" in str(exc.value)
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0


def test_conversation_bytes_limit_and_state_untouched(conn, keyring, a1):
    lim = Limits(conversation_bytes=10)
    append(conn, keyring, lim, a1, msgs(("claude", "123456")))
    with pytest.raises(memory.LimitExceeded) as exc:
        append(conn, keyring, lim, a1, msgs(("claude", "12"), ("claude", "123"), ("claude", "1")))
    assert "Cabem 1" in str(exc.value)
    assert conn.execute("SELECT COUNT(*), MAX(seq) FROM messages").fetchone() == (1, 1)
    assert conn.execute("SELECT total_bytes FROM conversations").fetchone()[0] == 6


def test_daily_and_total_limits(conn, keyring, a1):
    lim = Limits(daily_writes=1)
    append(conn, keyring, lim, a1, msgs(("claude", "a")))
    with pytest.raises(memory.LimitExceeded):
        append(conn, keyring, lim, a1, msgs(("claude", "b")))
    lim = Limits(stored_bytes=3, database_bytes=1000)
    with pytest.raises(memory.LimitExceeded):
        append(conn, keyring, lim, a1, msgs(("claude", "abcd")), conversa="Outra", now=T0 + 86400)
    assert (
        conn.execute("SELECT COUNT(*) FROM conversations WHERE name_mac IS NOT NULL").fetchone()[0]
        == 1
    )


def test_idempotency(conn, keyring, limits, a1, a2):
    m = msgs(("claude", "ok"), ("usuario", "ok"))
    first = append(conn, keyring, limits, a1, m, lote="k1")
    again = append(conn, keyring, limits, a1, m, lote="k1")
    assert again["repetido"] is True
    assert (again["first_seq"], again["last_seq"]) == (first["first_seq"], first["last_seq"])
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 2
    # repetição depois que a conversa avançou ainda devolve o resultado antigo
    append(conn, keyring, limits, a1, msgs(("claude", "mais")))
    assert append(conn, keyring, limits, a1, m, lote="k1", continua_de=1)["repetido"] is True
    with pytest.raises(memory.BatchConflict):
        append(conn, keyring, limits, a1, msgs(("claude", "diferente")), lote="k1")
    # outra conta com a mesma chave não colide
    other = append(conn, keyring, limits, a2, msgs(("claude", "diferente")), lote="k1")
    assert other["repetido"] is False and other["first_seq"] == 4
    # mesma chave em outra conversa também não
    assert append(conn, keyring, limits, a1, m, conversa="Fio 2", lote="k1")["first_seq"] == 1
    # sem chave: sempre anexa
    append(conn, keyring, limits, a1, m)
    append(conn, keyring, limits, a1, m)
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 2 + 1 + 1 + 2 + 2 + 2


def test_continua_de(conn, keyring, limits, a1, a2):
    assert append(conn, keyring, limits, a1, msgs(("claude", "a")), continua_de=0)["last_seq"] == 1
    append(conn, keyring, limits, a1, msgs(("claude", "b")), continua_de=1)
    with pytest.raises(memory.SequenceConflict) as exc:
        append(conn, keyring, limits, a2, msgs(("claude", "c")), continua_de=1)
    assert exc.value.current_seq == 2 and "2" in str(exc.value)
    with pytest.raises(memory.SequenceConflict):
        append(conn, keyring, limits, a2, msgs(("claude", "c")), conversa="Nova", continua_de=3)
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 2
    # a conversa "Nova" não foi criada (rollback)
    assert conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[0] == 1
    with pytest.raises(memory.InvalidInput):
        append(conn, keyring, limits, a1, msgs(("claude", "c")), continua_de=-1)


def test_requires_grant_and_valid_names(conn, keyring, limits, a1):
    with pytest.raises(memory.InvalidInput):
        append(conn, keyring, limits, CLI, msgs(("claude", "a")))
    with pytest.raises(memory.InvalidInput):
        append(conn, keyring, limits, a1, msgs(("claude", "a")), conversa="a/b")
    with pytest.raises(memory.InvalidInput):
        append(conn, keyring, limits, a1, msgs(("claude", "a")), lote="x\ny")


def test_project_link_and_listing(conn, keyring, limits, a1, a2):
    append(conn, keyring, limits, a1, msgs(("claude", "a")), projeto="Proj A")
    append(conn, keyring, limits, a1, msgs(("claude", "b")), conversa="Solta")
    append(conn, keyring, limits, a1, msgs(("claude", "c")), conversa="Fio 3", projeto="Proj A")
    with pytest.raises(memory.InvalidInput):
        append(conn, keyring, limits, a1, msgs(("claude", "x")), projeto="Proj B")
    allc = cv.list_conversations(conn, keyring, a1, now=T0)
    assert [c["conversa"] for c in allc["conversas"]] == ["Fio 1", "Solta", "Fio 3"]
    assert allc["conversas"][1]["projeto"] is None and allc["conversas"][0]["ultima_seq"] == 1
    page = cv.list_conversations(conn, keyring, a1, "proj a", None, 1, now=T0)
    assert [c["conversa"] for c in page["conversas"]] == ["Fio 1"]
    nxt = cv.list_conversations(conn, keyring, a1, "Proj A", page["proximo_cursor"], 1, now=T0)
    assert [c["conversa"] for c in nxt["conversas"]] == ["Fio 3"] and nxt["proximo_cursor"] is None
    # cursor preso ao projeto e ao ator
    with pytest.raises(memory.InvalidCursor):
        cv.list_conversations(conn, keyring, a1, None, page["proximo_cursor"], 1, now=T0)
    with pytest.raises(memory.InvalidCursor):
        cv.list_conversations(conn, keyring, a2, "Proj A", page["proximo_cursor"], 1, now=T0)
    with pytest.raises(memory.NotFound):
        cv.list_conversations(conn, keyring, a1, "Nada", now=T0)


def test_trash_message_conversation_and_restore(conn, keyring, limits, a1):
    append(conn, keyring, limits, a1, msgs(("claude", "m1"), ("claude", "m2"), ("claude", "m3")))
    m1, m2, _m3 = [r[0] for r in conn.execute("SELECT public_id FROM messages ORDER BY seq")]
    conv = conn.execute("SELECT public_id FROM conversations").fetchone()[0]
    _trash(conn, keyring, a1, m1)
    assert [i["seq"] for i in cv.read_conversation(conn, keyring, "Fio 1")["itens"]] == [2, 3]
    res = _trash(conn, keyring, a1, conv, now=T0 + 5)
    assert res["itens"] == 3  # conversa + m2 + m3
    with pytest.raises(memory.NotFound):
        cv.read_conversation(conn, keyring, "Fio 1")
    with pytest.raises(memory.TrashError):
        memory.restore(conn, CLI, m2, now=T0 + 6)
    memory.restore(conn, CLI, conv, now=T0 + 6)
    assert [i["seq"] for i in cv.read_conversation(conn, keyring, "Fio 1")["itens"]] == [2, 3]
    memory.restore(conn, CLI, m1, now=T0 + 7)
    assert len(cv.read_conversation(conn, keyring, "Fio 1")["itens"]) == 3
    # anexar a conversa na lixeira é recusado
    _trash(conn, keyring, a1, conv, now=T0 + 9)
    with pytest.raises(memory.TrashError):
        append(conn, keyring, limits, a1, msgs(("claude", "x")))


def test_search_and_purge_messages(conn, keyring, limits, a1):
    append(conn, keyring, limits, a1, msgs(("usuario", f"coisa {SECRET} aqui"), ("claude", "x")))
    res = memory.search(conn, keyring, limits, a1, "segredo-zebra", now=T0)
    hit = res["resultados"][0]
    assert hit["tipo"] == "mensagem" and hit["conversa"] == "Fio 1" and hit["seq"] == 1
    conv = conn.execute("SELECT public_id FROM conversations").fetchone()[0]
    old_mac = conn.execute("SELECT name_mac FROM conversations").fetchone()[0]
    assert memory.purge(conn, CLI, conv, now=T0)["expurgados"] == 3
    row = conn.execute("SELECT name_mac, name_ct, purged_at FROM conversations").fetchone()
    assert row[0] != old_mac and row[1] is None and row[2] == T0
    assert conn.execute("SELECT COUNT(*) FROM messages WHERE text_ct IS NULL").fetchone()[0] == 2
    assert memory.search(conn, keyring, limits, a1, "segredo-zebra", now=T0)["resultados"] == []
    # nome reutilizável: nova conversa com o mesmo nome começa na seq 1
    assert append(conn, keyring, limits, a1, msgs(("claude", "novo")))["first_seq"] == 1


def test_purge_project_cascades_to_conversations(conn, keyring, limits, a1):
    append(conn, keyring, limits, a1, msgs(("claude", SECRET)), projeto="Proj A")
    proj = conn.execute("SELECT public_id FROM projects").fetchone()[0]
    memory.purge(conn, CLI, proj, now=T0)
    assert conn.execute("SELECT COUNT(*) FROM messages WHERE purged_at IS NULL").fetchone()[0] == 0
    assert (
        conn.execute("SELECT COUNT(*) FROM conversations WHERE name_ct IS NOT NULL").fetchone()[0]
        == 0
    )


def test_tampered_message_detected(conn, keyring, limits, a1, a2):
    append(conn, keyring, limits, a1, msgs(("claude", "a")))
    conn.execute("UPDATE messages SET claimed_author = 'usuario'")
    with pytest.raises(memory.DataCorrupted):
        cv.read_conversation(conn, keyring, "Fio 1")
    # busca pula a linha ilegível sem abortar
    assert memory.search(conn, keyring, limits, a1, "aa", now=T0)["resultados"] == []


def test_errors_never_carry_content(conn, keyring, limits, a1):
    append(conn, keyring, limits, a1, msgs(("claude", SECRET)), lote="k")
    errors = []
    for fn in (
        lambda: append(conn, keyring, limits, a1, msgs(("claude", SECRET + "!")), lote="k"),
        lambda: append(conn, keyring, limits, a1, msgs(("claude", SECRET)), continua_de=9),
        lambda: append(conn, keyring, Limits(message_chars=5), a1, msgs(("claude", SECRET))),
        lambda: append(conn, keyring, limits, a1, msgs(("alguem", SECRET))),
        lambda: append(conn, keyring, limits, a1, msgs(("claude", SECRET)), conversa=SECRET + "/"),
        lambda: cv.read_conversation(conn, keyring, "Conversa-Secreta-Q"),
    ):
        with pytest.raises(memory.MemoryServiceError) as exc:
            fn()
        errors.append(str(exc.value))
    assert errors and all(SECRET not in e and "Secreta" not in e for e in errors)


def test_concurrent_appends_get_contiguous_seq(conn, keyring, limits, a1, a2):
    def work(c, i):
        actor = a1 if i % 2 else a2
        return append(c, keyring, limits, actor, msgs(*[("claude", f"{i}-{j}") for j in range(3)]))

    res = run_threads(conn, 8, work)
    assert all(k == "ok" for k, _ in res)
    seqs = sorted(s for _, r in res for s in range(r["first_seq"], r["last_seq"] + 1))
    assert seqs == list(range(1, 25))
    assert conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[0] == 1
    assert conn.execute("SELECT total_bytes FROM conversations").fetchone()[0] == 24 * 3


def test_concurrent_same_batch_key_writes_once(conn, keyring, limits, a1):
    m = msgs(("claude", "a"), ("usuario", "b"))
    res = run_threads(conn, 6, lambda c, i: append(c, keyring, limits, a1, m, lote="k"))
    assert all(k == "ok" for k, _ in res)
    assert sum(1 for _, r in res if not r["repetido"]) == 1
    assert {(r["first_seq"], r["last_seq"]) for _, r in res} == {(1, 2)}
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 2


def test_concurrent_continua_de_only_one_wins(conn, keyring, limits, a1, a2):
    res = run_threads(
        conn,
        6,
        lambda c, i: append(
            c, keyring, limits, a1 if i % 2 else a2, msgs(("claude", f"m{i}")), continua_de=0
        ),
    )
    assert sum(1 for k, _ in res if k == "ok") == 1
    assert all(isinstance(v, memory.SequenceConflict) for k, v in res if k == "err")
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 1


def test_concurrent_last_daily_write(conn, keyring, a1):
    lim = Limits(daily_writes=1)
    res = run_threads(conn, 5, lambda c, i: append(c, keyring, lim, a1, msgs(("claude", "x"))))
    assert sum(1 for k, _ in res if k == "ok") == 1
    assert all(isinstance(v, memory.LimitExceeded) for k, v in res if k == "err")


def test_batch_key_only_hmac_on_disk(conn, keyring, limits, a1):
    secret = "CHAVE-PRIVADA-IDEMPOTENCIA-987654321"
    append(conn, keyring, limits, a1, msgs(("claude", "oi")), lote=secret)
    expected = keyring.mac("lote", b"chave:" + secret.encode()).hex()
    assert conn.execute("SELECT client_batch_key FROM message_batches").fetchone() == (expected,)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    from pathlib import Path

    assert secret.encode() not in Path(path).read_bytes()
    again = append(conn, keyring, limits, a1, msgs(("claude", "oi")), lote=secret)
    assert again["first_seq"] == 1
