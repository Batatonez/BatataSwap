import sqlite3
import threading
from pathlib import Path

import pytest

from batataswap import memory
from batataswap.config import Limits
from batataswap.crypto import Keyring, generate_master_key
from batataswap.db import connect, migrate
from batataswap.memory import Actor

T0 = 1_800_000_000
SECRET = "SEGREDO-ZEBRA-42"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "private" / "swap.db", create=True)
    migrate(c)
    c.execute(
        "INSERT INTO oauth_clients(client_id, kind, metadata_json, fetched_at, cache_until) "
        "VALUES ('c', 'static', '{}', 0, 0)"
    )
    yield c
    c.close()


@pytest.fixture
def keyring():
    return Keyring(generate_master_key())


def _grant(conn, public_id, label):
    cur = conn.execute(
        "INSERT INTO oauth_grants(public_id, client_row_id, label, resource, scope, created_at, "
        "expires_at) VALUES (?, 1, ?, 'r', 'memoria', 0, 9999999999)",
        (public_id, label),
    )
    return Actor(cur.lastrowid, public_id, label)


@pytest.fixture
def a1(conn):
    return _grant(conn, "grant_aaaaaaaaaaaaaaaa", "conta-1")


@pytest.fixture
def a2(conn):
    return _grant(conn, "grant_bbbbbbbbbbbbbbbb", "conta-2")


CLI = Actor(None, None, "cli")
PAINEL = Actor(None, None, "painel")


@pytest.fixture
def limits():
    return Limits()


def save(conn, keyring, limits, actor, projeto="Meu Projeto", resumo="r", now=T0, **kw):
    return memory.save_context(
        conn,
        keyring,
        limits,
        actor,
        projeto,
        resumo,
        kw.get("decisoes", []),
        kw.get("pendencias", []),
        kw.get("preferencias", []),
        now=now,
    )


def test_versions_increase_and_never_overwrite(conn, keyring, limits, a1, a2):
    v1 = save(conn, keyring, limits, a1, resumo="primeira")
    v2 = save(conn, keyring, limits, a2, projeto="meu projeto", resumo="segunda", now=T0 + 5)
    assert (v1["versao"], v2["versao"]) == (1, 2)
    assert v1["projeto_id"] == v2["projeto_id"]  # sem caixa
    assert memory.get_context(conn, keyring, "Meu Projeto")["resumo"] == "segunda"
    old = memory.get_context(conn, keyring, "Meu Projeto", versao=1)
    assert old["resumo"] == "primeira" and old["enviado_por"] == "conta-1"
    assert memory.get_context(conn, keyring, "Meu Projeto", 2)["enviado_por"] == "conta-2"
    assert conn.execute("SELECT COUNT(*) FROM contexts").fetchone()[0] == 2


def test_get_context_not_found_has_no_name(conn, keyring, limits, a1):
    with pytest.raises(memory.NotFound) as exc:
        memory.get_context(conn, keyring, "Inexistente Xyz")
    assert "Inexistente" not in str(exc.value)
    save(conn, keyring, limits, a1)
    with pytest.raises(memory.NotFound):
        memory.get_context(conn, keyring, "Meu Projeto", versao=9)


def test_cli_and_painel_origin(conn, keyring, limits):
    save(conn, keyring, limits, CLI)
    save(conn, keyring, limits, PAINEL)
    assert memory.get_context(conn, keyring, "Meu Projeto", 1)["enviado_por"] == "cli"
    assert memory.get_context(conn, keyring, "Meu Projeto", 2)["enviado_por"] == "painel"
    with pytest.raises(memory.InvalidActor):
        save(conn, keyring, limits, Actor(None, None, "conta-1"))


@pytest.mark.parametrize("name", ["", "   ", "x" * 81, "a/b", "a;b", "a\nb", "<b>", "a b"])
def test_invalid_names(conn, keyring, limits, a1, name):
    with pytest.raises(memory.InvalidInput):
        save(conn, keyring, limits, a1, projeto=name)


def test_name_accent_insensitive(conn, keyring, limits, a1):
    save(conn, keyring, limits, a1, projeto="Ação-1_x.y")
    assert memory.get_context(conn, keyring, "acao-1_x.y")["resumo"] == "r"


def test_tamper_detected_by_aad(conn, keyring, limits, a1):
    save(conn, keyring, limits, a1)
    conn.execute("UPDATE contexts SET created_at = created_at + 1")
    with pytest.raises(memory.DataCorrupted):
        memory.get_context(conn, keyring, "Meu Projeto")


def test_limits_each(conn, keyring, a1):
    lim = Limits(
        summary_chars=10,
        context_list_items=2,
        context_list_item_chars=5,
        context_bytes=90,
        preference_chars=5,
    )
    with pytest.raises(memory.LimitExceeded):
        save(conn, keyring, lim, a1, resumo="x" * 11)
    with pytest.raises(memory.LimitExceeded):
        save(conn, keyring, lim, a1, decisoes=["a", "b", "c"])
    with pytest.raises(memory.LimitExceeded):
        save(conn, keyring, lim, a1, pendencias=["abcdef"])
    with pytest.raises(memory.LimitExceeded):
        save(
            conn,
            keyring,
            lim,
            a1,
            resumo="x" * 10,
            decisoes=["12345"] * 2,
            pendencias=["12345"] * 2,
        )
    with pytest.raises(memory.LimitExceeded):
        memory.add_preference(conn, keyring, lim, a1, "123456", now=T0)
    with pytest.raises(memory.InvalidInput):
        save(conn, keyring, lim, a1, decisoes="texto")
    # tudo ou nada: nenhum projeto criado
    assert conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM daily_usage").fetchone()[0] == 0


def test_daily_writes_and_bytes_and_total(conn, keyring, a1):
    lim = Limits(daily_writes=2)
    save(conn, keyring, lim, a1)
    save(conn, keyring, lim, a1)
    with pytest.raises(memory.LimitExceeded):
        save(conn, keyring, lim, a1)
    # outro dia libera
    save(conn, keyring, lim, a1, now=T0 + 86400)
    assert conn.execute("SELECT COUNT(*) FROM contexts").fetchone()[0] == 3

    lim = Limits(daily_bytes=100, stored_bytes=10_000, database_bytes=20_000)
    with pytest.raises(memory.LimitExceeded):
        save(conn, keyring, lim, a1, resumo="x" * 200, now=T0 + 3 * 86400)
    lim = Limits(stored_bytes=120, database_bytes=1000)
    with pytest.raises(memory.LimitExceeded):
        save(conn, keyring, lim, a1, resumo="x" * 200, now=T0 + 4 * 86400)


def test_stored_total_counts_trash_not_purged(conn, keyring, limits, a1):
    ctx = save(conn, keyring, limits, a1, resumo="x" * 100)
    size = memory.stored_bytes(conn)
    assert size > 100
    memory.purge(conn, CLI, ctx["id"], now=T0)
    assert memory.stored_bytes(conn) == 0


def test_list_projects_pagination_and_cursor_rules(conn, keyring, limits, a1, a2):
    for i in range(5):
        save(conn, keyring, limits, a1, projeto=f"P{i}", now=T0 + i)
    page1 = memory.list_projects(conn, keyring, a1, limit=2, now=T0)
    assert [p["projeto"] for p in page1["projetos"]] == ["P0", "P1"]
    assert page1["projetos"][0]["enviado_por"] == "conta-1"
    page2 = memory.list_projects(conn, keyring, a1, page1["proximo_cursor"], 2, now=T0 + 10)
    assert [p["projeto"] for p in page2["projetos"]] == ["P2", "P3"]
    page3 = memory.list_projects(conn, keyring, a1, page2["proximo_cursor"], 2, now=T0 + 10)
    assert [p["projeto"] for p in page3["projetos"]] == ["P4"]
    assert page3["proximo_cursor"] is None
    # adulterado, de outro ator, de outra consulta, expirado
    cur = page1["proximo_cursor"]
    flipped = cur[:-2] + ("AA" if cur[-2:] != "AA" else "BB")
    for bad in (flipped, "lixo", "a.b", ""):
        with pytest.raises(memory.InvalidCursor):
            memory.list_projects(conn, keyring, a1, bad, 2, now=T0)
    with pytest.raises(memory.InvalidCursor):
        memory.list_projects(conn, keyring, a2, cur, 2, now=T0)
    with pytest.raises(memory.InvalidCursor):
        memory.list_preferences(conn, keyring, a1, cur, 2, now=T0)
    with pytest.raises(memory.InvalidCursor) as exc:
        memory.list_projects(conn, keyring, a1, cur, 2, now=T0 + 3601)
    assert "expirado" in str(exc.value)
    memory.list_projects(conn, keyring, a1, cur, 2, now=T0 + 3600)
    # cursor de outro keyring (outra chave) também é recusado
    other = Keyring(generate_master_key())
    with pytest.raises(memory.InvalidCursor):
        memory.list_projects(conn, other, a1, cur, 2, now=T0)


def test_list_projects_hides_trashed(conn, keyring, limits, a1):
    save(conn, keyring, limits, a1, projeto="P0")
    p = save(conn, keyring, limits, a1, projeto="P1")
    req = memory.request_delete(conn, keyring, a1, p["projeto_id"], now=T0)
    memory.confirm_delete(conn, a1, p["projeto_id"], req["codigo"], now=T0)
    names = [x["projeto"] for x in memory.list_projects(conn, keyring, a1, now=T0)["projetos"]]
    assert names == ["P0"]


def test_preferences(conn, keyring, limits, a1, a2):
    for i in range(3):
        memory.add_preference(conn, keyring, limits, a1 if i % 2 else a2, f"pref {i}", now=T0 + i)
    page = memory.list_preferences(conn, keyring, a1, limit=2, now=T0)
    assert [p["texto"] for p in page["preferencias"]] == ["pref 0", "pref 1"]
    assert page["preferencias"][0]["enviado_por"] == "conta-2"
    rest = memory.list_preferences(conn, keyring, a1, page["proximo_cursor"], 2, now=T0)
    assert [p["texto"] for p in rest["preferencias"]] == ["pref 2"]
    old = page["preferencias"][0]["id"]
    new = memory.add_preference(
        conn, keyring, limits, CLI, "pref 0 editada", now=T0, supersedes=old
    )
    assert new["versao"] == 2
    texts = [p["texto"] for p in memory.list_preferences(conn, keyring, a1, now=T0)["preferencias"]]
    assert "pref 0" not in texts and "pref 0 editada" in texts
    with pytest.raises(memory.NotFound):
        memory.add_preference(
            conn, keyring, limits, CLI, "x", now=T0, supersedes="pref_aaaaaaaaaaaaaaaa"
        )


class FakeClock:
    def __init__(self, step=1.0):
        self.t = 0.0
        self.step = step

    def __call__(self):
        self.t += self.step
        return self.t


def test_search_basic_accent_case(conn, keyring, limits, a1):
    save(conn, keyring, limits, a1, resumo="Decidimos usar AÇÚCAR no bolo", decisoes=["outra"])
    memory.add_preference(conn, keyring, limits, a1, "Gosto de açucar", now=T0)
    res = memory.search(conn, keyring, limits, a1, "acucar", now=T0)
    assert {r["tipo"] for r in res["resultados"]} == {"contexto", "preferencia"}
    assert res["proximo_cursor"] is None and res["parcial"] is False
    ctx = next(r for r in res["resultados"] if r["tipo"] == "contexto")
    assert ctx["projeto"] == "Meu Projeto" and "AÇÚCAR" in ctx["trecho"]
    with pytest.raises(memory.InvalidInput):
        memory.search(conn, keyring, limits, a1, "a", now=T0)


def test_search_limit_and_cursor_continues(conn, keyring, limits, a1):
    for i in range(6):
        save(conn, keyring, limits, a1, projeto=f"P{i}", resumo=f"alvo {i}")
    seen = []
    cursor = None
    for _ in range(10):
        res = memory.search(conn, keyring, limits, a1, "alvo", 2, cursor, now=T0)
        seen += [r["trecho"] for r in res["resultados"]]
        cursor = res["proximo_cursor"]
        if cursor is None:
            break
    assert seen == [f"alvo {i}" for i in range(6)]


def test_search_time_budget_continues_without_hits(conn, keyring, a1):
    lim = Limits(search_seconds=2, search_block_rows=2)
    for i in range(7):
        save(conn, keyring, lim, a1, projeto=f"P{i}", resumo=f"nada {i}")
    memory.add_preference(conn, keyring, lim, a1, "o alvo escondido", now=T0)
    clock = FakeClock()
    cursor, calls, found = None, 0, []
    while True:
        res = memory.search(conn, keyring, lim, a1, "escondido", 5, cursor, now=T0, clock=clock)
        calls += 1
        found += res["resultados"]
        cursor = res["proximo_cursor"]
        if cursor is None:
            break
        assert res["parcial"] is True
        assert calls < 20
    assert calls > 1 and len(found) == 1 and found[0]["tipo"] == "preferencia"


def test_search_cursor_bound_to_query_and_actor(conn, keyring, a1, a2):
    lim = Limits(search_seconds=1)
    for i in range(3):
        save(conn, keyring, lim, a1, projeto=f"P{i}", resumo="nada")
    res = memory.search(conn, keyring, lim, a1, "zzz", 5, None, now=T0, clock=FakeClock())
    cur = res["proximo_cursor"]
    assert cur
    with pytest.raises(memory.InvalidCursor):
        memory.search(conn, keyring, lim, a1, "outra", 5, cur, now=T0)
    with pytest.raises(memory.InvalidCursor):
        memory.search(conn, keyring, lim, a2, "zzz", 5, cur, now=T0)


def test_search_skips_trashed_and_purged(conn, keyring, limits, a1):
    p = save(conn, keyring, limits, a1, resumo="achado unico")
    req = memory.request_delete(conn, keyring, a1, p["projeto_id"], now=T0)
    memory.confirm_delete(conn, a1, p["projeto_id"], req["codigo"], now=T0)
    assert memory.search(conn, keyring, limits, a1, "achado", now=T0)["resultados"] == []


def test_delete_two_steps(conn, keyring, limits, a1, a2):
    ctx = save(conn, keyring, limits, a1, resumo=SECRET)
    req = memory.request_delete(conn, keyring, a1, ctx["id"], now=T0)
    assert req["alvo"]["tipo"] == "contexto" and req["alvo"]["versao"] == 1
    assert req["alvo"]["projeto"] == "Meu Projeto"
    assert SECRET not in repr(req)
    code = req["codigo"]
    # grant diferente, código errado, alvo errado
    with pytest.raises(memory.InvalidConfirmation):
        memory.confirm_delete(conn, a2, ctx["id"], code, now=T0 + 1)
    with pytest.raises(memory.InvalidConfirmation):
        memory.confirm_delete(conn, a1, ctx["id"], "errado", now=T0 + 1)
    other = save(conn, keyring, limits, a1, resumo="outra")
    with pytest.raises(memory.InvalidConfirmation):
        memory.confirm_delete(conn, a1, other["id"], code, now=T0 + 1)
    # expirado
    with pytest.raises(memory.InvalidConfirmation):
        memory.confirm_delete(conn, a1, ctx["id"], code, now=T0 + 300)
    # ok dentro do prazo
    done = memory.confirm_delete(conn, a1, ctx["id"], code, now=T0 + 299)
    assert done["itens"] == 1
    # reuso
    with pytest.raises(memory.InvalidConfirmation):
        memory.confirm_delete(conn, a1, ctx["id"], code, now=T0 + 300)
    with pytest.raises(memory.NotFound):
        memory.request_delete(conn, keyring, a1, ctx["id"], now=T0 + 400)
    with pytest.raises(memory.InvalidInput):
        memory.request_delete(conn, keyring, a1, "xx_123", now=T0)
    with pytest.raises(memory.InvalidActor):
        memory.request_delete(conn, keyring, CLI, other["id"], now=T0)
    # a versão 1 sumiu; a mais recente viva agora é a 2
    assert memory.get_context(conn, keyring, "Meu Projeto")["versao"] == 2


def _ids(conn, table):
    return [r[0] for r in conn.execute(f"SELECT public_id FROM {table} ORDER BY id")]


def _trash(conn, keyring, actor, pid, now=T0):
    req = memory.request_delete(conn, keyring, actor, pid, now=now)
    return memory.confirm_delete(conn, actor, pid, req["codigo"], now=now)


def test_trash_cascade_and_restore_respects_earlier_children(conn, keyring, limits, a1):
    save(conn, keyring, limits, a1, resumo="v1")
    save(conn, keyring, limits, a1, resumo="v2")
    save(conn, keyring, limits, a1, resumo="v3")
    c1, c2, c3 = _ids(conn, "contexts")
    early = _trash(conn, keyring, a1, c1)  # filho apagado antes
    proj = _ids(conn, "projects")[0]
    res = _trash(conn, keyring, a1, proj, now=T0 + 10)
    assert res["itens"] == 3  # projeto + c2 + c3 (c1 já estava na lixeira)
    roots = dict(conn.execute("SELECT public_id, trash_root FROM contexts"))
    assert roots[c1] == early["lixeira_id"] and roots[c2] == res["lixeira_id"]
    # filho com pai na lixeira não restaura
    with pytest.raises(memory.TrashError) as exc:
        memory.restore(conn, CLI, c2, now=T0 + 20)
    assert "projeto" in str(exc.value)
    out = memory.restore(conn, CLI, proj, now=T0 + 20)
    assert out["restaurados"] == 3
    live = dict(conn.execute("SELECT public_id, trashed_at IS NULL FROM contexts"))
    assert live == {c1: 0, c2: 1, c3: 1}
    # agora o c1 restaura sozinho
    assert memory.restore(conn, CLI, c1, now=T0 + 30)["restaurados"] == 1
    # grant não restaura nem expurga
    with pytest.raises(memory.InvalidActor):
        memory.restore(conn, a1, c1, now=T0)
    with pytest.raises(memory.InvalidActor):
        memory.purge(conn, a1, c1, now=T0)
    with pytest.raises(memory.NotFound):
        memory.restore(conn, CLI, c1, now=T0)  # não está na lixeira


def test_purge_project_cascade(conn, keyring, limits, a1):
    ctx = save(conn, keyring, limits, a1, projeto="Segredo Alfa", resumo=SECRET)
    memory.add_preference(conn, keyring, limits, a1, "pref", now=T0)
    proj = ctx["projeto_id"]
    old_mac = conn.execute("SELECT name_mac FROM projects").fetchone()[0]
    out = memory.purge(conn, CLI, proj, now=T0 + 5)
    assert out["expurgados"] == 2
    row = conn.execute("SELECT name_mac, name_ct, purged_at FROM projects").fetchone()
    assert row[0] != old_mac and len(row[0]) == 32 and row[1] is None and row[2] == T0 + 5
    crow = conn.execute("SELECT content_ct, purged_at, content_size FROM contexts").fetchone()
    assert crow[0] is None and crow[1] == T0 + 5 and crow[2] > 0
    # nome liberado para reuso e nome não resolve mais
    with pytest.raises(memory.NotFound):
        memory.get_context(conn, keyring, "Segredo Alfa")
    again = save(conn, keyring, limits, a1, projeto="Segredo Alfa", resumo="novo")
    assert again["versao"] == 1 and again["projeto_id"] != proj
    # idempotente
    assert memory.purge(conn, CLI, proj, now=T0 + 6)["expurgados"] == 0
    # nada do segredo no arquivo do banco depois do checkpoint
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    with open(path, "rb") as fh:
        assert SECRET.encode() not in fh.read()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE contexts SET purged_at = NULL WHERE content_ct IS NULL")


def test_sweep_trash_after_30_days(conn, keyring, limits, a1):
    save(conn, keyring, limits, a1, projeto="Velho")
    save(conn, keyring, limits, a1, projeto="Novo")
    old, new = _ids(conn, "projects")
    _trash(conn, keyring, a1, old, now=T0)
    _trash(conn, keyring, a1, new, now=T0 + 20 * 86400)
    assert memory.sweep_trash(conn, now=T0 + 29 * 86400) == 0
    assert memory.sweep_trash(conn, now=T0 + 31 * 86400) == 2  # projeto + contexto
    purged = dict(conn.execute("SELECT public_id, purged_at IS NOT NULL FROM projects"))
    assert purged == {old: 1, new: 0}
    assert memory.sweep_trash(conn, now=T0 + 31 * 86400) == 0


def test_trashed_project_blocks_save(conn, keyring, limits, a1):
    p = save(conn, keyring, limits, a1)
    _trash(conn, keyring, a1, p["projeto_id"])
    with pytest.raises(memory.TrashError):
        save(conn, keyring, limits, a1)


def test_errors_never_carry_content(conn, keyring, limits, a1):
    save(conn, keyring, limits, a1, projeto="Projeto Secreto Q", resumo=SECRET)
    errors = []
    for fn in (
        lambda: memory.get_context(conn, keyring, "Projeto Secreto Q", 7),
        lambda: memory.request_delete(conn, keyring, a1, "ctx_aaaaaaaaaaaaaaaa", now=T0),
        lambda: memory.confirm_delete(conn, a1, "proj_aaaaaaaaaaaaaaaa", "x", now=T0),
        lambda: save(conn, keyring, limits, a1, projeto="Projeto Secreto Q", resumo=SECRET * 4000),
        lambda: save(conn, keyring, limits, a1, projeto=SECRET + "/"),
        lambda: memory.list_projects(conn, keyring, a1, SECRET, now=T0),
    ):
        with pytest.raises(memory.MemoryServiceError) as exc:
            fn()
        errors.append(str(exc.value))
    assert errors and all(SECRET not in e and "Secreto" not in e for e in errors)


def test_export_all_includes_everything(conn, keyring, limits, a1):
    from batataswap import conversations

    ctx = save(conn, keyring, limits, a1, resumo=SECRET, decisoes=["d1"])
    memory.add_preference(conn, keyring, limits, a1, "uma pref", now=T0)
    conversations.append_messages(
        conn, keyring, limits, a1, "Conv X", [{"autor": "usuario", "texto": "oi"}], now=T0
    )
    gone = save(conn, keyring, limits, a1, projeto="Apagado", resumo="sumiu")
    memory.purge(conn, CLI, gone["projeto_id"], now=T0)
    _trash(conn, keyring, a1, ctx["id"])
    data = memory.export_all(conn, keyring)
    by_name = {p["nome"]: p for p in data["projetos"]}
    assert by_name["Meu Projeto"]["contextos"][0]["resumo"] == SECRET
    assert by_name["Meu Projeto"]["contextos"][0]["na_lixeira"] is True
    skeleton = next(p for p in data["projetos"] if p["nome"] is None)
    assert skeleton["expurgado_em"] and "resumo" not in skeleton["contextos"][0]
    assert data["preferencias"][0]["texto"] == "uma pref"
    conv = data["conversas"][0]
    assert conv["nome"] == "Conv X" and conv["mensagens"][0]["texto"] == "oi"
    assert conv["lotes"][0]["enviado_por"] == "conta-1"


# --- revisão: checkpoint, teto do banco, snapshot do export, origem, busca, concorrência ---


def db_path(conn):
    return Path(conn.execute("PRAGMA database_list").fetchone()[2])


def run_threads(conn, n, fn):
    """Roda ``fn(conexão_própria, i)`` em n threads ao mesmo tempo. Devolve [("ok"|"err", valor)]."""
    path = db_path(conn)
    barrier = threading.Barrier(n)
    results = [None] * n

    def work(i):
        c = connect(path)
        try:
            barrier.wait()
            try:
                results[i] = ("ok", fn(c, i))
            except Exception as exc:  # noqa: BLE001
                results[i] = ("err", exc)
        finally:
            c.close()

    threads = [threading.Thread(target=work, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_purge_checkpoint_pending_with_concurrent_reader(conn, keyring, limits, a1):
    ctx = save(conn, keyring, limits, a1, resumo=SECRET)
    conn.execute("PRAGMA busy_timeout=0")
    reader = connect(db_path(conn))
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM projects").fetchall()  # segura um snapshot do WAL
    out = memory.purge(conn, CLI, ctx["id"], now=T0)
    assert out["limpeza_fisica"] == "pendente"
    assert conn.execute("SELECT value FROM meta WHERE key='checkpoint_pendente'").fetchone()[
        0
    ] == str(T0)
    assert memory.retry_checkpoint(conn, now=T0 + 1) == "pendente"
    reader.execute("ROLLBACK")
    reader.close()
    assert memory.sweep_trash(conn, now=T0 + 2) == 0  # a faxina refaz o checkpoint
    assert (
        conn.execute("SELECT COUNT(*) FROM meta WHERE key='checkpoint_pendente'").fetchone()[0] == 0
    )
    assert memory.retry_checkpoint(conn, now=T0 + 3) == "ok"
    ctx2 = save(conn, keyring, limits, a1, projeto="Outro")
    assert memory.purge(conn, CLI, ctx2["id"], now=T0 + 4)["limpeza_fisica"] == "ok"


def test_database_size_cap_rolls_back(conn, keyring, a1):
    current = memory.database_bytes(conn)
    lim = Limits(database_bytes=current + 10, stored_bytes=current + 10)
    with pytest.raises(memory.LimitExceeded) as exc:
        save(conn, keyring, lim, a1, resumo="x" * 100)
    assert "banco" in str(exc.value)
    with pytest.raises(memory.LimitExceeded):
        memory.add_preference(conn, keyring, lim, a1, "y" * 100, now=T0)
    from batataswap import conversations

    with pytest.raises(memory.LimitExceeded):
        conversations.append_messages(
            conn, keyring, lim, a1, "Fio", [{"autor": "claude", "texto": "z" * 100}], now=T0
        )
    for table in (
        "projects",
        "contexts",
        "preferences",
        "conversations",
        "messages",
        "daily_usage",
    ):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_export_is_a_single_snapshot(conn, keyring, limits, a1, monkeypatch):
    from batataswap import conversations

    conversations.append_messages(
        conn, keyring, limits, a1, "Fio", [{"autor": "claude", "texto": "antes"}], now=T0
    )
    path = db_path(conn)
    original = conversations.export_conversations

    def racing(c, k):
        w = connect(path)
        conversations.append_messages(
            w, keyring, limits, a1, "Fio", [{"autor": "claude", "texto": "tarde"}], now=T0 + 1
        )
        save(w, keyring, limits, a1, projeto="Novo Depois", now=T0 + 1)
        w.close()
        return original(c, k)

    monkeypatch.setattr(conversations, "export_conversations", racing)
    data = memory.export_all(conn, keyring)
    assert [m["texto"] for m in data["conversas"][0]["mensagens"]] == ["antes"]
    assert data["projetos"] == []
    assert not conn.in_transaction
    monkeypatch.setattr(conversations, "export_conversations", original)
    assert len(memory.export_all(conn, keyring)["conversas"][0]["mensagens"]) == 2
    conn.execute("BEGIN")
    with pytest.raises(memory.InvalidInput):
        memory.export_all(conn, keyring)
    conn.execute("ROLLBACK")


def test_export_keeps_origin_identity_of_same_label(conn, keyring, limits):
    from batataswap import conversations

    first = _grant(conn, "grant_dddddddddddddddd", "conta-1")
    conn.execute("UPDATE oauth_grants SET revoked_at = 5 WHERE id = ?", (first.grant_id,))
    second = _grant(conn, "grant_eeeeeeeeeeeeeeee", "conta-1")
    for actor in (first, second):
        save(conn, keyring, limits, actor, projeto=f"P{actor.grant_id}")
        memory.add_preference(conn, keyring, limits, actor, f"pref {actor.grant_id}", now=T0)
        conversations.append_messages(
            conn, keyring, limits, actor, "Fio", [{"autor": "claude", "texto": "m"}], now=T0
        )
    memory.add_preference(conn, keyring, limits, CLI, "da cli", now=T0)
    data = memory.export_all(conn, keyring)
    ctx_origins = [p["contextos"][0]["origem"] for p in data["projetos"]]
    assert ctx_origins == ["grant_dddddddddddddddd", "grant_eeeeeeeeeeeeeeee"]
    assert [p["origem"] for p in data["preferencias"]] == [*ctx_origins, "cli"]
    assert all(p["enviado_por"] == "conta-1" for p in data["preferencias"][:2])
    conv = data["conversas"][0]
    assert [b["origem"] for b in conv["lotes"]] == ctx_origins
    assert [m["origem"] for m in conv["mensagens"]] == ctx_origins


def test_search_many_skeletons_bounded_work(conn, keyring, a1, monkeypatch):
    lim = Limits(search_block_rows=5, search_seconds=2)
    for i in range(23):
        memory.add_preference(conn, keyring, lim, a1, f"lixo {i}", now=T0)
    for (pid,) in conn.execute("SELECT public_id FROM preferences").fetchall():
        memory.purge(conn, CLI, pid, now=T0)
    memory.add_preference(conn, keyring, lim, a1, "o tesouro", now=T0)
    blocks = []
    real = memory._search_rows

    def counting(c, key, low, high):
        assert high - low <= 5  # nunca varre além de um bloco
        blocks[-1] += 1
        return real(c, key, low, high)

    monkeypatch.setattr(memory, "_search_rows", counting)
    clock, cursor, found, calls = FakeClock(), None, [], 0
    while True:
        blocks.append(0)
        res = memory.search(conn, keyring, lim, a1, "tesouro", 5, cursor, now=T0, clock=clock)
        calls += 1
        found += res["resultados"]
        cursor = res["proximo_cursor"]
        if cursor is None:
            break
        assert calls < 30
    assert len(found) == 1 and calls > 1 and max(blocks) <= 2


def test_concurrent_daily_balance(conn, keyring, a1):
    lim = Limits(daily_writes=3)
    res = run_threads(conn, 8, lambda c, i: save(c, keyring, lim, a1, projeto=f"P{i}"))
    assert sum(1 for k, _ in res if k == "ok") == 3
    assert all(isinstance(v, memory.LimitExceeded) for k, v in res if k == "err")
    assert conn.execute("SELECT writes FROM daily_usage").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM contexts").fetchone()[0] == 3


def test_concurrent_delete_code_consumed_once(conn, keyring, limits, a1):
    ctx = save(conn, keyring, limits, a1)
    code = memory.request_delete(conn, keyring, a1, ctx["id"], now=T0)["codigo"]
    res = run_threads(
        conn, 6, lambda c, i: memory.confirm_delete(c, a1, ctx["id"], code, now=T0 + 1)
    )
    assert sum(1 for k, _ in res if k == "ok") == 1
    assert all(isinstance(v, memory.InvalidConfirmation) for k, v in res if k == "err")
