import json

from batataswap import logs


def test_closed_values(capsys):
    secret = "SEGREDO-XYZ"
    logs.emit(secret, 200)
    logs.emit("login_ok", secret, ms=secret, grant=secret, tamanho=secret, nivel=secret)
    record = json.loads(capsys.readouterr().out)
    assert set(record) == {"evento", "status", "ms", "grant", "tamanho", "nivel"}
    assert secret not in json.dumps(record)
    assert record["status"] is None


# A fixture prepara o dono com scrypt reduzido para o ensaio.
from tests.test_oauth import env  # noqa: F401


def test_entire_flow_does_not_leak(env, capsys, caplog, monkeypatch):  # noqa: F811
    import logging

    caplog.set_level(logging.DEBUG)
    # O cliente de teste registra URLs próprias; o ensaio verifica os logs do servidor.
    caplog.set_level(logging.WARNING, logger="httpx")

    from starlette.testclient import TestClient

    from batataswap.auth import passwords
    from tests.test_app import app_for, rpc
    from tests.test_oauth import ORIGIN
    from tests.test_oauth_routes import Server, connect_claude

    secret = "SEGREDO-XYZ"
    password = secret + "-senha-726!"
    env.conn.execute(
        "UPDATE owner SET password_hash=?", (passwords.hash_password(password, log_n=10),)
    )
    server = Server(env)
    server.deps.on_event = logs.emit
    server.app.on_event = logs.emit
    # O helper de login usa a senha padrão como argumento; substitui apenas neste teste.
    import tests.test_oauth_routes as routes

    original = routes.login
    monkeypatch.setattr(routes, "login", lambda *a, **kw: original(*a, **kw, password=password))
    with server.browser() as browser:
        tokens, _ = connect_claude(server, browser, "conta-1", state=secret + "-state")
        app = app_for(env)
        grant = env.conn.execute("SELECT id,public_id FROM oauth_grants").fetchone()

        with TestClient(app, base_url=ORIGIN) as client:
            for name, args in [
                (
                    "salvar_contexto",
                    {
                        "projeto": secret,
                        "resumo": secret + "-conteudo",
                        "decisoes": [],
                        "pendencias": [],
                        "preferencias": [],
                    },
                ),
                (
                    "anexar_mensagens",
                    {"conversa": secret, "mensagens": [{"autor": "usuario", "texto": secret}]},
                ),
                ("buscar", {"texto": secret}),
                (
                    "salvar_contexto",
                    {
                        "projeto": secret,
                        "resumo": secret * 1000,
                        "decisoes": [],
                        "pendencias": [],
                        "preferencias": [],
                    },
                ),
            ]:
                response = rpc(
                    client, tokens["access_token"], "tools/call", {"name": name, "arguments": args}
                )
                assert response.status_code == 200
                assert response.json()["result"].get("isError", False) == (
                    len(args.get("resumo", "")) > 5000
                )
            for url, headers in [
                ("/mcp?access_token=" + secret, {}),
                ("/" + secret, {}),
                ("/mcp", {"Authorization": "Bearer " + secret}),
            ]:
                assert client.post(url, headers=headers).status_code >= 400
        refreshed = browser.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": env.config.allowed_cimd_client_ids[0],
                "resource": ORIGIN + "/mcp",
            },
        )
        assert refreshed.status_code == 200
        tokens = refreshed.json()
        response = browser.post(
            "/oauth/revoke",
            data={
                "token": tokens["access_token"],
                "client_id": env.config.allowed_cimd_client_ids[0],
            },
        )
        assert response.status_code == 200
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err + caplog.text
    records = [json.loads(line) for line in captured.out.splitlines()]
    assert sum(r["evento"] == "ferramenta" for r in records) == 4
    assert any(r["evento"] == "login_ok" for r in records)

    assert all(r["grant"] == grant[1] for r in records if r["evento"] == "ferramenta")
    assert any(r["evento"] == "token_emitido" for r in records)


def test_native_journal(monkeypatch, capsys):
    from unittest.mock import MagicMock

    journal = MagicMock()
    monkeypatch.setattr(logs.socket, "socket", lambda *a: journal)
    monkeypatch.delenv("JOURNAL_STREAM", raising=False)
    logs.emit("backup_falhou", 500, nivel="err")
    assert capsys.readouterr().out == ""
    payload, path = journal.__enter__.return_value.sendto.call_args.args
    assert payload.startswith(b"PRIORITY=3\nSYSLOG_IDENTIFIER=batataswap\n")
    assert payload.endswith(b"\n")
    assert path == "/run/systemd/journal/socket"
    monkeypatch.setattr(logs, "ADMIN", True)
    logs.emit("backup_ok", 200)
    assert json.loads(capsys.readouterr().out)["evento"] == "backup_ok"
    payload, _ = journal.__enter__.return_value.sendto.call_args.args
    assert payload.startswith(b"PRIORITY=6\nSYSLOG_IDENTIFIER=batataswap-admin\n")
    assert payload.endswith(b"\n")


def test_missing_journal(monkeypatch, capsys):
    def missing(*args):
        raise FileNotFoundError

    monkeypatch.setattr(logs.socket, "socket", missing)
    logs.emit("backup_falhou", 500, nivel="err")
    assert capsys.readouterr().out == ""


from tests.test_cli import setup_cli  # noqa: F401


def test_cli_events(setup_cli, monkeypatch, capsys, caplog):  # noqa: F811
    import logging
    from unittest.mock import MagicMock

    from batataswap import cli, db

    caplog.set_level(logging.DEBUG)
    journal = MagicMock()
    monkeypatch.setattr(logs.socket, "socket", lambda *a: journal)
    config = setup_cli
    assert cli.main(["backup"], config=config) == 0
    assert cli.main(["restore-test"], config=config) == 0
    source = next(config.backup_dir.glob("*.db"))
    assert cli.main(["restore", str(source)], config=config) == 0
    conn = db.connect(config.data_dir / "batataswap.db")
    try:
        conn.execute("INSERT INTO oauth_clients VALUES (1,'client','static','{}',0,0)")
        conn.execute(
            "INSERT INTO oauth_grants VALUES (1,'grant_aaaaaaaaaaaaaaaa',1,'SEGREDO-XYZ',"
            "'https://example.ts.net/mcp','memoria',0,9999999999,NULL,NULL)"
        )
    finally:
        conn.close()
    assert cli.main(["revoke", "SEGREDO-XYZ"], config=config) == 0
    captured = capsys.readouterr()
    records = [json.loads(line) for line in captured.out.splitlines()]
    assert {r["evento"] for r in records} >= {
        "backup_ok",
        "restore_teste_ok",
        "restore_feito",
        "grant_revogado",
    }
    payloads = [call.args[0] for call in journal.__enter__.return_value.sendto.call_args_list]
    assert all(b"SYSLOG_IDENTIFIER=batataswap-admin\n" in p for p in payloads)
    assert "SEGREDO-XYZ" not in captured.out + captured.err + caplog.text + str(payloads)


def test_oauth_security_events(env, capsys, caplog):  # noqa: F811
    import logging

    import pytest

    from batataswap.auth import oauth
    from tests.test_oauth import NOW, claude_params, exchange, make_code, pkce, refresh

    caplog.set_level(logging.DEBUG)
    verifier, challenge = pkce()
    code, _ = make_code(env, claude_params(challenge))
    tokens = exchange(env, code, verifier)
    refresh(env, tokens.refresh_token, NOW + 1)
    with pytest.raises(oauth.OAuthError):
        refresh(env, tokens.refresh_token, NOW + 2)
    with pytest.raises(oauth.OAuthError):
        exchange(env, code, verifier, now=NOW + 3)
    public_id = env.conn.execute("SELECT public_id FROM oauth_grants").fetchone()[0]
    captured = capsys.readouterr()
    records = [json.loads(line) for line in captured.out.splitlines()]
    wanted = {"grant_criado", "token_emitido", "refresh_reuso", "codigo_reuso", "grant_revogado"}
    assert {r["evento"] for r in records} >= wanted
    assert all(r["grant"] == public_id for r in records if r["evento"] in wanted)
    for secret in (code, tokens.access_token, tokens.refresh_token, verifier):
        assert secret not in captured.out + captured.err + caplog.text
