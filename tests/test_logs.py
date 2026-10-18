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
    import asyncio

    from batataswap.auth import passwords
    from batataswap.memory import Actor
    from batataswap.tools import request_actor
    from tests.test_app import app_for
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

        async def run():
            marker = request_actor.set(Actor(*grant, "conta-1"))
            try:
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
                        {
                            "conversa": secret,
                            "mensagens": [{"autor": "usuario", "texto": secret + "-mensagem"}],
                        },
                    ),
                    ("buscar", {"texto": secret}),
                ]:
                    response = await app.state.dispatch_tool(name, args)
                    assert not response.is_error
            finally:
                request_actor.reset(marker)

        asyncio.run(run())
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
    assert sum(r["evento"] == "ferramenta" for r in records) == 3
    assert any(r["evento"] == "login_ok" for r in records)
