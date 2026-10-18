"""API do painel (§12) atrás da borda real, com o fluxo OAuth de verdade."""

import json

import pytest
from starlette.applications import Starlette

from batataswap import conversations, memory
from batataswap.auth import oauth
from batataswap.auth.routes import oauth_routes
from batataswap.edge import EdgeMiddleware
from batataswap.memory import Actor
from batataswap.panel_api import panel_routes
from tests.test_oauth import ORIGIN, VERCEL, env, pkce  # noqa: F401 (env é fixture)
from tests.test_oauth_routes import (
    Server,
    authorize,
    connect_claude,
    consent,
    login,
    painel_query,
    policy,
    redirect_query,
    token,
)

SECRET_TEXT = "SEGREDO-DO-PROJETO-xyzzy"
SECRET_NAME = "Projeto-Confidencial-Quux"
SECRET_PREF = "PREFERENCIA-SECRETA-plugh"
SECRET_MSG = "MENSAGEM-SECRETA-zork"


class PanelServer(Server):
    def __init__(self, environment):
        super().__init__(environment)
        self.routes = oauth_routes(self.deps) + panel_routes(self.deps)
        self.app = EdgeMiddleware(
            Starlette(routes=self.routes), config=environment.config, routes=policy()
        )

    def painel_token(self):
        browser = self.browser()
        verifier, challenge = pkce()
        tx, csrf, _ = authorize(browser, painel_query(challenge))
        response = login(self, browser, tx, csrf)
        _, response = consent(browser, response.headers["location"])
        _, query = redirect_query(response)
        response = token(
            browser,
            {
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "code_verifier": verifier,
                "client_id": "painel-vercel",
                "redirect_uri": VERCEL + "/callback",
                "resource": ORIGIN + "/api/painel",
            },
            origin=VERCEL,
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]


@pytest.fixture
def server(env):  # noqa: F811
    return PanelServer(env)


def auth(access):
    return {"Authorization": "Bearer " + access, "Origin": VERCEL}


def grant_actor(server, label):
    row = server.env.conn.execute(
        "SELECT id, public_id FROM oauth_grants WHERE label = ? AND revoked_at IS NULL", (label,)
    ).fetchone()
    return Actor(row[0], row[1], label)


@pytest.fixture
def world(server):
    """Duas contas conectadas, dados salvos e um token do painel."""
    browser = server.browser()
    tokens1, _ = connect_claude(server, browser, "conta-1", state="s1")
    tokens2, _ = connect_claude(server, server.browser(), "conta-2", state="s2")
    srv_env = server.env
    limits = srv_env.config.limits
    now = int(server.clock[0])
    a1, a2 = grant_actor(server, "conta-1"), grant_actor(server, "conta-2")
    memory.save_context(
        srv_env.conn, srv_env.keyring, limits, a1, SECRET_NAME, SECRET_TEXT, ["d"], [], [], now=now
    )
    memory.save_context(
        srv_env.conn,
        srv_env.keyring,
        limits,
        a1,
        SECRET_NAME,
        SECRET_TEXT + "2",
        [],
        [],
        [],
        now=now + 5,
    )
    memory.add_preference(srv_env.conn, srv_env.keyring, limits, a2, SECRET_PREF, now=now + 7)
    conversations.append_messages(
        srv_env.conn,
        srv_env.keyring,
        limits,
        a2,
        "Fio",
        [{"autor": "usuario", "texto": SECRET_MSG}],
        now=now + 9,
    )
    server.tick()
    server.access1, server.access2 = tokens1["access_token"], tokens2["access_token"]
    server.painel = server.painel_token()
    return server


def test_routes_match_edge_policy(server):
    # Faltam aqui as rotas de /mcp, /saude, /painel/* e do CSS (outras tarefas); as do painel casam.
    with pytest.raises(ValueError) as caught:
        policy().check_against(server.routes)
    message = str(caught.value)
    assert "rota sem regra" not in message and "api/painel" not in message


def test_connections_shape(world):
    client = world.browser()
    response = client.get("/api/painel/conexoes", headers=auth(world.painel))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["access-control-allow-origin"] == VERCEL
    items = response.json()["conexoes"]
    assert [i["rotulo"] for i in items] == ["conta-1", "conta-2"]
    for item in items:
        assert set(item) == {"rotulo", "ativo", "conectado_desde", "ultimo_uso"}
        assert item["ativo"] is True
        assert item["conectado_desde"].endswith("Z") and "T" in item["conectado_desde"]
    # O grant do painel não aparece.
    assert "painel" not in [i["rotulo"] for i in items]


def test_activity_shape_and_counts(world):
    response = world.browser().get("/api/painel/atividade", headers=auth(world.painel))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"por_conta", "limites"}
    by = {a["rotulo"]: a for a in body["por_conta"]}
    for entry in by.values():
        assert set(entry) == {"rotulo", "contextos", "mensagens", "preferencias", "ultima_escrita"}
    assert (by["conta-1"]["contextos"], by["conta-1"]["mensagens"]) == (2, 0)
    assert (by["conta-2"]["preferencias"], by["conta-2"]["mensagens"]) == (1, 1)
    assert by["conta-1"]["ultima_escrita"].endswith("Z")
    limits = body["limites"]
    assert set(limits) == {
        "escritas_hoje",
        "escritas_max",
        "bytes_hoje",
        "bytes_max",
        "total_bytes",
        "total_max",
    }
    config = world.env.config.limits
    assert limits["escritas_hoje"] == 4  # 2 contextos + 1 preferência + 1 lote de mensagens
    assert limits["escritas_max"] == config.daily_writes
    assert limits["bytes_max"] == config.daily_bytes and limits["total_max"] == config.stored_bytes
    assert limits["total_bytes"] > 0 and limits["bytes_hoje"] > 0


def test_responses_never_contain_saved_content(world):
    client = world.browser()
    texts = [
        client.get("/api/painel/conexoes", headers=auth(world.painel)).text,
        client.get("/api/painel/atividade", headers=auth(world.painel)).text,
    ]
    world.tick()
    bad = client.post(
        "/api/painel/revogar",
        headers=auth(world.painel),
        json={"rotulo": SECRET_NAME, "totp": "000000"},
    )
    texts.append(bad.text)
    for text in texts:
        for secret in (SECRET_TEXT, SECRET_NAME, SECRET_PREF, SECRET_MSG, world.access1):
            assert secret not in text


def test_auth_required(world):
    client = world.browser()
    for method, path in (
        ("get", "/api/painel/conexoes"),
        ("get", "/api/painel/atividade"),
        ("post", "/api/painel/revogar"),
    ):
        response = getattr(client, method)(path, headers={"Origin": VERCEL})
        assert response.status_code == 401
        assert "oauth-protected-resource/api/painel" in response.headers["www-authenticate"]


def test_claude_token_refused_on_panel(world):
    client = world.browser()
    for path in ("/api/painel/conexoes", "/api/painel/atividade"):
        response = client.get(path, headers=auth(world.access1))
        assert response.status_code == 401
        assert "oauth-protected-resource/api/painel" in response.headers["www-authenticate"]
    response = client.post(
        "/api/painel/revogar",
        headers=auth(world.access1),
        json={"rotulo": "conta-2", "totp": world.totp()},
    )
    assert response.status_code == 401
    assert oauth.validate_bearer(
        world.env.conn, world.access2, ORIGIN + "/mcp", "memoria", world.clock[0]
    )


def test_cors_preflight_and_origin(world):
    client = world.browser()
    pre = client.options(
        "/api/painel/revogar",
        headers={
            "Origin": VERCEL,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert pre.status_code in (200, 204)
    assert pre.headers["access-control-allow-origin"] == VERCEL
    other = client.get(
        "/api/painel/conexoes", headers={**auth(world.painel), "Origin": "https://evil.example"}
    )
    assert other.status_code == 200  # a borda não bloqueia; o navegador é que barra sem CORS
    assert "access-control-allow-origin" not in other.headers


def revoke(world, label, code=None, **extra):
    world.tick()
    body = {"rotulo": label, "totp": code or world.totp()}
    body.update(extra)
    return world.browser().post("/api/painel/revogar", headers=auth(world.painel), json=body)


def test_revoke_success_kills_that_account_only(world):
    response = revoke(world, "conta-1")
    assert response.status_code == 204 and response.content == b""
    items = {
        i["rotulo"]: i
        for i in world.browser()
        .get("/api/painel/conexoes", headers=auth(world.painel))
        .json()["conexoes"]
    }
    assert items["conta-1"]["ativo"] is False and items["conta-2"]["ativo"] is True
    now = world.clock[0]
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(world.env.conn, world.access1, ORIGIN + "/mcp", "memoria", now)
    assert oauth.validate_bearer(world.env.conn, world.access2, ORIGIN + "/mcp", "memoria", now)
    # Já revogado: não há grant ativo.
    assert revoke(world, "conta-1").status_code == 404
    audit = world.env.conn.execute("SELECT COUNT(*) FROM audit WHERE event='grant_revogado'")
    assert audit.fetchone()[0] == 1


def test_revoke_wrong_totp_consumes_budget_then_locks(world):
    for _ in range(4):
        response = revoke(world, "conta-1", code="000000")
        assert response.status_code == 403 and response.json() == {"erro": "código inválido"}
    # 5ª tentativa errada tranca; depois disso nem o código certo passa.
    assert revoke(world, "conta-1", code="000000").status_code == 403
    locked = revoke(world, "conta-1")
    assert locked.status_code == 429 and int(locked.headers["retry-after"]) >= 1
    now = world.clock[0]
    assert oauth.validate_bearer(world.env.conn, world.access1, ORIGIN + "/mcp", "memoria", now)


def test_revoke_unknown_label_is_404(world):
    response = revoke(world, "conta-9")
    assert response.status_code == 404
    assert "conta-9" not in json.dumps(response.json()) or response.json() == {
        "erro": "conexão não encontrada"
    }
    # O painel não é revogável por aqui.
    assert revoke(world, "painel").status_code == 404


def test_revoke_replay_of_same_totp_refused(world):
    world.tick()
    code = world.totp()
    first = world.browser().post(
        "/api/painel/revogar", headers=auth(world.painel), json={"rotulo": "conta-1", "totp": code}
    )
    assert first.status_code == 204
    second = world.browser().post(
        "/api/painel/revogar", headers=auth(world.painel), json={"rotulo": "conta-2", "totp": code}
    )
    assert second.status_code == 403
    now = world.clock[0]
    assert oauth.validate_bearer(world.env.conn, world.access2, ORIGIN + "/mcp", "memoria", now)


@pytest.mark.parametrize(
    "payload",
    [
        b"nao e json",
        b"[]",
        b'"x"',
        b"{}",
        b'{"rotulo":"conta-1"}',
        b'{"rotulo":"conta-1","totp":"123456","extra":1}',
        b'{"rotulo":1,"totp":"123456"}',
        b'{"rotulo":"conta-1","totp":123456}',
        b'{"rotulo":"conta-1","totp":"12345"}',
        b'{"rotulo":"conta-1","totp":"abcdef"}',
        b'{"rotulo":"","totp":"123456"}',
    ],
)
def test_revoke_bad_body_is_400_and_free(world, payload):
    world.tick()
    response = world.browser().post(
        "/api/painel/revogar",
        headers={**auth(world.painel), "Content-Type": "application/json"},
        content=payload,
    )
    assert response.status_code == 400
    # Pedido malformado não gasta o orçamento nem derruba nada.
    assert revoke(world, "conta-1").status_code == 204


def test_revoke_requires_json_content_type(world):
    world.tick()
    response = world.browser().post(
        "/api/painel/revogar",
        headers={**auth(world.painel), "Content-Type": "text/plain"},
        content=json.dumps({"rotulo": "conta-1", "totp": world.totp()}),
    )
    assert response.status_code == 400
