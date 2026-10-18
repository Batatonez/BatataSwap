"""Rotas do AS atrás da borda real (RoutePolicy.default + regra do CSS estático)."""

import logging
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from batataswap.auth import oauth, pages
from batataswap.auth.cimd import CLAUDE_REDIRECT_URI
from batataswap.auth.ratelimit import Budget, CreationRate, ScryptSlot
from batataswap.auth.routes import (
    DEVICE_COOKIE,
    TX_COOKIE,
    OAuthDeps,
    bearer_context,
    bearer_error_response,
    oauth_routes,
)
from batataswap.auth.totp import code_at
from batataswap.config import CLAUDE_CIMD_CLIENT_ID
from batataswap.edge import EdgeMiddleware, RoutePolicy, RouteRule
from tests.test_oauth import (  # noqa: F401 (env é fixture)
    NOW,
    ORIGIN,
    PAINEL_CALLBACK,
    PASSWORD,
    VERCEL,
    FakeFetcher,
    env,
    pkce,
)

STATIC_RULE = RouteRule("GET", "/static/*", "public", static=True)


def policy():
    return RoutePolicy([*RoutePolicy.default().rules, STATIC_RULE])


def stub_routes(deps):
    async def mcp(request):
        try:
            ctx = await bearer_context(deps, request.scope, "mcp")
        except oauth.BearerError as error:
            return bearer_error_response(error)
        return JSONResponse({"rotulo": ctx.label, "grant": ctx.grant_public_id})

    async def painel(request):
        try:
            ctx = await bearer_context(deps, request.scope, "painel")
        except oauth.BearerError as error:
            return bearer_error_response(error)
        return JSONResponse({"rotulo": ctx.label})

    async def nada(request):
        return JSONResponse({})

    return [
        Route("/mcp", mcp, methods=["POST"]),
        Route("/api/painel/{nome}", painel, methods=["GET", "POST"]),
        Route("/painel/{nome}", nada, methods=["GET", "POST"]),
        Route("/saude", nada, methods=["GET"]),
    ]


class Server:
    def __init__(self, environment, creation_rate=None):
        self.env = environment
        env = environment  # noqa: F811
        self.clock = [NOW]
        self.events = []
        self.deps = OAuthDeps(
            config=env.config,
            keyring=env.keyring,
            connect=env.connect,
            budget=Budget(),
            slot=ScryptSlot(),
            fetcher=FakeFetcher(),
            creation_rate=creation_rate or CreationRate(30, 600),
            clock=lambda: self.clock[0],
            on_event=lambda e, s: self.events.append((e, s)),
        )
        self.routes = oauth_routes(self.deps) + stub_routes(self.deps)
        self.app = EdgeMiddleware(Starlette(routes=self.routes), config=env.config, routes=policy())
        self.secrets = []

    def browser(self):
        return TestClient(self.app, base_url=ORIGIN, follow_redirects=False)

    def tick(self, seconds=30):
        self.clock[0] += seconds

    def totp(self):
        code = code_at(self.env.secret, int(self.clock[0]) // 30)
        self.secrets.append(code)
        return code


@pytest.fixture
def server(env):  # noqa: F811
    return Server(env)


def hidden(html, name):
    match = re.search(rf'name="{name}" value="([^"]*)"', html)
    return match.group(1) if match else None


def claude_query(challenge, state="estado-xyz", **changes):
    params = {
        "response_type": "code",
        "client_id": CLAUDE_CIMD_CLIENT_ID,
        "redirect_uri": CLAUDE_REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": ORIGIN + "/mcp",
        "scope": "memoria offline_access",
        "state": state,
    }
    params.update(changes)
    return {k: v for k, v in params.items() if v is not None}


def painel_query(challenge, state="st-painel"):
    return {
        "response_type": "code",
        "client_id": "painel-vercel",
        "redirect_uri": PAINEL_CALLBACK,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": ORIGIN + "/api/painel",
        "scope": "painel",
        "state": state,
    }


FORM = {"Origin": ORIGIN}


def authorize(browser, query):
    response = browser.get("/oauth/authorize", params=query)
    assert response.status_code == 200, response.text
    return hidden(response.text, "tx"), hidden(response.text, "csrf"), response


def login(server, browser, tx, csrf, remember=False, password=PASSWORD, code=None):
    server.tick()
    data = {"tx": tx, "csrf": csrf, "senha": password, "codigo": code or server.totp()}
    if remember:
        data["lembrar"] = "sim"
    return browser.post("/oauth/login", data=data, headers=FORM)


def consent(browser, location, **fields):
    page = browser.get(location)
    assert page.status_code == 200, page.text
    data = {
        "tx": hidden(page.text, "tx"),
        "csrf": hidden(page.text, "csrf"),
        "acao": "autorizar",
    }
    vistos = hidden(page.text, "vistos")
    if vistos is not None:
        data["vistos"] = vistos
    data.update(fields)
    return page, browser.post("/oauth/consent", data=data, headers=FORM)


def redirect_query(response):
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    return location, parse_qs(urlsplit(location).query, keep_blank_values=True)


def token(browser, data, origin=None):
    headers = {"Origin": origin} if origin else {}
    return browser.post("/oauth/token", data=data, headers=headers)


def connect_claude(server, browser, label, state="estado-xyz"):
    verifier, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge, state))
    response = login(server, browser, tx, csrf)
    assert response.status_code == 303
    _, response = consent(browser, response.headers["location"], rotulo=label)
    location, query = redirect_query(response)
    assert location.startswith(CLAUDE_REDIRECT_URI + "?")
    response = token(
        browser,
        {
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "code_verifier": verifier,
            "client_id": CLAUDE_CIMD_CLIENT_ID,
            "redirect_uri": CLAUDE_REDIRECT_URI,
            "resource": ORIGIN + "/mcp",
        },
    )
    assert response.status_code == 200, response.text
    server.secrets += [query["code"][0], verifier]
    return response.json(), query


def mcp(browser, access):
    return browser.post("/mcp", headers={"Authorization": "Bearer " + access}, json={})


# ---------------------------------------------------------------------------
# Metadados e política da borda
# ---------------------------------------------------------------------------


def test_metadata_routes(server):
    browser = server.browser()
    prm = browser.get("/.well-known/oauth-protected-resource/mcp")
    assert prm.status_code == 200
    assert prm.json() == oauth.protected_resource_metadata(server.env.config, "mcp")
    assert browser.get("/.well-known/oauth-protected-resource").json() == prm.json()
    painel = browser.get("/.well-known/oauth-protected-resource/api/painel").json()
    assert painel["resource"] == ORIGIN + "/api/painel"
    meta = browser.get("/.well-known/oauth-authorization-server").json()
    assert meta == oauth.authorization_server_metadata(server.env.config)
    assert prm.headers["cache-control"] == "no-store"
    # Descoberta feita pelo backend do Claude: sem Origin, POST sem token → 401 com PRM.
    response = browser.post("/mcp", json={})
    assert response.status_code == 401
    assert "oauth-protected-resource/mcp" in response.headers["www-authenticate"]


def test_routes_match_edge_policy(server):
    policy().check_against(server.routes)
    with pytest.raises(ValueError) as caught:
        RoutePolicy.default().check_against(server.routes)
    # Única divergência: o CSS das páginas (a borda precisa de uma regra estática).
    assert pages.STATIC_PATH in str(caught.value)
    assert str(caught.value).count("rota sem regra") == 1


def test_stylesheet_is_static(server):
    response = server.browser().get(pages.STATIC_PATH)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert response.headers["cache-control"] == "public, max-age=86400"


# ---------------------------------------------------------------------------
# Fluxos felizes
# ---------------------------------------------------------------------------


def test_two_accounts_happy_path(server):
    browser = server.browser()
    tokens1, query1 = connect_claude(server, browser, "conta-1", state="s1")
    assert query1["state"] == ["s1"] and query1["iss"] == [ORIGIN]
    tokens2, _ = connect_claude(server, server.browser(), "conta-2", state="s2")
    for tokens, label in ((tokens1, "conta-1"), (tokens2, "conta-2")):
        assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 3600
        assert tokens["scope"] == "memoria offline_access"
        assert set(tokens) == {"access_token", "token_type", "expires_in", "refresh_token", "scope"}
        response = mcp(browser, tokens["access_token"])
        assert response.status_code == 200 and response.json()["rotulo"] == label
    # Refresh rotativo pela rota.
    response = token(
        browser,
        {
            "grant_type": "refresh_token",
            "refresh_token": tokens1["refresh_token"],
            "client_id": CLAUDE_CIMD_CLIENT_ID,
        },
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    rotated = response.json()
    assert rotated["refresh_token"] != tokens1["refresh_token"]
    # Reuso do refresh antigo derruba a família.
    response = token(
        browser,
        {
            "grant_type": "refresh_token",
            "refresh_token": tokens1["refresh_token"],
            "client_id": CLAUDE_CIMD_CLIENT_ID,
        },
    )
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"
    assert mcp(browser, rotated["access_token"]).status_code == 401
    assert mcp(browser, tokens2["access_token"]).status_code == 200


def test_painel_flow_and_audience(server):
    browser = server.browser()
    verifier, challenge = pkce()
    tx, csrf, page = authorize(browser, painel_query(challenge))
    assert "Painel BatataSwap" in page.text and "batataswap.vercel.app" in page.text
    response = login(server, browser, tx, csrf)
    consent_page, response = consent(browser, response.headers["location"])
    assert 'name="rotulo"' not in consent_page.text
    location, query = redirect_query(response)
    assert location.startswith(PAINEL_CALLBACK + "?")
    assert query["state"] == ["st-painel"] and query["iss"] == [ORIGIN]
    response = token(
        browser,
        {
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "code_verifier": verifier,
            "client_id": "painel-vercel",
            "redirect_uri": PAINEL_CALLBACK,
            "resource": ORIGIN + "/api/painel",
        },
        origin=VERCEL,
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == VERCEL
    body = response.json()
    assert "refresh_token" not in body and body["expires_in"] == 900 and body["scope"] == "painel"
    auth = {"Authorization": "Bearer " + body["access_token"]}
    ok = browser.get("/api/painel/conexoes", headers=auth)
    assert ok.status_code == 200 and ok.json() == {"rotulo": "painel"}
    # Token do painel no /mcp: recusado. Token do Claude no painel: recusado.
    refused = mcp(browser, body["access_token"])
    assert refused.status_code == 401
    assert refused.headers["www-authenticate"].endswith(
        'resource_metadata="' + ORIGIN + '/.well-known/oauth-protected-resource/mcp"'
    )
    claude, _ = connect_claude(server, server.browser(), "conta-1")
    refused = browser.get(
        "/api/painel/conexoes", headers={"Authorization": "Bearer " + claude["access_token"]}
    )
    assert refused.status_code == 401
    assert "oauth-protected-resource/api/painel" in refused.headers["www-authenticate"]
    # Novo login no painel revoga o anterior.
    verifier2, challenge2 = pkce()
    tx, csrf, _ = authorize(browser, painel_query(challenge2))
    response = login(server, browser, tx, csrf)
    _, response = consent(browser, response.headers["location"])
    _, query = redirect_query(response)
    response = token(
        browser,
        {
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "code_verifier": verifier2,
            "client_id": "painel-vercel",
            "redirect_uri": PAINEL_CALLBACK,
            "resource": ORIGIN + "/api/painel",
        },
        origin=VERCEL,
    )
    assert response.status_code == 200
    assert browser.get("/api/painel/conexoes", headers=auth).status_code == 401


# ---------------------------------------------------------------------------
# Authorize: erros
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "changes",
    [
        {"client_id": "https://evil.example/cimd"},
        {"redirect_uri": "https://evil.example/callback"},
        {"redirect_uri": None},
    ],
)
def test_authorize_local_error_no_redirect(server, changes):
    _, challenge = pkce()
    response = server.browser().get("/oauth/authorize", params=claude_query(challenge, **changes))
    assert response.status_code == 400 and "location" not in response.headers
    assert "text/html" in response.headers["content-type"]
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize(
    "changes, error",
    [
        ({"code_challenge": "A" * 42}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"scope": "memoria painel"}, "invalid_scope"),
        ({"resource": ORIGIN + "/api/painel"}, "invalid_target"),
        ({"resource": None}, "invalid_target"),
    ],
)
def test_authorize_redirect_error_keeps_state(server, changes, error):
    _, challenge = pkce()
    state = "a b+c/=é&x"
    response = server.browser().get(
        "/oauth/authorize", params=claude_query(challenge, state, **changes)
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(CLAUDE_REDIRECT_URI + "?")
    assert parse_qs(urlsplit(location).query) == {
        "error": [error],
        "state": [state],
        "iss": [ORIGIN],
    }


def test_state_exact_and_absent(server):
    _, query = connect_claude(server, server.browser(), "conta-1", state="x y+z/%20=é")
    assert query["state"] == ["x y+z/%20=é"]
    browser = server.browser()
    _, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge, state=None))
    response = login(server, browser, tx, csrf)
    _, response = consent(browser, response.headers["location"], rotulo="conta-2")
    _, query = redirect_query(response)
    assert set(query) == {"code", "iss"}


def test_cookie_attributes_and_reuse(server):
    browser = server.browser()
    _, challenge = pkce()
    _, _, response = authorize(browser, claude_query(challenge))
    cookie = response.headers["set-cookie"]
    value = re.match(rf"{TX_COOKIE}=([^;]+); ", cookie).group(1)
    assert cookie == f"{TX_COOKIE}={value}; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax"
    _, _, again = authorize(browser, claude_query(challenge))
    assert value in again.headers["set-cookie"]  # mesma aba/navegador: mesmo cookie
    _, _, other = authorize(server.browser(), claude_query(challenge))
    assert value not in other.headers["set-cookie"]


def test_anonymous_creation_limit(env):  # noqa: F811
    server = Server(env, creation_rate=CreationRate(3, 600))
    browser = server.browser()
    _, challenge = pkce()
    for _ in range(3):
        authorize(browser, claude_query(challenge))
    response = browser.get("/oauth/authorize", params=claude_query(challenge))
    assert response.status_code == 429 and int(response.headers["retry-after"]) > 0
    assert "alguns minutos" in response.text
    count = env.conn.execute("SELECT count(*) FROM oauth_transactions").fetchone()[0]
    assert count == 3


# ---------------------------------------------------------------------------
# Transação: expirada, reusada, de outro navegador, CSRF, campos extras
# ---------------------------------------------------------------------------


def test_transaction_expired(server):
    browser = server.browser()
    _, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge))
    server.tick(oauth.TX_TTL)
    response = login(server, browser, tx, csrf)
    assert response.status_code == 400 and "expirou" in response.text


def test_transaction_other_browser_and_csrf(server):
    browser = server.browser()
    _, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge))
    stranger = server.browser()
    response = login(server, stranger, tx, csrf)
    assert response.status_code == 400
    response = login(server, browser, tx, "x" * 43)
    assert response.status_code == 400
    response = browser.post(
        "/oauth/login", data={"tx": tx, "senha": PASSWORD, "codigo": "000000"}, headers=FORM
    )
    assert response.status_code == 400
    # Sem Origin (ou com outra origem) a borda recusa o formulário.
    response = browser.post("/oauth/login", data={"tx": tx, "csrf": csrf})
    assert response.status_code == 403
    response = browser.post(
        "/oauth/login", data={"tx": tx, "csrf": csrf}, headers={"Origin": "https://claude.ai"}
    )
    assert response.status_code == 403
    # Login certo no navegador certo ainda funciona.
    response = login(server, browser, tx, csrf)
    assert response.status_code == 303
    location = response.headers["location"]
    assert stranger.get(location).status_code == 400
    _, consent_response = consent(browser, location, rotulo="conta-1")
    assert consent_response.status_code == 303
    # Transação usada: tudo recusa.
    assert browser.get(location).status_code == 400
    response = browser.post(
        "/oauth/consent",
        data={"tx": tx, "csrf": csrf, "acao": "autorizar", "rotulo": "conta-1"},
        headers=FORM,
    )
    assert response.status_code == 400
    assert login(server, browser, tx, csrf).status_code == 400


def test_consent_before_login_refused(server):
    browser = server.browser()
    _, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge))
    response = browser.post(
        "/oauth/consent",
        data={"tx": tx, "csrf": csrf, "acao": "autorizar", "rotulo": "conta-1"},
        headers=FORM,
    )
    assert response.status_code == 400
    page = browser.get("/oauth/consent", params={"tx": tx})
    assert page.status_code == 200 and 'action="/oauth/login"' in page.text


def test_form_fields_cannot_change_parameters(server):
    browser = server.browser()
    verifier, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge, state="original"))
    _, evil_challenge = pkce()
    tampering = {
        "client_id": "https://evil.example/cimd",
        "redirect_uri": "https://evil.example/cb",
        "scope": "memoria painel",
        "resource": ORIGIN + "/api/painel",
        "code_challenge": evil_challenge,
        "state": "trocado",
    }
    server.tick()
    response = browser.post(
        "/oauth/login",
        data={"tx": tx, "csrf": csrf, "senha": PASSWORD, "codigo": server.totp(), **tampering},
        headers=FORM,
    )
    assert response.status_code == 303
    _, response = consent(browser, response.headers["location"], rotulo="conta-1", **tampering)
    location, query = redirect_query(response)
    assert location.startswith(CLAUDE_REDIRECT_URI + "?")
    assert query["state"] == ["original"]
    data = {
        "grant_type": "authorization_code",
        "code": query["code"][0],
        "code_verifier": verifier,
        "client_id": CLAUDE_CIMD_CLIENT_ID,
        "redirect_uri": CLAUDE_REDIRECT_URI,
        "resource": ORIGIN + "/mcp",
    }
    response = token(browser, data)
    assert response.status_code == 200 and response.json()["scope"] == "memoria offline_access"


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def test_login_wrong_and_locked(server):
    browser = server.browser()
    _, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge))
    for password, code in (("senha errada qualquer", None), (PASSWORD, "000000")):
        response = login(server, browser, tx, csrf, password=password, code=code)
        assert response.status_code == 401
        assert "Senha ou código inválido." in response.text
        assert "senha errada" not in response.text and 'name="tx"' in response.text
    for _ in range(3):
        login(server, browser, tx, csrf, password="outra senha errada")
    response = login(server, browser, tx, csrf)  # certo, mas trancado
    assert response.status_code == 429 and "Muitas tentativas" in response.text
    assert int(response.headers["retry-after"]) > 0
    assert ("login_trancado", 429) in server.events


def test_remember_device_cookie(server):
    browser = server.browser()
    _, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge))
    response = login(server, browser, tx, csrf, remember=True)
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    value = re.match(rf"{DEVICE_COOKIE}=([^;]+); ", cookie).group(1)
    assert cookie == (
        f"{DEVICE_COOKIE}={value}; Max-Age=15552000; Path=/; Secure; HttpOnly; SameSite=Strict"
    )
    without = server.browser()
    tx, csrf, _ = authorize(without, claude_query(challenge))
    assert "set-cookie" not in login(server, without, tx, csrf).headers


# ---------------------------------------------------------------------------
# Consentimento: rótulo, substituição, corrida, cancelar
# ---------------------------------------------------------------------------


def test_invalid_label(server):
    browser = server.browser()
    _, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge))
    response = login(server, browser, tx, csrf)
    for label in ("painel", "conta-3", ""):
        _, refused = consent(browser, response.headers["location"], rotulo=label)
        assert refused.status_code == 400 and "Escolha uma das contas" in refused.text
    _, refused = consent(browser, response.headers["location"], rotulo="conta-1", acao="x")
    assert refused.status_code == 400


def test_replace_existing(server):
    old, _ = connect_claude(server, server.browser(), "conta-1")
    browser = server.browser()
    verifier, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge))
    response = login(server, browser, tx, csrf)
    page, asked = consent(browser, response.headers["location"], rotulo="conta-1")
    assert "(já conectada)" in page.text
    assert asked.status_code == 200 and "Substituir a conexão antiga?" in asked.text
    assert mcp(browser, old["access_token"]).status_code == 200
    data = {
        "tx": hidden(asked.text, "tx"),
        "csrf": hidden(asked.text, "csrf"),
        "acao": "autorizar",
        "rotulo": hidden(asked.text, "rotulo"),
        "substituir": hidden(asked.text, "substituir"),
    }
    response = browser.post("/oauth/consent", data=data, headers=FORM)
    _, query = redirect_query(response)
    assert mcp(browser, old["access_token"]).status_code == 401
    response = token(
        browser,
        {
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "code_verifier": verifier,
            "client_id": CLAUDE_CIMD_CLIENT_ID,
            "redirect_uri": CLAUDE_REDIRECT_URI,
            "resource": ORIGIN + "/mcp",
        },
    )
    assert mcp(browser, response.json()["access_token"]).json()["rotulo"] == "conta-1"


def test_two_tabs_race(server):
    browser = server.browser()
    tabs = []
    for _ in range(2):
        _, challenge = pkce()
        tx, csrf, _ = authorize(browser, claude_query(challenge))
        response = login(server, browser, tx, csrf)
        assert response.status_code == 303
        tabs.append(response.headers["location"])
    pages_ = [browser.get(location) for location in tabs]
    posts = []
    for page in pages_:
        posts.append(
            {
                "tx": hidden(page.text, "tx"),
                "csrf": hidden(page.text, "csrf"),
                "acao": "autorizar",
                "rotulo": "conta-1",
                "vistos": hidden(page.text, "vistos"),
            }
        )
    first = browser.post("/oauth/consent", data=posts[0], headers=FORM)
    assert first.status_code == 303
    second = browser.post("/oauth/consent", data=posts[1], headers=FORM)
    assert second.status_code == 409 and "Conexão já criada" in second.text
    assert 'href="/oauth/consent?tx=' in second.text
    # Recarregando, a aba vê a conexão nova e pode escolher substituir.
    _, asked = consent(browser, tabs[1], rotulo="conta-1")
    assert "Substituir a conexão antiga?" in asked.text


def test_cancel(server):
    browser = server.browser()
    _, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge, state="cancelado"))
    response = login(server, browser, tx, csrf)
    _, response = consent(browser, response.headers["location"], acao="cancelar")
    _, query = redirect_query(response)
    assert query == {"error": ["access_denied"], "state": ["cancelado"], "iss": [ORIGIN]}
    assert env_grants(server) == 0


def env_grants(server):
    return server.env.conn.execute("SELECT count(*) FROM oauth_grants").fetchone()[0]


# ---------------------------------------------------------------------------
# Token e revogação pela rota
# ---------------------------------------------------------------------------


def test_token_endpoint_errors(server):
    browser = server.browser()
    response = browser.post("/oauth/token", json={"grant_type": "authorization_code"})
    assert response.status_code == 400 and response.json()["error"] == "invalid_request"
    assert response.headers["cache-control"] == "no-store"
    response = browser.post(
        "/oauth/token",
        content="grant_type=refresh_token&grant_type=refresh_token",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.json()["error"] == "invalid_request"
    response = token(browser, {"grant_type": "client_credentials"})
    assert response.json()["error"] == "unsupported_grant_type"
    response = token(
        browser,
        {"grant_type": "refresh_token", "refresh_token": "x" * 40, "client_id": "quem"},
    )
    assert response.status_code == 401 and response.json()["error"] == "invalid_client"
    # Origin de outro site no token: a borda recusa.
    response = token(browser, {"grant_type": "x"}, origin="https://evil.example")
    assert response.status_code == 403


def test_code_reuse_over_http(server):
    browser = server.browser()
    verifier, challenge = pkce()
    tx, csrf, _ = authorize(browser, claude_query(challenge))
    response = login(server, browser, tx, csrf)
    _, response = consent(browser, response.headers["location"], rotulo="conta-1")
    _, query = redirect_query(response)
    data = {
        "grant_type": "authorization_code",
        "code": query["code"][0],
        "code_verifier": verifier,
        "client_id": CLAUDE_CIMD_CLIENT_ID,
        "redirect_uri": CLAUDE_REDIRECT_URI,
        "resource": ORIGIN + "/mcp",
    }
    wrong = token(browser, {**data, "code_verifier": pkce()[0]})
    assert wrong.status_code == 400 and wrong.json()["error"] == "invalid_grant"
    first = token(browser, data)
    assert first.status_code == 200
    second = token(browser, data)
    assert second.json()["error"] == "invalid_grant"
    assert mcp(browser, first.json()["access_token"]).status_code == 401


def test_revoke_route(server):
    browser = server.browser()
    tokens, _ = connect_claude(server, browser, "conta-1")
    for body in ({}, {"token": "lixo"}, {"token": "x" * 40}):
        assert browser.post("/oauth/revoke", data=body).status_code == 200
    assert browser.post("/oauth/revoke", json={"token": 1}).status_code == 200
    response = browser.post("/oauth/revoke", data={"token": tokens["access_token"]})
    assert response.status_code == 200 and response.content == b""
    assert mcp(browser, tokens["access_token"]).status_code == 401
    response = browser.post(
        "/oauth/revoke",
        data={"token": tokens["refresh_token"], "token_type_hint": "refresh_token"},
    )
    assert response.status_code == 200
    response = token(
        browser,
        {
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": CLAUDE_CIMD_CLIENT_ID,
        },
    )
    assert response.json()["error"] == "invalid_grant"


# ---------------------------------------------------------------------------
# Páginas e segredos
# ---------------------------------------------------------------------------


def assert_clean_page(html):
    lowered = html.lower()
    assert "<script" not in lowered and "<style" not in lowered and "style=" not in lowered
    assert not re.search(r"\son[a-z]+\s*=", lowered)
    assert "javascript:" not in lowered
    assert f'<link rel="stylesheet" href="{pages.STATIC_PATH}">' in html
    assert '<html lang="pt-BR">' in html
    assert '<meta name="referrer" content="same-origin">' in html
    assert 'name="viewport"' in html


def test_pages_have_no_script_or_inline(server):
    browser = server.browser()
    seen = []
    _, challenge = pkce()
    response = browser.get(
        "/oauth/authorize", params=claude_query(challenge, client_id="https://evil.example/x")
    )
    seen.append(response)
    tx, csrf, page = authorize(browser, claude_query(challenge))
    seen.append(page)
    assert "default-src 'none'" in page.headers["content-security-policy"]
    seen.append(login(server, browser, tx, csrf, password="errada errada"))
    response = login(server, browser, tx, csrf)
    consent_page, asked = consent(browser, response.headers["location"], rotulo="conta-9")
    seen += [consent_page, asked]
    _, done = consent(browser, response.headers["location"], rotulo="conta-1")
    assert done.status_code == 303
    seen.append(browser.get(response.headers["location"]))
    for item in seen:
        assert "text/html" in item.headers["content-type"]
        assert_clean_page(item.text)
    assert_clean_page(pages.replace_page("C", "claude.ai", "conta-1", "grant_x", "t", "c"))
    assert_clean_page(pages.message_page("T", "<script>alert(1)</script>", ("a", "/x")))
    css = pages.stylesheet().decode()
    assert "url(" not in css and "@import" not in css


def test_no_secret_in_logs_or_events(server, caplog):
    caplog.set_level(logging.DEBUG)
    browser = server.browser()
    tokens, _ = connect_claude(server, browser, "conta-1", state="estado-secreto-9")
    refreshed = token(
        browser,
        {
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": CLAUDE_CIMD_CLIENT_ID,
        },
    ).json()
    cookies = [c.value for c in browser.cookies.jar]
    secrets_ = (
        server.secrets
        + cookies
        + [PASSWORD, "estado-secreto-9", tokens["access_token"], tokens["refresh_token"]]
        + [refreshed["access_token"], refreshed["refresh_token"]]
    )
    # Os logs do httpx2 são do cliente de teste (o "navegador"), não do servidor.
    server_logs = "\n".join(
        r.getMessage() for r in caplog.records if not r.name.startswith("httpx")
    )
    text = server_logs + repr(server.events)
    for value in secrets_:
        assert value and value not in text
    for event, _ in server.events:
        assert re.fullmatch(r"[a-z_]+", event)
    rows = server.env.conn.execute(
        "SELECT * FROM audit UNION ALL SELECT id_hash, browser_hash, state, 0, 0 "
        "FROM oauth_transactions"
    ).fetchall()
    dump = repr(rows)
    for value in secrets_[:-1]:
        if value != "estado-secreto-9":
            assert value not in dump
