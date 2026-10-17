"""Borda HTTP (§8): cada regra com caso positivo e negativo, sobre um app de brinquedo."""

import asyncio
import json
from dataclasses import dataclass, field

import pytest

from batataswap.config import Config
from batataswap.edge import EVENTS, EdgeMiddleware, RoutePolicy, RouteRule

ORIGIN = "https://batatarp.exemplo.ts.net"
HOST = "batatarp.exemplo.ts.net"
VERCEL = "https://batataswap.vercel.app"
TOKEN = "A" * 32
PRM_MCP = f'Bearer resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource/mcp"'
PRM_PANEL = f'Bearer resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource/api/painel"'
PAGE_CSP = (
    "default-src 'none'; style-src 'self'; script-src 'self'; "
    f"form-action 'self' https://claude.ai {VERCEL}; frame-ancestors 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"


@dataclass
class Result:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    messages: list = field(default_factory=list)

    def header(self, name):
        found = [v for n, v in self.headers if n == name]
        assert len(found) <= 1, name
        return found[0] if found else None

    def all(self, name):
        return [v for n, v in self.headers if n == name]

    def json(self):
        return json.loads(self.body)


class Toy:
    """App de brinquedo: lê o corpo inteiro e ecoa o escopo que recebeu."""

    def __init__(self, mode="echo"):
        self.mode = mode
        self.calls = 0
        self.body_seen = 0

    async def __call__(self, scope, receive, send):
        self.calls += 1
        if self.mode == "boom":
            raise RuntimeError("segredo-que-nao-pode-vazar")
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            self.body_seen = len(body)
            if not message.get("more_body"):
                break
        if self.mode == "boom_late":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            raise RuntimeError("x")
        if self.mode == "html":
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"text/html; charset=utf-8"),
                        (b"content-security-policy", b"default-src *"),
                        (b"server", b"uvicorn"),
                        (b"cache-control", b"public, max-age=99"),
                        (b"access-control-allow-origin", b"*"),
                        (b"access-control-allow-credentials", b"true"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b"<p>oi</p>"})
            return
        payload = json.dumps(
            {
                "headers": sorted({n.decode() for n, _ in scope["headers"]}),
                "client": scope["client"],
                "scheme": scope["scheme"],
                "bearer": scope["state"].get("bearer"),
                "body": len(body),
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json"), (b"server", b"uvicorn")],
            }
        )
        await send({"type": "http.response.body", "body": payload})


def make(mode="echo", *, vercel=VERCEL, mcp_origins=(), rules=None, events=None, origin=ORIGIN):
    app = Toy(mode)
    config = Config(public_origin=origin, vercel_origin=vercel, allowed_mcp_origins=mcp_origins)
    policy = RoutePolicy(rules) if rules else RoutePolicy.default()
    on_event = (lambda e, s: events.append((e, s))) if events is not None else None
    return EdgeMiddleware(app, config=config, routes=policy, on_event=on_event), app


def call(
    edge,
    method="GET",
    path="/saude",
    headers=None,
    *,
    host=HOST,
    chunks=(b"",),
    raw_path=None,
    query=b"",
    scope_type="http",
    extensions=None,
):
    hdrs = [] if host is None else [("host", host)]
    hdrs += list(headers or [])
    scope = {
        "type": scope_type,
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": raw_path if raw_path is not None else path.encode(),
        "query_string": query,
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode("latin-1")) for k, v in hdrs],
        "client": ("203.0.113.9", 5555),
        "server": ("127.0.0.1", 8780),
        "state": {"bearer": "forjado"},
    }
    if extensions is not None:
        scope["extensions"] = extensions
    if scope_type == "websocket":
        inbox = [{"type": "websocket.connect"}]
    else:
        inbox = [
            {"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
            for i, c in enumerate(chunks)
        ]
    sent = []

    async def receive():
        if inbox:
            return inbox.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(edge(scope, receive, send))
    start = next((m for m in sent if m["type"].endswith("response.start")), None)
    if start is None:
        return Result(0, [], b"", sent)
    body = b"".join(m.get("body", b"") for m in sent if m["type"].endswith("response.body"))
    headers = [(n.decode().lower(), v.decode()) for n, v in start["headers"]]
    return Result(start["status"], headers, body, sent)


def bearer(token=TOKEN):
    return ("authorization", f"Bearer {token}")


def assert_security(r, *, html=False):
    assert r.header("x-content-type-options") == "nosniff"
    assert r.header("referrer-policy") == "no-referrer"
    assert r.header("x-frame-options") == "DENY"
    assert r.header("strict-transport-security") == "max-age=31536000"
    assert r.header("cache-control") == "no-store"
    assert r.header("content-security-policy") == (PAGE_CSP if html else API_CSP)
    assert r.header("server") is None
    assert r.header("access-control-allow-credentials") is None


# -- 0. escopo -----------------------------------------------------------------------------


def test_headers_de_proxy_somem_e_escopo_limpo():
    edge, _ = make()
    forged = [
        ("X-Forwarded-For", "1.1.1.1"),
        ("X-Forwarded-Proto", "http"),
        ("X-Forwarded-Host", "mal.example"),
        ("Forwarded", "for=1.1.1.1"),
        ("X-Real-IP", "1.1.1.1"),
        ("True-Client-IP", "1.1.1.1"),
        ("CF-Connecting-IP", "1.1.1.1"),
        ("X-Client-IP", "1.1.1.1"),
        ("Client-IP", "1.1.1.1"),
        ("Accept", "application/json"),
    ]
    r = call(edge, headers=forged)
    assert r.status == 200
    data = r.json()
    assert data["headers"] == ["accept", "host"]
    assert data["client"] is None
    assert data["scheme"] == "https"
    assert data["bearer"] is None  # estado forjado não sobrevive


def test_host_duplicado():
    edge, app = make()
    r = call(edge, headers=[("host", HOST)])
    assert r.status == 400 and app.calls == 0
    assert_security(r)


# -- 1. Host -------------------------------------------------------------------------------


@pytest.mark.parametrize("host", [HOST, HOST + ":443"])
def test_host_certo(host):
    edge, _ = make()
    assert call(edge, host=host).status == 200


@pytest.mark.parametrize(
    "host", ["mal.example", HOST.upper(), HOST + ":8780", "127.0.0.1:8780", "", None]
)
def test_host_errado_421(host):
    edge, app = make()
    r = call(edge, host=host)
    assert r.status == 421 and app.calls == 0
    assert r.json() == {"erro": "Host não reconhecido."}
    assert_security(r)


def test_host_com_porta_no_config():
    edge, _ = make(origin="https://swap.example:8443")
    assert call(edge, host="swap.example:8443").status == 200
    assert call(edge, host="swap.example").status == 421
    assert call(edge, host="swap.example:8443:443").status == 421


# -- caminho e rotas -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "raw"),
    [
        ("/oauth/../saude", b"/oauth/../saude"),
        ("/./saude", b"/./saude"),
        ("/oauth/token", b"/oauth%2Ftoken"),
        ("/oauth/token", b"/oauth%2ftoken"),
        ("/saude", b"/sa%75de"),
        ("//saude", b"//saude"),
        ("/sa\\ude", b"/sa\\ude"),
        ("/saude\x00", b"/saude\x00"),
        ("/saude\n", b"/saude\n"),
        ("/saúde", "/saúde".encode()),
        ("saude", b"saude"),
    ],
)
def test_caminho_estranho_400(path, raw):
    edge, app = make()
    r = call(edge, path=path, raw_path=raw)
    assert r.status == 400 and app.calls == 0
    assert r.json() == {"erro": "Requisição inválida."}


def test_raw_path_divergente_do_path_400():
    edge, app = make()
    assert call(edge, path="/saude", raw_path=b"/mcp").status == 400
    assert app.calls == 0


@pytest.mark.parametrize("path", ["/", "/nada", "/saude/", "/mcp/x", "/api/painel", "/api/painel/"])
def test_rota_inexistente_404(path):
    edge, app = make()
    r = call(edge, path=path)
    assert r.status == 404 and app.calls == 0
    assert r.json() == {"erro": "Não encontrado."}
    assert_security(r)


def test_erro_nao_ecoa_entrada():
    edge, _ = make()
    r = call(edge, path="/coisa-secreta-xyz", headers=[("x-marca", "valor-marcado")])
    assert b"coisa-secreta" not in r.body and b"valor-marcado" not in r.body
    assert all("coisa-secreta" not in v for _, v in r.headers)


def test_metodo_errado_405():
    edge, app = make()
    r = call(edge, "GET", "/mcp", [bearer()])
    assert r.status == 405 and app.calls == 0
    assert r.header("allow") == "POST"
    assert call(edge, "DELETE", "/mcp", [bearer()]).status == 405
    assert call(edge, "POST", "/saude").status == 405


def test_head_cabe_na_regra_get():
    edge, _ = make()
    assert call(edge, "HEAD", "/saude").status == 200


def test_rotas_publicas_passam_sem_credencial():
    edge, _ = make()
    for path in (
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/api/painel",
        "/.well-known/oauth-authorization-server",
        "/oauth/authorize",
        "/oauth/consent",
        "/saude",
    ):
        assert call(edge, path=path).status == 200, path
    assert call(edge, "POST", "/oauth/token").status == 200
    assert call(edge, "POST", "/oauth/revoke").status == 200


def test_politica_valida_regras():
    with pytest.raises(ValueError):
        RouteRule("GET", "/x", "aberta")
    with pytest.raises(ValueError):
        RouteRule("TRACE", "/x", "public")
    with pytest.raises(ValueError):
        RouteRule("GET", "/a/../b", "public")
    with pytest.raises(ValueError):
        RoutePolicy([])


def test_primeira_regra_vence():
    rules = [RouteRule("GET", "/x", "bearer:mcp"), RouteRule("GET", "/x", "public")]
    edge, _ = make(rules=rules)
    assert call(edge, path="/x").status == 401


# -- 2. CORS -------------------------------------------------------------------------------


def preflight(edge, path, method="POST", origin=VERCEL, req_headers="authorization, content-type"):
    hdrs = [("origin", origin), ("access-control-request-method", method)]
    if req_headers is not None:
        hdrs.append(("access-control-request-headers", req_headers))
    return call(edge, "OPTIONS", path, hdrs)


@pytest.mark.parametrize(
    ("path", "method", "allowed"),
    [
        ("/oauth/token", "POST", "POST"),
        ("/saude", "GET", "GET"),
        ("/api/painel/conexoes", "GET", "GET, POST"),
        ("/api/painel/revogar", "POST", "GET, POST"),
    ],
)
def test_preflight_certo(path, method, allowed):
    edge, app = make()
    r = preflight(edge, path, method)
    assert r.status == 204 and app.calls == 0
    assert r.header("access-control-allow-origin") == VERCEL
    assert r.header("access-control-allow-methods") == allowed
    assert r.header("access-control-allow-headers") == "Authorization, Content-Type"
    assert r.header("access-control-max-age") == "600"
    assert r.header("vary") == "Origin"
    assert_security(r)


def test_preflight_sem_headers_pedidos():
    edge, _ = make()
    assert preflight(edge, "/saude", "GET", req_headers=None).status == 204


@pytest.mark.parametrize(
    ("path", "kwargs"),
    [
        ("/oauth/token", {"origin": "https://mal.example"}),
        ("/oauth/token", {"origin": VERCEL + "/"}),
        ("/oauth/token", {"origin": "null"}),
        ("/oauth/token", {"method": "PUT"}),
        ("/oauth/token", {"method": "DELETE"}),
        ("/saude", {"method": "POST"}),
        ("/oauth/token", {"req_headers": "authorization, x-extra"}),
        ("/oauth/token", {"req_headers": "cookie"}),
        ("/mcp", {}),
        ("/oauth/revoke", {}),
        ("/oauth/login", {}),
    ],
)
def test_preflight_recusado_403(path, kwargs):
    edge, app = make()
    r = preflight(edge, path, **kwargs)
    assert r.status == 403 and app.calls == 0
    assert r.header("access-control-allow-origin") is None
    assert_security(r)


def test_preflight_sem_origin_ou_sem_metodo_403():
    edge, _ = make()
    assert call(edge, "OPTIONS", "/saude").status == 403
    assert call(edge, "OPTIONS", "/saude", [("origin", VERCEL)]).status == 403


def test_preflight_sem_vercel_no_config_403():
    edge, _ = make(vercel=None)
    assert preflight(edge, "/saude", "GET").status == 403


def test_preflight_rota_inexistente_404():
    edge, _ = make()
    assert preflight(edge, "/nada").status == 404


def test_resposta_normal_cors():
    edge, _ = make()
    r = call(edge, path="/saude", headers=[("origin", VERCEL)])
    assert r.status == 200
    assert r.header("access-control-allow-origin") == VERCEL
    assert r.header("vary") == "Origin"
    r = call(edge, path="/saude", headers=[("origin", "https://mal.example")])
    assert r.status == 200 and r.header("access-control-allow-origin") is None


def test_rota_sem_cors_nao_ganha_cors():
    edge, _ = make()
    r = call(edge, "POST", "/oauth/revoke", [("origin", VERCEL)])
    assert r.status == 200 and r.header("access-control-allow-origin") is None


def test_401_do_painel_legivel_pela_vercel():
    edge, _ = make()
    r = call(edge, "GET", "/api/painel/conexoes", [("origin", VERCEL)])
    assert r.status == 401
    assert r.header("access-control-allow-origin") == VERCEL
    assert r.header("www-authenticate") == PRM_PANEL


def test_borda_manda_nos_headers_do_app():
    edge, _ = make("html")
    r = call(edge, path="/saude", headers=[("origin", VERCEL)])
    assert r.header("access-control-allow-origin") == VERCEL  # o "*" do app some
    assert_security(r, html=True)


# -- 3. Origin -----------------------------------------------------------------------------


def test_origin_mcp():
    edge, _ = make()
    assert call(edge, "POST", "/mcp", [bearer()]).status == 200
    r = call(edge, "POST", "/mcp", [bearer(), ("origin", "https://claude.ai")])
    assert r.status == 403
    assert r.json() == {"erro": "Acesso negado."}
    edge, _ = make(mcp_origins=("https://claude.ai",))
    assert call(edge, "POST", "/mcp", [bearer(), ("origin", "https://claude.ai")]).status == 200
    assert call(edge, "POST", "/mcp", [bearer(), ("origin", "https://mal.example")]).status == 403
    two = [bearer(), ("origin", "https://claude.ai"), ("origin", "https://claude.ai")]
    assert call(edge, "POST", "/mcp", two).status == 403


@pytest.mark.parametrize("path", ["/oauth/login", "/oauth/consent", "/painel/editar"])
def test_form_exige_origin_proprio(path):
    edge, app = make()
    assert call(edge, "POST", path).status == 403
    assert call(edge, "POST", path, [("origin", VERCEL)]).status == 403
    assert call(edge, "POST", path, [("origin", "null")]).status == 403
    assert app.calls == 0
    assert call(edge, "POST", path, [("origin", ORIGIN)]).status == 200


@pytest.mark.parametrize("path", ["/oauth/token", "/oauth/revoke"])
def test_token_e_revoke_origin(path):
    edge, _ = make()
    assert call(edge, "POST", path).status == 200
    assert call(edge, "POST", path, [("origin", VERCEL)]).status == 200
    assert call(edge, "POST", path, [("origin", ORIGIN)]).status == 403
    assert call(edge, "POST", path, [("origin", "https://mal.example")]).status == 403


def test_api_painel_origin():
    edge, _ = make()
    path = "/api/painel/revogar"
    assert call(edge, "POST", path, [bearer()]).status == 200
    assert call(edge, "POST", path, [bearer(), ("origin", VERCEL)]).status == 200
    assert call(edge, "POST", path, [bearer(), ("origin", "https://mal.example")]).status == 403


def test_get_de_navegacao_sem_origin():
    edge, _ = make()
    assert call(edge, path="/oauth/authorize").status == 200
    assert (
        call(edge, path="/oauth/authorize", headers=[("origin", "https://x.example")]).status == 200
    )


# -- 4. credencial -------------------------------------------------------------------------


def test_bearer_ok_vai_pro_estado():
    edge, _ = make()
    for scheme in ("Bearer", "bearer", "BEARER"):
        r = call(edge, "POST", "/mcp", [("authorization", f"{scheme} {TOKEN}")])
        assert r.status == 200
        assert r.json()["bearer"] == TOKEN


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("authorization", f"Basic {TOKEN}")],
        [("authorization", "Bearer curto")],
        [("authorization", f"Bearer  {TOKEN}")],
        [("authorization", f"Bearer {TOKEN} extra")],
        [("authorization", "Bearer " + "A" * 513)],
        [("authorization", "Bearer " + "A" * 19 + "!")],
        [("authorization", f"Bearer{TOKEN}")],
        [bearer(), bearer()],
    ],
)
def test_bearer_ausente_ou_malformado_401(headers):
    edge, app = make()
    r = call(edge, "POST", "/mcp", headers)
    assert r.status == 401 and app.calls == 0
    assert r.header("www-authenticate") == PRM_MCP
    assert r.json() == {"erro": "Credencial ausente ou inválida."}
    assert_security(r)


def test_bearer_painel_aponta_prm_do_painel():
    edge, _ = make()
    r = call(edge, "GET", "/api/painel/conexoes")
    assert r.status == 401 and r.header("www-authenticate") == PRM_PANEL
    assert call(edge, "GET", "/api/painel/conexoes", [bearer()]).status == 200


@pytest.mark.parametrize(
    "query", [b"access_token=" + TOKEN.encode(), b"a=1&ACCESS_TOKEN=x", b"access%5Ftoken=x"]
)
def test_token_na_query_400(query):
    edge, app = make()
    r = call(edge, "POST", "/mcp", [bearer()], query=query)
    assert r.status == 400 and app.calls == 0
    assert call(edge, "GET", "/saude", query=query).status == 400


def test_query_comum_passa():
    edge, _ = make()
    assert call(edge, path="/oauth/authorize", query=b"client_id=x&state=y").status == 200


def test_cookie_presenca():
    edge, app = make()
    assert call(edge, path="/painel/memorias").status == 401
    assert call(edge, path="/painel/memorias", headers=[("cookie", "bsw_sess=x")]).status == 401
    assert (
        call(edge, path="/painel/memorias", headers=[("cookie", "__Host-bsw_sess=")]).status == 401
    )
    assert app.calls == 0
    r = call(edge, path="/painel/memorias", headers=[("cookie", "a=1; __Host-bsw_sess=abc")])
    assert r.status == 200


# -- 5. corpo ------------------------------------------------------------------------------


def test_content_length_acima_do_teto_413_imediato():
    edge, app = make()
    r = call(edge, "POST", "/oauth/token", [("content-length", str(8 * 1024 + 1))])
    assert r.status == 413 and app.calls == 0
    assert r.json() == {"erro": "Corpo da requisição grande demais."}
    assert_security(r)


@pytest.mark.parametrize("value", ["abc", "-1", "1, 2", ""])
def test_content_length_invalido_400(value):
    edge, app = make()
    assert call(edge, "POST", "/oauth/token", [("content-length", value)]).status == 400
    assert app.calls == 0


def test_content_length_duplicado_400():
    edge, _ = make()
    hdrs = [("content-length", "1"), ("content-length", "1")]
    assert call(edge, "POST", "/oauth/token", hdrs).status == 400


def test_streaming_sem_credencial_estoura_8k():
    edge, app = make()
    chunk = b"x" * 3000
    r = call(edge, "POST", "/oauth/token", chunks=(chunk, chunk, chunk))
    assert r.status == 413
    assert app.body_seen <= 8 * 1024
    assert sum(1 for m in r.messages if m["type"] == "http.response.start") == 1


def test_streaming_dentro_do_teto_passa():
    edge, _ = make()
    r = call(edge, "POST", "/oauth/token", chunks=(b"x" * 4096, b"x" * 4096))
    assert r.status == 200 and r.json()["body"] == 8192


def test_content_length_mentiroso_nao_engana():
    edge, _ = make()
    r = call(edge, "POST", "/oauth/token", [("content-length", "10")], chunks=(b"x" * 9000,))
    assert r.status == 413


def test_mcp_autenticado_256k():
    edge, _ = make()
    big = b"x" * (200 * 1024)
    assert (
        call(edge, "POST", "/mcp", [bearer()], chunks=(big[:100_000], big[100_000:])).status == 200
    )
    too_big = (b"x" * (128 * 1024), b"x" * (128 * 1024), b"x")
    assert call(edge, "POST", "/mcp", [bearer()], chunks=too_big).status == 413
    r = call(edge, "POST", "/mcp", [bearer(), ("content-length", str(256 * 1024 + 1))])
    assert r.status == 413


def test_resto_16k():
    edge, _ = make()
    assert (
        call(edge, "POST", "/api/painel/revogar", [bearer()], chunks=(b"x" * 16384,)).status == 200
    )
    r = call(edge, "POST", "/api/painel/revogar", [bearer()], chunks=(b"x" * 16385,))
    assert r.status == 413


# -- 6. headers de segurança ---------------------------------------------------------------


def test_headers_de_seguranca_em_resposta_do_app():
    edge, _ = make()
    r = call(edge, path="/saude")
    assert r.status == 200
    assert_security(r)


def test_csp_de_pagina_em_html_e_borda_manda():
    edge, _ = make("html")
    r = call(edge, path="/oauth/authorize")
    assert r.status == 200
    assert_security(r, html=True)
    assert r.all("content-security-policy") == [PAGE_CSP]


def test_csp_de_pagina_sem_vercel():
    edge, _ = make("html", vercel=None)
    r = call(edge, path="/oauth/authorize")
    assert r.header("content-security-policy") == (
        "default-src 'none'; style-src 'self'; script-src 'self'; "
        "form-action 'self' https://claude.ai; frame-ancestors 'none'"
    )


def test_rota_estatica_mantem_cache():
    edge, _ = make("html", rules=[RouteRule("GET", "/painel/app.css", "public", static=True)])
    r = call(edge, path="/painel/app.css")
    assert r.header("cache-control") == "public, max-age=99"


def test_excecao_vira_500_generico():
    events = []
    edge, _ = make("boom", events=events)
    r = call(edge, path="/saude")
    assert r.status == 500
    assert r.json() == {"erro": "Erro interno."}
    assert b"segredo" not in r.body and b"Traceback" not in r.body
    assert_security(r)
    assert ("erro_interno", 500) in events


def test_excecao_depois_do_inicio_nao_vaza():
    events = []
    edge, _ = make("boom_late", events=events)
    r = call(edge, path="/saude")
    assert r.status == 200
    assert ("erro_interno", 500) in events


def test_app_que_nao_responde_vira_500():
    async def silent(scope, receive, send):
        return None

    config = Config(public_origin=ORIGIN)
    edge = EdgeMiddleware(silent, config=config, routes=RoutePolicy.default())
    assert call(edge, path="/saude").status == 500


# -- websocket, lifespan, eventos ----------------------------------------------------------


def test_websocket_recusado_404():
    edge, app = make()
    r = call(edge, path="/mcp", scope_type="websocket", extensions={"websocket.http.response": {}})
    assert r.status == 404 and app.calls == 0
    assert_security(r)


def test_websocket_sem_extensao_fecha():
    edge, app = make()
    r = call(edge, path="/mcp", scope_type="websocket")
    assert r.messages == [{"type": "websocket.close", "code": 1008}] and app.calls == 0


def test_lifespan_repassa():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    edge = EdgeMiddleware(app, config=Config(public_origin=ORIGIN), routes=RoutePolicy.default())
    asyncio.run(edge({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]


def test_eventos_tem_nomes_fixos():
    events = []
    edge, _ = make(events=events)
    call(edge, host="mal.example")
    call(edge, path="/nada")
    call(edge, "POST", "/mcp")
    call(edge, path="/saude")
    preflight(edge, "/saude", "GET")
    assert events == [
        ("host_invalido", 421),
        ("rota_inexistente", 404),
        ("credencial_ausente", 401),
        ("repassado", 200),
        ("preflight_aceito", 204),
    ]
    assert {e for e, _ in events} <= EVENTS


def test_callback_que_falha_nao_derruba():
    def bad(event, status):
        raise RuntimeError

    edge = EdgeMiddleware(
        Toy(), config=Config(public_origin=ORIGIN), routes=RoutePolicy.default(), on_event=bad
    )
    assert call(edge, path="/saude").status == 200
