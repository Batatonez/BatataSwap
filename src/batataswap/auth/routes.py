"""Rotas Starlette do AS (§3, §4) e o helper de Bearer do RS.

Toda conversa com o banco (e o scrypt, e a busca do CIMD) roda fora do event loop, numa conexão
SQLite própria aberta por ``deps.connect()`` (o ``sqlite3`` não deixa a conexão mudar de thread).
A borda (``edge.py``) fica na frente: Host, Origin dos formulários, corpo e headers de segurança.
"""

import contextlib
import re
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from urllib.parse import urlencode, urlsplit

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from batataswap.config import Config
from batataswap.crypto import Keyring

from . import oauth, pages
from .cimd import Fetcher, httpx_fetcher
from .owner import check_login
from .ratelimit import Budget, CreationRate, ScryptSlot

TX_COOKIE = "__Host-bsw_tx"
DEVICE_COOKIE = "__Host-bsw_dev"
DEVICE_MAX_AGE = 180 * 24 * 3600
ROUTE_EVENTS = frozenset(
    {
        "authorize_limite",
        "authorize_recusado",
        "transacao_criada",
        "transacao_invalida",
        "login_ok",
        "login_falhou",
        "login_trancado",
        "grant_criado",
        "consentimento_cancelado",
        "token_emitido",
        "token_recusado",
        "token_revogado",
    }
)
_FORM = "application/x-www-form-urlencoded"
_GRANT_ID = re.compile(r"grant_[a-z2-7]{16}")
_NO_STORE = {"cache-control": "no-store", "pragma": "no-cache"}


@dataclass
class OAuthDeps:
    config: Config
    keyring: Keyring = field(repr=False)
    connect: Callable[[], sqlite3.Connection]
    budget: Budget
    slot: ScryptSlot
    fetcher: Fetcher = httpx_fetcher
    creation_rate: CreationRate = field(default_factory=lambda: CreationRate(30, 600))
    clock: Callable[[], float] = time.time
    on_event: Callable[[str, int], None] | None = None

    def emit(self, event: str, status: int) -> None:
        if self.on_event is not None and event in ROUTE_EVENTS:
            with contextlib.suppress(Exception):  # log nunca derruba a requisição
                self.on_event(event, status)


async def _db(deps: OAuthDeps, fn, *args, **kwargs):
    def run():
        conn = deps.connect()
        try:
            return fn(conn, *args, **kwargs)
        finally:
            conn.close()

    return await anyio.to_thread.run_sync(run)


def _html(body: str, status: int = 200, headers: dict | None = None) -> HTMLResponse:
    return HTMLResponse(body, status_code=status, headers={**_NO_STORE, **(headers or {})})


def _message(title: str, message: str, status: int, link=None) -> HTMLResponse:
    return _html(pages.message_page(title, message, link), status)


def _tx_error(deps: OAuthDeps) -> HTMLResponse:
    deps.emit("transacao_invalida", 400)
    return _message("Pedido expirado", oauth.TransactionError.message, 400)


def _cookie(name: str, value: str, max_age: int, samesite: str) -> str:
    return f"{name}={value}; Max-Age={max_age}; Path=/; Secure; HttpOnly; SameSite={samesite}"


async def _form(request: Request) -> dict[str, list[str]] | None:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != _FORM:
        return None
    try:
        return oauth.parse_params(await request.body())
    except (ValueError, UnicodeError):
        return None


def _first(params: dict[str, list[str]], name: str) -> str | None:
    values = params.get(name)
    return values[0] if values and len(values) == 1 else None


def _see_other(location: str, headers: dict | None = None) -> RedirectResponse:
    return RedirectResponse(location, status_code=303, headers={**_NO_STORE, **(headers or {})})


# ---------------------------------------------------------------------------
# Metadados
# ---------------------------------------------------------------------------


def _json(data: dict) -> JSONResponse:
    return JSONResponse(data, headers={"cache-control": "no-store"})


# ---------------------------------------------------------------------------
# Authorize
# ---------------------------------------------------------------------------


async def _authorize(deps: OAuthDeps, request: Request) -> Response:
    # Orçamento da etapa anônima antes de qualquer banco ou rede (§4.2).
    if not deps.creation_rate.allow():
        deps.emit("authorize_limite", 429)
        retry = max(1, deps.creation_rate.check())
        return _html(
            pages.message_page(
                "Tente de novo em alguns minutos",
                "Muitos pedidos de conexão em pouco tempo. Espere alguns minutos e tente de novo.",
            ),
            429,
            {"retry-after": str(retry)},
        )
    now = deps.clock()
    try:
        params = oauth.parse_params(request.scope.get("query_string", b""))
    except (ValueError, UnicodeError):
        deps.emit("authorize_recusado", 400)
        return _message("Conexão recusada", oauth.BAD_REQUEST, 400)
    try:
        req = await _db(deps, oauth.validate_authorize, deps.config, params, deps.fetcher, now)
    except oauth.LocalError as error:
        deps.emit("authorize_recusado", 400)
        return _message("Conexão recusada", error.message, 400)
    except oauth.RedirectError as error:
        deps.emit("authorize_recusado", 302)
        return RedirectResponse(error.location(), status_code=302, headers=_NO_STORE)
    tx = await _db(
        deps,
        oauth.create_transaction,
        deps.keyring,
        req,
        request.cookies.get(TX_COOKIE),
        now,
        deps.config.limits.pending_transactions,
    )
    deps.emit("transacao_criada", 200)
    host = urlsplit(req.redirect_uri).hostname or ""
    response = _html(pages.login_page(req.client.client_name, host, tx.tx_id, tx.csrf))
    response.headers.append("set-cookie", _cookie(TX_COOKIE, tx.browser, oauth.TX_TTL, "Lax"))
    return response


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def _consent_url(tx_id: str) -> str:
    return "/oauth/consent?" + urlencode([("tx", tx_id)])


async def _login(deps: OAuthDeps, request: Request) -> Response:
    form = await _form(request)
    if form is None:
        return _tx_error(deps)
    tx_id, csrf = _first(form, "tx"), _first(form, "csrf")
    now = deps.clock()
    try:
        tx = await _db(
            deps,
            oauth.load_transaction,
            deps.config,
            deps.keyring,
            tx_id,
            request.cookies.get(TX_COOKIE),
            csrf,
            now,
            check_csrf=True,
        )
    except oauth.TransactionError:
        return _tx_error(deps)
    if tx.authenticated:
        return _see_other(_consent_url(tx.tx_id))
    password = _first(form, "senha") or ""
    code = _first(form, "codigo") or ""
    remember = _first(form, "lembrar") == "sim"
    result = await _db(
        deps,
        partial(check_login, remember_device=remember),
        deps.keyring,
        deps.budget,
        deps.slot,
        password,
        code,
        request.cookies.get(DEVICE_COOKIE),
        now,
    )
    if not result.ok:
        if result.status == "trancado":
            deps.emit("login_trancado", 429)
            status, headers = 429, {"retry-after": str(max(1, result.retry_after))}
        elif result.status == "ocupado":
            deps.emit("login_falhou", 503)
            status, headers = 503, {"retry-after": "5"}
        else:
            deps.emit("login_falhou", 401)
            status, headers = 401, {}
        page = pages.login_page(
            tx.client_name, tx.redirect_host, tx.tx_id, csrf, _login_message(result)
        )
        return _html(page, status, headers)
    if not await _db(deps, oauth.mark_authenticated, tx, now):
        return _tx_error(deps)
    deps.emit("login_ok", 303)
    response = _see_other(_consent_url(tx.tx_id))
    if result.device_token:
        response.headers.append(
            "set-cookie",
            _cookie(DEVICE_COOKIE, result.device_token, DEVICE_MAX_AGE, "Strict"),
        )
    return response


def _login_message(result) -> str:
    if result.status == "trancado":
        return "Muitas tentativas. Tente de novo em alguns minutos."
    if result.status == "ocupado":
        return "Tente novamente em instantes."
    return "Senha ou código inválido."


# ---------------------------------------------------------------------------
# Consentimento
# ---------------------------------------------------------------------------


def _load_with_grants(conn, deps: OAuthDeps, tx_id, browser, csrf, now, check_csrf):
    tx = oauth.load_transaction(
        conn, deps.config, deps.keyring, tx_id, browser, csrf, now, check_csrf=check_csrf
    )
    active = oauth.active_grants(conn, tx.client_row_id) if tx.policy.name == "claude" else {}
    return tx, active


def _consent_html(deps: OAuthDeps, tx, active, message=None) -> str:
    labels = deps.config.account_labels if tx.policy.name == "claude" else None
    return pages.consent_page(
        tx.client_name,
        tx.redirect_host,
        tx.scope,
        tx.tx_id,
        oauth.csrf_token(deps.keyring, tx.tx_id),
        labels,
        active,
        message,
    )


async def _consent(deps: OAuthDeps, request: Request) -> Response:
    if request.method == "POST":
        return await _consent_post(deps, request)
    try:
        params = oauth.parse_params(request.scope.get("query_string", b""))
    except (ValueError, UnicodeError):
        return _tx_error(deps)
    try:
        tx, active = await _db(
            deps,
            _load_with_grants,
            deps,
            _first(params, "tx"),
            request.cookies.get(TX_COOKIE),
            None,
            deps.clock(),
            False,
        )
    except oauth.TransactionError:
        return _tx_error(deps)
    if not tx.authenticated:
        csrf = oauth.csrf_token(deps.keyring, tx.tx_id)
        return _html(pages.login_page(tx.client_name, tx.redirect_host, tx.tx_id, csrf))
    return _html(_consent_html(deps, tx, active))


async def _consent_post(deps: OAuthDeps, request: Request) -> Response:
    form = await _form(request)
    if form is None:
        return _tx_error(deps)
    now = deps.clock()
    try:
        tx, active = await _db(
            deps,
            _load_with_grants,
            deps,
            _first(form, "tx"),
            request.cookies.get(TX_COOKIE),
            _first(form, "csrf"),
            now,
            True,
        )
    except oauth.TransactionError:
        return _tx_error(deps)
    if not tx.authenticated:
        return _tx_error(deps)
    action = _first(form, "acao")
    if action == "cancelar":
        try:
            location = await _db(deps, oauth.cancel_transaction, deps.config, tx, now)
        except oauth.TransactionError:
            return _tx_error(deps)
        deps.emit("consentimento_cancelado", 303)
        return _see_other(location)
    if action != "autorizar":
        return _html(_consent_html(deps, tx, active, "Escolha uma opção."), 400)
    label = None
    if tx.policy.name == "claude":
        label = _first(form, "rotulo")
        if label not in deps.config.account_labels:
            return _html(_consent_html(deps, tx, active, "Escolha uma das contas da lista."), 400)
    replace = _first(form, "substituir")
    if replace is not None and not _GRANT_ID.fullmatch(replace):
        replace = ""  # valor estranho nunca casa com um grant: cai em "recarregue"
    seen_raw = _first(form, "vistos") or ""
    seen = frozenset(p for p in seen_raw.split(",")[:20] if _GRANT_ID.fullmatch(p))
    try:
        result = await _db(deps, oauth.finish_consent, deps.config, tx, label, replace, seen, now)
    except oauth.TransactionError:
        return _tx_error(deps)
    if result.kind == "redirect":
        deps.emit("grant_criado", 303)
        return _see_other(result.location)
    csrf = oauth.csrf_token(deps.keyring, tx.tx_id)
    if result.kind == "ask_replace":
        return _html(
            pages.replace_page(
                tx.client_name, tx.redirect_host, label, result.old_grant, tx.tx_id, csrf
            )
        )
    return _message(
        "Conexão já criada",
        "Esta conta acabou de ser conectada em outra aba. Recarregue para ver a situação atual.",
        409,
        ("Recarregar", _consent_url(tx.tx_id)),
    )


# ---------------------------------------------------------------------------
# Token e revogação
# ---------------------------------------------------------------------------


def _token_error(error: oauth.OAuthError) -> JSONResponse:
    return JSONResponse(error.to_json(), status_code=error.status, headers=_NO_STORE)


async def _token(deps: OAuthDeps, request: Request) -> Response:
    form = await _form(request)
    if form is None:
        deps.emit("token_recusado", 400)
        return _token_error(oauth.OAuthError("invalid_request", "corpo urlencoded obrigatorio"))
    try:
        result = await _db(deps, oauth.token_request, deps.config, form, deps.clock())
    except oauth.OAuthError as error:
        deps.emit("token_recusado", error.status)
        return _token_error(error)
    deps.emit("token_emitido", 200)
    return JSONResponse(result.to_json(), headers=_NO_STORE)


async def _revoke(deps: OAuthDeps, request: Request) -> Response:
    form = await _form(request)
    if form is not None:
        await _db(deps, oauth.revoke_token, deps.config, form, deps.clock())
    deps.emit("token_revogado", 200)
    return Response(b"", status_code=200, headers=_NO_STORE)


async def _stylesheet(request: Request) -> Response:
    return Response(
        pages.stylesheet(),
        media_type="text/css; charset=utf-8",
        headers={"cache-control": "public, max-age=86400"},
    )


def oauth_routes(deps: OAuthDeps) -> list[Route]:
    """Rotas do AS. A borda precisa de uma regra pública e estática para ``pages.STATIC_PATH``."""
    config = deps.config

    def bind(handler):
        async def endpoint(request: Request) -> Response:
            return await handler(deps, request)

        return endpoint

    prm_mcp = oauth.protected_resource_metadata(config, "mcp")
    prm_painel = oauth.protected_resource_metadata(config, "painel")
    as_meta = oauth.authorization_server_metadata(config)

    async def prm_mcp_endpoint(request):
        return _json(prm_mcp)

    async def prm_painel_endpoint(request):
        return _json(prm_painel)

    async def as_endpoint(request):
        return _json(as_meta)

    wk = "/.well-known/"
    return [
        Route(wk + "oauth-protected-resource/mcp", prm_mcp_endpoint, methods=["GET"]),
        Route(wk + "oauth-protected-resource", prm_mcp_endpoint, methods=["GET"]),
        Route(wk + "oauth-protected-resource/api/painel", prm_painel_endpoint, methods=["GET"]),
        Route(wk + "oauth-authorization-server", as_endpoint, methods=["GET"]),
        Route("/oauth/authorize", bind(_authorize), methods=["GET"]),
        Route("/oauth/login", bind(_login), methods=["POST"]),
        Route("/oauth/consent", bind(_consent), methods=["GET", "POST"]),
        Route("/oauth/token", bind(_token), methods=["POST"]),
        Route("/oauth/revoke", bind(_revoke), methods=["POST"]),
        Route(pages.STATIC_PATH, _stylesheet, methods=["GET"]),
    ]


# ---------------------------------------------------------------------------
# RS: helper para /mcp e /api/painel (T10/T11)
# ---------------------------------------------------------------------------


async def bearer_context(deps: OAuthDeps, scope, which: str) -> oauth.AccessContext:
    """Valida o Bearer que a borda deixou em ``scope["state"]["bearer"]``.

    ``which`` é ``"mcp"`` (recurso ``<api>/mcp``, scope ``memoria``) ou ``"painel"``
    (``<api>/api/painel``, scope ``painel``). Levanta ``oauth.BearerError``.
    """
    if which == "mcp":
        resource, required = deps.config.mcp_resource, "memoria"
    elif which == "painel":
        resource, required = deps.config.panel_resource, "painel"
    else:
        raise ValueError("recurso desconhecido")
    token = (scope.get("state") or {}).get("bearer")
    return await _db(deps, oauth.validate_bearer, token, resource, required, deps.clock())


def bearer_error_response(error: oauth.BearerError) -> JSONResponse:
    return JSONResponse(
        {"error": error.error},
        status_code=error.status,
        headers={"www-authenticate": error.www_authenticate, "cache-control": "no-store"},
    )
