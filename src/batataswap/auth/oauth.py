"""Regras do AS e do RS (ARQUITETURA §4): transações, grants, códigos, tokens, revogação.

Código próprio: não usamos os handlers de auth do SDK ``mcp`` porque eles não deixam aplicar a
matriz cliente/recurso/scope do §4.1 em cada etapa (authorize, token e todo refresh) nem prender
a transação ao navegador como o §4.2 pede.

Tudo aqui é síncrono e recebe a conexão SQLite: as rotas rodam estas funções fora do event loop.
Mensagens de erro são fixas: nunca carregam token, código, state, senha, TOTP ou cookie.
``error_description`` é ASCII (RFC 6749 §5.2), por isso sem acentos.
"""

import base64
import hashlib
import hmac
import json
import re
import sqlite3
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit

from batataswap.config import Config
from batataswap.crypto import Keyring, new_public_id, new_token, token_hash
from batataswap.db import write_transaction

from .cimd import CLAUDE_REDIRECT_URI, CIMDError, ClientInfo, Fetcher, is_known_client
from .cimd import resolve_client as _resolve_client

TX_TTL = 10 * 60
CODE_TTL = 60
CLAUDE_ACCESS_TTL = 3600
PAINEL_ACCESS_TTL = 15 * 60
REFRESH_TTL = 30 * 24 * 3600
CLAUDE_GRANT_TTL = 180 * 24 * 3600
PAINEL_GRANT_TTL = PAINEL_ACCESS_TTL
LAST_USED_EVERY = 60
STATE_MAX = 512
PAINEL_LABEL = "painel"
ACCESS_PREFIX = "bsw_at_"
REFRESH_PREFIX = "bsw_rt_"
SCOPE_ORDER = ("memoria", "painel", "offline_access")
AUDIT_EVENTS = frozenset(
    {
        "grant_criado",
        "grant_revogado",
        "token_emitido",
        "refresh_reuso",
        "refresh_reuso_tolerado",
        "codigo_reuso",
    }
)

_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_OPAQUE = re.compile(r"[A-Za-z0-9._~+/=-]{20,512}")

# ---------------------------------------------------------------------------
# Matriz §4.1
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientPolicy:
    name: str  # "claude" ou "painel"
    redirect_uri: str
    resource: str
    scopes: frozenset[str]
    required_scope: str
    refresh: bool
    access_ttl: int
    grant_ttl: int


def policy_for(config: Config, client_id: str) -> ClientPolicy | None:
    """Linha da matriz para o ``client_id``; ``None`` se o cliente não está na lista fechada."""
    if not is_known_client(config, client_id):
        return None
    if client_id == config.painel_client_id:
        return ClientPolicy(
            "painel",
            config.painel_redirect_uri,
            config.panel_resource,
            frozenset({"painel"}),
            "painel",
            False,
            PAINEL_ACCESS_TTL,
            PAINEL_GRANT_TTL,
        )
    return ClientPolicy(
        "claude",
        CLAUDE_REDIRECT_URI,
        config.mcp_resource,
        frozenset({"memoria", "offline_access"}),
        "memoria",
        True,
        CLAUDE_ACCESS_TTL,
        CLAUDE_GRANT_TTL,
    )


def canonical_scope(scopes) -> str:
    return " ".join(s for s in SCOPE_ORDER if s in scopes)


def _parse_scope(value: str | None, allowed: frozenset[str], required: str) -> str | None:
    """Scope pedido → string canônica; ``None`` se pede algo fora de ``allowed``."""
    if value is None:
        return required
    parts = value.split(" ")
    if not value or any(not p for p in parts) or not set(parts) <= allowed:
        return None
    if required not in parts:
        return None
    return canonical_scope(set(parts))


# ---------------------------------------------------------------------------
# Erros
# ---------------------------------------------------------------------------


class OAuthError(Exception):
    """Erro RFC 6749 do endpoint de token. ``description`` é fixa e ASCII."""

    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(error)
        self.error = error
        self.description = description
        self.status = status

    def to_json(self) -> dict:
        return {"error": self.error, "error_description": self.description}


class LocalError(Exception):
    """Erro do authorize que NUNCA redireciona (client_id ou redirect_uri inválidos)."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class RedirectError(Exception):
    """Erro do authorize depois de validar client e redirect: volta ao cliente com ``error``."""

    def __init__(self, error: str, redirect_uri: str, issuer: str, state: str | None = None):
        super().__init__(error)  # só o código do erro; state nunca entra na mensagem
        self.error = error
        self.redirect_uri = redirect_uri
        self.issuer = issuer
        self.state = state

    def location(self) -> str:
        return build_redirect(self.redirect_uri, [("error", self.error)], self.state, self.issuer)


class TransactionError(Exception):
    """Transação inexistente, vencida, usada, de outro navegador ou com CSRF errado."""

    message = (
        "Este pedido de conexão expirou ou não é deste navegador. "
        "Volte ao aplicativo e conecte de novo."
    )


class BearerError(Exception):
    """Falha do RS: 401 ``invalid_token`` ou 403 ``insufficient_scope``."""

    def __init__(self, status: int, error: str, www_authenticate: str):
        super().__init__(error)
        self.status = status
        self.error = error
        self.www_authenticate = www_authenticate


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------


def parse_params(raw: bytes | str, *, max_fields: int = 30) -> dict[str, list[str]]:
    """Query string ou corpo urlencoded → multi-dict. ``ValueError`` se malformado."""
    if isinstance(raw, bytes):
        raw = raw.decode("ascii")
    out: dict[str, list[str]] = {}
    for name, value in parse_qsl(
        raw, keep_blank_values=True, encoding="utf-8", errors="strict", max_num_fields=max_fields
    ):
        out.setdefault(name, []).append(value)
    return out


class _Duplicate(Exception):
    pass


def _one(params: dict[str, list[str]], name: str) -> str | None:
    values = params.get(name)
    if not values:
        return None
    if len(values) > 1:
        raise _Duplicate(name)
    return values[0]


def _opaque(value: object) -> bool:
    return isinstance(value, str) and bool(_OPAQUE.fullmatch(value))


def build_redirect(redirect_uri: str, params: list, state: str | None, issuer: str) -> str:
    query = list(params)
    if state is not None:
        query.append(("state", state))
    query.append(("iss", issuer))
    sep = "&" if urlsplit(redirect_uri).query else "?"
    return redirect_uri + sep + urlencode(query)


def csrf_token(keyring: Keyring, tx_id: str) -> str:
    tag = keyring.mac("csrf", b"oauth-tx|" + tx_id.encode("ascii"))
    return base64.urlsafe_b64encode(tag).rstrip(b"=").decode("ascii")


def _audit(conn, event: str, grant_id: int | None, target: str | None, now: int) -> None:
    from batataswap import logs

    logs.emit(event, 200, grant=target)
    assert event in AUDIT_EVENTS
    conn.execute(
        "INSERT INTO audit(at,event,grant_id,target) VALUES (?,?,?,?)",
        (now, event, grant_id, target),
    )


def _revoke_grant(conn, grant_id: int, public_id: str, now: int) -> None:
    conn.execute(
        "UPDATE oauth_grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now, grant_id)
    )
    conn.execute(
        "UPDATE oauth_tokens SET revoked_at=? WHERE grant_id=? AND revoked_at IS NULL",
        (now, grant_id),
    )
    _audit(conn, "grant_revogado", grant_id, public_id, now)


def _revoke_expired_grants(conn, now: int) -> None:
    rows = conn.execute(
        "SELECT id, public_id FROM oauth_grants WHERE revoked_at IS NULL AND expires_at<=?",
        (now,),
    ).fetchall()
    for grant_id, public_id in rows:
        _revoke_grant(conn, grant_id, public_id, now)


def revoke_grant(conn: sqlite3.Connection, grant_public_id: str, now: float) -> bool:
    """Revoga um grant e todos os tokens dele (CLI e painel). ``True`` se estava ativo."""
    now = int(now)
    with write_transaction(conn):
        row = conn.execute(
            "SELECT id FROM oauth_grants WHERE public_id=? AND revoked_at IS NULL",
            (grant_public_id,),
        ).fetchone()
        if row is None:
            return False
        _revoke_grant(conn, row[0], grant_public_id, now)
        return True


# ---------------------------------------------------------------------------
# Metadados (§3)
# ---------------------------------------------------------------------------


def protected_resource_metadata(config: Config, which: str) -> dict:
    if which == "mcp":
        return {
            "resource": config.mcp_resource,
            "authorization_servers": [config.issuer],
            "scopes_supported": ["memoria"],
        }
    if which == "painel":
        return {
            "resource": config.panel_resource,
            "authorization_servers": [config.issuer],
            "scopes_supported": ["painel"],
        }
    raise ValueError("recurso desconhecido")


def authorization_server_metadata(config: Config) -> dict:
    origin = config.issuer
    return {
        "issuer": origin,
        "authorization_endpoint": origin + "/oauth/authorize",
        "token_endpoint": origin + "/oauth/token",
        "revocation_endpoint": origin + "/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["memoria", "painel", "offline_access"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
    }


def resource_metadata_url(resource: str) -> str:
    url = urlsplit(resource)
    return f"{url.scheme}://{url.netloc}/.well-known/oauth-protected-resource{url.path}"


# ---------------------------------------------------------------------------
# Authorize e transação (§4.2)
# ---------------------------------------------------------------------------

_UNKNOWN_CLIENT = "Este aplicativo não está autorizado a se conectar ao BatataSwap."
BAD_REQUEST = "Pedido de conexão inválido. Volte ao aplicativo e tente de novo."
_BAD_REDIRECT = "O endereço de retorno deste pedido não é o esperado. A conexão foi recusada."


@dataclass(frozen=True)
class AuthorizeRequest:
    client: ClientInfo
    policy: ClientPolicy
    redirect_uri: str
    resource: str
    scope: str
    code_challenge: str
    state: str | None = field(repr=False)


def validate_authorize(
    conn: sqlite3.Connection,
    config: Config,
    params: dict[str, list[str]],
    fetcher: Fetcher,
    now: float,
) -> AuthorizeRequest:
    """§4.2 passos 1 e 2. ``LocalError`` não redireciona; ``RedirectError`` volta ao cliente."""
    # 1. client_id e redirect_uri primeiro. Qualquer problema: erro local, nunca redirect.
    try:
        client_id = _one(params, "client_id")
        redirect_uri = _one(params, "redirect_uri")
    except _Duplicate:
        raise LocalError(BAD_REQUEST) from None
    if client_id is None:
        raise LocalError(BAD_REQUEST)
    policy = policy_for(config, client_id)
    if policy is None:
        raise LocalError(_UNKNOWN_CLIENT)
    try:
        client = _resolve_client(conn, config, client_id, fetcher, now)
    except CIMDError:
        raise LocalError(_UNKNOWN_CLIENT) from None
    if redirect_uri is None or redirect_uri != policy.redirect_uri:
        raise LocalError(_BAD_REDIRECT)
    if client.redirect_uri != policy.redirect_uri:
        raise LocalError(_BAD_REDIRECT)

    # 2. O resto. Erro aqui volta ao cliente com error + state (se veio e é válido) + iss.
    def fail(error, state=None):
        return RedirectError(error, redirect_uri, config.issuer, state)

    try:
        state = _one(params, "state")
    except _Duplicate:
        raise fail("invalid_request") from None
    if state is not None and (
        not state or len(state) > STATE_MAX or not all(ch.isprintable() for ch in state)
    ):
        raise fail("invalid_request")
    try:
        response_type = _one(params, "response_type")
        method = _one(params, "code_challenge_method")
        challenge = _one(params, "code_challenge")
        resource = _one(params, "resource")
        scope = _one(params, "scope")
    except _Duplicate:
        raise fail("invalid_request", state) from None
    if response_type != "code":
        raise fail("unsupported_response_type", state)
    if method != "S256" or challenge is None or not _CHALLENGE.fullmatch(challenge):
        raise fail("invalid_request", state)
    if resource is None or resource != policy.resource:
        raise fail("invalid_target", state)
    scope_value = _parse_scope(scope, policy.scopes, policy.required_scope)
    if scope_value is None:
        raise fail("invalid_scope", state)
    return AuthorizeRequest(client, policy, redirect_uri, resource, scope_value, challenge, state)


@dataclass(frozen=True)
class NewTransaction:
    tx_id: str = field(repr=False)
    browser: str = field(repr=False)
    csrf: str = field(repr=False)


def create_transaction(
    conn: sqlite3.Connection,
    keyring: Keyring,
    req: AuthorizeRequest,
    browser: str | None,
    now: float,
    max_pending: int,
    device_key: str | None = None,
) -> NewTransaction:
    """§4.2 passo 3: grava a transação (10 min) e descarta as pendentes mais antigas."""
    now = int(now)
    if not _opaque(browser):
        browser = new_token("")
    tx_id = new_token("")
    with write_transaction(conn):
        conn.execute(
            "DELETE FROM oauth_transactions WHERE expires_at<=? OR used_at IS NOT NULL", (now,)
        )
        conn.execute(
            "DELETE FROM oauth_transactions WHERE rowid IN (SELECT rowid FROM oauth_transactions "
            "WHERE device_key IS ? AND authenticated_at IS NULL ORDER BY expires_at DESC, rowid DESC LIMIT -1 OFFSET ?)",
            (device_key, max_pending - 1),
        )
        conn.execute(
            "INSERT INTO oauth_transactions(id_hash,browser_hash,client_row_id,redirect_uri,"
            "resource,scope,code_challenge,state,expires_at,device_key) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                token_hash(tx_id),
                token_hash(browser),
                req.client.row_id,
                req.redirect_uri,
                req.resource,
                req.scope,
                req.code_challenge,
                req.state,
                now + TX_TTL,
                device_key,
            ),
        )
    return NewTransaction(tx_id, browser, csrf_token(keyring, tx_id))


@dataclass(frozen=True)
class Transaction:
    tx_id: str = field(repr=False)
    id_hash: bytes = field(repr=False)
    client_row_id: int = 0
    client_id: str = ""
    client_name: str = ""
    policy: ClientPolicy | None = None
    redirect_uri: str = ""
    resource: str = ""
    scope: str = ""
    code_challenge: str = field(default="", repr=False)
    state: str | None = field(default=None, repr=False)
    authenticated: bool = False

    @property
    def redirect_host(self) -> str:
        return urlsplit(self.redirect_uri).hostname or ""


def load_transaction(
    conn: sqlite3.Connection,
    config: Config,
    keyring: Keyring,
    tx_id: object,
    browser: object,
    csrf: object,
    now: float,
    *,
    check_csrf: bool,
) -> Transaction:
    """Lê SÓ a transação. Cookie, id e (em POST) token anti-CSRF precisam bater."""
    if not _opaque(tx_id) or not _opaque(browser):
        raise TransactionError
    if check_csrf and (
        not isinstance(csrf, str)
        or not hmac.compare_digest(
            csrf.encode("ascii", "replace"), csrf_token(keyring, tx_id).encode()
        )
    ):
        raise TransactionError
    row = conn.execute(
        "SELECT t.id_hash, t.browser_hash, t.client_row_id, c.client_id, c.metadata_json, "
        "t.redirect_uri, t.resource, t.scope, t.code_challenge, t.state, t.authenticated_at "
        "FROM oauth_transactions t JOIN oauth_clients c ON c.id = t.client_row_id "
        "WHERE t.id_hash=? AND t.used_at IS NULL AND t.expires_at>?",
        (token_hash(tx_id), int(now)),
    ).fetchone()
    if row is None or not hmac.compare_digest(row[1], token_hash(browser)):
        raise TransactionError
    policy = policy_for(config, row[3])
    if policy is None or policy.redirect_uri != row[5] or policy.resource != row[6]:
        raise TransactionError
    try:
        name = json.loads(row[4])["client_name"]
    except (ValueError, KeyError, TypeError):
        raise TransactionError from None
    return Transaction(
        tx_id,
        row[0],
        row[2],
        row[3],
        name,
        policy,
        row[5],
        row[6],
        row[7],
        row[8],
        row[9],
        row[10] is not None,
    )


def mark_authenticated(conn: sqlite3.Connection, tx: Transaction, now: float) -> bool:
    with write_transaction(conn):
        return (
            conn.execute(
                "UPDATE oauth_transactions SET authenticated_at=? WHERE id_hash=? "
                "AND used_at IS NULL AND expires_at>?",
                (int(now), tx.id_hash, int(now)),
            ).rowcount
            == 1
        )


def active_grants(conn: sqlite3.Connection, client_row_id: int) -> dict[str, str]:
    """Rótulo → public_id dos grants ativos (não revogados e no prazo) de um cliente."""
    return {
        label: public_id
        for label, public_id in conn.execute(
            "SELECT label, public_id FROM oauth_grants WHERE client_row_id=? "
            "AND revoked_at IS NULL",
            (client_row_id,),
        )
    }


@dataclass(frozen=True)
class ConsentResult:
    kind: str  # "redirect", "ask_replace" ou "race"
    location: str = field(default="", repr=False)
    old_grant: str | None = None


class _Race(Exception):
    pass


def cancel_transaction(
    conn: sqlite3.Connection, config: Config, tx: Transaction, now: float
) -> str:
    with write_transaction(conn):
        if (
            conn.execute(
                "UPDATE oauth_transactions SET used_at=? WHERE id_hash=? AND used_at IS NULL "
                "AND expires_at>?",
                (int(now), tx.id_hash, int(now)),
            ).rowcount
            != 1
        ):
            raise TransactionError
    return build_redirect(tx.redirect_uri, [("error", "access_denied")], tx.state, config.issuer)


def finish_consent(
    conn: sqlite3.Connection,
    config: Config,
    tx: Transaction,
    label: str | None,
    replace: str | None,
    seen: frozenset[str],
    now: float,
) -> ConsentResult:
    """§4.2 fim + §4.5: tudo numa transação do banco (BEGIN IMMEDIATE).

    Claude: ``label`` da lista do config. Se já existe grant ativo com o rótulo:
    - ``replace`` é o public_id dele → revoga e cria o novo;
    - o usuário já tinha visto esse grant (``seen``) → pergunta se substitui;
    - senão, outra aba criou no meio do caminho → "conexão já criada, recarregue".
    Painel: rótulo fixo ``painel``; revoga o grant de painel anterior sem perguntar.
    """
    now = int(now)
    policy = tx.policy
    if policy.name == "painel":
        label = PAINEL_LABEL
    elif label not in config.account_labels:
        raise ValueError("rótulo inválido")
    try:
        with write_transaction(conn):
            row = conn.execute(
                "SELECT 1 FROM oauth_transactions WHERE id_hash=? AND used_at IS NULL "
                "AND authenticated_at IS NOT NULL AND expires_at>?",
                (tx.id_hash, now),
            ).fetchone()
            if row is None:
                raise TransactionError
            _revoke_expired_grants(conn, now)
            current = conn.execute(
                "SELECT id, public_id FROM oauth_grants WHERE label=? AND client_row_id=? "
                "AND revoked_at IS NULL",
                (label, tx.client_row_id),
            ).fetchone()
            if current is not None:
                if policy.name == "painel" or replace == current[1]:
                    _revoke_grant(conn, current[0], current[1], now)
                elif replace is None and current[1] in seen:
                    return ConsentResult("ask_replace", old_grant=current[1])
                else:
                    return ConsentResult("race")
            conn.execute(
                "UPDATE oauth_transactions SET used_at=? WHERE id_hash=?", (now, tx.id_hash)
            )
            public_id = new_public_id("grant_")
            try:
                grant_id = conn.execute(
                    "INSERT INTO oauth_grants(public_id,client_row_id,label,resource,scope,"
                    "created_at,expires_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        public_id,
                        tx.client_row_id,
                        label,
                        tx.resource,
                        tx.scope,
                        now,
                        now + policy.grant_ttl,
                    ),
                ).lastrowid
            except sqlite3.IntegrityError:
                raise _Race from None
            code = new_token("")
            conn.execute(
                "INSERT INTO oauth_codes(code_hash,grant_id,redirect_uri,resource,code_challenge,"
                "expires_at) VALUES (?,?,?,?,?,?)",
                (
                    token_hash(code),
                    grant_id,
                    tx.redirect_uri,
                    tx.resource,
                    tx.code_challenge,
                    now + CODE_TTL,
                ),
            )
            _audit(conn, "grant_criado", grant_id, public_id, now)
    except _Race:
        return ConsentResult("race")
    location = build_redirect(tx.redirect_uri, [("code", code)], tx.state, config.issuer)
    return ConsentResult("redirect", location=location)


# ---------------------------------------------------------------------------
# Token (§4.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenResponse:
    access_token: str = field(repr=False)
    expires_in: int = 0
    scope: str = ""
    refresh_token: str | None = field(default=None, repr=False)

    def to_json(self) -> dict:
        out = {
            "access_token": self.access_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "scope": self.scope,
        }
        if self.refresh_token is not None:
            out["refresh_token"] = self.refresh_token
        return out


def _err(error: str, description: str, status: int = 400) -> OAuthError:
    return OAuthError(error, description, status)


def _client_policy(config: Config, params) -> tuple[str, ClientPolicy]:
    client_id = _one(params, "client_id")
    if client_id is None:
        raise _err("invalid_request", "client_id obrigatorio")
    policy = policy_for(config, client_id)
    if policy is None:
        raise _err("invalid_client", "cliente desconhecido", 401)
    return client_id, policy


def _issue(conn, grant, policy: ClientPolicy, family_id, code_hash, scope_out, now, keyring=None):
    grant_id, public_id, grant_expires = grant
    access = new_token(ACCESS_PREFIX)
    if keyring is not None:
        access += "." + access_tag(keyring, access[len(ACCESS_PREFIX) :])
    access_exp = min(now + policy.access_ttl, grant_expires)
    conn.execute(
        "INSERT INTO oauth_tokens(token_hash,kind,grant_id,family_id,code_hash,expires_at,scope) "
        "VALUES (?,?,?,?,?,?,?)",
        (token_hash(access), "access", grant_id, family_id, code_hash, access_exp, scope_out),
    )
    refresh = None
    if policy.refresh:
        refresh = new_token(REFRESH_PREFIX)
        conn.execute(
            "INSERT INTO oauth_tokens(token_hash,kind,grant_id,family_id,code_hash,expires_at,"
            "scope) VALUES (?,?,?,?,?,?,?)",
            (
                token_hash(refresh),
                "refresh",
                grant_id,
                family_id,
                code_hash,
                min(now + REFRESH_TTL, grant_expires),
                scope_out,
            ),
        )
    _audit(conn, "token_emitido", grant_id, public_id, now)
    return TokenResponse(access, access_exp - now, scope_out, refresh)


def _pkce_ok(verifier: str | None, challenge: str) -> bool:
    if verifier is None or not _VERIFIER.fullmatch(verifier):
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, challenge)


def _exchange_code(conn, config: Config, params, now: int, keyring=None) -> TokenResponse:
    code = _one(params, "code")
    redirect_uri = _one(params, "redirect_uri")
    verifier = _one(params, "code_verifier")
    resource = _one(params, "resource")
    client_id, policy = _client_policy(config, params)
    if code is None or redirect_uri is None or verifier is None:
        raise _err("invalid_request", "parametros obrigatorios ausentes")
    if resource is not None and resource != policy.resource:
        raise _err("invalid_target", "resource invalido para este cliente")
    if not _opaque(code):
        raise _err("invalid_grant", "codigo invalido ou expirado")
    code_hash = token_hash(code)
    reused = None
    if conn.execute("SELECT 1 FROM oauth_codes WHERE code_hash=?", (code_hash,)).fetchone() is None:
        raise _err("invalid_grant", "credencial invalida ou expirada")
    with write_transaction(conn):
        row = conn.execute(
            "SELECT o.grant_id, o.redirect_uri, o.resource, o.code_challenge, o.expires_at, "
            "o.used_at, g.public_id, g.expires_at, g.revoked_at, g.scope, c.client_id "
            "FROM oauth_codes o JOIN oauth_grants g ON g.id=o.grant_id "
            "JOIN oauth_clients c ON c.id=g.client_row_id WHERE o.code_hash=?",
            (code_hash,),
        ).fetchone()
        if row is None:
            raise _err("invalid_grant", "codigo invalido ou expirado")
        (
            grant_id,
            code_redirect,
            code_resource,
            challenge,
            code_exp,
            used_at,
            public_id,
            grant_exp,
            grant_revoked,
            grant_scope,
            grant_client,
        ) = row
        # Vínculos e PKCE primeiro, mesmo para código já usado: quem tem só o código (sem o
        # verifier, ou com outro client/redirect/resource) não consegue derrubar a conexão.
        if grant_client != client_id:
            raise _err("invalid_grant", "codigo emitido para outro cliente")
        if code_redirect != redirect_uri or redirect_uri != policy.redirect_uri:
            raise _err("invalid_grant", "redirect_uri nao confere")
        if resource is not None and code_resource != resource:
            raise _err("invalid_target", "resource nao confere")
        if not _pkce_ok(verifier, challenge):
            raise _err("invalid_grant", "PKCE invalido")
        if used_at is not None:
            # RFC 9700 §4.2.4: replay validado revoga o que foi emitido com ele (e o grant).
            conn.execute(
                "UPDATE oauth_tokens SET revoked_at=? WHERE code_hash=? AND revoked_at IS NULL",
                (now, code_hash),
            )
            _audit(conn, "codigo_reuso", grant_id, public_id, now)
            if grant_revoked is None:
                _revoke_grant(conn, grant_id, public_id, now)
            reused = True
        else:
            if code_exp <= now:
                raise _err("invalid_grant", "codigo invalido ou expirado")
            if grant_revoked is not None or grant_exp <= now:
                raise _err("invalid_grant", "autorizacao revogada ou expirada")
            if not set(grant_scope.split(" ")) <= policy.scopes:
                raise _err("invalid_scope", "scope fora da matriz")
            if (
                conn.execute(
                    "UPDATE oauth_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL",
                    (now, code_hash),
                ).rowcount
                != 1
            ):
                raise _err("invalid_grant", "codigo invalido ou expirado")
            family_id = new_public_id("fam_")
            return _issue(
                conn,
                (grant_id, public_id, grant_exp),
                policy,
                family_id,
                code_hash,
                grant_scope,
                now,
                keyring,
            )
    assert reused
    raise _err("invalid_grant", "codigo invalido ou expirado")


def _refresh(conn, config: Config, params, now: int, keyring=None) -> TokenResponse:
    refresh = _one(params, "refresh_token")
    scope = _one(params, "scope")
    resource = _one(params, "resource")
    client_id, policy = _client_policy(config, params)
    if refresh is None:
        raise _err("invalid_request", "refresh_token obrigatorio")
    if not policy.refresh:
        raise _err("unauthorized_client", "cliente sem refresh")
    if resource is not None and resource != policy.resource:
        raise _err("invalid_target", "resource invalido para este cliente")
    if not _opaque(refresh):
        raise _err("invalid_grant", "credencial invalida ou expirada")
    refresh_hash = token_hash(refresh)
    reused = False
    if (
        conn.execute(
            "SELECT 1 FROM oauth_tokens WHERE token_hash=? AND kind='refresh'", (refresh_hash,)
        ).fetchone()
        is None
    ):
        raise _err("invalid_grant", "credencial invalida ou expirada")
    with write_transaction(conn):
        row = conn.execute(
            "SELECT t.grant_id, t.family_id, t.expires_at, t.used_at, t.revoked_at, "
            "g.public_id, g.expires_at, g.revoked_at, g.scope, g.resource, c.client_id "
            "FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id "
            "JOIN oauth_clients c ON c.id=g.client_row_id "
            "WHERE t.token_hash=? AND t.kind='refresh'",
            (refresh_hash,),
        ).fetchone()
        if row is None:
            raise _err("invalid_grant", "credencial invalida ou expirada")
        (
            grant_id,
            family_id,
            token_exp,
            used_at,
            token_revoked,
            public_id,
            grant_exp,
            grant_revoked,
            grant_scope,
            grant_resource,
            grant_client,
        ) = row
        if grant_client != client_id:
            raise _err("invalid_grant", "credencial invalida ou expirada")
        if token_revoked is not None or grant_revoked is not None:
            raise _err("invalid_grant", "credencial invalida ou expirada")
        if used_at is not None:
            successor = conn.execute(
                "SELECT s.used_at FROM oauth_tokens t JOIN oauth_tokens s "
                "ON s.token_hash=t.successor_hash WHERE t.token_hash=?",
                (refresh_hash,),
            ).fetchone()
            if now - used_at <= 60 and successor is not None and successor[0] is None:
                if (
                    conn.execute(
                        "SELECT 1 FROM audit WHERE event='refresh_reuso_tolerado' AND target=?",
                        (family_id,),
                    ).fetchone()
                    is None
                ):
                    _audit(conn, "refresh_reuso_tolerado", grant_id, family_id, now)
                reused = True
            else:
                # Reuso fora da tolerância revoga a família e o grant.
                conn.execute(
                    "UPDATE oauth_tokens SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL",
                    (now, family_id),
                )
                _audit(conn, "refresh_reuso", grant_id, public_id, now)
                if grant_revoked is None:
                    _revoke_grant(conn, grant_id, public_id, now)
                reused = True
        else:
            if token_revoked is not None or token_exp <= now:
                raise _err("invalid_grant", "credencial invalida ou expirada")
            if grant_revoked is not None or grant_exp <= now:
                raise _err("invalid_grant", "credencial invalida ou expirada")
            if grant_resource != policy.resource or (
                resource is not None and resource != grant_resource
            ):
                raise _err("invalid_target", "resource nao confere")
            granted = set(grant_scope.split(" "))
            if not granted <= policy.scopes:
                raise _err("invalid_scope", "scope fora da matriz")
            if scope is None:
                scope_out = grant_scope
            else:
                parsed = _parse_scope(scope, policy.scopes, policy.required_scope)
                if parsed is None or not set(parsed.split(" ")) <= granted:
                    raise _err("invalid_scope", "scope maior que o concedido")
                scope_out = parsed
            rotations = conn.execute(
                "SELECT count(*) FROM oauth_tokens WHERE family_id=? AND kind='refresh' "
                "AND used_at>?",
                (family_id, now - 3600),
            ).fetchone()[0]
            if rotations >= 120:
                raise _err(
                    "temporarily_unavailable", "Limite de 120 rotações por hora por família.", 429
                )
            if (
                conn.execute(
                    "UPDATE oauth_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL",
                    (now, refresh_hash),
                ).rowcount
                != 1
            ):
                raise _err("invalid_grant", "credencial invalida ou expirada")
            issued = _issue(
                conn,
                (grant_id, public_id, grant_exp),
                policy,
                family_id,
                None,
                scope_out,
                now,
                keyring,
            )
            conn.execute(
                "UPDATE oauth_tokens SET successor_hash=? WHERE token_hash=?",
                (token_hash(issued.refresh_token), refresh_hash),
            )
            return issued
    assert reused
    raise _err("invalid_grant", "credencial invalida ou expirada")


def token_request(
    conn: sqlite3.Connection, config: Config, params: dict[str, list[str]], now: float, keyring=None
) -> TokenResponse:
    """``POST /oauth/token`` já com o corpo parseado. Levanta ``OAuthError``."""
    try:
        grant_type = _one(params, "grant_type")
        if grant_type == "authorization_code":
            return _exchange_code(conn, config, params, int(now), keyring)
        if grant_type == "refresh_token":
            return _refresh(conn, config, params, int(now), keyring)
    except _Duplicate:
        raise _err("invalid_request", "parametro repetido") from None
    if grant_type is None:
        raise _err("invalid_request", "grant_type obrigatorio")
    raise _err("unsupported_grant_type", "grant_type nao suportado")


# ---------------------------------------------------------------------------
# Revogação (RFC 7009)
# ---------------------------------------------------------------------------


def revoke_token(
    conn: sqlite3.Connection, config: Config, params: dict[str, list[str]], now: float
) -> None:
    """Revoga access (só ele) ou refresh (a família inteira e o grant). Nunca levanta."""
    now = int(now)
    try:
        token = _one(params, "token")
        client_id = _one(params, "client_id")
    except _Duplicate:
        return
    if not _opaque(token):
        return
    if (
        conn.execute(
            "SELECT 1 FROM oauth_tokens WHERE token_hash=?", (token_hash(token),)
        ).fetchone()
        is None
    ):
        return
    with write_transaction(conn):
        row = conn.execute(
            "SELECT t.kind, t.family_id, t.grant_id, g.public_id, g.revoked_at, c.client_id "
            "FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id "
            "JOIN oauth_clients c ON c.id=g.client_row_id WHERE t.token_hash=?",
            (token_hash(token),),
        ).fetchone()
        if row is None:
            return
        kind, family_id, grant_id, public_id, grant_revoked, owner_client = row
        if client_id is not None and client_id != owner_client:
            return
        if kind == "access":
            conn.execute(
                "UPDATE oauth_tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                (now, token_hash(token)),
            )
            return
        conn.execute(
            "UPDATE oauth_tokens SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL",
            (now, family_id),
        )
        if grant_revoked is None:
            _revoke_grant(conn, grant_id, public_id, now)


# ---------------------------------------------------------------------------
# RS: validação do Bearer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccessContext:
    grant_id: int
    grant_public_id: str
    label: str
    scope: tuple[str, ...]


def _www_authenticate(resource: str, error: str, scope: str | None = None) -> str:
    parts = [f'error="{error}"']
    if scope is not None:
        parts.append(f'scope="{scope}"')
    parts.append(f'resource_metadata="{resource_metadata_url(resource)}"')
    return "Bearer " + ", ".join(parts)


def access_tag(keyring, random: str) -> str:
    return base64.urlsafe_b64encode(keyring.mac("access", random.encode("ascii"))).decode()[:22]


def precheck_access(keyring, token, resource):
    valid = isinstance(token, str) and re.fullmatch(
        r"bsw_at_[A-Za-z0-9_-]{43}(?:\.[A-Za-z0-9_-]{22})?", token
    )
    if valid and "." in token:
        random, tag = token[len(ACCESS_PREFIX) :].split(".")
        valid = hmac.compare_digest(tag, access_tag(keyring, random))
    if not valid:
        raise BearerError(401, "invalid_token", _www_authenticate(resource, "invalid_token"))


def check_access_active(conn, token, resource, now):
    row = conn.execute(
        "SELECT 1 FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id "
        "WHERE t.token_hash=? AND t.revoked_at IS NULL AND g.revoked_at IS NULL "
        "AND t.expires_at>? AND g.expires_at>?",
        (token_hash(token), now, now),
    ).fetchone()
    if row is None:
        raise BearerError(401, "invalid_token", _www_authenticate(resource, "invalid_token"))


def validate_bearer(
    conn: sqlite3.Connection,
    token: object,
    expected_resource: str,
    required_scope: str,
    now: float,
) -> AccessContext:
    """Confere o access token pelo hash, o recurso exato e o scope. Levanta ``BearerError``."""
    now = int(now)

    def invalid():
        return BearerError(
            401, "invalid_token", _www_authenticate(expected_resource, "invalid_token")
        )

    if not _opaque(token) or not token.startswith(ACCESS_PREFIX):
        raise invalid()
    row = conn.execute(
        "SELECT g.id, g.public_id, g.label, COALESCE(t.scope, g.scope), g.resource, "
        "g.last_used_at "
        "FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id "
        "WHERE t.token_hash=? AND t.kind='access' AND t.revoked_at IS NULL AND t.expires_at>? "
        "AND g.revoked_at IS NULL AND g.expires_at>?",
        (token_hash(token), now, now),
    ).fetchone()
    if row is None or row[4] != expected_resource:
        raise invalid()
    grant_id, public_id, label, scope, _, last_used = row
    scopes = tuple(scope.split(" "))
    if required_scope not in scopes:
        raise BearerError(
            403,
            "insufficient_scope",
            _www_authenticate(expected_resource, "insufficient_scope", required_scope),
        )
    if last_used is None or last_used <= now - LAST_USED_EVERY:
        conn.execute(
            "UPDATE oauth_grants SET last_used_at=? WHERE id=? "
            "AND (last_used_at IS NULL OR last_used_at<=?)",
            (now, grant_id, now - LAST_USED_EVERY),
        )
    return AccessContext(grant_id, public_id, label, scopes)


# ---------------------------------------------------------------------------
# Faxina
# ---------------------------------------------------------------------------


def cleanup_expired(
    conn: sqlite3.Connection, now: float, audit_retention_days: int = 180
) -> dict[str, int]:
    """Apaga transações, códigos e tokens vencidos.

    Refresh usado fica até a família inteira vencer (precisa dele para detectar reuso, §4.3).
    Grants vencidos são marcados revogados (nunca apagados: conteúdo aponta para eles).
    """
    now = int(now)
    with write_transaction(conn):
        _revoke_expired_grants(conn, now)
        conn.execute("DELETE FROM audit WHERE at<?", (now - audit_retention_days * 86400,))
        conn.execute(
            "DELETE FROM pending_deletions WHERE expires_at<=? OR used_at IS NOT NULL", (now,)
        )
        counts = {
            "transacoes": conn.execute(
                "DELETE FROM oauth_transactions WHERE expires_at<=?", (now,)
            ).rowcount,
            "codigos": conn.execute("DELETE FROM oauth_codes WHERE expires_at<=?", (now,)).rowcount,
            "access": conn.execute(
                "DELETE FROM oauth_tokens WHERE kind='access' AND expires_at<=?", (now,)
            ).rowcount,
            "refresh": conn.execute(
                "DELETE FROM oauth_tokens WHERE kind='refresh' AND family_id NOT IN "
                "(SELECT family_id FROM oauth_tokens WHERE kind='refresh' AND expires_at>?)",
                (now,),
            ).rowcount,
        }
    return counts
