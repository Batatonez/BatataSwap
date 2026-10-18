"""Regras do AS e do RS (§4) direto nas funções, sem HTTP."""

import base64
import hashlib
import json
import secrets
import threading
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import pytest

from batataswap import db
from batataswap.auth import oauth, owner, passwords
from batataswap.auth.cimd import CLAUDE_REDIRECT_URI, FetchResult
from batataswap.auth.totp import code_at, generate_secret
from batataswap.config import CLAUDE_CIMD_CLIENT_ID, Config
from batataswap.crypto import Keyring, token_hash

ORIGIN = "https://batatarp.exemplo.ts.net"
VERCEL = "https://batataswap.vercel.app"
PAINEL_CALLBACK = VERCEL + "/callback"
PASSWORD = "uma frase longa e incomum 726!"
NOW = 1_800_000_000
DAY = 24 * 3600


def claude_document(**changes) -> bytes:
    doc = {
        "client_id": CLAUDE_CIMD_CLIENT_ID,
        "client_name": "Claude",
        "redirect_uris": [CLAUDE_REDIRECT_URI],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "logo_uri": "https://claude.ai/logo.png",
    }
    for key, value in changes.items():
        if value is None:
            doc.pop(key, None)
        else:
            doc[key] = value
    return json.dumps(doc).encode()


class FakeFetcher:
    def __init__(self, body=None, status=200, headers=None, error=None):
        self.body = claude_document() if body is None else body
        self.status = status
        self.headers = headers or {"cache-control": "max-age=3600"}
        self.error = error
        self.calls = []

    def __call__(self, url, max_bytes, timeout):
        self.calls.append((url, max_bytes, timeout))
        if self.error is not None:
            raise self.error
        return FetchResult(self.status, self.headers, self.body)


def pkce():
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass
class Env:
    config: Config
    keyring: Keyring
    path: object
    conn: object
    secret: bytes

    def connect(self):
        return db.connect(self.path)


@pytest.fixture
def env(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    path = tmp_path / "oauth.db"
    conn = db.connect(path, create=True)
    db.migrate(conn)
    keyring = Keyring(secrets.token_bytes(32))
    secret = generate_secret()
    monkeypatch.setattr(owner, "hash_password", lambda pw: passwords.hash_password(pw, log_n=10))
    owner.create_owner(conn, keyring, PASSWORD, secret, code_at(secret, NOW // 30 - 2), NOW - 60)
    config = Config(public_origin=ORIGIN, vercel_origin=VERCEL)
    yield Env(config, keyring, path, conn, secret)
    conn.close()


def claude_params(challenge, **changes):
    params = {
        "response_type": "code",
        "client_id": CLAUDE_CIMD_CLIENT_ID,
        "redirect_uri": CLAUDE_REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": ORIGIN + "/mcp",
        "scope": "memoria offline_access",
        "state": "estado-123",
    }
    params.update(changes)
    return {k: [v] for k, v in params.items() if v is not None}


def painel_params(challenge, **changes):
    params = {
        "response_type": "code",
        "client_id": "painel-vercel",
        "redirect_uri": PAINEL_CALLBACK,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": ORIGIN + "/api/painel",
        "scope": "painel",
        "state": "s-painel",
    }
    params.update(changes)
    return {k: [v] for k, v in params.items() if v is not None}


def make_code(env, params, label="conta-1", now=NOW, replace=None, seen=frozenset()):
    """Fluxo completo pelas funções: authorize → transação → login → consentimento."""
    req = oauth.validate_authorize(env.conn, env.config, params, FakeFetcher(), now)
    tx = oauth.create_transaction(env.conn, env.keyring, req, None, now, 20)
    loaded = oauth.load_transaction(
        env.conn, env.config, env.keyring, tx.tx_id, tx.browser, tx.csrf, now, check_csrf=True
    )
    assert oauth.mark_authenticated(env.conn, loaded, now)
    loaded = oauth.load_transaction(
        env.conn, env.config, env.keyring, tx.tx_id, tx.browser, tx.csrf, now, check_csrf=True
    )
    result = oauth.finish_consent(env.conn, env.config, loaded, label, replace, seen, now)
    assert result.kind == "redirect", result
    query = parse_qs(urlsplit(result.location).query)
    return query["code"][0], query


def exchange(env, auth_code, verifier, now=NOW, **changes):
    params = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "code_verifier": verifier,
        "client_id": CLAUDE_CIMD_CLIENT_ID,
        "redirect_uri": CLAUDE_REDIRECT_URI,
        "resource": ORIGIN + "/mcp",
    }
    params.update(changes)
    return oauth.token_request(
        env.conn, env.config, {k: [v] for k, v in params.items() if v is not None}, now
    )


def refresh(env, token, now, **changes):
    params = {
        "grant_type": "refresh_token",
        "refresh_token": token,
        "client_id": CLAUDE_CIMD_CLIENT_ID,
    }
    params.update(changes)
    return oauth.token_request(
        env.conn, env.config, {k: [v] for k, v in params.items() if v is not None}, now
    )


def claude_tokens(env, label="conta-1", now=NOW):
    verifier, challenge = pkce()
    code, _ = make_code(env, claude_params(challenge), label, now)
    return exchange(env, code, verifier, now)


# ---------------------------------------------------------------------------
# Metadados
# ---------------------------------------------------------------------------


def test_metadata_exact(env):
    assert oauth.protected_resource_metadata(env.config, "mcp") == {
        "resource": ORIGIN + "/mcp",
        "authorization_servers": [ORIGIN],
        "scopes_supported": ["memoria"],
    }
    assert oauth.protected_resource_metadata(env.config, "painel") == {
        "resource": ORIGIN + "/api/painel",
        "authorization_servers": [ORIGIN],
        "scopes_supported": ["painel"],
    }
    meta = oauth.authorization_server_metadata(env.config)
    assert meta == {
        "issuer": ORIGIN,
        "authorization_endpoint": ORIGIN + "/oauth/authorize",
        "token_endpoint": ORIGIN + "/oauth/token",
        "revocation_endpoint": ORIGIN + "/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["memoria", "painel", "offline_access"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
    }
    assert "registration_endpoint" not in meta
    assert oauth.resource_metadata_url(ORIGIN + "/api/painel") == (
        ORIGIN + "/.well-known/oauth-protected-resource/api/painel"
    )


def test_config_defaults():
    config = Config(public_origin=ORIGIN)
    assert config.allowed_cimd_client_ids == (CLAUDE_CIMD_CLIENT_ID,)
    assert config.painel_redirect_uri is None
    assert oauth.policy_for(config, "painel-vercel") is None


# ---------------------------------------------------------------------------
# Authorize (§4.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "changes",
    [
        {"client_id": "https://evil.example/cimd"},
        {"client_id": "https://claude.ai/oauth/claude-code-client-metadata"},
        {"client_id": None},
        {"redirect_uri": "https://claude.ai/api/mcp/auth_callback/"},
        {"redirect_uri": "https://evil.example/cb"},
        {"redirect_uri": None},
    ],
)
def test_authorize_local_errors_never_redirect(env, changes):
    _, challenge = pkce()
    fetcher = FakeFetcher()
    with pytest.raises(oauth.LocalError):
        oauth.validate_authorize(
            env.conn, env.config, claude_params(challenge, **changes), fetcher, NOW
        )
    if changes.get("client_id", CLAUDE_CIMD_CLIENT_ID) != CLAUDE_CIMD_CLIENT_ID:
        assert fetcher.calls == []  # fora da lista: nem toca na rede


def test_authorize_duplicate_client_or_redirect_is_local(env):
    _, challenge = pkce()
    for name in ("client_id", "redirect_uri"):
        params = claude_params(challenge)
        params[name] = params[name] * 2
        with pytest.raises(oauth.LocalError):
            oauth.validate_authorize(env.conn, env.config, params, FakeFetcher(), NOW)


def test_authorize_painel_redirect_must_match(env):
    _, challenge = pkce()
    with pytest.raises(oauth.LocalError):
        oauth.validate_authorize(
            env.conn,
            env.config,
            painel_params(challenge, redirect_uri=CLAUDE_REDIRECT_URI),
            FakeFetcher(),
            NOW,
        )


@pytest.mark.parametrize(
    "changes, error",
    [
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"code_challenge_method": None}, "invalid_request"),
        ({"code_challenge": "A" * 42}, "invalid_request"),
        ({"code_challenge": "A" * 44}, "invalid_request"),
        ({"code_challenge": "A" * 42 + "="}, "invalid_request"),
        ({"code_challenge": None}, "invalid_request"),
        ({"resource": None}, "invalid_target"),
        ({"resource": ORIGIN + "/api/painel"}, "invalid_target"),
        ({"resource": ORIGIN + "/mcp/"}, "invalid_target"),
        ({"scope": "memoria painel"}, "invalid_scope"),
        ({"scope": "memoria  offline_access"}, "invalid_scope"),
        ({"scope": "offline_access"}, "invalid_scope"),
        ({"scope": ""}, "invalid_scope"),
    ],
)
def test_authorize_redirect_errors(env, changes, error):
    _, challenge = pkce()
    with pytest.raises(oauth.RedirectError) as caught:
        oauth.validate_authorize(
            env.conn, env.config, claude_params(challenge, **changes), FakeFetcher(), NOW
        )
    query = parse_qs(urlsplit(caught.value.location()).query, keep_blank_values=True)
    assert caught.value.location().startswith(CLAUDE_REDIRECT_URI + "?")
    assert query == {"error": [error], "state": ["estado-123"], "iss": [ORIGIN]}
    assert "estado-123" not in str(caught.value) and "estado-123" not in repr(caught.value)


def test_authorize_painel_matrix(env):
    _, challenge = pkce()
    for changes, error in (
        ({"scope": "memoria"}, "invalid_scope"),
        ({"scope": "painel offline_access"}, "invalid_scope"),
        ({"resource": ORIGIN + "/mcp"}, "invalid_target"),
    ):
        with pytest.raises(oauth.RedirectError) as caught:
            oauth.validate_authorize(
                env.conn, env.config, painel_params(challenge, **changes), FakeFetcher(), NOW
            )
        assert caught.value.error == error
        assert caught.value.redirect_uri == PAINEL_CALLBACK


def test_authorize_state_rules(env):
    _, challenge = pkce()
    req = oauth.validate_authorize(
        env.conn, env.config, claude_params(challenge, state=None), FakeFetcher(), NOW
    )
    assert req.state is None and req.scope == "memoria offline_access"
    for bad in ("x" * 513, "a\nb"):
        with pytest.raises(oauth.RedirectError) as caught:
            oauth.validate_authorize(
                env.conn, env.config, claude_params(challenge, state=bad), FakeFetcher(), NOW
            )
        assert "state" not in parse_qs(urlsplit(caught.value.location()).query)
    params = claude_params(challenge)
    params["state"] = ["a", "b"]
    with pytest.raises(oauth.RedirectError) as caught:
        oauth.validate_authorize(env.conn, env.config, params, FakeFetcher(), NOW)
    assert caught.value.error == "invalid_request"
    params = claude_params(challenge)
    params["scope"] = ["memoria", "memoria"]
    with pytest.raises(oauth.RedirectError) as caught:
        oauth.validate_authorize(env.conn, env.config, params, FakeFetcher(), NOW)
    assert caught.value.error == "invalid_request"
    assert caught.value.state == "estado-123"


def test_scope_default_and_canonical(env):
    _, challenge = pkce()
    req = oauth.validate_authorize(
        env.conn, env.config, claude_params(challenge, scope=None), FakeFetcher(), NOW
    )
    assert req.scope == "memoria"
    req = oauth.validate_authorize(
        env.conn,
        env.config,
        claude_params(challenge, scope="offline_access memoria memoria"),
        FakeFetcher(),
        NOW,
    )
    assert req.scope == "memoria offline_access"


def test_pending_transactions_capped(env):
    _, challenge = pkce()
    req = oauth.validate_authorize(
        env.conn, env.config, claude_params(challenge), FakeFetcher(), NOW
    )
    created = [
        oauth.create_transaction(env.conn, env.keyring, req, None, NOW + i, 20) for i in range(25)
    ]
    assert env.conn.execute("SELECT count(*) FROM oauth_transactions").fetchone()[0] == 20
    for tx, alive in ((created[0], False), (created[4], False), (created[5], True)):
        try:
            oauth.load_transaction(
                env.conn,
                env.config,
                env.keyring,
                tx.tx_id,
                tx.browser,
                tx.csrf,
                NOW + 30,
                check_csrf=True,
            )
            assert alive
        except oauth.TransactionError:
            assert not alive
    # Banco guarda só hashes.
    row = env.conn.execute(
        "SELECT id_hash, browser_hash FROM oauth_transactions ORDER BY expires_at DESC"
    ).fetchone()
    assert row == (token_hash(created[-1].tx_id), token_hash(created[-1].browser))


def test_transaction_binding(env):
    _, challenge = pkce()
    req = oauth.validate_authorize(
        env.conn, env.config, claude_params(challenge), FakeFetcher(), NOW
    )
    tx = oauth.create_transaction(env.conn, env.keyring, req, None, NOW, 20)
    other = oauth.create_transaction(env.conn, env.keyring, req, None, NOW, 20)
    assert tx.browser != other.browser
    same_browser = oauth.create_transaction(env.conn, env.keyring, req, tx.browser, NOW, 20)
    assert same_browser.browser == tx.browser and same_browser.tx_id != tx.tx_id

    def load(tx_id=tx.tx_id, browser=tx.browser, csrf=tx.csrf, now=NOW, check=True):
        return oauth.load_transaction(
            env.conn, env.config, env.keyring, tx_id, browser, csrf, now, check_csrf=check
        )

    assert not load().authenticated
    assert load(csrf=None, check=False)
    for kwargs in (
        {"browser": other.browser},
        {"browser": None},
        {"csrf": other.csrf},
        {"csrf": None},
        {"csrf": "x" * 43},
        {"tx_id": other.tx_id},  # transação de outro navegador
        {"now": NOW + oauth.TX_TTL},
    ):
        with pytest.raises(oauth.TransactionError):
            load(**kwargs)
    assert "tx_id" not in repr(tx) or tx.tx_id not in repr(tx)
    assert tx.csrf not in repr(tx) and tx.browser not in repr(tx)


# ---------------------------------------------------------------------------
# Consentimento e grants (§4.5)
# ---------------------------------------------------------------------------


def test_two_accounts_and_replace(env):
    t1 = claude_tokens(env, "conta-1")
    t2 = claude_tokens(env, "conta-2")
    c1 = oauth.validate_bearer(env.conn, t1.access_token, ORIGIN + "/mcp", "memoria", NOW)
    c2 = oauth.validate_bearer(env.conn, t2.access_token, ORIGIN + "/mcp", "memoria", NOW)
    assert (c1.label, c2.label) == ("conta-1", "conta-2")
    assert c1.grant_public_id != c2.grant_public_id
    assert c1.scope == ("memoria", "offline_access")

    # Mesmo rótulo de novo: sem substituir → pergunta; o grant antigo continua valendo.
    _, challenge = pkce()
    req = oauth.validate_authorize(
        env.conn, env.config, claude_params(challenge), FakeFetcher(), NOW
    )
    tx = oauth.create_transaction(env.conn, env.keyring, req, None, NOW, 20)
    loaded = oauth.load_transaction(
        env.conn, env.config, env.keyring, tx.tx_id, tx.browser, tx.csrf, NOW, check_csrf=True
    )
    oauth.mark_authenticated(env.conn, loaded, NOW)
    loaded = oauth.load_transaction(
        env.conn, env.config, env.keyring, tx.tx_id, tx.browser, tx.csrf, NOW, check_csrf=True
    )
    active = oauth.active_grants(env.conn, loaded.client_row_id)
    assert set(active) == {"conta-1", "conta-2"}
    seen = frozenset(active.values())
    asked = oauth.finish_consent(env.conn, env.config, loaded, "conta-1", None, seen, NOW)
    assert asked.kind == "ask_replace" and asked.old_grant == c1.grant_public_id
    assert oauth.validate_bearer(env.conn, t1.access_token, ORIGIN + "/mcp", "memoria", NOW)
    # Sem ter visto o grant (outra aba criou): corrida.
    race = oauth.finish_consent(env.conn, env.config, loaded, "conta-1", None, frozenset(), NOW)
    assert race.kind == "race"
    # substituir apontando para outro grant: corrida também.
    race = oauth.finish_consent(
        env.conn, env.config, loaded, "conta-1", c2.grant_public_id, seen, NOW
    )
    assert race.kind == "race"
    done = oauth.finish_consent(
        env.conn, env.config, loaded, "conta-1", c1.grant_public_id, seen, NOW
    )
    assert done.kind == "redirect"
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, t1.access_token, ORIGIN + "/mcp", "memoria", NOW)
    with pytest.raises(oauth.OAuthError) as caught:
        refresh(env, t1.refresh_token, NOW + 10)
    assert caught.value.error == "invalid_grant"
    assert oauth.validate_bearer(env.conn, t2.access_token, ORIGIN + "/mcp", "memoria", NOW)
    labels = env.conn.execute(
        "SELECT label, revoked_at IS NULL FROM oauth_grants ORDER BY id"
    ).fetchall()
    assert labels == [("conta-1", 0), ("conta-2", 1), ("conta-1", 1)]
    # Transação usada não serve mais.
    with pytest.raises(oauth.TransactionError):
        oauth.finish_consent(env.conn, env.config, loaded, "conta-1", None, frozenset(), NOW)
    events = [r[0] for r in env.conn.execute("SELECT event FROM audit ORDER BY id")]
    assert events.count("grant_criado") == 3 and "grant_revogado" in events


def test_invalid_label_rejected(env):
    _, challenge = pkce()
    req = oauth.validate_authorize(
        env.conn, env.config, claude_params(challenge), FakeFetcher(), NOW
    )
    tx = oauth.create_transaction(env.conn, env.keyring, req, None, NOW, 20)
    loaded = oauth.load_transaction(
        env.conn, env.config, env.keyring, tx.tx_id, tx.browser, tx.csrf, NOW, check_csrf=True
    )
    oauth.mark_authenticated(env.conn, loaded, NOW)
    for label in ("painel", "cli", "conta-3", None):
        with pytest.raises(ValueError):
            oauth.finish_consent(env.conn, env.config, loaded, label, None, frozenset(), NOW)


def test_consent_requires_login(env):
    _, challenge = pkce()
    req = oauth.validate_authorize(
        env.conn, env.config, claude_params(challenge), FakeFetcher(), NOW
    )
    tx = oauth.create_transaction(env.conn, env.keyring, req, None, NOW, 20)
    loaded = oauth.load_transaction(
        env.conn, env.config, env.keyring, tx.tx_id, tx.browser, tx.csrf, NOW, check_csrf=True
    )
    with pytest.raises(oauth.TransactionError):
        oauth.finish_consent(env.conn, env.config, loaded, "conta-1", None, frozenset(), NOW)


def test_expired_grants_revoked_before_new(env):
    t1 = claude_tokens(env, "conta-1")
    later = NOW + oauth.CLAUDE_GRANT_TTL + 1
    claude_tokens(env, "conta-1", now=later)  # sem pergunta: o antigo venceu e foi revogado
    rows = env.conn.execute("SELECT revoked_at FROM oauth_grants ORDER BY id").fetchall()
    assert rows[0][0] == later and rows[1][0] is None
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, t1.access_token, ORIGIN + "/mcp", "memoria", NOW)


def test_painel_grant_replaces_previous(env):
    tokens = []
    for i in range(2):
        verifier, challenge = pkce()
        code, query = make_code(env, painel_params(challenge), label=None, now=NOW + i)
        assert query["state"] == ["s-painel"] and query["iss"] == [ORIGIN]
        tokens.append(
            exchange(
                env,
                code,
                verifier,
                NOW + i,
                client_id="painel-vercel",
                redirect_uri=PAINEL_CALLBACK,
                resource=ORIGIN + "/api/painel",
            )
        )
    first, second = tokens
    assert second.refresh_token is None and second.expires_in == 15 * 60
    assert second.to_json() == {
        "access_token": second.access_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "scope": "painel",
    }
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, first.access_token, ORIGIN + "/api/painel", "painel", NOW)
    ctx = oauth.validate_bearer(
        env.conn, second.access_token, ORIGIN + "/api/painel", "painel", NOW
    )
    assert ctx.label == "painel"
    # Token do painel não vale no /mcp, nem com scope memoria.
    with pytest.raises(oauth.BearerError) as caught:
        oauth.validate_bearer(env.conn, second.access_token, ORIGIN + "/mcp", "memoria", NOW)
    assert caught.value.status == 401
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, second.access_token, ORIGIN + "/mcp", "painel", NOW)
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(
            env.conn, second.access_token, ORIGIN + "/api/painel", "painel", NOW + 901
        )


# ---------------------------------------------------------------------------
# Token (§4.3)
# ---------------------------------------------------------------------------


def test_code_exchange_happy(env):
    verifier, challenge = pkce()
    code, query = make_code(env, claude_params(challenge))
    assert query["state"] == ["estado-123"] and query["iss"] == [ORIGIN]
    tokens = exchange(env, code, verifier)
    body = tokens.to_json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 3600
    assert body["scope"] == "memoria offline_access"
    assert body["access_token"].startswith("bsw_at_")
    assert body["refresh_token"].startswith("bsw_rt_")
    assert tokens.access_token not in repr(tokens) and tokens.refresh_token not in repr(tokens)
    stored = {r[0] for r in env.conn.execute("SELECT token_hash FROM oauth_tokens")}
    assert stored == {token_hash(tokens.access_token), token_hash(tokens.refresh_token)}
    assert (
        env.conn.execute(
            "SELECT count(*) FROM oauth_codes WHERE code_hash=?", (token_hash(code),)
        ).fetchone()[0]
        == 1
    )


@pytest.mark.parametrize(
    "changes, error",
    [
        ({"code_verifier": "x" * 43}, "invalid_grant"),
        ({"code_verifier": "curto"}, "invalid_grant"),
        ({"code_verifier": None}, "invalid_request"),
        ({"redirect_uri": "https://claude.ai/outro"}, "invalid_grant"),
        ({"redirect_uri": None}, "invalid_request"),
        ({"resource": None}, "invalid_target"),
        ({"resource": ORIGIN + "/api/painel"}, "invalid_target"),
        ({"client_id": "https://evil.example/x"}, "invalid_client"),
        ({"client_id": "painel-vercel", "resource": ORIGIN + "/api/painel"}, "invalid_grant"),
        ({"client_id": None}, "invalid_request"),
        ({"code": "codigo-inexistente-com-tamanho-ok"}, "invalid_grant"),
        ({"code": "ç"}, "invalid_grant"),
        ({"grant_type": "password"}, "unsupported_grant_type"),
        ({"grant_type": None}, "invalid_request"),
    ],
)
def test_code_exchange_errors(env, changes, error):
    verifier, challenge = pkce()
    code, _ = make_code(env, claude_params(challenge))
    with pytest.raises(oauth.OAuthError) as caught:
        exchange(env, code, verifier, **changes)
    assert caught.value.error == error
    assert caught.value.description.isascii()
    assert code not in str(caught.value) and code not in caught.value.description
    # O código continua usável depois de um erro de validação.
    assert exchange(env, code, verifier).access_token


def test_code_expired(env):
    verifier, challenge = pkce()
    code, _ = make_code(env, claude_params(challenge))
    with pytest.raises(oauth.OAuthError) as caught:
        exchange(env, code, verifier, now=NOW + oauth.CODE_TTL)
    assert caught.value.error == "invalid_grant"


def test_code_reuse_revokes(env):
    verifier, challenge = pkce()
    code, _ = make_code(env, claude_params(challenge))
    tokens = exchange(env, code, verifier)
    with pytest.raises(oauth.OAuthError) as caught:
        exchange(env, code, verifier, now=NOW + 5)
    assert caught.value.error == "invalid_grant"
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW + 6)
    with pytest.raises(oauth.OAuthError):
        refresh(env, tokens.refresh_token, NOW + 6)
    events = [r[0] for r in env.conn.execute("SELECT event FROM audit ORDER BY id")]
    assert "codigo_reuso" in events and "grant_revogado" in events


def test_code_concurrent_exchange_single_winner(env):
    verifier, challenge = pkce()
    code, _ = make_code(env, claude_params(challenge))
    barrier = threading.Barrier(4)
    results = []

    def worker():
        conn = env.connect()
        try:
            barrier.wait()
            try:
                oauth.token_request(
                    conn,
                    env.config,
                    {
                        "grant_type": ["authorization_code"],
                        "code": [code],
                        "code_verifier": [verifier],
                        "client_id": [CLAUDE_CIMD_CLIENT_ID],
                        "redirect_uri": [CLAUDE_REDIRECT_URI],
                        "resource": [ORIGIN + "/mcp"],
                    },
                    NOW,
                )
                results.append("ok")
            except oauth.OAuthError as error:
                results.append(error.error)
        finally:
            conn.close()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1 and results.count("invalid_grant") == 3


def test_refresh_rotation_inherit_and_subset(env):
    tokens = claude_tokens(env)
    second = refresh(env, tokens.refresh_token, NOW + 100)
    assert second.scope == "memoria offline_access"
    assert second.refresh_token != tokens.refresh_token
    family = env.conn.execute("SELECT count(DISTINCT family_id) FROM oauth_tokens").fetchone()[0]
    assert family == 1
    third = refresh(env, second.refresh_token, NOW + 200, scope="memoria", resource=ORIGIN + "/mcp")
    assert third.scope == "memoria"
    ctx = oauth.validate_bearer(env.conn, third.access_token, ORIGIN + "/mcp", "memoria", NOW + 200)
    assert ctx.label == "conta-1"
    # O access antigo continua até vencer (não é revogado na rotação).
    assert oauth.validate_bearer(
        env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW + 200
    )


@pytest.mark.parametrize(
    "changes, error",
    [
        ({"scope": "memoria painel"}, "invalid_scope"),
        ({"scope": "offline_access"}, "invalid_scope"),
        ({"scope": "memoria  offline_access"}, "invalid_scope"),
        ({"resource": ORIGIN + "/api/painel"}, "invalid_target"),
        ({"resource": "https://evil.example/mcp"}, "invalid_target"),
        ({"client_id": "painel-vercel"}, "unauthorized_client"),
        ({"client_id": "https://evil.example/x"}, "invalid_client"),
        ({"refresh_token": None}, "invalid_request"),
    ],
)
def test_refresh_matrix_errors(env, changes, error):
    tokens = claude_tokens(env)
    with pytest.raises(oauth.OAuthError) as caught:
        refresh(env, tokens.refresh_token, NOW + 10, **changes)
    assert caught.value.error == error
    # Erro de validação não queima o refresh.
    assert refresh(env, tokens.refresh_token, NOW + 20).access_token


def test_refresh_scope_narrower_than_grant(env):
    verifier, challenge = pkce()
    code, _ = make_code(env, claude_params(challenge, scope="memoria"))
    tokens = exchange(env, code, verifier)
    assert tokens.scope == "memoria" and tokens.refresh_token
    with pytest.raises(oauth.OAuthError) as caught:
        refresh(env, tokens.refresh_token, NOW + 10, scope="memoria offline_access")
    assert caught.value.error == "invalid_scope"


def test_refresh_reuse_revokes_family(env):
    tokens = claude_tokens(env)
    second = refresh(env, tokens.refresh_token, NOW + 100)
    with pytest.raises(oauth.OAuthError) as caught:
        refresh(env, tokens.refresh_token, NOW + 200)
    assert caught.value.error == "invalid_grant"
    for token in (second.access_token, tokens.access_token):
        with pytest.raises(oauth.BearerError):
            oauth.validate_bearer(env.conn, token, ORIGIN + "/mcp", "memoria", NOW + 201)
    with pytest.raises(oauth.OAuthError):
        refresh(env, second.refresh_token, NOW + 202)
    assert env.conn.execute("SELECT revoked_at FROM oauth_grants").fetchone()[0] == NOW + 200
    events = [r[0] for r in env.conn.execute("SELECT event FROM audit ORDER BY id")]
    assert "refresh_reuso" in events


def test_refresh_concurrent_single_winner(env):
    tokens = claude_tokens(env)
    barrier = threading.Barrier(3)
    results = []

    def worker():
        conn = env.connect()
        try:
            barrier.wait()
            try:
                oauth.token_request(
                    conn,
                    env.config,
                    {
                        "grant_type": ["refresh_token"],
                        "refresh_token": [tokens.refresh_token],
                        "client_id": [CLAUDE_CIMD_CLIENT_ID],
                    },
                    NOW + 50,
                )
                results.append("ok")
            except oauth.OAuthError as error:
                results.append(error.error)
        finally:
            conn.close()

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1
    # Os outros viram reuso: a família inteira cai (inclusive o par do vencedor).
    assert (
        env.conn.execute("SELECT count(*) FROM oauth_tokens WHERE revoked_at IS NULL").fetchone()[0]
        == 0
    )


def test_refresh_expiry_and_ceiling(env):
    tokens = claude_tokens(env)
    with pytest.raises(oauth.OAuthError):
        refresh(env, tokens.refresh_token, NOW + oauth.REFRESH_TTL)
    tokens = claude_tokens(env, "conta-2")
    current = tokens
    now = NOW
    while now + 29 * DAY < NOW + oauth.CLAUDE_GRANT_TTL:
        now += 29 * DAY
        current = refresh(env, current.refresh_token, now)
    assert current.expires_in <= 3600
    # Refresh emitido perto do teto vence junto com o grant.
    ceiling = NOW + oauth.CLAUDE_GRANT_TTL
    expires = env.conn.execute(
        "SELECT max(expires_at) FROM oauth_tokens WHERE kind='refresh' AND used_at IS NULL "
        "AND revoked_at IS NULL"
    ).fetchone()[0]
    assert expires == ceiling
    with pytest.raises(oauth.OAuthError) as caught:
        refresh(env, current.refresh_token, ceiling)
    assert caught.value.error == "invalid_grant"


def test_access_capped_by_grant(env):
    tokens = claude_tokens(env)
    near = NOW + oauth.CLAUDE_GRANT_TTL - 600
    current = tokens
    now = NOW
    while now + 29 * DAY < near:
        now += 29 * DAY
        current = refresh(env, current.refresh_token, now)
    last = refresh(env, current.refresh_token, near)
    assert last.expires_in == 600


# ---------------------------------------------------------------------------
# Revogação e RS
# ---------------------------------------------------------------------------


def revoke(env, token, now=NOW, **extra):
    params = {"token": [token], **{k: [v] for k, v in extra.items()}}
    oauth.revoke_token(env.conn, env.config, params, now)


def test_revoke_access_and_refresh(env):
    tokens = claude_tokens(env)
    revoke(env, "token-desconhecido-qualquer-coisa")
    revoke(env, tokens.access_token, client_id="painel-vercel")  # outro cliente: nada
    assert oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW)
    revoke(env, tokens.access_token)
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW)
    second = refresh(env, tokens.refresh_token, NOW + 1)
    revoke(env, second.refresh_token, client_id=CLAUDE_CIMD_CLIENT_ID)
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, second.access_token, ORIGIN + "/mcp", "memoria", NOW + 2)
    with pytest.raises(oauth.OAuthError):
        refresh(env, second.refresh_token, NOW + 3)
    assert env.conn.execute("SELECT revoked_at FROM oauth_grants").fetchone()[0] == NOW
    oauth.revoke_token(env.conn, env.config, {}, NOW)
    oauth.revoke_token(env.conn, env.config, {"token": ["a", "b"]}, NOW)


def test_revoke_grant_helper(env):
    tokens = claude_tokens(env)
    ctx = oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW)
    assert oauth.revoke_grant(env.conn, ctx.grant_public_id, NOW + 1)
    assert not oauth.revoke_grant(env.conn, ctx.grant_public_id, NOW + 2)
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW + 3)


def test_bearer_errors_and_last_used(env):
    tokens = claude_tokens(env)
    for bad in (None, "", "x" * 600, tokens.refresh_token, "bsw_at_" + "A" * 43, 12):
        with pytest.raises(oauth.BearerError) as caught:
            oauth.validate_bearer(env.conn, bad, ORIGIN + "/mcp", "memoria", NOW)
        assert caught.value.status == 401 and caught.value.error == "invalid_token"
        assert caught.value.www_authenticate == (
            'Bearer error="invalid_token", resource_metadata="'
            + ORIGIN
            + '/.well-known/oauth-protected-resource/mcp"'
        )
    with pytest.raises(oauth.BearerError):
        oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW + 3600)
    # Token do Claude no recurso do painel: 401 (audiência errada).
    with pytest.raises(oauth.BearerError) as caught:
        oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/api/painel", "painel", NOW)
    assert caught.value.status == 401
    # Scope insuficiente: 403.
    with pytest.raises(oauth.BearerError) as caught:
        oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "admin", NOW)
    assert caught.value.status == 403 and caught.value.error == "insufficient_scope"
    assert 'scope="admin"' in caught.value.www_authenticate
    assert tokens.access_token not in str(caught.value)

    def last_used():
        return env.conn.execute("SELECT last_used_at FROM oauth_grants").fetchone()[0]

    assert last_used() is None
    oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW + 10)
    assert last_used() == NOW + 10
    oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW + 69)
    assert last_used() == NOW + 10
    oauth.validate_bearer(env.conn, tokens.access_token, ORIGIN + "/mcp", "memoria", NOW + 70)
    assert last_used() == NOW + 70


def test_cleanup_expired(env):
    tokens = claude_tokens(env)
    second = refresh(env, tokens.refresh_token, NOW + 100)
    _, challenge = pkce()
    req = oauth.validate_authorize(
        env.conn, env.config, claude_params(challenge), FakeFetcher(), NOW
    )
    oauth.create_transaction(env.conn, env.keyring, req, None, NOW, 20)
    counts = oauth.cleanup_expired(env.conn, NOW + 3601)
    assert counts["transacoes"] == 1 and counts["codigos"] == 1 and counts["access"] == 1
    # O refresh usado fica: a família ainda tem refresh no prazo.
    assert counts["refresh"] == 0
    with pytest.raises(oauth.OAuthError):
        refresh(env, tokens.refresh_token, NOW + 4000)  # reuso ainda é detectado
    counts = oauth.cleanup_expired(env.conn, NOW + 100 + oauth.REFRESH_TTL)
    assert counts["refresh"] == 2 and counts["access"] == 1
    assert env.conn.execute("SELECT count(*) FROM oauth_tokens").fetchone()[0] == 0
    assert second.refresh_token


def test_audit_has_no_secrets(env):
    tokens = claude_tokens(env)
    refresh(env, tokens.refresh_token, NOW + 1)
    rows = env.conn.execute("SELECT event, grant_id, target FROM audit").fetchall()
    assert {r[0] for r in rows} <= oauth.AUDIT_EVENTS
    for _, _, target in rows:
        assert target is None or target.startswith("grant_")
