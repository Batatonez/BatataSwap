"""Borda HTTP: middleware ASGI que nega por padrão e fica na frente de tudo (§8).

A borda não valida token (isso é do RS, T08). Ela decide, por rota, que credencial é
exigida e recusa cedo o que nem tem a forma certa. Ordem das checagens:

0. limpa o escopo (headers de proxy, client, scheme) e recusa Host duplicado;
1. Host exato do ``public_origin``;
   (caminho estranho → 400, rota inexistente → 404, método fora da rota → 405)
2. CORS/preflight, antes de qualquer credencial;
3. Origin em métodos que mudam estado;
4. presença e forma da credencial (Bearer ou cookie);
5. corpo contado em streaming;
6. headers de segurança em toda resposta, inclusive nos erros da própria borda.

O uvicorn precisa rodar com ``server_header=False``, ``proxy_headers=False`` e
``forwarded_allow_ips=""``: o header ``Server`` é escrito pelo próprio uvicorn, fora do ASGI,
e a borda só consegue remover o que o app mandar.

Nada aqui loga. Quem quiser registrar eventos passa ``on_event(evento, status)``; os nomes
de evento são fixos (``EVENTS``) e nunca carregam valor vindo da requisição.
"""

import asyncio
import contextlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from starlette.routing import Route

from batataswap.config import Config

CATEGORIES = frozenset({"public", "form", "bearer:mcp", "bearer:painel", "cookie"})
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CORS_METHODS = ("GET", "POST")
CORS_HEADERS = frozenset({"authorization", "content-type"})
OTHER_BODY_BYTES = 16 * 1024
SESSION_COOKIE = "__Host-bsw_sess"

EVENTS = frozenset(
    {
        "websocket_recusado",
        "corpo_timeout",
        "host_duplicado",
        "host_invalido",
        "caminho_invalido",
        "token_na_query",
        "rota_inexistente",
        "metodo_nao_permitido",
        "preflight_aceito",
        "preflight_recusado",
        "origem_recusada",
        "credencial_ausente",
        "requisicao_invalida",
        "corpo_grande",
        "erro_interno",
        "repassado",
    }
)

_PROXY_HEADERS = frozenset(
    {
        b"forwarded",
        b"x-real-ip",
        b"true-client-ip",
        b"x-client-ip",
        b"client-ip",
        b"x-cluster-client-ip",
        b"fastly-client-ip",
        b"x-original-forwarded-for",
    }
)
_PROXY_PREFIXES = (b"x-forwarded-", b"cf-")
_MANAGED_HEADERS = frozenset(
    {
        b"server",
        b"x-powered-by",
        b"x-content-type-options",
        b"referrer-policy",
        b"x-frame-options",
        b"strict-transport-security",
        b"content-security-policy",
        b"content-security-policy-report-only",
    }
)
_SEGMENT = r"[A-Za-z0-9._~-]+"
_PREFIX_REST = re.compile(rf"{_SEGMENT}(?:/{_SEGMENT})*")
_BEARER = re.compile(r"(?i:bearer) ([A-Za-z0-9._~+/=-]{20,512})")
_CONTENT_LENGTH = re.compile(r"[0-9]{1,19}")
_API_CSP = "default-src 'none'; frame-ancestors 'none'"


@dataclass(frozen=True)
class RouteRule:
    """Uma linha da política: método, caminho e a credencial que a borda exige.

    ``path`` é exato, ou termina em ``/*`` para casar um ou mais segmentos depois do prefixo.
    ``GET`` também cobre ``HEAD`` (como no Starlette). ``cors`` diz se a rota responde CORS
    para a origem da Vercel. ``static`` mantém o ``Cache-Control`` que o app mandar.
    """

    method: str
    path: str
    category: str
    cors: bool = False
    static: bool = False

    def __post_init__(self):
        if self.method not in METHODS:
            raise ValueError("RouteRule.method: método não suportado.")
        if self.category not in CATEGORIES:
            raise ValueError("RouteRule.category: categoria desconhecida.")
        base = self.path.removesuffix("/*")
        if (
            not self.path.startswith("/")
            or not re.fullmatch(rf"(/{_SEGMENT})*", base)
            or any(seg in (".", "..") for seg in base.split("/"))
        ):
            raise ValueError("RouteRule.path: caminho inválido.")

    def matches_path(self, path: str) -> bool:
        if self.path.endswith("/*"):
            prefix = self.path[:-1]
            return path.startswith(prefix) and bool(_PREFIX_REST.fullmatch(path[len(prefix) :]))
        return path == self.path

    def matches_method(self, method: str) -> bool:
        return method == self.method or (method == "HEAD" and self.method == "GET")


class RoutePolicy:
    """Lista ordenada de regras. Vale a primeira regra que casa caminho e método."""

    def __init__(self, rules: Iterable[RouteRule]):
        self.rules = tuple(rules)
        if not self.rules or any(not isinstance(r, RouteRule) for r in self.rules):
            raise ValueError("RoutePolicy: lista de regras inválida.")

    def for_path(self, path: str) -> tuple[RouteRule, ...]:
        return tuple(r for r in self.rules if r.matches_path(path))

    def check_against(self, routes: Iterable[object]) -> None:
        """Confere a política contra as rotas do Starlette, na montagem do app.

        Falha (``ValueError``) se uma rota do Starlette não tiver regra para algum método,
        se uma regra não tiver rota que a atenda, se uma regra ficar inalcançável por causa de
        uma anterior, ou se aparecer ``Mount``/websocket/outro tipo de rota (a borda não sabe
        decidir por eles). ``HEAD`` vem junto com ``GET`` dos dois lados; ``OPTIONS`` é da borda.
        """
        problems: list[str] = []
        served: list[tuple[str, object, frozenset[str] | None]] = []
        for route in routes:
            if not isinstance(route, Route):
                problems.append(f"tipo de rota não suportado: {type(route).__name__}")
                continue
            sample = re.sub(r"\{[^}]*\}", "x", route.path)
            methods = None if route.methods is None else frozenset(route.methods)
            served.append((sample, route, methods))
            if methods is None:
                if not self.for_path(sample):
                    problems.append(f"rota sem regra: {route.path}")
                continue
            for method in sorted(methods - {"HEAD", "OPTIONS"}):
                if not any(r.matches_path(sample) and r.method == method for r in self.rules):
                    problems.append(f"rota sem regra: {method} {route.path}")
        for i, rule in enumerate(self.rules):
            prefix = rule.path.endswith("/*")
            probe = rule.path[:-1] + "x" if prefix else rule.path
            if any(
                r.method == rule.method
                and r.matches_path(probe)
                and (not prefix or r.path.endswith("/*"))
                for r in self.rules[:i]
            ):
                problems.append(f"regra inalcançável: {rule.method} {rule.path}")
            if not any(
                (
                    rule.matches_path(sample)
                    or (probe == rule.path and route.path_regex.match(probe))
                )
                and (methods is None or rule.method in methods)
                for sample, route, methods in served
            ):
                problems.append(f"regra sem rota: {rule.method} {rule.path}")
        if problems:
            raise ValueError("Política da borda diverge do roteador: " + "; ".join(problems))

    @classmethod
    def default(cls) -> "RoutePolicy":
        """Tabela de rotas do §3 da arquitetura."""
        wk = "/.well-known/"
        return cls(
            [
                RouteRule("GET", wk + "oauth-protected-resource/mcp", "public"),
                RouteRule("GET", wk + "oauth-protected-resource", "public"),
                RouteRule("GET", wk + "oauth-protected-resource/api/painel", "public"),
                RouteRule("GET", wk + "oauth-authorization-server", "public"),
                RouteRule("GET", "/oauth/authorize", "public"),
                RouteRule("POST", "/oauth/login", "form"),
                # Página de consentimento: a transação presa ao navegador é conferida na T08.
                RouteRule("GET", "/oauth/consent", "public"),
                RouteRule("POST", "/oauth/consent", "form"),
                RouteRule("POST", "/oauth/token", "public", cors=True),
                RouteRule("POST", "/oauth/revoke", "public"),
                RouteRule("POST", "/mcp", "bearer:mcp"),
                RouteRule("GET", "/api/painel/*", "bearer:painel", cors=True),
                RouteRule("POST", "/api/painel/*", "bearer:painel", cors=True),
                RouteRule("GET", "/painel/*", "cookie"),
                RouteRule("POST", "/painel/*", "form"),
                RouteRule("GET", "/saude", "public", cors=True),
                RouteRule("GET", "/static/*", "public", static=True),
            ]
        )


def _json(message: str) -> bytes:
    return json.dumps({"erro": message}, ensure_ascii=False).encode()


_ERRORS = {
    400: _json("Requisição inválida."),
    401: _json("Credencial ausente ou inválida."),
    403: _json("Acesso negado."),
    404: _json("Não encontrado."),
    405: _json("Método não permitido."),
    408: _json("Prazo de leitura do corpo excedido."),
    413: _json("Corpo da requisição grande demais."),
    421: _json("Host não reconhecido."),
    500: _json("Erro interno."),
}


class EdgeMiddleware:
    def __init__(
        self,
        app,
        *,
        config: Config,
        routes: RoutePolicy,
        on_event: Callable[[str, int], None] | None = None,
        body_total_timeout: float = 10,
        body_idle_timeout: float = 5,
    ):
        if not isinstance(config, Config) or not isinstance(routes, RoutePolicy):
            raise TypeError("EdgeMiddleware: config e routes são obrigatórios.")
        self.app = app
        self.body_total_timeout = body_total_timeout
        self.body_idle_timeout = body_idle_timeout
        self.config = config
        self.routes = routes
        self.on_event = on_event
        self._hosts = {config.authority}
        if urlsplit(config.public_origin).port is None:
            self._hosts.add(config.authority + ":443")
        self._vercel = config.vercel_origin
        self._mcp_origins = frozenset(config.allowed_mcp_origins)
        form_action = " ".join(
            ["'self'", "https://claude.ai"] + ([self._vercel] if self._vercel else [])
        )
        self._page_csp = (
            "default-src 'none'; style-src 'self'; script-src 'self'; "
            f"form-action {form_action}; frame-ancestors 'none'"
        ).encode()
        self._www_auth = {
            "bearer:mcp": (
                f'Bearer resource_metadata="{config.public_origin}'
                '/.well-known/oauth-protected-resource/mcp"'
            ).encode(),
            "bearer:painel": (
                f'Bearer resource_metadata="{config.public_origin}'
                '/.well-known/oauth-protected-resource/api/painel"'
            ).encode(),
        }

    # -- utilitários -------------------------------------------------------------------------

    def _emit(self, event: str, status: int) -> None:
        if self.on_event is None:
            return
        with contextlib.suppress(Exception):  # o callback de log nunca derruba a requisição
            self.on_event(event, status)

    def _finalize(
        self,
        app_headers: Iterable[tuple[bytes, bytes]],
        *,
        static: bool = False,
        cors: bool = False,
        cors_origin: str | None = None,
        extra: Iterable[tuple[bytes, bytes]] = (),
    ) -> list[tuple[bytes, bytes]]:
        """Filtra os headers do app e acrescenta os da borda (a borda manda)."""
        out: list[tuple[bytes, bytes]] = []
        content_type = b""
        for name, value in app_headers:
            lname = name.lower()
            if lname == b"content-type":
                content_type = value
            if (
                lname in _MANAGED_HEADERS
                or lname.startswith(b"access-control-")
                or (lname == b"cache-control" and not static)
            ):
                continue
            out.append((name, value))
        out.extend(extra)
        is_html = content_type.split(b";", 1)[0].strip().lower() == b"text/html"
        out += [
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"same-origin" if is_html else b"no-referrer"),
            (b"x-frame-options", b"DENY"),
            (b"strict-transport-security", b"max-age=31536000"),
            (b"content-security-policy", self._page_csp if is_html else _API_CSP.encode()),
        ]
        if not static:
            out.append((b"cache-control", b"no-store"))
        if cors:
            if cors_origin is not None:
                out.append((b"access-control-allow-origin", cors_origin.encode()))
            out.append((b"vary", b"Origin"))
        return out

    async def _send_error(
        self,
        send,
        status: int,
        event: str,
        *,
        cors: bool = False,
        cors_origin: str | None = None,
        extra: Iterable[tuple[bytes, bytes]] = (),
    ) -> None:
        self._emit(event, status)
        body = _ERRORS[status]
        headers = self._finalize(
            [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
            ],
            cors=cors,
            cors_origin=cors_origin,
            extra=extra,
        )
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    # -- ASGI --------------------------------------------------------------------------------

    async def __call__(self, scope, receive, send):
        kind = scope.get("type")
        if kind == "lifespan":
            await self.app(scope, receive, send)
        elif kind == "websocket":
            await self._refuse_websocket(scope, receive, send)
        elif kind == "http":
            await self._http(scope, receive, send)

    async def _refuse_websocket(self, scope, receive, send):
        self._emit("websocket_recusado", 404)
        await receive()
        if "websocket.http.response" in (scope.get("extensions") or {}):
            body = _ERRORS[404]
            headers = self._finalize(
                [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ]
            )
            await send({"type": "websocket.http.response.start", "status": 404, "headers": headers})
            await send({"type": "websocket.http.response.body", "body": body})
        else:
            await send({"type": "websocket.close", "code": 1008})

    async def _http(self, scope, receive, send):
        # 0. Limpa o escopo. Nada depois disso enxerga IP, proxy ou esquema vindo de fora.
        headers = [
            (n.lower(), v)
            for n, v in scope.get("headers", [])
            if n.lower() not in _PROXY_HEADERS and not n.lower().startswith(_PROXY_PREFIXES)
        ]
        state = dict(scope.get("state") or {})
        state.pop("bearer", None)
        scope = {
            **scope,
            "headers": headers,
            "client": None,
            "scheme": "https",
            "state": state,
        }

        def values(name: bytes) -> list[bytes]:
            return [v for n, v in headers if n == name]

        hosts = values(b"host")
        if len(hosts) > 1:
            return await self._send_error(send, 400, "host_duplicado")

        # 1. Host exato.
        if not hosts or hosts[0].decode("latin-1") not in self._hosts:
            return await self._send_error(send, 421, "host_invalido")

        path = self._clean_path(scope)
        if path is None:
            return await self._send_error(send, 400, "caminho_invalido")
        if self._query_has_token(scope.get("query_string", b"")):
            return await self._send_error(send, 400, "token_na_query")

        rules = self.routes.for_path(path)
        if not rules:
            return await self._send_error(send, 404, "rota_inexistente")
        method = scope.get("method", "")
        cors_rules = [r for r in rules if r.cors]
        cors = bool(cors_rules)

        origins = values(b"origin")
        origin = origins[0].decode("latin-1") if len(origins) == 1 else None
        cors_origin = (
            origin if cors and self._vercel is not None and origin == self._vercel else None
        )

        # 2. CORS/preflight, antes de qualquer credencial.
        if method == "OPTIONS":
            return await self._preflight(send, cors_rules, origins, values)

        rule = next((r for r in rules if r.matches_method(method)), None)
        if rule is None:
            allowed = {r.method for r in rules} | (
                {"HEAD"} if any(r.method == "GET" for r in rules) else set()
            )
            if cors:
                allowed.add("OPTIONS")
            return await self._send_error(
                send,
                405,
                "metodo_nao_permitido",
                cors=cors,
                cors_origin=cors_origin,
                extra=[(b"allow", ", ".join(sorted(allowed)).encode())],
            )
        cors = rule.cors
        if not cors:
            cors_origin = None

        # 3. Origin.
        if not self._origin_ok(rule, method, origins):
            return await self._send_error(send, 403, "origem_recusada")

        # 4. Credencial: só presença e forma. Quem valida o token é o RS (T08).
        if rule.category.startswith("bearer:"):
            auths = values(b"authorization")
            match = _BEARER.fullmatch(auths[0].decode("latin-1")) if len(auths) == 1 else None
            if match is None:
                return await self._send_error(
                    send,
                    401,
                    "credencial_ausente",
                    cors=cors,
                    cors_origin=cors_origin,
                    extra=[(b"www-authenticate", self._www_auth[rule.category])],
                )
            state["bearer"] = match.group(1)
        elif rule.category == "cookie" and not self._has_session_cookie(values(b"cookie")):
            return await self._send_error(
                send, 401, "credencial_ausente", cors=cors, cors_origin=cors_origin
            )

        # 5. Corpo.
        if rule.category == "bearer:mcp":
            limit = self.config.limits.mcp_body_bytes
        elif rule.category in ("bearer:painel", "cookie"):
            limit = OTHER_BODY_BYTES
        else:
            limit = self.config.limits.unauthenticated_mcp_body_bytes
        lengths = values(b"content-length")
        if len(lengths) > 1 or (
            lengths and not _CONTENT_LENGTH.fullmatch(lengths[0].decode("latin-1"))
        ):
            return await self._send_error(
                send, 400, "requisicao_invalida", cors=cors, cors_origin=cors_origin
            )
        if lengths and int(lengths[0]) > limit:
            return await self._send_error(
                send, 413, "corpo_grande", cors=cors, cors_origin=cors_origin
            )

        await self._forward(scope, receive, send, rule, limit, cors_origin)

    async def _forward(self, scope, receive, send, rule, limit, cors_origin):
        # O corpo inteiro é lido e contado ANTES de chamar o app: com corpo grande demais o
        # handler nem roda, então nenhum efeito dele acontece. Os tetos são pequenos (≤ 256 KiB).
        chunks: list[bytes] = []
        received = 0
        deadline = asyncio.get_running_loop().time() + self.body_total_timeout
        while True:
            try:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError
                async with asyncio.timeout(min(remaining, self.body_idle_timeout)):
                    message = await receive()
            except TimeoutError:
                return await self._send_error(
                    send,
                    408,
                    "corpo_timeout",
                    cors=rule.cors,
                    cors_origin=cors_origin,
                    extra=((b"connection", b"close"),),
                )
            if message.get("type") != "http.request":
                return  # cliente desconectou no meio do corpo: não há a quem responder
            body = message.get("body", b"")
            received += len(body)
            if received > limit:
                return await self._send_error(
                    send, 413, "corpo_grande", cors=rule.cors, cors_origin=cors_origin
                )
            chunks.append(body)
            if not message.get("more_body", False):
                break

        replayed = False
        started = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        async def guarded_send(message):
            nonlocal started
            if message.get("type") == "http.response.start":
                if started:
                    return
                started = True
                status = message.get("status", 500)
                message = {
                    **message,
                    "headers": self._finalize(
                        message.get("headers", []),
                        static=rule.static,
                        cors=rule.cors,
                        cors_origin=cors_origin,
                    ),
                }
                self._emit("repassado", status)
            elif not started:
                return
            await send(message)

        try:
            await self.app(scope, replay_receive, guarded_send)
        except Exception:  # noqa: BLE001 (toda exceção do app vira 500 genérico, sem detalhe)
            if started:
                self._emit("erro_interno", 500)
                # A resposta já começou: o status não muda mais. Relança uma exceção genérica,
                # sem a original encadeada, para o servidor abortar a conexão.
                raise RuntimeError("erro interno") from None
            started = True
            await self._send_error(
                send, 500, "erro_interno", cors=rule.cors, cors_origin=cors_origin
            )
            return
        if not started:
            await self._send_error(
                send, 500, "erro_interno", cors=rule.cors, cors_origin=cors_origin
            )

    # -- checagens ---------------------------------------------------------------------------

    @staticmethod
    def _clean_path(scope) -> str | None:
        """Devolve o caminho se ele for limpo; ``None`` → 400.

        Recusa percent-encoding de qualquer tipo (nenhuma rota precisa), barra invertida,
        ``//``, segmentos ``.``/``..``, bytes de controle e não-ASCII. Assim o caminho que a
        borda decide é byte a byte o mesmo que o roteador vai usar.
        """
        raw = scope.get("raw_path")
        if not isinstance(raw, bytes):
            raw = str(scope.get("path", "")).encode("utf-8", "surrogateescape")
        raw = raw.split(b"?", 1)[0]
        if (
            not re.fullmatch(rb"/[\x21-\x7e]*", raw)
            or b"%" in raw
            or b"\\" in raw
            or b"//" in raw
            or any(seg in (b".", b"..") for seg in raw.split(b"/"))
        ):
            return None
        path = raw.decode("ascii")
        if scope.get("path") != path:
            return None
        return path

    @staticmethod
    def _query_has_token(query: bytes) -> bool:
        try:
            pairs = parse_qsl(query.decode("latin-1"), keep_blank_values=True)
        except ValueError:
            return True
        return any(k.strip().lower() == "access_token" for k, _ in pairs)

    def _origin_ok(self, rule: RouteRule, method: str, origins: list[bytes]) -> bool:
        if len(origins) > 1:
            return False
        origin = origins[0].decode("latin-1") if origins else None
        if rule.category == "bearer:mcp":
            # A doc do Claude avisa: Origin estrito demais quebra. Ausente passa (§1.0).
            return origin is None or origin in self._mcp_origins
        if method not in STATE_CHANGING:
            return True
        if rule.category == "form":
            return origin == self.config.public_origin
        return origin is None or (self._vercel is not None and origin == self._vercel)

    @staticmethod
    def _has_session_cookie(cookies: list[bytes]) -> bool:
        for header in cookies:
            for part in header.decode("latin-1").split(";"):
                name, sep, value = part.strip().partition("=")
                if sep and name == SESSION_COOKIE and value:
                    return True
        return False

    async def _preflight(self, send, cors_rules, origins, values):
        if not cors_rules:
            return await self._send_error(send, 403, "preflight_recusado")
        methods = [m for m in CORS_METHODS if any(r.method == m for r in cors_rules)]
        req_methods = values(b"access-control-request-method")
        req_headers = b",".join(values(b"access-control-request-headers")).decode("latin-1")
        asked = {h.strip().lower() for h in req_headers.split(",") if h.strip()}
        if (
            self._vercel is None
            or len(origins) != 1
            or origins[0].decode("latin-1") != self._vercel
            or len(req_methods) != 1
            or req_methods[0].decode("latin-1") not in methods
            or not asked <= CORS_HEADERS
        ):
            return await self._send_error(send, 403, "preflight_recusado")
        self._emit("preflight_aceito", 204)
        headers = self._finalize(
            [],
            extra=[
                (b"access-control-allow-origin", self._vercel.encode()),
                (b"access-control-allow-methods", ", ".join(methods).encode()),
                (b"access-control-allow-headers", b"Authorization, Content-Type"),
                (b"access-control-max-age", b"600"),
                (b"vary", b"Origin"),
            ],
        )
        await send({"type": "http.response.start", "status": 204, "headers": headers})
        await send({"type": "http.response.body", "body": b""})
