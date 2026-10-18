"""API do painel da Vercel (§12): conexões, atividade e revogação.

Só números e rótulos: nada de conteúdo, nome de projeto ou segredo sai daqui, e nada é decifrado.
Todas as rotas exigem Bearer com recurso ``<api>/api/painel`` e scope ``painel``.
"""

import json
import re
import time

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from batataswap import memory
from batataswap.auth import oauth
from batataswap.auth.owner import verify_totp_only
from batataswap.auth.routes import OAuthDeps, _db, bearer_context, bearer_error_response

_NO_STORE = {"cache-control": "no-store"}
_TOTP = re.compile(r"[0-9]{6}")


def _json(data: dict, status: int = 200, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers={**_NO_STORE, **(headers or {})})


def _iso_or_none(ts: int | None) -> str | None:
    return None if ts is None else memory.iso(ts)


def _connections(conn, deps: OAuthDeps, now: int) -> dict:
    """Um cartão por rótulo: o grant ativo, ou o mais recente se não houver ativo."""
    rows = conn.execute(
        "SELECT label, created_at, last_used_at, revoked_at, expires_at FROM oauth_grants "
        "WHERE resource = ? ORDER BY created_at DESC, id DESC",
        (deps.config.mcp_resource,),
    ).fetchall()
    chosen: dict[str, tuple] = {}
    for row in rows:
        active = row[3] is None and row[4] > now
        best = chosen.get(row[0])
        if best is None or (active and not best[1]):
            chosen[row[0]] = (row, active)
    items = []
    for label in sorted(chosen):
        row, active = chosen[label]
        items.append(
            {
                "rotulo": label,
                "ativo": active,
                "conectado_desde": memory.iso(row[1]),
                "ultimo_uso": _iso_or_none(row[2]),
            }
        )
    return {"conexoes": items}


def _scalar(conn, sql: str, params: tuple = ()) -> int:
    return conn.execute(sql, params).fetchone()[0]


def _activity(conn, deps: OAuthDeps, now: int) -> dict:
    limits = deps.config.limits
    per_account = []
    for label in deps.config.account_labels:
        live = "purged_at IS NULL AND trashed_at IS NULL"
        contexts = _scalar(
            conn, f"SELECT COUNT(*) FROM contexts WHERE source_label = ? AND {live}", (label,)
        )
        prefs = _scalar(
            conn, f"SELECT COUNT(*) FROM preferences WHERE source_label = ? AND {live}", (label,)
        )
        messages = _scalar(
            conn,
            "SELECT COUNT(*) FROM messages m JOIN message_batches b ON b.id = m.batch_id "
            "JOIN oauth_grants g ON g.id = b.grant_id "
            "WHERE g.label = ? AND m.purged_at IS NULL AND m.trashed_at IS NULL",
            (label,),
        )
        last = conn.execute(
            "SELECT MAX(t) FROM ("
            " SELECT MAX(created_at) AS t FROM contexts WHERE source_label = ?"
            " UNION ALL SELECT MAX(created_at) FROM preferences WHERE source_label = ?"
            " UNION ALL SELECT MAX(b.created_at) FROM message_batches b"
            "  JOIN oauth_grants g ON g.id = b.grant_id WHERE g.label = ?)",
            (label, label, label),
        ).fetchone()[0]
        per_account.append(
            {
                "rotulo": label,
                "contextos": contexts,
                "mensagens": messages,
                "preferencias": prefs,
                "ultima_escrita": _iso_or_none(last),
            }
        )
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    usage = conn.execute("SELECT writes, bytes FROM daily_usage WHERE day = ?", (day,)).fetchone()
    writes, written = usage if usage else (0, 0)
    return {
        "por_conta": per_account,
        "limites": {
            "escritas_hoje": writes,
            "escritas_max": limits.daily_writes,
            "bytes_hoje": written,
            "bytes_max": limits.daily_bytes,
            "total_bytes": memory.stored_bytes(conn),
            "total_max": limits.stored_bytes,
        },
    }


def _revoke(conn, deps: OAuthDeps, label: str, code: str, now: float):
    """Confere o TOTP (mesmo orçamento e consumo atômico do login) e revoga o grant ativo."""
    result = verify_totp_only(conn, deps.keyring, deps.budget, code, None, now)
    if not result.ok:
        return result.status, result.retry_after
    row = conn.execute(
        "SELECT public_id FROM oauth_grants WHERE label = ? AND resource = ? "
        "AND revoked_at IS NULL AND expires_at > ?",
        (label, deps.config.mcp_resource, int(now)),
    ).fetchone()
    if row is None or not oauth.revoke_grant(conn, row[0], now):
        return "sem_grant", 0
    return "ok", 0


def _parse_revoke(raw: bytes, content_type: str) -> tuple[str, str] | None:
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        return None
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if not isinstance(data, dict) or set(data) != {"rotulo", "totp"}:
        return None
    label, code = data["rotulo"], data["totp"]
    if not isinstance(label, str) or not isinstance(code, str):
        return None
    if not 1 <= len(label) <= 64 or not _TOTP.fullmatch(code):
        return None
    return label, code


def panel_routes(deps: OAuthDeps) -> list[Route]:
    async def authorized(request: Request):
        try:
            await bearer_context(deps, request.scope, "painel")
        except oauth.BearerError as error:
            return bearer_error_response(error)
        return None

    async def conexoes(request: Request) -> Response:
        if (denied := await authorized(request)) is not None:
            return denied
        now = int(deps.clock())
        return _json(await _db(deps, _connections, deps, now))

    async def atividade(request: Request) -> Response:
        if (denied := await authorized(request)) is not None:
            return denied
        now = int(deps.clock())
        return _json(await _db(deps, _activity, deps, now))

    async def revogar(request: Request) -> Response:
        if (denied := await authorized(request)) is not None:
            return denied
        parsed = _parse_revoke(await request.body(), request.headers.get("content-type", ""))
        if parsed is None:
            return _json({"erro": "pedido inválido"}, 400)
        label, code = parsed
        status, retry = await _db(deps, _revoke, deps, label, code, deps.clock())
        if status == "ok":
            return Response(status_code=204, headers=_NO_STORE)
        if status == "trancado":
            return _json({"erro": "muitas tentativas"}, 429, {"retry-after": str(max(1, retry))})
        if status == "sem_grant":
            return _json({"erro": "conexão não encontrada"}, 404)
        return _json({"erro": "código inválido"}, 403)

    return [
        Route("/api/painel/conexoes", conexoes, methods=["GET"]),
        Route("/api/painel/atividade", atividade, methods=["GET"]),
        Route("/api/painel/revogar", revogar, methods=["POST"]),
    ]
