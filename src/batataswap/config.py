"""Configuração local; origens são exatas e a porta HTTPS 443 explícita é recusada."""

import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import unquote, urlsplit

CLAUDE_CIMD_CLIENT_ID = "https://claude.ai/oauth/mcp-oauth-client-metadata"


class ConfigError(ValueError):
    """Configuração ausente ou inválida."""


def _https(value: object, *, name: str, origin: bool = True) -> str:
    try:
        if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError
        url = urlsplit(value)
        host = url.hostname
        port = url.port
        if not host or "%" in url.netloc:
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
            host = f"[{host}]" if address.version == 6 else host
        except ValueError:
            if not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*", host):
                raise ValueError
        canonical = f"https://{host}" + (f":{port}" if port else "")
        if port is not None and (not 1 <= port <= 65535 or port == 443):
            raise ValueError
        if origin:
            if value != canonical:
                raise ValueError
        elif (
            not url.path
            or value != canonical + url.path
            or any(segment in (".", "..") for segment in unquote(url.path).split("/"))
            or "\\" in unquote(url.path)
        ):
            raise ValueError
    except (ValueError, TypeError):
        raise ConfigError(f"{name}: URL HTTPS canônica inválida.") from None
    return value


@dataclass(frozen=True)
class Limits:
    summary_chars: int = 8_000
    context_list_items: int = 50
    context_list_item_chars: int = 500
    context_bytes: int = 32 * 1024
    preference_chars: int = 1_000
    message_chars: int = 4_000
    messages_per_call: int = 40
    message_batch_bytes: int = 192 * 1024
    conversation_bytes: int = 2 * 1024**2
    mcp_body_bytes: int = 256 * 1024
    unauthenticated_mcp_body_bytes: int = 8 * 1024
    daily_writes: int = 300
    daily_bytes: int = 4 * 1024**2
    stored_bytes: int = 200 * 1024**2
    pending_transactions: int = 20
    operational_cleanup_seconds: int = 3600
    audit_retention_days: int = 180
    database_bytes: int = 300 * 1024**2
    tool_response_chars: int = 140_000
    search_block_rows: int = 500
    search_results: int = 20
    search_seconds: int = 2

    def __post_init__(self):
        for f in fields(self):
            if type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0:
                raise ConfigError(f"limits.{f.name}: deve ser inteiro positivo.")
        for left, right, strict in (
            ("message_batch_bytes", "mcp_body_bytes", True),
            ("unauthenticated_mcp_body_bytes", "mcp_body_bytes", False),
            ("stored_bytes", "database_bytes", False),
        ):
            if getattr(self, left) > getattr(self, right) or (
                strict and getattr(self, left) == getattr(self, right)
            ):
                raise ConfigError(f"limits.{left}: incompatível com limits.{right}.")


@dataclass(frozen=True)
class Config:
    public_origin: str
    bind_host: str = "127.0.0.1"
    port: int = 8780
    data_dir: Path = Path("/var/lib/batataswap")
    backup_dir: Path = Path("/var/backups/batataswap")
    vercel_origin: str | None = None
    painel_client_id: str = "painel-vercel"
    # client_id do CIMD do Claude hospedado, medido no spike (ARQUITETURA §1.0 e §4.1).
    allowed_cimd_client_ids: tuple[str, ...] = field(
        default_factory=lambda: (CLAUDE_CIMD_CLIENT_ID,)
    )
    allowed_mcp_origins: tuple[str, ...] = field(default_factory=tuple)
    account_labels: tuple[str, ...] = field(default_factory=lambda: ("conta-1", "conta-2"))
    limits: Limits = field(default_factory=Limits)

    def __post_init__(self):
        _https(self.public_origin, name="public_origin")
        if self.vercel_origin is not None:
            _https(self.vercel_origin, name="vercel_origin")
        try:
            if (
                not isinstance(self.bind_host, str)
                or not ipaddress.ip_address(self.bind_host).is_loopback
            ):
                raise ValueError
        except (ValueError, TypeError):
            raise ConfigError("bind_host: deve ser um IP de loopback.") from None
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ConfigError("port: porta de escuta inválida.")
        for name in ("allowed_cimd_client_ids", "allowed_mcp_origins", "account_labels"):
            values = getattr(self, name)
            if not isinstance(values, (list, tuple)) or any(
                not isinstance(v, str) or not v for v in values
            ):
                raise ConfigError(f"{name}: lista inválida.")
            object.__setattr__(self, name, tuple(values))
        for value in self.allowed_cimd_client_ids:
            _https(value, name="allowed_cimd_client_ids", origin=False)
        for value in self.allowed_mcp_origins:
            _https(value, name="allowed_mcp_origins")
        if len(set(self.account_labels)) != len(self.account_labels) or any(
            not re.fullmatch(r"[a-z0-9-]{1,32}", label) or label in {"painel", "cli"}
            for label in self.account_labels
        ):
            raise ConfigError("account_labels: rótulos inválidos ou duplicados.")
        if not isinstance(self.painel_client_id, str) or not self.painel_client_id:
            raise ConfigError("painel_client_id: identificador inválido.")
        if not isinstance(self.limits, Limits):
            raise ConfigError("limits: tabela inválida.")
        for name in ("data_dir", "backup_dir"):
            value = getattr(self, name)
            if (
                not isinstance(value, (str, Path))
                or not str(value)
                or not Path(value).is_absolute()
            ):
                raise ConfigError(f"{name}: deve ser caminho absoluto.")
            object.__setattr__(self, name, Path(value))

    @property
    def mcp_resource(self) -> str:
        return self.public_origin + "/mcp"

    @property
    def panel_resource(self) -> str:
        return self.public_origin + "/api/painel"

    @property
    def painel_redirect_uri(self) -> str | None:
        """Redirect exato do client estático ``painel-vercel`` (§4.1); sem Vercel, sem painel."""
        return None if self.vercel_origin is None else self.vercel_origin + "/callback"

    @property
    def issuer(self) -> str:
        return self.public_origin

    @property
    def authority(self) -> str:
        return urlsplit(self.public_origin).netloc


def load_config(path: Path | None = None) -> Config:
    path = Path(
        path
        if path is not None
        else os.environ.get("BATATASWAP_CONFIG", "/etc/batataswap/batataswap.toml")
    )
    try:
        with path.open("rb") as file:
            values = tomllib.load(file)
        for name in values:
            if name not in {f.name for f in fields(Config)}:
                raise ConfigError(f"{name}: chave desconhecida.")
        if "public_origin" not in values:
            raise ConfigError("public_origin: campo obrigatório.")
        if "limits" in values:
            if not isinstance(values["limits"], dict):
                raise ConfigError("limits: tabela inválida.")
            for name in values["limits"]:
                if name not in {f.name for f in fields(Limits)}:
                    raise ConfigError(f"limits.{name}: chave desconhecida.")
            values["limits"] = Limits(**values["limits"])
        return Config(**values)
    except ConfigError:
        raise
    except (OSError, ValueError, TypeError):
        raise ConfigError(
            "Não foi possível carregar a configuração: arquivo ou campos inválidos."
        ) from None
