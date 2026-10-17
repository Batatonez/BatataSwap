"""Configuração local; origens são exatas e a porta HTTPS 443 explícita é recusada."""

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(ValueError):
    """Configuração ausente ou inválida."""


def _https(value: object, *, origin: bool = True) -> str:
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        raise ConfigError("URL HTTPS inválida na configuração.")
    try:
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or "?" in value
            or "#" in value
            or "\\" in value
            or url.port == 443
            or (origin and url.path)
            or url.netloc.endswith(":")
        ):
            raise ValueError
    except ValueError:
        raise ConfigError(
            "URL HTTPS inválida na configuração (porta 443 deve ser omitida)."
        ) from None
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
    tool_response_chars: int = 100_000
    search_block_rows: int = 500
    search_results: int = 20
    search_seconds: int = 2

    def __post_init__(self):
        if any(
            type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0
            for f in fields(self)
        ):
            raise ConfigError("Limites devem ser números inteiros positivos.")


@dataclass(frozen=True)
class Config:
    public_origin: str
    bind_host: str = "127.0.0.1"
    port: int = 8780
    data_dir: Path = Path("/var/lib/batataswap")
    backup_dir: Path = Path("/var/backups/batataswap")
    vercel_origin: str | None = None
    painel_client_id: str = "painel-vercel"
    allowed_cimd_client_ids: list[str] = field(default_factory=list)
    allowed_mcp_origins: list[str] = field(default_factory=list)
    account_labels: list[str] = field(default_factory=lambda: ["conta-1", "conta-2"])
    limits: Limits = field(default_factory=Limits)

    def __post_init__(self):
        _https(self.public_origin)
        if self.vercel_origin is not None:
            _https(self.vercel_origin)
        try:
            if not ipaddress.ip_address(self.bind_host).is_loopback:
                raise ValueError
        except (ValueError, TypeError):
            raise ConfigError("O endereço de escuta deve ser um IP de loopback.") from None
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ConfigError("Porta de escuta inválida.")
        for name in ("allowed_cimd_client_ids", "allowed_mcp_origins", "account_labels"):
            values = getattr(self, name)
            if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
                raise ConfigError("Lista inválida na configuração.")
        for value in self.allowed_cimd_client_ids:
            _https(value, origin=False)
        for value in self.allowed_mcp_origins:
            _https(value)
        if not isinstance(self.painel_client_id, str) or not self.painel_client_id:
            raise ConfigError("Identificador do painel inválido.")
        if not isinstance(self.limits, Limits):
            raise ConfigError("Tabela de limites inválida.")
        for name in ("data_dir", "backup_dir"):
            value = getattr(self, name)
            if (
                not isinstance(value, (str, Path))
                or not str(value)
                or not Path(value).is_absolute()
            ):
                raise ConfigError("Diretórios devem ser caminhos absolutos.")
            object.__setattr__(self, name, Path(value))

    @property
    def mcp_resource(self) -> str:
        return self.public_origin + "/mcp"

    @property
    def panel_resource(self) -> str:
        return self.public_origin + "/api/painel"

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
        if "limits" in values:
            values["limits"] = Limits(**values["limits"])
        return Config(**values)
    except ConfigError:
        raise
    except (OSError, ValueError, TypeError):
        raise ConfigError(
            "Não foi possível carregar a configuração: arquivo ou campos inválidos."
        ) from None
