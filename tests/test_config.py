import pytest

from batataswap.config import Config, ConfigError, load_config


def test_minimal_config(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text('public_origin = "https://swap.example:8443"\n')
    monkeypatch.setenv("BATATASWAP_CONFIG", str(path))
    config = load_config()
    assert config == load_config(path)
    assert config.authority == "swap.example:8443"
    assert config.issuer == "https://swap.example:8443"
    assert config.mcp_resource == config.issuer + "/mcp"
    assert config.panel_resource == config.issuer + "/api/painel"
    assert config.limits.stored_bytes == 200 * 1024**2


@pytest.mark.parametrize(
    "origin",
    [
        "http://swap.example",
        "https://swap.example/path",
        "https://swap.example/",
        "https://swap.example:443",
        "https://user@swap.example",
        "https://swap.example?q=x",
    ],
)
def test_invalid_origin(origin):
    with pytest.raises(ConfigError):
        Config(public_origin=origin)


def test_non_loopback():
    with pytest.raises(ConfigError):
        Config(public_origin="https://swap.example", bind_host="0.0.0.0")


def test_invalid_config_does_not_echo(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text('public_origin = "SEGREDO"')
    with pytest.raises(ConfigError) as error:
        load_config(path)
    assert "SEGREDO" not in str(error.value)


@pytest.mark.parametrize("field", ["public_origin", "vercel_origin", "allowed_mcp_origins"])
@pytest.mark.parametrize(
    "origin",
    [
        "https://SWAP.example",
        "https://swap.example.",
        "https://s w.example",
        "https://á.example",
        "https://swap.example:0",
        "https://swap.example:443",
        "https://swap.example:65536",
        "https://swap.example:0444",
        "https://swap%2eexample",
        "https://-swap.example",
        "https://swap.example#",
        "https://swap.example?",
        "https://user@swap.example",
        "https://swap.example/",
        "https://swap.example:",
    ],
)
def test_canonical_origins(field, origin):
    kwargs = {"public_origin": "https://swap.example", field: origin}
    if field == "allowed_mcp_origins":
        kwargs[field] = [origin]
    with pytest.raises(ConfigError, match=field):
        Config(**kwargs)


@pytest.mark.parametrize(
    "value",
    [
        "https://claude.ai",
        "https://CLAUDE.ai/document",
        "http://claude.ai/document",
        "https://claude.ai/a/../document",
        "https://claude.ai/./document",
        "https://claude.ai/%2e%2e/document",
        "https://claude.ai/document?q=1",
        "https://claude.ai/document#fragment",
        "https://claude.ai:443/document",
        "https://claude.ai./document",
        "https://claude.ai:0/document",
        42,
    ],
)
def test_invalid_cimd(value):
    with pytest.raises(ConfigError, match="allowed_cimd_client_ids"):
        Config(public_origin="https://swap.example", allowed_cimd_client_ids=[value])


@pytest.mark.parametrize(
    "field,value",
    [
        ("data_dir", "relative"),
        ("port", 0),
        ("port", 65536),
        ("port", True),
        ("bind_host", 2130706433),
        ("bind_host", True),
        ("allowed_mcp_origins", "https://swap.example"),
        ("allowed_cimd_client_ids", [False]),
        ("vercel_origin", 42),
        ("account_labels", ["painel"]),
        ("account_labels", ["cli"]),
        ("account_labels", ["conta-1", "conta-1"]),
        ("account_labels", ["Conta"]),
        ("account_labels", ["x" * 33]),
    ],
)
def test_invalid_fields(field, value):
    with pytest.raises(ConfigError, match=field):
        Config(public_origin="https://swap.example", **{field: value})


@pytest.mark.parametrize(
    "table,key,value",
    [
        ("", "unknown", '"sensitive"'),
        ("[limits]", "unknown", "1"),
        ("[limits]", "summary_chars", "0"),
        ("[limits]", "summary_chars", "-1"),
        ("[limits]", "summary_chars", "true"),
    ],
)
def test_invalid_toml_fields(tmp_path, table, key, value):
    path = tmp_path / "config.toml"
    path.write_text(f'public_origin = "https://swap.example"\n{table}\n{key} = {value}\n')
    with pytest.raises(ConfigError, match=key) as error:
        load_config(path)
    assert "sensitive" not in str(error.value)


@pytest.mark.parametrize(
    "values,field",
    [
        ({"message_batch_bytes": 256 * 1024}, "message_batch_bytes"),
        ({"unauthenticated_mcp_body_bytes": 256 * 1024 + 1}, "unauthenticated_mcp_body_bytes"),
        ({"stored_bytes": 300 * 1024**2 + 1}, "stored_bytes"),
    ],
)
def test_cross_limits(values, field):
    from batataswap.config import Limits

    with pytest.raises(ConfigError, match=field):
        Limits(**values)


def test_valid_config_and_immutable_lists():
    origins = ["https://127.0.0.1", "https://[::1]:8443"]
    config = Config(
        public_origin="https://swap.example",
        bind_host="::1",
        allowed_mcp_origins=origins,
        allowed_cimd_client_ids=["https://claude.ai/metadata"],
        account_labels=["conta-1", "conta-2"],
    )
    origins.append("invalid")
    assert config.allowed_mcp_origins == ("https://127.0.0.1", "https://[::1]:8443")
    assert isinstance(config.allowed_cimd_client_ids, tuple)
    assert isinstance(config.account_labels, tuple)
