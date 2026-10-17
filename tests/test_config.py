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
