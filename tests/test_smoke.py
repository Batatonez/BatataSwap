import pytest

from batataswap.__main__ import main


def test_version_imprime_versao(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "batataswap 0.1.0"


def test_serve_delega(monkeypatch):
    from batataswap import app
    from batataswap.config import Config

    config = Config(public_origin="https://example.ts.net")
    called = []
    monkeypatch.setattr("batataswap.cli.load_config", lambda: config)
    monkeypatch.setattr(app, "serve", called.append)
    assert main(["serve"]) == 0
    assert called == [config]
