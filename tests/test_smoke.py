import pytest

from batataswap.__main__ import main


def test_version_imprime_versao(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "batataswap 0.1.0"


def test_serve_ainda_nao_implementado(capsys):
    assert main(["serve"]) == 2
    assert "ainda não implementado" in capsys.readouterr().err
