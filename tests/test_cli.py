import json
from unittest.mock import Mock

import pytest

from batataswap import cli, crypto, db
from batataswap.config import Config


@pytest.fixture
def setup_cli(tmp_path, monkeypatch):
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    key = credentials / "batataswap-master"
    key.write_bytes(b"k" * 32)
    key.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials))
    config = Config(
        public_origin="https://example.ts.net",
        data_dir=tmp_path / "data",
        backup_dir=tmp_path / "backups",
    )
    assert cli.main(["migrate"], config=config) == 0
    return config


def test_commands(setup_cli, capsys, monkeypatch):
    config = setup_cli
    assert cli.main(["backup"], config=config) == 0
    assert cli.main(["restore-test"], config=config) == 0
    capsys.readouterr()
    assert cli.main(["export", "--out", "-"], config=config) == 0
    assert json.loads(capsys.readouterr().out)["formato"] == "batataswap-export-1"
    for command in ("grants", "unlock", "cleanup", "key-export"):
        assert cli.main([command], config=config) == 0
    monkeypatch.setattr("builtins.input", lambda _: "não")
    assert cli.main(["wipe"], config=config) == 1
    monkeypatch.setattr("builtins.input", lambda _: "APAGAR TUDO")
    assert cli.main(["wipe"], config=config) == 0
    assert cli.main(["revoke", "conta-1"], config=config) == 1


def test_restore_and_tampering(setup_cli):
    config = setup_cli
    assert cli.main(["backup"], config=config) == 0
    source = next(config.backup_dir.glob("*.db"))
    assert cli.main(["restore", str(source)], config=config) == 0
    conn = db.connect(config.data_dir / "batataswap.db")
    assert conn.execute("SELECT value FROM meta WHERE key='restore_epoch'").fetchone() == ("1",)
    conn.close()
    with source.open("ab") as stream:
        stream.write(b"adulterado")
    assert cli.main(["restore-test"], config=config) == 1


def test_keys(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    runner = Mock()
    target = tmp_path / "credential"
    assert cli.main(["key-init"], runner=runner, credstore=target) == 0
    args, kwargs = runner.call_args
    assert args[0] == ["systemd-creds", "encrypt", "--name=batataswap-master", "-", str(target)]
    assert len(kwargs["input"]) == 32 and kwargs["shell"] is False and kwargs["check"] is True
    text = capsys.readouterr().out.splitlines()[-1]
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: text)
    assert cli.main(["key-import"], runner=runner, credstore=target) == 0
    assert runner.call_args.kwargs["input"] == crypto.import_key(text)
    target.touch()
    assert cli.main(["key-init"], runner=runner, credstore=target) == 1


def test_init_and_revoke(setup_cli, monkeypatch):
    from batataswap.auth import owner, passwords, totp

    config = setup_cli
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "senha rara longa 726!")
    secret = b"t" * 20
    monkeypatch.setattr(totp, "generate_secret", lambda: secret)
    monkeypatch.setattr(
        "builtins.input", lambda _: totp.code_at(secret, int(cli.time.time()) // 30)
    )
    monkeypatch.setattr(owner, "hash_password", lambda pw: passwords.hash_password(pw, log_n=10))
    assert cli.main(["init"], config=config) == 0
    assert cli.main(["init"], config=config) == 1
    conn = db.connect(config.data_dir / "batataswap.db")
    conn.execute("INSERT INTO oauth_clients VALUES (1,'client','static','{}',0,0)")
    conn.execute(
        "INSERT INTO oauth_grants VALUES (1,'grant_aaaaaaaaaaaaaaaa',1,'conta-1',"
        "'https://example.ts.net/mcp','memoria',0,9999999999,NULL,NULL)"
    )
    conn.execute(
        "INSERT INTO oauth_tokens(token_hash,kind,grant_id,family_id,expires_at,scope) "
        "VALUES (x'00','access',1,'family',9999999999,'memoria')"
    )
    assert cli.main(["backup"], config=config) == 0
    assert cli.main(["revoke", "conta-1"], config=config) == 0
    source = next(config.backup_dir.glob("*.db"))
    conn.close()
    assert cli.main(["restore", str(source)], config=config) == 0
    conn = db.connect(config.data_dir / "batataswap.db")
    assert conn.execute("SELECT revoked_at FROM oauth_grants").fetchone()[0] is not None
    assert conn.execute("SELECT revoked_at FROM oauth_tokens").fetchone()[0] is not None
    conn.close()
