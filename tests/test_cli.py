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

    def encrypt(argv, **kwargs):
        from pathlib import Path

        Path(argv[-1]).write_bytes(b"encrypted")

    runner = Mock(side_effect=encrypt)
    target = tmp_path / "credential"
    assert cli.main(["key-init"], runner=runner, credstore=target) == 0
    args, kwargs = runner.call_args
    assert args[0] == [
        "/usr/bin/systemd-creds",
        "encrypt",
        "--name=batataswap-master",
        "-",
        str(target) + ".novo",
    ]
    assert len(kwargs["input"]) == 32 and kwargs["shell"] is False and kwargs["check"] is True
    text = capsys.readouterr().out.splitlines()[-1]
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: text)
    target.unlink()
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


def test_export_only_stdout(setup_cli, capsys, tmp_path):
    target = tmp_path / "memoria.json"
    assert cli.main(["export", "--out", str(target)], config=setup_cli) == 1
    assert not target.exists()
    assert "sudo batataswap-admin export --out - > ~/memoria.json" in capsys.readouterr().err


def test_init_retries(setup_cli, monkeypatch, capsys):
    from batataswap.auth import owner, passwords, totp

    prompts = iter(
        [
            "curta",
            "senha longa rara 726!",
            "diferente",
            "senha longa rara 726!",
            "senha longa rara 726!",
        ]
    )
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(prompts))
    secret = b"t" * 20
    generate = Mock(return_value=secret)
    monkeypatch.setattr(totp, "generate_secret", generate)
    codes = iter(["errado", totp.code_at(secret, int(cli.time.time()) // 30)])
    monkeypatch.setattr("builtins.input", lambda _: next(codes))
    monkeypatch.setattr(owner, "hash_password", lambda pw: passwords.hash_password(pw, log_n=10))
    assert cli.main(["init"], config=setup_cli) == 0
    generate.assert_called_once()
    output = capsys.readouterr().err
    assert "12 e 1024" in output
    assert "não conferem" in output
    assert "Código inválido, tente de novo" in output


@pytest.mark.parametrize("field", ["password", "totp"])
def test_init_attempt_limits(setup_cli, monkeypatch, field):
    monkeypatch.setattr(
        cli.getpass,
        "getpass",
        Mock(return_value=("curta" if field == "password" else "senha longa rara 726!")),
    )
    codes = Mock(return_value="errado")
    monkeypatch.setattr("builtins.input", codes)
    assert cli.main(["init"], config=setup_cli) == 1
    if field == "totp":
        assert codes.call_count == 5
    else:
        assert cli.getpass.getpass.call_count == 3
    with db.connect(setup_cli.data_dir / "batataswap.db") as conn:
        assert conn.execute("SELECT count(*) FROM owner").fetchone() == (0,)


def test_key_replace_and_runner_failure(setup_cli, tmp_path, monkeypatch, capsys):
    import subprocess

    target = tmp_path / "credential"
    target.write_bytes(b"old")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr("builtins.input", lambda _: "SUBSTITUIR CHAVE")
    runner = Mock()
    assert (
        cli.main(["key-init", "--substituir"], config=setup_cli, runner=runner, credstore=target)
        == 1
    )
    runner.assert_not_called()
    assert "ilegível" in capsys.readouterr().err

    def encrypt(argv, **kwargs):
        assert cli.os.umask(0o077) == 0o077
        from pathlib import Path

        Path(argv[-1]).write_bytes(b"new")

    assert (
        cli.main(
            ["key-init", "--substituir", "--banco-sera-perdido"],
            config=setup_cli,
            runner=encrypt,
            credstore=target,
        )
        == 0
    )
    assert target.read_bytes() == b"new"
    assert target.stat().st_mode & 0o777 == 0o600
    capsys.readouterr()
    secret = b"z" * 32
    monkeypatch.setattr(crypto, "generate_master_key", lambda: secret)
    runner = Mock(side_effect=subprocess.CalledProcessError(1, "SEGREDO"))
    assert (
        cli.main(
            ["key-init", "--substituir", "--banco-sera-perdido"],
            config=setup_cli,
            runner=runner,
            credstore=target,
        )
        == 1
    )
    captured = capsys.readouterr()
    assert crypto.export_key(secret) not in captured.out + captured.err
    assert "SEGREDO" not in captured.out + captured.err
    assert target.read_bytes() == b"new"


def test_parser_does_not_echo_values(capsys):
    with pytest.raises(SystemExit):
        cli.main(["SEGREDO"])
    assert "SEGREDO" not in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["key-init", "--SEGREDO"])
    assert "SEGREDO" not in capsys.readouterr().err


def test_locked_message(setup_cli, monkeypatch, capsys):
    import sqlite3

    monkeypatch.setattr(cli.backup, "restore", Mock(side_effect=sqlite3.OperationalError("locked")))
    assert cli.main(["restore", "backup.db"], config=setup_cli) == 1
    assert "sudo systemctl stop batataswap" in capsys.readouterr().err


from tests.test_oauth import env  # noqa: F401


def test_wipe_real_data(env, tmp_path, monkeypatch, capsys):  # noqa: F811
    from dataclasses import replace

    from batataswap import memory
    from tests.test_oauth import NOW, claude_tokens

    claude_tokens(env)
    grant = env.conn.execute("SELECT id,public_id FROM oauth_grants").fetchone()
    memory.save_context(
        env.conn,
        env.keyring,
        env.config.limits,
        memory.Actor(*grant, "conta-1"),
        "projeto",
        "resumo",
        [],
        [],
        [],
        now=NOW,
    )
    env.conn.execute(
        "INSERT INTO known_devices(token_hash,created_at,expires_at) VALUES (x'01',?,?)",
        (NOW, NOW + 1000),
    )
    # A CLI usa o nome de banco de produção.
    env.conn.close()
    path = tmp_path / "batataswap.db"
    env.path.rename(path)
    config = replace(env.config, data_dir=tmp_path, backup_dir=tmp_path / "missing")
    monkeypatch.setattr(crypto, "load_master_key", lambda: b"k" * 32)
    monkeypatch.setattr(crypto, "Keyring", lambda _: env.keyring)
    monkeypatch.setattr("builtins.input", lambda _: "APAGAR TUDO")
    folder = tmp_path / "antes-do-restore-velho"
    folder.mkdir()
    (folder / "old.db").write_bytes(b"old")
    plain = tmp_path / "memoria.json"
    plain.write_text("segredo")
    assert cli.main(["wipe", "--incluir-backups"], config=config) == 0
    assert not plain.exists() and not folder.exists()
    output = capsys.readouterr().out
    assert str(plain) in output and str(folder) in output
    with db.connect(path) as conn:
        assert conn.execute("SELECT name_ct FROM projects").fetchone() == (None,)
        assert conn.execute("SELECT content_ct FROM contexts").fetchone() == (None,)
        assert conn.execute("SELECT count(*) FROM known_devices").fetchone() == (0,)
        assert conn.execute("SELECT revoked_at FROM oauth_grants").fetchone()[0] is not None
        assert conn.execute(
            "SELECT count(*) FROM oauth_tokens WHERE revoked_at IS NULL"
        ).fetchone() == (0,)


def test_trash_restore_cascade_cli(setup_cli, capsys):
    from batataswap import conversations
    from tests.test_memory import _grant, _trash, save

    config = setup_cli
    conn = db.connect(config.data_dir / "batataswap.db")
    conn.execute("INSERT INTO oauth_clients VALUES (1,'client','static','{}',0,0)")
    actor = _grant(conn, "grant_aaaaaaaaaaaaaaaa", "conta-1")
    keyring = crypto.Keyring(crypto.load_master_key())
    now = int(cli.time.time())
    save(conn, keyring, config.limits, actor, projeto="NOME-SECRETO", now=now)
    conversations.append_messages(
        conn,
        keyring,
        config.limits,
        actor,
        "FIO-SECRETO",
        [{"autor": "claude", "texto": "CONTEUDO-SECRETO"}],
        projeto="NOME-SECRETO",
        now=now,
    )
    project = conn.execute("SELECT public_id FROM projects").fetchone()[0]
    context = conn.execute("SELECT public_id FROM contexts").fetchone()[0]
    # Filho apagado antes não é restaurado pela operação do pai.
    _trash(conn, keyring, actor, context, now=now - 1)
    _trash(conn, keyring, actor, project, now=now)
    capsys.readouterr()
    assert cli.main(["lixeira"], config=config) == 0
    output = capsys.readouterr().out
    assert project in output and context in output
    assert actor.grant_public_id in output
    assert all(
        secret not in output for secret in ["NOME-SECRETO", "FIO-SECRETO", "CONTEUDO-SECRETO"]
    )
    assert cli.main(["restaurar", context], config=config) == 1
    assert cli.main(["restaurar", project], config=config) == 0
    for table in ["projects", "conversations", "messages"]:
        assert conn.execute(f"SELECT trashed_at FROM {table}").fetchone() == (None,)
    assert conn.execute("SELECT trashed_at FROM contexts").fetchone() == (now - 1,)
    assert cli.main(["restaurar", context], config=config) == 0
    assert conn.execute("SELECT trashed_at FROM contexts").fetchone() == (None,)
    assert conn.execute("SELECT grant_id FROM audit WHERE event='restaurar'").fetchall() == [
        (None,),
        (None,),
    ]
    conn.close()


def test_preferences_and_purge_cli(setup_cli, capsys):
    from batataswap import memory
    from tests.test_memory import _grant

    config = setup_cli
    conn = db.connect(config.data_dir / "batataswap.db")
    conn.execute("INSERT INTO oauth_clients VALUES (1,'client','static','{}',0,0)")
    actor = _grant(conn, "grant_aaaaaaaaaaaaaaaa", "conta-1")
    keyring = crypto.Keyring(crypto.load_master_key())
    now = int(cli.time.time())
    ids = [
        memory.add_preference(conn, keyring, config.limits, actor, f"texto {i}", now=now)["id"]
        for i in range(21)
    ]
    capsys.readouterr()
    assert cli.main(["preferencias"], config=config) == 0
    output = capsys.readouterr().out
    assert all(pid in output for pid in ids)
    assert "texto 20" in output and "conta-1" in output and memory.iso(now) in output
    assert cli.main(["expurgar", ids[0]], config=config) == 0
    assert conn.execute(
        "SELECT text_ct FROM preferences WHERE public_id=?", (ids[0],)
    ).fetchone() == (None,)
    assert conn.execute("SELECT grant_id FROM audit WHERE event='expurgar'").fetchone() == (None,)
    conn.close()


def test_serve_prints_config_error_and_exits_1(setup_cli, monkeypatch, capsys):
    from dataclasses import replace

    from batataswap.config import Limits

    config = replace(setup_cli, limits=Limits(tool_response_chars=1000))
    run = Mock(side_effect=AssertionError("servidor não deve subir"))
    monkeypatch.setattr("uvicorn.run", run)
    assert cli.main(["serve"], config=config) == 1
    err = capsys.readouterr().err
    assert "tool_response_chars" in err
    run.assert_not_called()


def test_check_config_valid_and_invalid(setup_cli, capsys):
    from dataclasses import replace

    from batataswap.config import Limits

    assert cli.main(["check-config"], config=setup_cli) == 0
    assert "Configuração válida." in capsys.readouterr().out
    broken = replace(setup_cli, limits=Limits(tool_response_chars=1000))
    assert cli.main(["check-config"], config=broken) == 1
    assert "tool_response_chars" in capsys.readouterr().err


def test_check_config_needs_no_db_or_key(tmp_path, monkeypatch):
    from batataswap.config import Config

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "sem-chave"))
    config = Config(
        public_origin="https://example.ts.net",
        data_dir=tmp_path / "sem-banco",
        backup_dir=tmp_path / "backups",
    )
    assert cli.main(["check-config"], config=config) == 0
    assert not (tmp_path / "sem-banco").exists()
