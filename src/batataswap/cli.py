"""Administração local; segredos só entram pelo terminal ou credencial systemd."""

import argparse
import getpass
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import unicodedata
from contextlib import closing
from pathlib import Path

from batataswap import __version__, backup, crypto, db, logs, memory
from batataswap.auth import oauth, owner, passwords, totp
from batataswap.config import ConfigError, check_coherence, load_config


def terminal_text(value: object) -> str:
    return "".join(
        f"\\u{ord(c):04X}" if unicodedata.category(c) in {"Cc", "Cf"} else c for c in str(value)
    )


class AdminError(Exception):
    """Mensagem administrativa segura para exibição."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        expected = []
        for action in self._actions:
            expected.extend(action.option_strings)
            if isinstance(action, argparse._SubParsersAction):
                expected.extend(action.choices)
        self.exit(2, "Uso inválido. Opções/comandos esperados: " + ", ".join(expected) + "\n")


def main(
    argv=None,
    *,
    config=None,
    runner=None,
    credstore=Path("/etc/credstore.encrypted/batataswap-master"),
    creds_binary="/usr/bin/systemd-creds",
):
    parser = Parser(prog="batataswap", description="Administração do BatataSwap.")
    parser.add_argument("--version", action="version", version=f"batataswap {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="comando")
    for name in (
        "serve",
        "check-config",
        "key-import",
        "init",
        "migrate",
        "key-export",
        "backup",
        "restore-test",
        "grants",
        "lixeira",
        "preferencias",
        "unlock",
        "cleanup",
    ):
        commands.add_parser(name)
    key_parser = commands.add_parser("key-init")
    key_parser.add_argument("--substituir", action="store_true")
    key_parser.add_argument("--banco-sera-perdido", action="store_true")
    commands.add_parser("restore").add_argument("arquivo", type=Path)
    commands.add_parser("restaurar").add_argument("id")
    commands.add_parser("expurgar").add_argument("id")
    commands.add_parser("revoke").add_argument("rotulo")
    commands.add_parser("export").add_argument("--out", required=True)
    commands.add_parser("wipe").add_argument("--incluir-backups", action="store_true")
    args = parser.parse_args(argv)
    command = args.command
    logs.ADMIN = True
    try:
        if command == "export" and args.out != "-":
            raise AdminError("Use sudo batataswap-admin export --out - > ~/memoria.json")
        if command in {"key-init", "key-import"}:
            if os.geteuid() != 0:
                raise AdminError("Execute como root.")
            if credstore.exists() or credstore.is_symlink():
                if command != "key-init" or not args.substituir:
                    raise AdminError("Credencial já existe.")
                if input("Digite SUBSTITUIR CHAVE: ") != "SUBSTITUIR CHAVE":
                    raise AdminError("Substituição cancelada.")
            if command == "key-init" and args.substituir:
                config = config or load_config()
                if (config.data_dir / "batataswap.db").exists() and not args.banco_sera_perdido:
                    raise AdminError(
                        "A troca deixa o banco ilegível. Use --substituir "
                        "--banco-sera-perdido para confirmar."
                    )
            key = (
                crypto.generate_master_key()
                if command == "key-init"
                else crypto.import_key(getpass.getpass("Chave de recuperação: "))
            )
            temporary = Path(str(credstore) + ".novo")
            if temporary.exists() or temporary.is_symlink():
                raise AdminError("Credencial temporária já existe.")
            mask = os.umask(0o077)
            try:
                (runner or subprocess.run)(
                    [creds_binary, "encrypt", "--name=batataswap-master", "-", str(temporary)],
                    input=key,
                    shell=False,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                temporary.chmod(0o600)
                os.replace(temporary, credstore)
                credstore.chmod(0o600)
            finally:
                os.umask(mask)
                temporary.unlink(missing_ok=True)
            if command == "key-init":
                print("Guarde esta chave no gerenciador de senhas. Ela aparece uma vez.")
                print(crypto.export_key(key))
            return 0
        config = config or load_config()
        if command == "check-config":
            # Só config: sem banco e sem chave, para o atualizar.sh validar antes de subir.
            check_coherence(config)
            print("Configuração válida.")
            return 0
        if command == "serve":
            from batataswap.app import serve

            serve(config)
            return 0
        key = crypto.load_master_key()
        keyring = crypto.Keyring(key)
        if command == "key-export":
            print("Guarde no gerenciador de senhas; exibida uma vez.", file=sys.stderr)
            print(crypto.export_key(key))
            return 0
        path = config.data_dir / "batataswap.db"
        now = int(time.time())
        if command == "restore-test":
            backup.restore_test(config.backup_dir, keyring)
            logs.emit("restore_teste_ok", 200)
            return 0
        if command == "restore":
            backup.restore(args.arquivo, path, config.backup_dir, keyring, now)
            logs.emit("restore_feito", 200)
            return 0
        with closing(db.connect(path, create=command in {"init", "migrate"})) as conn:
            if command in {"init", "migrate"}:
                db.migrate(conn)
            if command == "init":
                if conn.execute("SELECT 1 FROM owner").fetchone():
                    raise AdminError("Dono já cadastrado.")
                for attempt in range(3):
                    try:
                        password = passwords.validate_new_password(getpass.getpass("Senha: "))
                        if password != getpass.getpass("Confirme a senha: "):
                            raise AdminError("As senhas não conferem.")
                        break
                    except (ValueError, AdminError) as error:
                        print(str(error), file=sys.stderr)
                else:
                    raise AdminError("Tentativas de senha esgotadas.")
                secret = totp.generate_secret()
                uri = totp.provisioning_uri(secret)
                print(totp.qr_text(uri))
                print(uri)
                for attempt in range(5):
                    code = input("Código TOTP: ")
                    if totp.verify(secret, code, time.time(), -1) is None:
                        print("Código inválido, tente de novo", file=sys.stderr)
                        continue
                    owner.create_owner(conn, keyring, password, secret, code, time.time())
                    break
                else:
                    raise AdminError("Tentativas de TOTP esgotadas.")
            elif command == "backup":
                backup.backup(conn, config.backup_dir, now)
                logs.emit("backup_ok", 200)
            elif command == "export":
                print("Aviso: exportação em texto puro, sem cifra.", file=sys.stderr)
                payload = json.dumps(memory.export_all(conn, keyring), ensure_ascii=True)
                print(payload)
            elif command == "preferencias":
                print("id\tdata\torigem\ttexto")
                cursor = None
                while True:
                    page = memory.list_preferences(
                        conn, keyring, memory.Actor(None, None, "cli"), cursor, now=now
                    )
                    for item in page["preferencias"]:
                        origin = conn.execute(
                            "SELECT COALESCE(g.public_id, p.source_label) FROM preferences p "
                            "LEFT JOIN oauth_grants g ON g.id=p.grant_id WHERE p.public_id=?",
                            (item["id"],),
                        ).fetchone()[0]
                        print(
                            f"{terminal_text(item['id'])}\t{terminal_text(item['salvo_em'])}\t"
                            f"{terminal_text(origin)} ({terminal_text(item['enviado_por'] or 'cli')})\t"
                            f"{terminal_text(item['texto'])}"
                        )
                    cursor = page["proximo_cursor"]
                    if cursor is None:
                        break
            elif command == "expurgar":
                purged = memory.purge(conn, memory.Actor(None, None, "cli"), args.id, now=now)
                print(json.dumps(purged, ensure_ascii=True))
            elif command == "restaurar":
                restored = memory.restore(conn, memory.Actor(None, None, "cli"), args.id, now=now)
                print(json.dumps(restored, ensure_ascii=True))
            elif command == "lixeira":
                print("id\ttipo\tapagado em\torigem")
                for item in memory.list_trash(conn, memory.Actor(None, None, "cli")):
                    print(
                        f"{terminal_text(item['id'])}\t{terminal_text(item['tipo'])}\t"
                        f"{terminal_text(item['apagado_em'])}\t{terminal_text(item['origem'] or '—')}"
                    )
            elif command == "grants":
                print("rótulo\tativo\tdesde\túltimo uso\treusos tolerados")
                for label, revoked, created, used, expires, tolerated in conn.execute(
                    "SELECT g.label,g.revoked_at,g.created_at,g.last_used_at,g.expires_at,"
                    "(SELECT count(*) FROM audit a WHERE a.grant_id=g.id "
                    "AND a.event='refresh_reuso_tolerado') FROM oauth_grants g"
                ):
                    print(
                        f"{terminal_text(label)}\t{'sim' if revoked is None and expires > now else 'não'}"
                        f"\t{memory.iso(created)}\t{memory.iso(used) if used else '—'}\t{tolerated}"
                    )
            elif command == "revoke":
                rows = conn.execute(
                    "SELECT public_id FROM oauth_grants WHERE label=? "
                    "AND revoked_at IS NULL AND expires_at>?",
                    (args.rotulo, now),
                ).fetchall()
                if not rows:
                    raise AdminError("Grant ativo não encontrado.")
                for (public_id,) in rows:
                    oauth.revoke_grant(conn, public_id, now)
            elif command == "unlock":
                owner.unlock(conn, now)
            elif command == "cleanup":
                oauth.cleanup_expired(conn, now, config.limits.audit_retention_days)
                memory.sweep_trash(conn, now=now)
                memory.retry_checkpoint(conn, now=now)
                owner.cleanup_known_devices(conn, now)
            elif command == "wipe":
                if input("Digite APAGAR TUDO: ") != "APAGAR TUDO":
                    raise AdminError("Exclusão cancelada.")
                for table in ("projects", "preferences", "conversations"):
                    for (public_id,) in conn.execute(f"SELECT public_id FROM {table}").fetchall():
                        memory.purge(conn, memory.Actor(None, None, "cli"), public_id, now=now)
                backup.revoke_all(conn, now)
                conn.execute("VACUUM")
                items = list(config.data_dir.glob("antes-do-restore-*"))
                items += list(config.data_dir.glob("*.json"))
                if args.incluir_backups and config.backup_dir.exists():
                    items += list(config.backup_dir.iterdir())
                for item in items:
                    if item.is_dir() and not item.is_symlink():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                    print(f"Removido: {item}")
        return 0
    except Exception as error:  # noqa: BLE001 — fronteira CLI: nunca imprimir segredos da exceção
        if command in {"backup", "restore-test"}:
            logs.emit(
                "backup_falhou" if command == "backup" else "restore_teste_falhou", 500, nivel="err"
            )
        message = "Não foi possível concluir o comando. Confira a configuração, os dados e as confirmações informadas."
        if isinstance(
            error,
            (AdminError, ConfigError, memory.InvalidInput, db.DatabaseError, crypto.CryptoError),
        ):
            message = str(error)
        elif isinstance(error, sqlite3.OperationalError) and "locked" in str(error):
            message = "banco em uso: pare o serviço (sudo systemctl stop batataswap)"
        elif type(error) is ValueError and str(error) in {
            "Dono já cadastrado.",
            "Segredo TOTP inválido.",
            "Código TOTP inválido.",
            "A senha deve ter entre 12 e 1024 caracteres.",
            "Escolha uma senha menos comum.",
            "Senha inválida.",
        }:
            message = str(error)
        print(message, file=sys.stderr)
        return 1
    finally:
        logs.ADMIN = False
