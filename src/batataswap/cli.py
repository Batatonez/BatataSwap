"""Administração local; segredos só entram pelo terminal ou credencial systemd."""

import argparse
import getpass
import json
import os
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

from batataswap import __version__, backup, crypto, db, logs, memory
from batataswap.auth import oauth, owner, passwords, totp
from batataswap.config import load_config


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "Uso inválido. Confira os argumentos do comando.\n")


def main(
    argv=None,
    *,
    config=None,
    runner=None,
    credstore=Path("/etc/credstore.encrypted/batataswap-master"),
    creds_binary="systemd-creds",
):
    parser = Parser(prog="batataswap", description="Administração do BatataSwap.")
    parser.add_argument("--version", action="version", version=f"batataswap {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="comando")
    for name in (
        "serve",
        "key-import",
        "init",
        "migrate",
        "key-export",
        "backup",
        "restore-test",
        "grants",
        "unlock",
        "cleanup",
    ):
        commands.add_parser(name)
    commands.add_parser("key-init").add_argument("--substituir", action="store_true")
    commands.add_parser("restore").add_argument("arquivo", type=Path)
    commands.add_parser("revoke").add_argument("rotulo")
    commands.add_parser("export").add_argument("--out", required=True)
    commands.add_parser("wipe").add_argument("--incluir-backups", action="store_true")
    args = parser.parse_args(argv)
    command = args.command
    try:
        if command in {"key-init", "key-import"}:
            if os.geteuid() != 0:
                raise ValueError("Execute como root.")
            if credstore.exists() or credstore.is_symlink():
                if command != "key-init" or not args.substituir:
                    raise ValueError("Credencial já existe.")
                if input("Digite SUBSTITUIR CHAVE: ") != "SUBSTITUIR CHAVE":
                    raise ValueError("Substituição cancelada.")
            key = (
                crypto.generate_master_key()
                if command == "key-init"
                else crypto.import_key(getpass.getpass("Chave de recuperação: "))
            )
            (runner or subprocess.run)(
                [creds_binary, "encrypt", "--name=batataswap-master", "-", str(credstore)],
                input=key,
                shell=False,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if command == "key-init":
                print("Guarde esta chave no gerenciador de senhas. Ela aparece uma vez.")
                print(crypto.export_key(key))
            return 0
        config = config or load_config()
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
                    raise ValueError("Dono já cadastrado.")
                password = passwords.validate_new_password(getpass.getpass("Senha: "))
                if password != getpass.getpass("Confirme a senha: "):
                    raise ValueError("As senhas não conferem.")
                secret = totp.generate_secret()
                uri = totp.provisioning_uri(secret)
                print(totp.qr_text(uri))
                print(uri)
                owner.create_owner(
                    conn, keyring, password, secret, input("Código TOTP: "), time.time()
                )
            elif command == "backup":
                backup.backup(conn, config.backup_dir, now)
                logs.emit("backup_ok", 200)
            elif command == "export":
                print("Aviso: exportação em texto puro, sem cifra.", file=sys.stderr)
                payload = json.dumps(memory.export_all(conn, keyring), ensure_ascii=False)
                if args.out == "-":
                    print(payload)
                else:
                    backup.private_write(Path(args.out), payload.encode())
            elif command == "grants":
                print("rótulo\tativo\tdesde\túltimo uso")
                for label, revoked, created, used, expires in conn.execute(
                    "SELECT label,revoked_at,created_at,last_used_at,expires_at FROM oauth_grants"
                ):
                    print(
                        f"{label}\t{'sim' if revoked is None and expires > now else 'não'}"
                        f"\t{memory.iso(created)}\t{memory.iso(used) if used else '—'}"
                    )
            elif command == "revoke":
                rows = conn.execute(
                    "SELECT public_id FROM oauth_grants WHERE label=? "
                    "AND revoked_at IS NULL AND expires_at>?",
                    (args.rotulo, now),
                ).fetchall()
                if not rows:
                    raise ValueError("Grant ativo não encontrado.")
                for (public_id,) in rows:
                    oauth.revoke_grant(conn, public_id, now)
                    logs.emit("grant_revogado", 200, grant=public_id)
            elif command == "unlock":
                owner.unlock(conn, now)
            elif command == "cleanup":
                oauth.cleanup_expired(conn, now)
                memory.sweep_trash(conn, now=now)
                memory.retry_checkpoint(conn, now=now)
                owner.cleanup_known_devices(conn, now)
            elif command == "wipe":
                if input("Digite APAGAR TUDO: ") != "APAGAR TUDO":
                    raise ValueError("Exclusão cancelada.")
                for table in ("projects", "preferences", "conversations"):
                    for (public_id,) in conn.execute(f"SELECT public_id FROM {table}").fetchall():
                        memory.purge(conn, memory.Actor(None, None, "cli"), public_id, now=now)
                backup.revoke_all(conn, now)
                conn.execute("VACUUM")
                if args.incluir_backups:
                    import shutil

                    for item in config.backup_dir.iterdir():
                        if item.is_dir() and not item.is_symlink():
                            shutil.rmtree(item)
                        else:
                            item.unlink()
        return 0
    except Exception:  # noqa: BLE001 — fronteira CLI: nunca imprimir segredos da exceção
        if command in {"backup", "restore-test"}:
            logs.emit(
                "backup_falhou" if command == "backup" else "restore_teste_falhou", 500, nivel="err"
            )
        print(
            "Não foi possível concluir o comando. Confira a configuração, os dados "
            "e as confirmações informadas.",
            file=sys.stderr,
        )
        return 1
