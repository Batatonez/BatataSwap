"""Contrato estático do deploy; não inicia serviços nem precisa de root."""

import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import fields
from pathlib import Path

import pytest

from batataswap.config import Config, Limits

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
ALL_SERVICES = sorted(DEPLOY.glob("*.service"))
SERVICES = [p for p in ALL_SERVICES if "@" not in p.name]
SCRIPTS = [*DEPLOY.glob("*.sh"), DEPLOY / "batataswap-admin"]
REQUIRED = {
    "User": "batataswap",
    "Group": "batataswap",
    "LoadCredentialEncrypted": "batataswap-master:/etc/credstore.encrypted/batataswap-master",
    "Environment": "BATATASWAP_CONFIG=/etc/batataswap/batataswap.toml",
    "StateDirectory": "batataswap",
    "StateDirectoryMode": "0700",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "PrivateUsers": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "RestrictRealtime": "yes",
    "RestrictSUIDSGID": "yes",
    "ProtectHostname": "yes",
    "ProtectClock": "yes",
    "SystemCallArchitectures": "native",
    "NoNewPrivileges": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectControlGroups": "yes",
    "SystemCallErrorNumber": "EPERM",
    "ProtectKernelLogs": "yes",
    "RemoveIPC": "yes",
    "RestrictNamespaces": "yes",
    "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes",
    "SystemCallFilter": "@system-service",
    "CapabilityBoundingSet": "",
    "UMask": "0077",
    "MemoryMax": "512M",
    "SyslogIdentifier": "batataswap",
}


def parse_unit(path):
    result = {}
    section = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line[1:-1]
        elif "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[section, key] = value
    return result


@pytest.mark.parametrize("path", SERVICES, ids=lambda p: p.name)
def test_service_contract(path):
    unit = parse_unit(path)
    for key, value in REQUIRED.items():
        assert unit["Service", key] == value
    if path.name in {"batataswap-backup.service", "batataswap-restore-test.service"}:
        assert unit["Service", "ReadWritePaths"] == "/var/backups/batataswap"
    else:
        assert ("Service", "ReadWritePaths") not in unit
    assert not any(key in {"IPAddressDeny", "IPAddressAllow"} for _, key in unit)
    assert unit["Unit", "StartLimitIntervalSec"] == "300"
    assert unit["Unit", "StartLimitBurst"] == "10"
    command = path.stem.removeprefix("batataswap-") if "-" in path.stem else "serve"
    assert unit["Service", "ExecStart"] == (
        f"/opt/batataswap/.venv/bin/python -m batataswap {command}"
    )
    if command == "serve":
        assert unit["Service", "Type"] == "exec"
        assert unit["Unit", "Wants"] == "network-online.target"
        assert unit["Service", "RestrictAddressFamilies"] == "AF_INET AF_INET6 AF_UNIX"
        assert unit["Service", "Restart"] == "on-failure"
        assert unit["Service", "RestartSec"] == "3"
    else:
        assert unit["Service", "Type"] == "oneshot"
        assert unit["Service", "PrivateNetwork"] == "yes"
        assert unit["Service", "RestrictAddressFamilies"] == "AF_UNIX"
        assert ("Unit", "After") not in unit
        if command in {"backup", "restore-test", "cleanup"}:
            assert unit["Unit", "OnFailure"] == "batataswap-alerta@%n.service"


def test_units_and_timers_exist():
    assert len(SERVICES) == 4
    for name, calendar in (
        ("backup", "*-*-* 03:17:00"),
        ("restore-test", "Sun *-*-* 04:17:00"),
        ("cleanup", "hourly"),
    ):
        timer = parse_unit(DEPLOY / f"batataswap-{name}.timer")
        assert timer["Timer", "OnCalendar"] == calendar
        assert timer["Timer", "Persistent"] == "true"
        assert timer["Timer", "Unit"] == f"batataswap-{name}.service"
        assert timer["Install", "WantedBy"] == "timers.target"
        if name == "backup":
            assert timer["Timer", "RandomizedDelaySec"] == "5min"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_shell_syntax(path):
    assert "set -euo pipefail" in path.read_text()
    subprocess.run(["bash", "-n", str(path)], check=True, capture_output=True)


def test_admin_allowlist(tmp_path):
    script = (DEPLOY / "batataswap-admin").read_text()
    assert not re.search(r"\beval\b", script)
    branches = re.findall(r"^    ([a-z][a-z|-]*)\)", script, flags=re.MULTILINE)
    accepted = {cmd for branch in branches for cmd in branch.split("|")}
    accepted -= {"key-init", "key-import"}
    assert accepted == {
        "serve",
        "check-config",
        "init",
        "migrate",
        "key-export",
        "backup",
        "restore",
        "restore-test",
        "export",
        "wipe",
        "grants",
        "lixeira",
        "preferencias",
        "expurgar",
        "restaurar",
        "revoke",
        "unlock",
        "cleanup",
    }
    assert 'case "${1:-}" in' in script
    assert "--state=active,activating" in script
    assert "--expand-environment=no" in script
    assert "terminal=(--pty -E TERM)" in script
    assert "--uid=batataswap --gid=batataswap" in script
    assert 'python -m batataswap "$@"' in script
    if os.geteuid() != 0:
        pytest.skip("execução do allowlist requer root; contrato estático já conferido")
    # Mesmo como root, comando recusado não pode chegar ao systemd-run.
    fake = tmp_path / "systemd-run"
    fake.write_text("#!/bin/bash\nexit 99\n")
    fake.chmod(0o755)
    for command in ("key-init", "key-import", "unknown", "--help", ""):
        result = subprocess.run(
            ["bash", str(DEPLOY / "batataswap-admin"), command],
            env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"},
            capture_output=True,
            check=False,
        )
        assert result.returncode in (1, 2)  # root obrigatório ou comando recusado


def test_example_config():
    values = tomllib.loads((DEPLOY / "batataswap.toml.exemplo").read_text())
    assert set(values) | {"vercel_origin"} == {f.name for f in fields(Config)}
    assert set(values["limits"]) == {f.name for f in fields(Limits)}
    # Placeholder deliberadamente precisa ser substituído pelo nome DNS real.
    values["public_origin"] = "https://batatarp.tail-example.ts.net"
    values["limits"] = Limits(**values["limits"])
    Config(**values)


def test_no_unsafe_content():
    for path in DEPLOY.iterdir():
        text = path.read_text()
        assert not re.search(r"curl[^\n|]*\|\s*(?:ba)?sh\b", text)
        assert not re.search(r"chmod\s+(?:-[a-zA-Z]+\s+)*777\b", text)
        assert "0.0.0.0" not in text
        assert not re.search(r"-----BEGIN .*PRIVATE KEY-----|otpauth://|bsw_(?:at|rt)_", text)
        assert not re.search(r"(?im)^\s*(?:password|secret|master_key)\s*=", text)


def test_systemd_verify(tmp_path):
    binary = shutil.which("systemd-analyze")
    if not binary:
        pytest.skip("systemd-analyze indisponível")
    # verify confere existência do executável. Troque só esse caminho na cópia
    # temporária, pois a instalação /opt não existe na máquina de testes.
    units = []
    for path in [*ALL_SERVICES, *sorted(DEPLOY.glob("*.timer"))]:
        target = tmp_path / path.name
        target.write_text(path.read_text().replace("/opt/batataswap/.venv/bin/python", "/bin/true"))
        units.append(str(target))
    result = subprocess.run([binary, "verify", *units], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason="wrapper requer root")
def test_admin_terminal_and_quiescence(tmp_path):
    runner = tmp_path / "systemd-run"
    runner.write_text('#!/bin/bash\nprintf "%s\\n" "$@"\n')
    runner.chmod(0o755)
    controller = tmp_path / "systemctl"
    controller.write_text('#!/bin/bash\nprintf "%s" "${TEST_ACTIVE_UNITS:-}"\n')
    controller.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

    def run(*args, active=""):
        return subprocess.run(
            ["bash", str(DEPLOY / "batataswap-admin"), *args],
            env={**env, "TEST_ACTIVE_UNITS": active},
            capture_output=True,
            text=True,
            check=False,
        )

    for command in ("init", "wipe", "key-export"):
        result = run(command)
        assert result.returncode == 0
        assert "--pty\n-E\nTERM\n" in result.stdout
        assert "--pipe" not in result.stdout
    for command in ("migrate", "backup", "export", "restore-test", "cleanup"):
        result = run(command)
        assert result.returncode == 0
        assert "--pipe" in result.stdout
        assert "--pty" not in result.stdout
    for active in (
        "batataswap.service loaded active running",
        "batataswap-extra.service loaded activating start",
        "batataswap-backup.timer loaded active waiting",
    ):
        for command in ("wipe", "restore"):
            result = run(command, active=active)
            assert result.returncode == 1
            assert not result.stdout
    outside = tmp_path / "backup.db"
    outside.touch()
    result = run("restore", str(outside))
    assert result.returncode == 2
    assert not result.stdout
    for command in ("key-init", "key-import"):
        result = run(command)
        assert result.returncode == 2
        assert (
            f"rode como root diretamente: sudo /opt/batataswap/.venv/bin/python -m batataswap {command}"
            in result.stderr
        )


def test_build_and_revision_contract():
    for name in ("instalar.sh", "atualizar.sh"):
        script = (DEPLOY / name).read_text()
        assert "^[a-fA-F0-9]{40}$" in script
        assert script.index("fetch origin") < script.index('checkout --detach "$sha"')
        assert 'rev-parse HEAD) == "$sha"' in script
        assert "pip install --require-hashes -r requirements.lock" in script
        assert "pip install --require-hashes -r requirements-build.lock" in script
        assert "pip install --no-deps --no-build-isolation --no-index ." in script
    lock = (ROOT / "requirements-build.lock").read_text()
    assert "hatchling==" in lock
    assert "--allow-unsafe" in lock
    entries = re.findall(
        r"^([a-z][a-z-]*==[^\n]+) \\\n    --hash=sha256:[0-9a-f]{64}", lock, re.MULTILINE
    )
    assert len(entries) >= 2


def test_atualizar_valida_config_antes_de_iniciar():
    script = (DEPLOY / "atualizar.sh").read_text()
    check = (
        'batataswap-admin check-config || { echo "Config inválida: corrija '
        '/etc/batataswap/batataswap.toml e rode o atualizar de novo"; exit 1; }'
    )
    assert check in script
    assert script.index(check) < script.index("systemctl start batataswap.service")


def test_alert_unit():
    unit = parse_unit(DEPLOY / "batataswap-alerta@.service")
    assert unit["Service", "SyslogLevel"] == "crit"
    assert unit["Service", "StandardOutput"] == "journal"
    assert unit["Service", "ExecStart"].startswith("/usr/bin/echo ")


def test_admin_preferences_pty_and_purge_pipe():
    script = (DEPLOY / "batataswap-admin").read_text()
    terminal_cases = script.split("terminal=(--pipe)", 1)[1].split("exec systemd-run", 1)[0]
    assert "preferencias)" in terminal_cases
    assert "expurgar" not in terminal_cases
    assert "terminal=(--pty -E TERM)" in terminal_cases
