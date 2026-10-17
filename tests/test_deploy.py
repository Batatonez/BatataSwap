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
SERVICES = sorted(DEPLOY.glob("*.service"))
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
    "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
    "RestrictNamespaces": "yes",
    "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes",
    "SystemCallFilter": "@system-service",
    "CapabilityBoundingSet": "",
    "UMask": "0077",
    "MemoryMax": "512M",
    "ReadWritePaths": "/var/backups/batataswap",
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
    assert not any(key in {"IPAddressDeny", "IPAddressAllow"} for _, key in unit)
    assert unit["Unit", "StartLimitIntervalSec"] == "300"
    assert unit["Unit", "StartLimitBurst"] == "10"
    command = path.stem.removeprefix("batataswap-") if "-" in path.stem else "serve"
    assert unit["Service", "ExecStart"] == (
        f"/opt/batataswap/.venv/bin/python -m batataswap {command}"
    )
    if command == "serve":
        assert unit["Service", "Restart"] == "on-failure"
        assert unit["Service", "RestartSec"] == "3"
    else:
        assert unit["Service", "Type"] == "oneshot"


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
    assert accepted == {
        "serve",
        "init",
        "key-export",
        "backup",
        "restore",
        "restore-test",
        "export",
        "wipe",
        "grants",
        "revoke",
        "unlock",
        "cleanup",
    }
    assert 'case "${1:-}" in' in script
    assert "systemctl is-active batataswap.service" in script
    assert "--uid=batataswap --gid=batataswap" in script
    assert 'python -m batataswap "$@"' in script
    # Mesmo como root, comando recusado não pode chegar ao systemd-run.
    fake = tmp_path / "systemd-run"
    fake.write_text("#!/bin/bash\nexit 99\n")
    fake.chmod(0o755)
    for command in ("key-import", "unknown", "--help", ""):
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
    for path in [*SERVICES, *sorted(DEPLOY.glob("*.timer"))]:
        target = tmp_path / path.name
        target.write_text(path.read_text().replace("/opt/batataswap/.venv/bin/python", "/bin/true"))
        units.append(str(target))
    result = subprocess.run([binary, "verify", *units], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
