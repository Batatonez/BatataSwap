#!/bin/bash
set -euo pipefail
if (( EUID != 0 )); then echo 'Execute como root (sudo).' >&2; exit 1; fi
cd /opt/batataswap
branch=$(git symbolic-ref --short HEAD)
git pull --ff-only origin "$branch"
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --no-deps .
install -o root -g root -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/
install -o root -g root -m 0755 deploy/batataswap-admin /usr/local/sbin/batataswap-admin
systemctl daemon-reload
if systemctl is-active --quiet batataswap.service; then systemctl restart batataswap.service; fi
systemctl --no-pager --lines=8 status batataswap.service || {
    result=$?
    if [[ $result != 3 ]]; then exit "$result"; fi
}
