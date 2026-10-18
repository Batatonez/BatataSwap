#!/bin/bash
set -euo pipefail
umask 022
if (( EUID != 0 )); then echo 'Execute como root (sudo).' >&2; exit 1; fi
if [[ $# != 1 || ! "$1" =~ ^[a-fA-F0-9]{40}$ ]]; then
    echo 'Uso: atualizar.sh <sha de 40 hex>' >&2; exit 2
fi
sha=${1,,}
cd /opt/batataswap
restart=no
if systemctl is-active --quiet batataswap.service; then restart=yes; fi
systemctl stop batataswap-backup.timer batataswap-restore-test.timer batataswap-cleanup.timer
systemctl stop batataswap-backup.service batataswap-restore-test.service batataswap-cleanup.service batataswap.service
git fetch origin
git checkout --detach "$sha"
[[ $(git rev-parse HEAD) == "$sha" ]]
# Preserva o ambiente antigo para diagnóstico; o novo começa vazio.
if [[ -e .venv ]]; then mv .venv ".venv-anterior-$(date +%s%N)"; fi
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --require-hashes -r requirements-build.lock
.venv/bin/pip install --no-deps --no-build-isolation --no-index .
install -o root -g root -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/
install -o root -g root -m 0755 deploy/batataswap-admin /usr/local/sbin/batataswap-admin
systemctl daemon-reload
batataswap-admin check-config || { echo "Config inválida: corrija /etc/batataswap/batataswap.toml e rode o atualizar de novo"; exit 1; }
batataswap-admin migrate
if [[ "$restart" == yes ]]; then
    systemctl start batataswap.service
    systemctl start batataswap-backup.timer batataswap-restore-test.timer batataswap-cleanup.timer
fi
systemctl --no-pager --lines=8 status batataswap.service || {
    result=$?
    if [[ $result != 3 ]]; then exit "$result"; fi
}
