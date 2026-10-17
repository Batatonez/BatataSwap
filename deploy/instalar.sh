#!/bin/bash
set -euo pipefail
umask 022
if (( EUID != 0 )); then echo 'Execute como root (sudo).' >&2; exit 1; fi
. /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 ]]; then
    echo 'É necessário Ubuntu 24.04.' >&2; exit 1
fi
if [[ $# != 1 || ! "$1" =~ ^[a-fA-F0-9]{40}$ ]]; then
    echo 'Uso: instalar.sh <sha de 40 hex>' >&2; exit 2
fi
sha=${1,,}
apt-get update
apt-get install -y git python3.12-venv
if ! getent passwd batataswap >/dev/null; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin batataswap
fi
install -d -o root -g root -m 0700 /etc/credstore.encrypted
install -d -o root -g batataswap -m 0750 /etc/batataswap
install -d -o batataswap -g batataswap -m 0700 /var/backups/batataswap
if [[ ! -d /opt/batataswap/.git ]]; then
    git clone --no-checkout -- https://github.com/Batatonez/BatataSwap /opt/batataswap
fi
git -C /opt/batataswap fetch origin
git -C /opt/batataswap checkout --detach "$sha"
[[ $(git -C /opt/batataswap rev-parse HEAD) == "$sha" ]]
chown -R root:root /opt/batataswap
cd /opt/batataswap
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --require-hashes -r requirements-build.lock
.venv/bin/pip install --no-deps --no-build-isolation --no-index .
install -o root -g root -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/
install -o root -g root -m 0755 deploy/batataswap-admin /usr/local/sbin/batataswap-admin
if [[ ! -e /etc/batataswap/batataswap.toml ]]; then
    install -o root -g batataswap -m 0640 deploy/batataswap.toml.exemplo /etc/batataswap/batataswap.toml
fi
systemctl daemon-reload
echo 'Instalado. Edite o TOML e execute key-init como root e init pelo wrapper antes de habilitar o serviço.'
