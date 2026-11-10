#!/usr/bin/env bash
# Installs logwarden into /opt/logwarden with its own virtualenv and a locked-down systemd service.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
cd "$(dirname "$0")"

id logwarden >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin logwarden
python3 -m venv /opt/logwarden/venv
/opt/logwarden/venv/bin/pip install --quiet --upgrade .
install -d -m 0750 -g logwarden /etc/logwarden
[[ -e /etc/logwarden/config.toml ]] || install -m 0640 -g logwarden config.example.toml /etc/logwarden/config.toml
install -d -m 0755 /var/lib/node_exporter/textfile_collector
install -m 0644 systemd/logwarden.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now logwarden
echo "installed. Discord: put the webhook URL into /etc/logwarden/discord_webhook (chmod 640, group logwarden)"
