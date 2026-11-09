#!/usr/bin/env bash
# Installs log-watcher into /opt/log-watcher with its own virtualenv and a locked-down systemd service.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
cd "$(dirname "$0")"

id log-watcher >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin log-watcher
python3 -m venv /opt/log-watcher/venv
/opt/log-watcher/venv/bin/pip install --quiet --upgrade .
install -d -m 0750 -g log-watcher /etc/log-watcher
[[ -e /etc/log-watcher/config.toml ]] || install -m 0640 -g log-watcher config.example.toml /etc/log-watcher/config.toml
install -d -m 0755 /var/lib/node_exporter/textfile_collector
install -m 0644 systemd/log-watcher.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now log-watcher
echo "installed. Discord: put the webhook URL into /etc/log-watcher/discord_webhook (chmod 640, group log-watcher)"
