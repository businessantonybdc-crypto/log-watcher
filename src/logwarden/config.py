"""Loads config.toml into typed settings."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from .detector import Settings


@dataclass
class Config:
    source: str = "journal"  # "journal" or "file"
    log_file: Path = Path("/var/log/auth.log")
    state_file: Path = Path("/var/lib/logwarden/state.json")
    metrics_dir: Path | None = Path("/var/lib/node_exporter/textfile_collector")
    discord_webhook: str | None = None
    host: str = field(default_factory=lambda: os.uname().nodename)
    detector: Settings = field(default_factory=Settings)


def load(path: Path | None) -> Config:
    cfg = Config()
    if path is None:
        return cfg
    data = tomllib.loads(path.read_text())

    src = data.get("source", {})
    cfg.source = src.get("type", cfg.source)
    cfg.log_file = Path(src.get("file", cfg.log_file))

    out = data.get("output", {})
    cfg.state_file = Path(out.get("state_file", cfg.state_file))
    metrics_dir = out.get("metrics_dir", str(cfg.metrics_dir))
    cfg.metrics_dir = Path(metrics_dir) if metrics_dir else None
    cfg.host = out.get("host", cfg.host)
    # Secrets can come from the environment or a file instead of the config.
    cfg.discord_webhook = (
        os.environ.get("LOGWARDEN_DISCORD_WEBHOOK")
        or _read_secret(out.get("discord_webhook_file"))
        or out.get("discord_webhook")
        or None
    )

    d = data.get("detection", {})
    s = cfg.detector
    s.bruteforce_threshold = int(d.get("bruteforce_threshold", s.bruteforce_threshold))
    s.bruteforce_window = timedelta(minutes=float(d.get("bruteforce_window_minutes", 10)))
    s.alert_cooldown = timedelta(minutes=float(d.get("alert_cooldown_minutes", 60)))
    s.success_after_failures = int(d.get("success_after_failures", s.success_after_failures))
    s.ignore_networks = list(d.get("ignore_networks", s.ignore_networks))
    s.alert_on_sudo = bool(d.get("alert_on_sudo", s.alert_on_sudo))
    return cfg


def _read_secret(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return Path(path).read_text().strip() or None
    except FileNotFoundError:
        return None
