"""Prometheus textfile-collector output."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def render(counters: dict[str, int], host: str) -> str:
    lines = [
        "# HELP logwarden_events_total Parsed log events by kind.",
        "# TYPE logwarden_events_total counter",
    ]
    for key in sorted(counters):
        if key.startswith("events_"):
            lines.append(f'logwarden_events_total{{host="{host}",kind="{key[7:]}"}} {counters[key]}')
    lines += [
        "# HELP logwarden_alerts_total Alerts raised by rule.",
        "# TYPE logwarden_alerts_total counter",
    ]
    for key in sorted(counters):
        if key.startswith("alerts_"):
            lines.append(f'logwarden_alerts_total{{host="{host}",rule="{key[7:]}"}} {counters[key]}')
    return "\n".join(lines) + "\n"


def write(directory: Path, counters: dict[str, int], host: str) -> None:
    """Atomic write so node_exporter never reads a half-written file."""
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".logwarden.")
    with os.fdopen(fd, "w") as fh:
        fh.write(render(counters, host))
    os.chmod(tmp, 0o644)
    os.replace(tmp, directory / "logwarden.prom")
