"""Persists which source IPs each user has logged in from."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def load(path: Path) -> dict[str, set[str]]:
    try:
        raw = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return {user: set(ips) for user, ips in raw.get("known_ips", {}).items()}


def save(path: Path, known_ips: dict[str, set[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".state.")
    with os.fdopen(fd, "w") as fh:
        json.dump({"known_ips": {u: sorted(ips) for u, ips in known_ips.items()}}, fh, indent=2)
    os.replace(tmp, path)
