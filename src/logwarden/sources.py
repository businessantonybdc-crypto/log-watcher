"""Log sources: follow a file (survives logrotate) or read the systemd journal."""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from .parser import Event, parse_line, parse_message


def _now() -> datetime:
    return datetime.now().astimezone()


def read_file(path: Path) -> Iterator[Event]:
    """One-shot: parse an existing log file (also used for testing and backfilling)."""
    now = _now()
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if event := parse_line(line.rstrip("\n"), now):
                yield event


def follow_file(
    path: Path, poll: float = 1.0, from_start: bool = False, stop_after: float | None = None
) -> Iterator[Event]:
    """Like `tail -F`: keeps reading when the file is rotated or truncated."""
    started = time.monotonic()
    fh = None
    inode = None
    while True:
        if fh is None:
            try:
                fh = path.open(encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
                if not from_start:
                    fh.seek(0, os.SEEK_END)
                from_start = True  # after a rotation, read the new file from the beginning
            except FileNotFoundError:
                fh = None
        if fh is not None:
            while line := fh.readline():
                if event := parse_line(line.rstrip("\n"), _now()):
                    yield event
            try:
                st = path.stat()
                if st.st_ino != inode or st.st_size < fh.tell():  # rotated or truncated
                    fh.close()
                    fh = None
                    continue
            except FileNotFoundError:
                fh.close()
                fh = None
        if stop_after is not None and time.monotonic() - started > stop_after:
            return
        time.sleep(poll)


def follow_journal() -> Iterator[Event]:
    """Follow sshd and sudo messages from journald (no auth.log needed)."""
    cmd = ["journalctl", "--follow", "--lines=0", "--output=json", "_COMM=sshd", "_COMM=sshd-session", "_COMM=sudo"]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
        assert proc.stdout is not None
        for raw in proc.stdout:
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            message = entry.get("MESSAGE")
            if not isinstance(message, str):
                continue
            ident = entry.get("SYSLOG_IDENTIFIER", "")
            micros = int(entry.get("__REALTIME_TIMESTAMP", "0"))
            ts = datetime.fromtimestamp(micros / 1_000_000, tz=UTC).astimezone()
            # Prefix the program name so the same patterns work for files and the journal.
            if event := parse_message(f"{ident}: {message}", ts):
                yield event
