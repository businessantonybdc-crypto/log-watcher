"""Turns raw sshd / sudo log lines into structured events."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Kind(StrEnum):
    FAILED = "failed"  # wrong password / key, or unknown user
    ACCEPTED = "accepted"  # successful login
    SUDO = "sudo"  # command run with sudo
    SUDO_FAILED = "sudo_failed"  # wrong sudo password


@dataclass(frozen=True)
class Event:
    kind: Kind
    time: datetime
    user: str
    ip: str | None = None
    method: str | None = None
    invalid_user: bool = False
    detail: str | None = None


_IP = r"(?P<ip>[0-9a-fA-F:.]+)"

_SSHD_PATTERNS: list[tuple[Kind, re.Pattern[str]]] = [
    (Kind.ACCEPTED, re.compile(rf"Accepted (?P<method>\S+) for (?P<user>\S+) from {_IP} port \d+")),
    (
        Kind.FAILED,
        re.compile(rf"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from {_IP} port \d+"),
    ),
    (Kind.FAILED, re.compile(rf"Invalid user (?P<user>\S*) from {_IP} port \d+")),
]

_SUDO_CMD = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*?COMMAND=(?P<cmd>.+)$")
_SUDO_FAIL = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?")

# "Nov  9 10:15:01 host sshd[812]: ..."   classic syslog
_SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ ")
# "2026-11-09T10:15:01.123456+01:00 host sshd[812]: ..."   rsyslog high precision (Ubuntu 24.04 default)
_ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)) \S+ ")


def parse_timestamp(line: str, now: datetime) -> datetime | None:
    if m := _ISO_TS.match(line):
        return datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
    if m := _SYSLOG_TS.match(line):
        ts = datetime.strptime(f"{now.year} {m['ts']}", "%Y %b %d %H:%M:%S")
        ts = ts.replace(tzinfo=now.tzinfo)
        # Syslog has no year: a December line read in January belongs to last year.
        if ts > now and (ts - now).days > 1:
            ts = ts.replace(year=now.year - 1)
        return ts
    return None


def parse_message(message: str, time: datetime) -> Event | None:
    """Parse the message part of a log line (works for auth.log lines and bare journald messages)."""
    for kind, pattern in _SSHD_PATTERNS:
        if m := pattern.search(message):
            g = m.groupdict()
            if g.get("invalid"):
                # sshd logs "Invalid user X from ..." first and then "Failed password for invalid user X".
                # The first line is already counted; counting both would double every attempt.
                return None
            return Event(
                kind=kind,
                time=time,
                user=g["user"] or "<empty>",
                ip=g["ip"],
                method=g.get("method"),
                invalid_user=pattern is _SSHD_PATTERNS[2][1],
            )
    if m := _SUDO_FAIL.search(message):
        return Event(Kind.SUDO_FAILED, time, m["user"], detail=f"{m['n']} attempts")
    if m := _SUDO_CMD.search(message):
        return Event(Kind.SUDO, time, m["user"], detail=m["cmd"].strip())
    return None


def parse_line(line: str, now: datetime) -> Event | None:
    """Parse a full line from /var/log/auth.log (syslog or ISO timestamps)."""
    time = parse_timestamp(line, now)
    if time is None:
        return None
    return parse_message(line, time)
