"""Alert sinks: Discord webhook and stdout (JSON lines)."""

from __future__ import annotations

import json
import logging
import sys
import urllib.request
from typing import Protocol

from .detector import Alert, Severity

log = logging.getLogger(__name__)

_ICON = {Severity.INFO: ":large_blue_circle:", Severity.WARNING: ":orange_circle:", Severity.CRITICAL: ":red_circle:"}
_COLOR = {Severity.INFO: 0x5865F2, Severity.WARNING: 0xF0A020, Severity.CRITICAL: 0xE03030}


class Sink(Protocol):
    def send(self, alert: Alert, host: str) -> None: ...


class StdoutSink:
    def send(self, alert: Alert, host: str) -> None:
        print(
            json.dumps(
                {
                    "time": alert.time.isoformat(),
                    "host": host,
                    "rule": alert.rule,
                    "severity": alert.severity.value,
                    "ip": alert.ip,
                    "user": alert.user,
                    "message": alert.message,
                }
            ),
            file=sys.stdout,
            flush=True,
        )


class DiscordSink:
    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self.url = webhook_url
        self.timeout = timeout

    def payload(self, alert: Alert, host: str) -> dict:
        return {
            "embeds": [
                {
                    "title": f"{_ICON[alert.severity]} {alert.rule.replace('_', ' ')} on {host}",
                    "description": alert.message,
                    "color": _COLOR[alert.severity],
                    "timestamp": alert.time.isoformat(),
                    "footer": {"text": "log-watcher"},
                }
            ],
            # Usernames and IPs come from attackers: never let them ping @everyone.
            "allowed_mentions": {"parse": []},
        }

    def send(self, alert: Alert, host: str) -> None:
        data = json.dumps(self.payload(alert, host)).encode()
        req = urllib.request.Request(
            self.url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "log-watcher/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout):
                pass
        except OSError as exc:  # never crash the watcher because Discord is down
            log.warning("discord delivery failed: %s", exc)
