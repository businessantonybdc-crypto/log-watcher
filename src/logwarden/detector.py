"""Stateful detection rules. Pure logic: no I/O, so it is easy to test."""

from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

from .parser import Event, Kind


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: Severity
    message: str
    time: datetime
    ip: str | None = None
    user: str | None = None


@dataclass
class Settings:
    bruteforce_threshold: int = 5  # failures ...
    bruteforce_window: timedelta = timedelta(minutes=10)  # ... within this window
    alert_cooldown: timedelta = timedelta(hours=1)  # don't repeat the same alert sooner
    success_after_failures: int = 3  # login that follows this many failures is suspicious
    ignore_networks: list[str] = field(default_factory=lambda: ["127.0.0.0/8", "::1/128"])
    alert_on_sudo: bool = False  # every sudo command as info alert


class Detector:
    def __init__(self, settings: Settings, known_ips: dict[str, set[str]] | None = None) -> None:
        self.s = settings
        self._ignored = [ipaddress.ip_network(n, strict=False) for n in settings.ignore_networks]
        self._failures: dict[str, deque[datetime]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], datetime] = {}
        # user -> set of source IPs seen in successful logins (persisted between runs)
        self.known_ips: dict[str, set[str]] = known_ips if known_ips is not None else {}
        self.counters: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------ helpers

    def _is_ignored(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._ignored)

    def _recent_failures(self, ip: str, now: datetime) -> int:
        q = self._failures[ip]
        while q and now - q[0] > self.s.bruteforce_window:
            q.popleft()
        return len(q)

    def _cooldown_ok(self, rule: str, key: str, now: datetime) -> bool:
        last = self._last_alert.get((rule, key))
        if last is not None and now - last < self.s.alert_cooldown:
            return False
        self._last_alert[(rule, key)] = now
        return True

    # --------------------------------------------------------------------- main

    def process(self, event: Event) -> list[Alert]:
        self.counters[f"events_{event.kind.value}"] += 1
        if self._is_ignored(event.ip):
            return []
        alerts: list[Alert] = []

        if event.kind is Kind.FAILED and event.ip:
            self._failures[event.ip].append(event.time)
            count = self._recent_failures(event.ip, event.time)
            if count >= self.s.bruteforce_threshold and self._cooldown_ok("bruteforce", event.ip, event.time):
                minutes = int(self.s.bruteforce_window.total_seconds() // 60)
                alerts.append(
                    Alert(
                        "bruteforce",
                        Severity.WARNING,
                        f"{count} failed SSH logins from {event.ip} in {minutes} min (last user: {event.user})",
                        event.time,
                        ip=event.ip,
                        user=event.user,
                    )
                )

        elif event.kind is Kind.ACCEPTED and event.ip:
            failures = self._recent_failures(event.ip, event.time)
            if failures >= self.s.success_after_failures:
                alerts.append(
                    Alert(
                        "success_after_failures",
                        Severity.CRITICAL,
                        f"{event.user} logged in from {event.ip} after {failures} failed attempts, "
                        "possibly a guessed password",
                        event.time,
                        ip=event.ip,
                        user=event.user,
                    )
                )
            seen = self.known_ips.setdefault(event.user, set())
            # The first login of a user is learned silently; after that, new sources are reported.
            if seen and event.ip not in seen:
                alerts.append(
                    Alert(
                        "new_source_ip",
                        Severity.INFO,
                        f"{event.user} logged in from a new address {event.ip} ({event.method})",
                        event.time,
                        ip=event.ip,
                        user=event.user,
                    )
                )
            seen.add(event.ip)
            self._failures.pop(event.ip, None)

        elif event.kind is Kind.SUDO_FAILED:
            if self._cooldown_ok("sudo_failed", event.user, event.time):
                alerts.append(
                    Alert(
                        "sudo_failed",
                        Severity.WARNING,
                        f"{event.user} entered a wrong sudo password ({event.detail})",
                        event.time,
                        user=event.user,
                    )
                )

        elif event.kind is Kind.SUDO and self.s.alert_on_sudo:
            alerts.append(
                Alert("sudo", Severity.INFO, f"{event.user} ran: {event.detail}", event.time, user=event.user)
            )

        for alert in alerts:
            self.counters[f"alerts_{alert.rule}"] += 1
        return alerts
