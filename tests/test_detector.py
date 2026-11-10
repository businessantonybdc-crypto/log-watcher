from datetime import UTC, datetime, timedelta

from logwarden.detector import Detector, Settings, Severity
from logwarden.parser import Event, Kind

T0 = datetime(2026, 11, 9, 10, 0, tzinfo=UTC)


def fail(ip: str, t: datetime, user: str = "root") -> Event:
    return Event(Kind.FAILED, t, user, ip=ip, method="password")


def ok(ip: str, t: datetime, user: str = "ops") -> Event:
    return Event(Kind.ACCEPTED, t, user, ip=ip, method="publickey")


def rules(alerts):
    return [a.rule for a in alerts]


def test_bruteforce_fires_at_threshold():
    d = Detector(Settings(bruteforce_threshold=5))
    out = [d.process(fail("203.0.113.5", T0 + timedelta(seconds=i))) for i in range(5)]
    assert all(not a for a in out[:4])
    assert rules(out[4]) == ["bruteforce"]


def test_failures_outside_window_do_not_count():
    d = Detector(Settings(bruteforce_threshold=3, bruteforce_window=timedelta(minutes=10)))
    d.process(fail("203.0.113.5", T0))
    d.process(fail("203.0.113.5", T0 + timedelta(minutes=11)))
    assert d.process(fail("203.0.113.5", T0 + timedelta(minutes=12))) == []


def test_cooldown_suppresses_repeats():
    d = Detector(Settings(bruteforce_threshold=2, alert_cooldown=timedelta(hours=1)))
    alerts = []
    for i in range(10):
        alerts += d.process(fail("203.0.113.5", T0 + timedelta(seconds=i)))
    assert rules(alerts) == ["bruteforce"]
    # after the cooldown it reports again
    later = T0 + timedelta(hours=1, seconds=5)
    d.process(fail("203.0.113.5", later))
    assert rules(d.process(fail("203.0.113.5", later + timedelta(seconds=1)))) == ["bruteforce"]


def test_success_after_failures_is_critical():
    d = Detector(Settings(success_after_failures=3, bruteforce_threshold=99))
    for i in range(3):
        d.process(fail("198.51.100.7", T0 + timedelta(seconds=i), user="ops"))
    alerts = d.process(ok("198.51.100.7", T0 + timedelta(seconds=10)))
    crit = [a for a in alerts if a.rule == "success_after_failures"]
    assert crit and crit[0].severity is Severity.CRITICAL


def test_new_source_ip_after_first_login():
    d = Detector(Settings())
    assert d.process(ok("192.168.1.10", T0)) == []  # learned silently
    assert d.process(ok("192.168.1.10", T0 + timedelta(1))) == []
    assert rules(d.process(ok("198.51.100.99", T0 + timedelta(2)))) == ["new_source_ip"]


def test_known_ips_are_restored_from_state():
    d = Detector(Settings(), known_ips={"ops": {"192.168.1.10"}})
    assert rules(d.process(ok("198.51.100.99", T0))) == ["new_source_ip"]


def test_ignored_networks():
    d = Detector(Settings(bruteforce_threshold=1, ignore_networks=["192.168.1.0/24"]))
    assert d.process(fail("192.168.1.77", T0)) == []
    assert rules(d.process(fail("203.0.113.1", T0))) == ["bruteforce"]


def test_counters():
    d = Detector(Settings(bruteforce_threshold=2))
    d.process(fail("203.0.113.5", T0))
    d.process(fail("203.0.113.5", T0))
    assert d.counters["events_failed"] == 2
    assert d.counters["alerts_bruteforce"] == 1
