from datetime import datetime, timedelta, timezone

from logwatcher.parser import Kind, parse_line, parse_message

TZ = timezone(timedelta(hours=1))
NOW = datetime(2026, 11, 9, 12, 0, tzinfo=TZ)


def test_invalid_user_is_a_failure():
    e = parse_line("Nov  9 10:00:01 mc-01 sshd[1]: Invalid user admin from 203.0.113.50 port 5", NOW)
    assert e and e.kind is Kind.FAILED and e.user == "admin" and e.ip == "203.0.113.50" and e.invalid_user


def test_failed_password_for_invalid_user_is_not_counted_twice():
    line = "Nov  9 10:00:03 mc-01 sshd[1]: Failed password for invalid user admin from 203.0.113.50 port 5 ssh2"
    assert parse_line(line, NOW) is None


def test_failed_password_for_existing_user():
    e = parse_line("Nov  9 10:00:03 mc-01 sshd[1]: Failed password for ops from 198.51.100.7 port 4 ssh2", NOW)
    assert e and e.kind is Kind.FAILED and e.user == "ops" and e.method == "password" and not e.invalid_user


def test_accepted_publickey_iso_timestamp():
    line = (
        "2026-11-09T10:05:00.123+01:00 mc-01 sshd[1]: Accepted publickey for ops from 192.168.1.10 "
        "port 50022 ssh2: ED25519 SHA256:abc"
    )
    e = parse_line(line, NOW)
    assert e and e.kind is Kind.ACCEPTED and e.method == "publickey"
    assert e.time == datetime(2026, 11, 9, 10, 5, 0, 123000, tzinfo=TZ)


def test_ipv6_address():
    e = parse_line("Nov  9 10:00:01 h sshd[1]: Invalid user x from 2001:db8::1 port 5", NOW)
    assert e and e.ip == "2001:db8::1"


def test_sudo_command_and_failure():
    ok = parse_line("Nov  9 10:11:00 h sudo[2]:      ops : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id", NOW)
    assert ok and ok.kind is Kind.SUDO and ok.detail == "/usr/bin/id"
    bad = parse_line("Nov  9 10:10:00 h sudo[2]:      ops : 3 incorrect password attempts ; TTY=pts/0", NOW)
    assert bad and bad.kind is Kind.SUDO_FAILED and bad.detail == "3 attempts"


def test_journald_message_without_header():
    e = parse_message("sshd: Accepted publickey for ops from 10.0.0.2 port 22 ssh2", NOW)
    assert e and e.kind is Kind.ACCEPTED and e.ip == "10.0.0.2"


def test_unrelated_lines_are_ignored():
    assert parse_line("Nov  9 10:00:00 h CRON[1]: pam_unix(cron:session): session opened", NOW) is None
    assert parse_line("garbage without timestamp", NOW) is None


def test_syslog_year_rollover():
    january = datetime(2027, 1, 1, 0, 5, tzinfo=TZ)
    e = parse_line("Dec 31 23:59:00 h sshd[1]: Invalid user a from 203.0.113.9 port 1", january)
    assert e and e.time.year == 2026
