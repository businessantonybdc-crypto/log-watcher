import json
import threading
import time
from datetime import UTC
from pathlib import Path

from logwarden import metrics, state
from logwarden.alerts import DiscordSink
from logwarden.cli import main
from logwarden.detector import Alert, Severity
from logwarden.sources import follow_file

FIXTURE = Path(__file__).parent / "fixtures" / "auth.log"
LINE = "2026-11-09T10:00:0{i}.000000+01:00 h sshd[1]: Invalid user u{i} from 203.0.113.{i} port 1\n"


def test_scan_fixture_end_to_end(capsys):
    assert main(["--scan", str(FIXTURE)]) == 0
    out = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [a["rule"] for a in out] == ["bruteforce", "success_after_failures", "new_source_ip", "sudo_failed"]
    assert out[0]["ip"] == "203.0.113.50"
    # 6 "Invalid user" lines, the duplicate "Failed ... invalid user" line is not counted


def test_follow_survives_rotation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    seen = []

    def writer():
        time.sleep(0.3)
        with log.open("a") as fh:
            fh.write(LINE.format(i=1))
        time.sleep(0.3)
        log.rename(tmp_path / "auth.log.1")  # logrotate
        log.write_text(LINE.format(i=2))
        time.sleep(0.3)
        with log.open("a") as fh:
            fh.write(LINE.format(i=3))

    t = threading.Thread(target=writer)
    t.start()
    for event in follow_file(log, poll=0.05, stop_after=1.5):
        seen.append(event.ip)
    t.join()
    assert seen == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]


def test_metrics_render_and_atomic_write(tmp_path):
    counters = {"events_failed": 7, "alerts_bruteforce": 1}
    metrics.write(tmp_path, counters, "mc-01")
    text = (tmp_path / "logwarden.prom").read_text()
    assert 'logwarden_events_total{host="mc-01",kind="failed"} 7' in text
    assert 'logwarden_alerts_total{host="mc-01",rule="bruteforce"} 1' in text
    assert [p.name for p in tmp_path.iterdir()] == ["logwarden.prom"]  # no temp files left


def test_state_roundtrip(tmp_path):
    path = tmp_path / "state.json"
    state.save(path, {"ops": {"10.0.0.1", "10.0.0.2"}})
    assert state.load(path) == {"ops": {"10.0.0.1", "10.0.0.2"}}
    assert state.load(tmp_path / "missing.json") == {}


def test_discord_payload_never_pings_anyone():
    from datetime import datetime

    alert = Alert("bruteforce", Severity.WARNING, "@everyone 5 failures", datetime.now(UTC))
    payload = DiscordSink("https://example.invalid").payload(alert, "mc-01")
    assert payload["allowed_mentions"] == {"parse": []}
    assert payload["embeds"][0]["title"].endswith("bruteforce on mc-01")
