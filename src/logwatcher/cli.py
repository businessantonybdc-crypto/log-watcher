"""Command line entry point."""

from __future__ import annotations

import argparse
import contextlib
import logging
import signal
import sys
import time
from collections.abc import Iterable
from pathlib import Path

from . import __version__, metrics, state
from .alerts import DiscordSink, Sink, StdoutSink
from .config import Config, load
from .detector import Detector
from .parser import Event
from .sources import follow_file, follow_journal, read_file

log = logging.getLogger("log-watcher")


def run(events: Iterable[Event], cfg: Config, sinks: list[Sink], persist: bool = True) -> Detector:
    detector = Detector(cfg.detector, known_ips=state.load(cfg.state_file) if persist else {})
    last_flush = 0.0
    try:
        for event in events:
            for alert in detector.process(event):
                for sink in sinks:
                    sink.send(alert, cfg.host)
            if time.monotonic() - last_flush > 15:
                _flush(detector, cfg, persist)
                last_flush = time.monotonic()
    finally:
        _flush(detector, cfg, persist)
    return detector


def _flush(detector: Detector, cfg: Config, persist: bool) -> None:
    if cfg.metrics_dir:
        try:
            metrics.write(cfg.metrics_dir, detector.counters, cfg.host)
        except OSError as exc:
            log.warning("could not write metrics: %s", exc)
    if persist:
        try:
            state.save(cfg.state_file, detector.known_ips)
        except OSError as exc:
            log.warning("could not save state: %s", exc)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="log-watcher", description=__doc__)
    p.add_argument("-c", "--config", type=Path, help="path to config.toml")
    p.add_argument(
        "--scan", type=Path, metavar="LOGFILE", help="analyse an existing log file once and exit (no state, no Discord)"
    )
    p.add_argument("--dry-run", action="store_true", help="print alerts instead of sending them")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    cfg = load(args.config)
    # SIGTERM from systemd: leave the loop through the finally block, so state is saved.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    if args.scan:
        cfg.metrics_dir = None
        detector = run(read_file(args.scan), cfg, [StdoutSink()], persist=False)
        summary = ", ".join(f"{k}={v}" for k, v in sorted(detector.counters.items()))
        print(f"# {summary}", file=sys.stderr)
        return 0

    sinks: list[Sink] = [StdoutSink()]
    if cfg.discord_webhook and not args.dry_run:
        sinks.append(DiscordSink(cfg.discord_webhook))
    source = follow_journal() if cfg.source == "journal" else follow_file(cfg.log_file)
    log.info("watching %s", "journald" if cfg.source == "journal" else cfg.log_file)
    with contextlib.suppress(KeyboardInterrupt):
        run(source, cfg, sinks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
