"""Command line entry point.

    deception-shield replay  capture.pcap      dissect a capture and report on it
    deception-shield analyse --since 24h       analyse what the sensors indexed
    deception-shield score   --text '...'      check a payload against the rules
    deception-shield extract                   run the capture extraction service
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from deception_shield import __version__
from deception_shield.report import analyse as run_analysis
from deception_shield.report import to_json, to_markdown

log = logging.getLogger("deception_shield")

_DURATION = re.compile(r"^(\d+)([smhdw])$")
_DURATION_UNITS = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
}


def parse_duration(value: str) -> timedelta:
    """Parse a duration such as ``30m``, ``24h`` or ``7d``."""
    match = _DURATION.match(value.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError(
            f"invalid duration {value!r}; use a number followed by s, m, h, d or w"
        )
    amount, unit = int(match.group(1)), match.group(2)
    return timedelta(**{_DURATION_UNITS[unit]: amount})


def _emit(findings, args) -> None:
    rendered = to_json(findings) if args.format == "json" else to_markdown(findings)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(rendered)


def cmd_replay(args: argparse.Namespace) -> int:
    """Dissect one or more captures and report on what they contain."""
    from deception_shield.pcap import TsharkNotAvailable, extract_records

    captures: list[Path] = []
    for target in args.capture:
        path = Path(target)
        if path.is_dir():
            captures.extend(sorted(path.glob("*.pcap*")))
        else:
            captures.append(path)

    missing = [str(c) for c in captures if not c.exists()]
    if missing:
        print(f"no such capture: {', '.join(missing)}", file=sys.stderr)
        return 2
    if not captures:
        print("no captures matched", file=sys.stderr)
        return 2

    records = []
    try:
        for capture in captures:
            found = list(extract_records(capture, sensor_id=args.sensor_id))
            log.info("%s yielded %s records", capture.name, len(found))
            records.extend(found)
    except TsharkNotAvailable as exc:
        print(str(exc), file=sys.stderr)
        return 3

    if args.min_score:
        records = [r for r in records if r.score >= args.min_score]

    _emit(run_analysis(records), args)
    return 0


def cmd_analyse(args: argparse.Namespace) -> int:
    """Analyse telemetry already indexed in Elasticsearch."""
    from deception_shield.es_client import TelemetryStore

    store = TelemetryStore(args.elasticsearch)
    if not store.ping():
        print(f"could not reach elasticsearch at {args.elasticsearch}", file=sys.stderr)
        return 3

    since = datetime.now(timezone.utc) - parse_duration(args.since)
    records = store.fetch_payloads(
        since=since,
        min_score=args.min_score,
        sensor_id=args.sensor_id if args.sensor_id != "unknown" else None,
        limit=args.limit,
    )

    if not records:
        print("no records matched the query", file=sys.stderr)

    _emit(run_analysis(records), args)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    """Check a payload against the signature set."""
    from deception_shield.scoring import score_payload

    if args.text is not None:
        payload: bytes = args.text.encode("utf-8")
    elif args.file:
        payload = Path(args.file).read_bytes()
    else:
        payload = sys.stdin.buffer.read()

    result = score_payload(payload)
    print(f"score      {result.score}")
    print(f"triage     {result.triage.value}")
    print(f"signatures {', '.join(result.signatures) or 'none'}")
    print(f"techniques {', '.join(result.techniques) or 'none'}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    """Run the capture extraction service in the foreground."""
    from deception_shield.extractor import build_from_environment

    build_from_environment().run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deception-shield",
        description="Packet capture dissection and attack pattern analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version=f"deception-shield {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="emit debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["markdown", "json"], default="markdown")
    common.add_argument("-o", "--output", help="write the report to this path")
    common.add_argument("--min-score", type=int, default=0, help="discard records below this score")
    common.add_argument("--sensor-id", default="unknown", help="sensor identifier to attribute records to")

    replay = sub.add_parser("replay", parents=[common], help="dissect captures and report")
    replay.add_argument("capture", nargs="+", help="capture files or a directory of them")
    replay.set_defaults(func=cmd_replay)

    analyse_cmd = sub.add_parser("analyse", parents=[common], aliases=["analyze"], help="analyse indexed telemetry")
    analyse_cmd.add_argument("--elasticsearch", default="http://localhost:9200")
    analyse_cmd.add_argument("--since", default="24h", help="how far back to look, for example 24h or 7d")
    analyse_cmd.add_argument("--limit", type=int, default=None, help="cap the number of records retrieved")
    analyse_cmd.set_defaults(func=cmd_analyse)

    score = sub.add_parser("score", help="score a single payload")
    group = score.add_mutually_exclusive_group()
    group.add_argument("--text", help="payload as a string")
    group.add_argument("--file", help="payload read from a file")
    score.set_defaults(func=cmd_score)

    extract = sub.add_parser("extract", help="run the capture extraction service")
    extract.set_defaults(func=cmd_extract)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(message)s",
        stream=sys.stderr,
    )

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
