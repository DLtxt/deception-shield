"""Command line entry point.

    deception-shield replay  capture.pcap      dissect a capture and report on it
    deception-shield analyse --since 24h       analyse what the sensors indexed
    deception-shield score   --text '...'      check a payload against the rules
    deception-shield extract                   run the capture extraction service

Detection as code:

    deception-shield sessions build LOGS       assemble Cowrie command sessions
    deception-shield sessions import-history   turn shell history into a benign baseline
    deception-shield sessions stats CORPUS     describe a session corpus
    deception-shield label CORPUS              label session families by hand
    deception-shield rules check               validate the Sigma rules for both engines
    deception-shield rules test                run the rules through the CI fixture gate
    deception-shield detect CORPUS             run the rules over a corpus
    deception-shield evaluate CORPUS           measure the rules on a held-out window
    deception-shield fixtures export CORPUS    commit labelled sessions as fixtures
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from deception_shield import __version__
from deception_shield.report import analyse as run_analysis
from deception_shield.report import to_json, to_markdown

log = logging.getLogger("deception_shield")

# Rules, pipeline, fixtures and thresholds live beside the package in a checkout.
DETECTIONS_DIR = Path(__file__).resolve().parents[2] / "detections"

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


# ------------------------------------------------------------ detection as code


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text, encoding="utf-8")
        print(f"wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _load_rules(directory: str):
    from deception_shield.sigma import SigmaError, load_rules

    try:
        return load_rules(directory)
    except SigmaError as exc:
        print(f"the rule set did not load:\n{exc}", file=sys.stderr)
        return None


def _load_corpus(paths: list[str]):
    from deception_shield.sessions import read_sessions

    missing = [p for p in paths if not Path(p).is_file()]
    if missing:
        print(f"no such corpus: {', '.join(missing)}", file=sys.stderr)
        return None
    try:
        return read_sessions([Path(p) for p in paths])
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return None


def cmd_sessions_build(args: argparse.Namespace) -> int:
    """Assemble command sessions from Cowrie logs or from Elasticsearch."""
    from deception_shield.sessions import CowrieSessionAssembler, build_sessions, write_sessions

    if bool(args.logs) == bool(args.elasticsearch):
        print(
            "give Cowrie log files or directories, or --elasticsearch, but not both",
            file=sys.stderr,
        )
        return 2

    if args.elasticsearch:
        from deception_shield.es_client import TelemetryStore

        store = TelemetryStore(args.elasticsearch)
        if not store.ping():
            print(f"could not reach elasticsearch at {args.elasticsearch}", file=sys.stderr)
            return 3
        assembler = CowrieSessionAssembler(sensor_id=args.sensor_id)
        since = datetime.now(timezone.utc) - parse_duration(args.since)
        for event in store.fetch_session_events(since=since, sensor_id=args.sensor_id):
            assembler.add(event)
        sessions = assembler.sessions()
        source = f"{assembler.events:,} events from {args.elasticsearch}"
    else:
        paths = [Path(p) for p in args.logs]
        missing = [str(p) for p in paths if not p.exists()]
        if missing:
            print(f"no such log: {', '.join(missing)}", file=sys.stderr)
            return 2
        assembly = build_sessions(paths, sensor_id=args.sensor_id)
        sessions = assembly.sessions
        source = f"{assembly.events:,} events in {assembly.files} file(s)"
        if assembly.skipped:
            source += f", {assembly.skipped:,} malformed events skipped"

    count = write_sessions(Path(args.output), sessions)
    print(f"wrote {count:,} command sessions to {args.output} ({source})", file=sys.stderr)
    return 0


def cmd_sessions_import_history(args: argparse.Namespace) -> int:
    """Turn shell history from a host you control into benign sessions."""
    from deception_shield.sessions import import_shell_history, read_sessions, write_sessions

    try:
        sessions = import_shell_history(
            [Path(p) for p in args.history],
            host=args.host,
            user=args.user,
            idle=parse_duration(args.idle),
        )
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output = Path(args.output)
    if args.append and output.exists():
        imported = {s.id for s in sessions}
        sessions = [s for s in read_sessions([output]) if s.id not in imported] + sessions
        sessions.sort(key=lambda s: (s.start, s.id))

    count = write_sessions(output, sessions)
    print(f"wrote {count:,} benign sessions to {args.output}", file=sys.stderr)
    return 0


def cmd_sessions_stats(args: argparse.Namespace) -> int:
    """Describe a corpus: how many sessions, over how long, from where."""
    from deception_shield.sessions import corpus_stats, stats_to_markdown

    sessions = _load_corpus(args.corpus)
    if sessions is None:
        return 2
    stats = corpus_stats(sessions)
    _write(
        json.dumps(stats, indent=2) if args.format == "json" else stats_to_markdown(stats),
        args.output,
    )
    return 0


def cmd_label(args: argparse.Namespace) -> int:
    """Label sessions, a family at a time or all at once."""
    from deception_shield.labels import label_all, label_interactively, parse_techniques

    sessions = _load_corpus(args.corpus)
    if sessions is None:
        return 2
    if args.origin:
        sessions = [s for s in sessions if s.origin == args.origin]

    labels_path = Path(args.labels)
    if args.all:
        try:
            techniques = parse_techniques(args.techniques or "")
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        count = label_all(
            sessions, labels_path, args.all, techniques=techniques, note=args.note or ""
        )
    else:
        ruleset = _load_rules(args.rules) if Path(args.rules).is_dir() else None
        count = label_interactively(
            sessions, labels_path, techniques=ruleset.techniques if ruleset else ()
        )

    print(f"labelled {count:,} session(s) in {args.labels}", file=sys.stderr)
    return 0


def cmd_rules_check(args: argparse.Namespace) -> int:
    """Validate every rule, and check that it converts faithfully for Elasticsearch."""
    from deception_shield.sigma import pipeline_fields, portability_problems

    ruleset = _load_rules(args.rules)
    if ruleset is None:
        return 1

    fields = None
    if args.pipeline:
        if Path(args.pipeline).is_file():
            fields = pipeline_fields(args.pipeline)
        else:
            print(f"no pipeline at {args.pipeline}; field mapping not checked", file=sys.stderr)
    problems = [
        problem for rule in ruleset for problem in portability_problems(rule, fields=fields)
    ]

    if args.format == "json":
        _write(
            json.dumps(
                {
                    "summary": ruleset.describe(),
                    "fingerprint": ruleset.fingerprint,
                    "techniques": list(ruleset.techniques),
                    "rules": [
                        {
                            "id": rule.id,
                            "title": rule.title,
                            "file": rule.source,
                            "level": rule.level,
                            "status": rule.status,
                            "techniques": list(rule.techniques),
                            "tactics": list(rule.tactics),
                        }
                        for rule in ruleset
                    ],
                    "problems": problems,
                },
                indent=2,
            ),
            args.output,
        )
    else:
        lines = [
            f"{ruleset.describe()}, rule set {ruleset.fingerprint[:12]}",
            "",
            "| Rule | Technique | Tactic | Level | File |",
            "| --- | --- | --- | --- | --- |",
        ]
        for rule in sorted(ruleset, key=lambda r: (r.techniques, r.title)):
            lines.append(
                f"| {rule.title} | {', '.join(rule.techniques)} | {', '.join(rule.tactics)} "
                f"| {rule.level} | {rule.source} |"
            )
        if problems:
            lines += [
                "",
                "Would not convert faithfully for Elasticsearch:",
                *(f"- {p}" for p in problems),
            ]
        _write("\n".join(lines), args.output)

    return 1 if problems else 0


def cmd_rules_test(args: argparse.Namespace) -> int:
    """Run the rules through the fixture gate; non-zero exit fails the build."""
    from deception_shield.fixtures import (
        Thresholds,
        gate_to_markdown,
        load_fixtures,
        load_thresholds,
        run_gate,
    )

    ruleset = _load_rules(args.rules)
    if ruleset is None:
        return 1
    if not Path(args.fixtures).is_dir():
        print(f"no fixtures directory at {args.fixtures}", file=sys.stderr)
        return 2
    try:
        fixtures = load_fixtures(Path(args.fixtures))
        thresholds = (
            load_thresholds(Path(args.thresholds))
            if Path(args.thresholds).is_file()
            else Thresholds()
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    result = run_gate(fixtures, ruleset, thresholds)
    report = gate_to_markdown(result)
    _write(report, args.output)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.step_summary and summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(report)
    return 0 if result.passed else 1


def cmd_detect(args: argparse.Namespace) -> int:
    """Run the rules over a corpus and list what alerted."""
    from deception_shield.detection import detect, detections_to_json, detections_to_markdown

    ruleset = _load_rules(args.rules)
    sessions = _load_corpus(args.corpus)
    if ruleset is None or sessions is None:
        return 2
    results = detect(sessions, ruleset)
    if args.format == "json":
        _write(detections_to_json(sessions, results, ruleset), args.output)
    else:
        _write(detections_to_markdown(sessions, results, ruleset), args.output)
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    """Measure the rules on a held-out window against labelled sessions."""
    from deception_shield.evaluation import evaluate, parse_window
    from deception_shield.evaluation import to_json as evaluation_json
    from deception_shield.evaluation import to_markdown as evaluation_markdown
    from deception_shield.labels import read_labels

    try:
        window = parse_window(args.holdout)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    ruleset = _load_rules(args.rules)
    sessions = _load_corpus(args.corpus)
    if ruleset is None or sessions is None:
        return 2
    labels_path = Path(args.labels)
    if not labels_path.is_file():
        print(f"no labels at {args.labels}; label the corpus first", file=sys.stderr)
        return 2
    try:
        labels = read_labels(labels_path)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    evaluation = evaluate(
        sessions, labels, ruleset, window, inputs=[*(Path(p) for p in args.corpus), labels_path]
    )
    if args.format == "json":
        _write(evaluation_json(evaluation), args.output)
    else:
        _write(evaluation_markdown(evaluation, details=args.details), args.output)
    return 0


def cmd_fixtures_export(args: argparse.Namespace) -> int:
    """Export labelled sessions from the tuning weeks as committed fixtures."""
    from deception_shield.evaluation import parse_window
    from deception_shield.fixtures import Sanitiser, select_fixtures, write_fixtures
    from deception_shield.labels import read_labels

    if not args.holdout and not args.no_holdout:
        print(
            "give --holdout with the evaluation window so none of it becomes a fixture, "
            "or --no-holdout if there is none",
            file=sys.stderr,
        )
        return 2
    try:
        window = parse_window(args.holdout) if args.holdout else None
        replacements = dict(item.split("=", 1) for item in args.replace)
    except ValueError as exc:
        print(f"{exc}; --replace takes OLD=NEW", file=sys.stderr)
        return 2

    sessions = _load_corpus(args.corpus)
    if sessions is None:
        return 2
    labels = read_labels(Path(args.labels))

    provenance = args.provenance or f"captured:{datetime.now(timezone.utc):%Y-%m-%d}"
    fixtures = select_fixtures(
        sessions,
        labels,
        per_family=args.per_family,
        exclude=window,
        provenance=provenance,
        sanitiser=Sanitiser(replacements),
    )

    root = Path(args.fixtures)
    for label in ("attack", "benign"):
        chosen = [f for f in fixtures if f.label == label]
        if not chosen:
            continue
        path = root / label / f"{args.name}.jsonl"
        total, added = write_fixtures(path, chosen)
        print(f"{path}: {added} new, {total} in file", file=sys.stderr)
    if not fixtures:
        print("no labelled sessions outside the held-out window to export", file=sys.stderr)
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

    _add_detection_commands(sub)
    return parser


def _add_detection_commands(sub: argparse._SubParsersAction) -> None:
    output = argparse.ArgumentParser(add_help=False)
    output.add_argument("--format", choices=["markdown", "json"], default="markdown")
    output.add_argument("-o", "--output", help="write to this path instead of standard output")

    rules_option = argparse.ArgumentParser(add_help=False)
    rules_option.add_argument(
        "--rules", default=str(DETECTIONS_DIR / "sigma"), help="directory of Sigma rules"
    )

    # sessions
    sessions = sub.add_parser("sessions", help="build and describe session corpora")
    sessions_sub = sessions.add_subparsers(dest="sessions_command", required=True)

    build = sessions_sub.add_parser("build", help="assemble Cowrie command sessions")
    build.add_argument("logs", nargs="*", help="Cowrie JSON logs, or directories of them")
    build.add_argument(
        "--elasticsearch", help="read Cowrie events from this cluster instead of files"
    )
    build.add_argument(
        "--since", default="28d", help="with --elasticsearch, how far back to look (default 28d)"
    )
    build.add_argument(
        "--sensor-id",
        help="sensor the sessions belong to; with --elasticsearch, fetch only that sensor's",
    )
    build.add_argument("-o", "--output", required=True, help="corpus file to write")
    build.set_defaults(func=cmd_sessions_build)

    history = sessions_sub.add_parser(
        "import-history", help="benign sessions from timestamped shell history"
    )
    history.add_argument("history", nargs="+", help="bash or zsh history files")
    history.add_argument("--host", required=True, help="name of the host the history came from")
    history.add_argument("--user", help="account the history belongs to")
    history.add_argument("--idle", default="30m", help="pause that ends a session (default 30m)")
    history.add_argument("--append", action="store_true", help="merge into an existing corpus file")
    history.add_argument("-o", "--output", required=True, help="corpus file to write")
    history.set_defaults(func=cmd_sessions_import_history)

    stats = sessions_sub.add_parser("stats", parents=[output], help="describe a corpus")
    stats.add_argument("corpus", nargs="+")
    stats.set_defaults(func=cmd_sessions_stats)

    # labelling
    label = sub.add_parser(
        "label", parents=[rules_option], help="label sessions, a family at a time"
    )
    label.add_argument("corpus", nargs="+")
    label.add_argument("--labels", required=True, help="label CSV, created when missing")
    label.add_argument("--origin", help="only sessions of this origin: cowrie or shell-history")
    label.add_argument(
        "--all", choices=["attack", "benign", "exclude"], help="label every unlabelled session"
    )
    label.add_argument(
        "--techniques", help="with --all, techniques to record, such as T1105;T1059.004"
    )
    label.add_argument("--note", help="with --all, a note stored with each label")
    label.set_defaults(func=cmd_label)

    # rules
    rules = sub.add_parser(
        "rules", help="validate the Sigma rules and run them through the fixture gate"
    )
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)

    check = rules_sub.add_parser(
        "check", parents=[output, rules_option], help="validate the rules for both engines"
    )
    check.add_argument(
        "--pipeline",
        default=str(DETECTIONS_DIR / "pipelines" / "cowrie-ecs.yml"),
        help="sigma-cli pipeline whose field mapping every rule field must appear in",
    )
    check.set_defaults(func=cmd_rules_check)

    test = rules_sub.add_parser("test", parents=[rules_option], help="run the CI fixture gate")
    test.add_argument(
        "--fixtures", default=str(DETECTIONS_DIR / "fixtures"), help="directory of fixture files"
    )
    test.add_argument(
        "--thresholds", default=str(DETECTIONS_DIR / "thresholds.yml"), help="gate thresholds"
    )
    test.add_argument(
        "-o", "--output", help="write the report to this path instead of standard output"
    )
    test.add_argument(
        "--step-summary", action="store_true", help="also append the report to $GITHUB_STEP_SUMMARY"
    )
    test.set_defaults(func=cmd_rules_test)

    # running and measuring
    detect = sub.add_parser(
        "detect", parents=[output, rules_option], help="run the rules over a corpus"
    )
    detect.add_argument("corpus", nargs="+")
    detect.set_defaults(func=cmd_detect)

    evaluate = sub.add_parser(
        "evaluate", parents=[output, rules_option], help="measure the rules on a held-out window"
    )
    evaluate.add_argument("corpus", nargs="+", help="honeypot and benign corpora")
    evaluate.add_argument("--labels", required=True, help="label CSV")
    evaluate.add_argument(
        "--holdout", required=True, help="an ISO week such as 2026-W40, or START/END"
    )
    evaluate.add_argument(
        "--details", action="store_true", help="also list the held-out misses and false alerts"
    )
    evaluate.set_defaults(func=cmd_evaluate)

    # fixtures
    fixtures = sub.add_parser("fixtures", help="manage the fixtures the CI gate runs against")
    fixtures_sub = fixtures.add_subparsers(dest="fixtures_command", required=True)

    export = fixtures_sub.add_parser(
        "export", help="sanitise labelled sessions and add them as fixtures"
    )
    export.add_argument("corpus", nargs="+")
    export.add_argument("--labels", required=True, help="label CSV")
    export.add_argument("--holdout", help="evaluation window to keep out of the fixtures")
    export.add_argument(
        "--no-holdout", action="store_true", help="export without excluding any window"
    )
    export.add_argument(
        "--per-family", type=int, default=1, help="sessions to take from each family (default 1)"
    )
    export.add_argument(
        "--replace",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="replace a string everywhere, such as a host or account name in a benign baseline",
    )
    export.add_argument(
        "--provenance", help="where the fixtures came from (default captured:<today>)"
    )
    export.add_argument(
        "--fixtures", default=str(DETECTIONS_DIR / "fixtures"), help="fixtures directory"
    )
    export.add_argument("--name", default="captured", help="file name under attack/ and benign/")
    export.set_defaults(func=cmd_fixtures_export)


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
