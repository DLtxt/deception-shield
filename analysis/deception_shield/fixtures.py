"""Detection fixtures, and the gate CI runs the rules through.

Fixtures are labelled sessions committed to the repository: attack sessions the
rules must keep catching and benign sessions they must not fire on. On every
commit CI runs the rules against both and fails the build when the rule set
misses too many attacks, misses a technique's attacks, or alerts on too much
benign activity, so a rule change that breaks detection stops at review rather
than reaching the sensors.

Each fixture carries its label and its provenance on the same line as the
session, so a fixture file stands on its own. Fixtures exported from captured
sessions are sanitised on the way out, because the repository is public:
public addresses are remapped into the documentation ranges, since the
addresses in an attack belong to its victims as often as to the attacker;
passwords are dropped; and operator supplied strings, such as a host or account
name in a benign baseline, are replaced.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from deception_shield.detection import Alert, detect
from deception_shield.evaluation import Window
from deception_shield.labels import Label, parse_techniques
from deception_shield.sessions import (
    Command,
    Session,
    group_families,
    markdown_cell,
    read_session_records,
)
from deception_shield.sigma import RuleSet

FIXTURE_LABELS = ("attack", "benign")

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d])")
# RFC 5737 reserves these for documentation; nothing real lives at them.
_DOCUMENTATION_NETWORKS = ("192.0.2", "198.51.100", "203.0.113")


@dataclass(frozen=True, slots=True)
class Fixture:
    session: Session
    label: str
    techniques: tuple[str, ...] = ()
    provenance: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.session.to_dict(),
            "label": self.label,
            "techniques": list(self.techniques),
            "provenance": self.provenance,
        }


def load_fixtures(directory: Path) -> list[Fixture]:
    """Every fixture under ``directory``, from any ``.jsonl`` file below it."""
    paths = sorted(directory.rglob("*.jsonl"))
    fixtures: list[Fixture] = []
    seen: dict[str, str] = {}
    for path, number, record in read_session_records(paths):
        where = f"{path}:{number}"
        try:
            session = Session.from_dict(record)
            label = str(record.get("label", "")).lower()
            if label not in FIXTURE_LABELS:
                raise ValueError(f"label must be attack or benign, not {label!r}")
            techniques = parse_techniques(";".join(record.get("techniques") or []))
        except ValueError as exc:
            raise ValueError(f"{where}: {exc}") from exc
        if session.id in seen:
            raise ValueError(f"{where}: fixture {session.id} also appears at {seen[session.id]}")
        seen[session.id] = where
        fixtures.append(Fixture(session, label, techniques, str(record.get("provenance") or "")))
    return fixtures


# ----------------------------------------------------------------- thresholds


@dataclass(frozen=True, slots=True)
class Thresholds:
    """What the gate requires of the rule set, from ``detections/thresholds.yml``."""

    attack_recall: float = 0.95
    technique_recall: float = 0.90
    false_positive_rate: float = 0.01
    rule_false_positives: int = 0
    require_coverage: bool = True
    technique_recall_overrides: Mapping[str, float] = field(default_factory=dict)
    rule_false_positive_overrides: Mapping[str, int] = field(default_factory=dict)

    def technique_minimum(self, technique: str) -> float:
        return float(self.technique_recall_overrides.get(technique, self.technique_recall))

    def rule_maximum(self, rule_id: str) -> int:
        return int(self.rule_false_positive_overrides.get(rule_id, self.rule_false_positives))


def load_thresholds(path: Path) -> Thresholds:
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(document, Mapping):
        raise ValueError(f"{path}: expected a mapping")
    known = {
        "attack_recall",
        "technique_recall",
        "false_positive_rate",
        "rule_false_positives",
        "require_coverage",
        "overrides",
    }
    unknown = sorted(set(document) - known)
    if unknown:
        raise ValueError(f"{path}: unknown setting {', '.join(unknown)}")

    overrides = document.get("overrides") or {}
    defaults = Thresholds()
    try:
        return Thresholds(
            attack_recall=float(document.get("attack_recall", defaults.attack_recall)),
            technique_recall=float(document.get("technique_recall", defaults.technique_recall)),
            false_positive_rate=float(
                document.get("false_positive_rate", defaults.false_positive_rate)
            ),
            rule_false_positives=int(
                document.get("rule_false_positives", defaults.rule_false_positives)
            ),
            require_coverage=bool(document.get("require_coverage", defaults.require_coverage)),
            technique_recall_overrides={
                str(k): float(v) for k, v in (overrides.get("technique_recall") or {}).items()
            },
            rule_false_positive_overrides={
                str(k): int(v) for k, v in (overrides.get("rule_false_positives") or {}).items()
            },
        )
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"{path}: {exc}") from exc


# ----------------------------------------------------------------------- gate


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    passed: bool
    detail: str


@dataclass(slots=True)
class GateResult:
    checks: list[Check]
    ruleset: RuleSet
    attack: int
    benign: int
    provenance: dict[str, int]
    technique_rows: list[tuple[str, int, int, float]]
    rule_rows: list[tuple[str, str, int, int, int]]
    missed: list[Fixture]
    false_positives: list[tuple[Fixture, list[Alert]]]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)


def run_gate(fixtures: Sequence[Fixture], ruleset: RuleSet, thresholds: Thresholds) -> GateResult:
    """Run every rule over every fixture and judge the outcome against ``thresholds``."""
    results = detect([f.session for f in fixtures], ruleset)
    attack = [f for f in fixtures if f.label == "attack"]
    benign = [f for f in fixtures if f.label == "benign"]
    checks: list[Check] = []

    if not attack or not benign:
        checks.append(
            Check(
                "fixtures present",
                False,
                f"{len(attack)} attack and {len(benign)} benign fixtures; the gate needs both",
            )
        )

    detected = sum(1 for f in attack if results[f.session.id])
    if attack:
        rate = detected / len(attack)
        checks.append(
            Check(
                "attack detection",
                rate >= thresholds.attack_recall,
                f"{detected} of {len(attack)} attack fixtures detected ({rate:.1%}); "
                f"minimum {thresholds.attack_recall:.0%}",
            )
        )

    technique_rows: list[tuple[str, int, int, float]] = []
    for technique in ruleset.techniques:
        labelled = [f for f in attack if technique in f.techniques]
        caught = sum(
            1 for f in labelled if any(technique in a.techniques for a in results[f.session.id])
        )
        minimum = thresholds.technique_minimum(technique)
        technique_rows.append((technique, len(labelled), caught, minimum))
        if labelled:
            rate = caught / len(labelled)
            checks.append(
                Check(
                    f"{technique} detection",
                    rate >= minimum,
                    f"{caught} of {len(labelled)} fixtures labelled {technique} "
                    f"caught by its rules "
                    f"({rate:.1%}); minimum {minimum:.0%}",
                )
            )
        elif thresholds.require_coverage:
            checks.append(
                Check(f"{technique} detection", False, f"no attack fixture is labelled {technique}")
            )

    alerted = sum(1 for f in benign if results[f.session.id])
    if benign:
        rate = alerted / len(benign)
        checks.append(
            Check(
                "false positive rate",
                rate <= thresholds.false_positive_rate,
                f"{alerted} of {len(benign)} benign fixtures alerted ({rate:.1%}); "
                f"maximum {thresholds.false_positive_rate:.0%}",
            )
        )

    attack_hits = Counter(a.rule_id for f in attack for a in results[f.session.id])
    benign_hits = Counter(a.rule_id for f in benign for a in results[f.session.id])
    rule_rows: list[tuple[str, str, int, int, int]] = []
    for rule in ruleset:
        maximum = thresholds.rule_maximum(rule.id)
        rule_rows.append(
            (
                rule.title,
                ", ".join(rule.techniques),
                attack_hits[rule.id],
                benign_hits[rule.id],
                maximum,
            )
        )
        if benign_hits[rule.id] > maximum:
            checks.append(
                Check(
                    f"{rule.title}: false positives",
                    False,
                    f"alerted on {benign_hits[rule.id]} benign fixture(s); maximum {maximum}",
                )
            )
        if thresholds.require_coverage and attack_hits[rule.id] == 0:
            checks.append(
                Check(
                    f"{rule.title}: coverage",
                    False,
                    "detects no attack fixture, so nothing tests it",
                )
            )

    return GateResult(
        checks=checks,
        ruleset=ruleset,
        attack=len(attack),
        benign=len(benign),
        provenance=dict(
            Counter(f.provenance.split(":", 1)[0] or "unknown" for f in fixtures).most_common()
        ),
        technique_rows=technique_rows,
        rule_rows=rule_rows,
        missed=[f for f in attack if not results[f.session.id]],
        false_positives=[(f, results[f.session.id]) for f in benign if results[f.session.id]],
    )


def gate_to_markdown(result: GateResult) -> str:
    """The gate's verdict, written for a CI job summary."""
    failed = [check for check in result.checks if not check.passed]
    verdict = (
        "passed" if not failed else f"failed {len(failed)} check{'' if len(failed) == 1 else 's'}"
    )
    sources = ", ".join(f"{name} {count}" for name, count in result.provenance.items())

    lines = [
        f"# Detection gate {verdict}",
        "",
        f"{result.ruleset.describe()}, rule set `{result.ruleset.fingerprint[:12]}`, run against "
        f"{result.attack} attack and {result.benign} benign fixtures ({sources}).",
        "",
        "| Check | Result | Detail |",
        "| --- | --- | --- |",
    ]
    for check in sorted(result.checks, key=lambda c: c.passed):
        lines.append(f"| {check.name} | {'ok' if check.passed else '**FAIL**'} | {check.detail} |")

    lines += [
        "",
        "| Technique | Labelled fixtures | Caught by its rules | Minimum |",
        "| --- | ---: | ---: | ---: |",
    ]
    for technique, labelled, caught, minimum in result.technique_rows:
        lines.append(f"| {technique} | {labelled} | {caught} | {minimum:.0%} |")

    lines += [
        "",
        "| Rule | Technique | Attack fixtures | Benign fixtures | Benign allowed |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for title, techniques, attack_hits, benign_hits, maximum in result.rule_rows:
        lines.append(f"| {title} | {techniques} | {attack_hits} | {benign_hits} | {maximum} |")

    if result.missed:
        lines += ["", "Attack fixtures no rule detects:", ""]
        for fixture in result.missed:
            first = fixture.session.commands[0].text if fixture.session.commands else ""
            lines.append(
                f"- `{fixture.session.id}` {', '.join(fixture.techniques)}: "
                f"{markdown_cell(first, 160)}"
            )
    if result.false_positives:
        lines += ["", "Benign fixtures that alerted:", ""]
        for fixture, alerts in result.false_positives:
            for alert in alerts:
                lines.append(
                    f"- `{fixture.session.id}` {alert.rule_title}: "
                    f"{markdown_cell(alert.command, 160)}"
                )

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------- export


class Sanitiser:
    """Makes captured sessions safe to commit to a public repository.

    Public IPv4 addresses are mapped into the RFC 5737 documentation ranges.
    The mapping is a hash, so one address becomes the same stand-in wherever it
    appears and sessions that shared a server still share it afterwards, while
    the original cannot be read back. Private, loopback and link local
    addresses are kept, since rules distinguish them and they identify no one.
    """

    def __init__(self, replacements: Mapping[str, str] | None = None) -> None:
        self.replacements = dict(replacements or {})

    def address(self, text: str) -> str:
        try:
            parsed = ipaddress.IPv4Address(text)
        except ValueError:
            return text
        if not parsed.is_global:
            return text
        digest = int(hashlib.sha256(text.encode("ascii")).hexdigest(), 16)
        network = _DOCUMENTATION_NETWORKS[digest % len(_DOCUMENTATION_NETWORKS)]
        return f"{network}.{digest // len(_DOCUMENTATION_NETWORKS) % 254 + 1}"

    def text(self, value: str) -> str:
        for old, new in self.replacements.items():
            value = value.replace(old, new)
        return _IPV4.sub(lambda m: self.address(m.group()), value)

    def optional(self, value: str | None) -> str | None:
        return None if value is None else self.text(value)

    def session(self, session: Session) -> Session:
        return Session(
            id=self.text(session.id),
            origin=session.origin,
            sensor=self.text(session.sensor),
            start=session.start,
            end=session.end,
            source_ip=self.optional(session.source_ip),
            protocol=session.protocol,
            username=self.optional(session.username),
            password=None,
            login_success=session.login_success,
            client_version=session.client_version,
            commands=[Command(c.timestamp, self.text(c.text)) for c in session.commands],
            downloads=[
                {key: self.text(value) for key, value in d.items()} for d in session.downloads
            ],
        )


def select_fixtures(
    sessions: Iterable[Session],
    labels: Mapping[str, Label],
    *,
    per_family: int = 1,
    exclude: Window | None = None,
    provenance: str = "",
    sanitiser: Sanitiser | None = None,
) -> list[Fixture]:
    """Choose labelled sessions to commit as fixtures.

    Up to ``per_family`` sessions are taken from each family, earliest first,
    so a script a botnet ran a thousand times becomes one fixture rather than
    drowning out everything else. Sessions inside ``exclude`` (the held-out
    window) are never exported: a fixture is something CI tunes the rules
    against, and the held-out week must stay unseen.
    """
    sanitiser = sanitiser or Sanitiser()
    eligible = [
        s
        for s in sessions
        if s.id in labels
        and labels[s.id].label in FIXTURE_LABELS
        and (exclude is None or not exclude.contains(s.start))
    ]

    chosen: list[Fixture] = []
    for members in group_families(eligible).values():
        for session in sorted(members, key=lambda s: s.start)[:per_family]:
            label = labels[session.id]
            chosen.append(
                Fixture(
                    sanitiser.session(session),
                    label.label,
                    label.techniques if label.label == "attack" else (),
                    provenance,
                )
            )
    return sorted(chosen, key=lambda f: (f.label, f.session.start, f.session.id))


def write_fixtures(path: Path, fixtures: Iterable[Fixture]) -> tuple[int, int]:
    """Merge fixtures into a file, replacing any with the same identifier.

    Returns how many fixtures the file holds afterwards and how many were new.
    """
    existing: dict[str, dict[str, Any]] = {}
    if path.exists():
        for _, _, record in read_session_records([path]):
            existing[str(record.get("id"))] = record

    added = 0
    for fixture in fixtures:
        added += fixture.session.id not in existing
        existing[fixture.session.id] = fixture.to_dict()

    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(
        existing.values(),
        key=lambda r: (str(r.get("label")), str(r.get("start")), str(r.get("id"))),
    )
    path.write_text(
        "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in ordered), encoding="utf-8"
    )
    return len(ordered), added
