"""Measuring the rules against labelled sessions.

The protocol is a temporal split. Rules are written and tuned on the weeks
before a held-out window, and the window is evaluated once the rules are
frozen. Sessions are assigned by start time, honeypot and benign alike, so the
held-out week is unseen in both directions: no rule was shaped to catch its
attacks, and none was shaped to stay quiet on its benign sessions.

Rates come with Wilson score intervals, because a detection rate measured on a
hundred and fifty sessions is not a precise number and the interval says how
imprecise it is. Botnets also run one script thousands of times, so the session
rate is reported beside the family rate, which counts each distinct script once,
and the rate on families first seen in the held-out window, the nearest thing
to a measure of whether the rules generalise or merely remember.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from deception_shield.detection import Alert, detect
from deception_shield.labels import Label, labelled_sessions
from deception_shield.sessions import Session, iso, markdown_cell, parse_timestamp, session_family
from deception_shield.sigma import RuleSet

_ISO_WEEK = re.compile(r"^(\d{4})-?W(\d{2})$", re.IGNORECASE)
_Z_95 = 1.959964


@dataclass(frozen=True, slots=True)
class Window:
    """A half-open interval of session start times."""

    start: datetime
    end: datetime

    def contains(self, moment: datetime) -> bool:
        return self.start <= moment < self.end

    def describe(self) -> str:
        return f"{iso(self.start)[:10]} to {iso(self.end)[:10]} (end exclusive)"


def parse_window(text: str) -> Window:
    """Read ``2026-W40`` as that ISO week, or ``START/END`` as an interval."""
    text = text.strip()
    match = _ISO_WEEK.match(text)
    if match:
        try:
            start = datetime.fromisocalendar(int(match.group(1)), int(match.group(2)), 1)
        except ValueError as exc:
            raise ValueError(f"{text} is not an ISO week") from exc
        start = start.replace(tzinfo=timezone.utc)
        return Window(start, start + timedelta(days=7))

    if "/" in text:
        left, right = text.split("/", 1)
        start, end = parse_timestamp(left), parse_timestamp(right)
        if start is None or end is None:
            raise ValueError(f"cannot read the interval {text!r}")
        if end <= start:
            raise ValueError("the window must end after it starts")
        return Window(start, end)

    raise ValueError(
        "give an ISO week such as 2026-W40 or an interval such as 2026-09-28/2026-10-05"
    )


def wilson_interval(hits: int, total: int, z: float = _Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Unlike the normal approximation it stays inside [0, 1] and remains sensible
    near 0 and 1, which is exactly where detection and false positive rates
    live: zero false positives in five hundred sessions still bounds the true
    rate at about 0.8%, not at zero.
    """
    if total <= 0:
        raise ValueError("an interval needs at least one trial")
    proportion = hits / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    half_width = (
        z
        * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
        / denominator
    )
    # At no hits or all hits the bound is exactly 0 or 1; floating point would
    # otherwise leave a residue such as 4e-19.
    low = 0.0 if hits == 0 else max(0.0, centre - half_width)
    high = 1.0 if hits == total else min(1.0, centre + half_width)
    return low, high


@dataclass(frozen=True, slots=True)
class Rate:
    hits: int
    total: int

    @property
    def value(self) -> float | None:
        return self.hits / self.total if self.total else None

    @property
    def interval(self) -> tuple[float, float] | None:
        return wilson_interval(self.hits, self.total) if self.total else None

    def percent(self) -> str:
        return "n/a" if self.value is None else f"{self.value:.1%}"

    def interval_text(self) -> str:
        if self.interval is None:
            return "n/a"
        low, high = self.interval
        return f"{low:.1%}–{high:.1%}"

    def describe(self) -> str:
        if not self.total:
            return "none"
        return f"{self.hits:,} of {self.total:,} ({self.percent()})"

    def to_dict(self) -> dict[str, Any]:
        interval = self.interval
        return {
            "hits": self.hits,
            "total": self.total,
            "rate": self.value,
            "ci95": list(interval) if interval else None,
        }


@dataclass(slots=True)
class RuleOutcome:
    rule_id: str
    title: str
    techniques: tuple[str, ...]
    level: str
    attack_sessions: int = 0
    sole_detector: int = 0
    benign_sessions: int = 0


@dataclass(slots=True)
class TechniqueOutcome:
    """Sessions labelled with a technique, and how many its own rules caught."""

    technique: str
    rules: int
    labelled: int = 0
    detected: int = 0

    @property
    def rate(self) -> Rate:
        return Rate(self.detected, self.labelled)


@dataclass(slots=True)
class SplitResult:
    name: str
    window: Window | None
    sessions: int
    attack: int
    detected: int
    benign: int
    benign_alerted: int
    false_alerts: int
    excluded: int
    unlabelled: int
    families: int
    families_detected: int
    new_families: int | None
    new_families_detected: int | None
    rules: list[RuleOutcome] = field(default_factory=list)
    techniques: list[TechniqueOutcome] = field(default_factory=list)
    uncovered: dict[str, int] = field(default_factory=dict)
    missed: list[Session] = field(default_factory=list)
    false_positives: list[tuple[Session, list[Alert]]] = field(default_factory=list)

    @property
    def recall(self) -> Rate:
        return Rate(self.detected, self.attack)

    @property
    def false_positive_rate(self) -> Rate:
        return Rate(self.benign_alerted, self.benign)

    @property
    def family_recall(self) -> Rate:
        return Rate(self.families_detected, self.families)

    @property
    def new_family_recall(self) -> Rate | None:
        if self.new_families is None or self.new_families_detected is None:
            return None
        return Rate(self.new_families_detected, self.new_families)

    @property
    def precision(self) -> float | None:
        """Share of alerted sessions that were attacks, at this split's class mix.

        Only meaningful for the mix measured: add benign sessions and it falls
        without the rules changing at all. Reported, but not as a headline.
        """
        alerted = self.detected + self.benign_alerted
        return self.detected / alerted if alerted else None

    def headline(self) -> str:
        false_alerts = f"{self.false_alerts:,} false alert{'' if self.false_alerts == 1 else 's'}"
        return (
            f"Detected **{self.detected:,} of {self.attack:,}** labelled attack sessions "
            f"(**{self.recall.percent()}**, 95% CI {self.recall.interval_text()}) "
            f"with **{false_alerts}** "
            f"across **{self.benign:,}** benign sessions ({self.benign_alerted:,} session"
            f"{'' if self.benign_alerted == 1 else 's'} alerted, "
            f"{self.false_positive_rate.percent()}, "
            f"95% CI {self.false_positive_rate.interval_text()})."
        )


@dataclass(slots=True)
class Evaluation:
    generated_at: datetime
    rules_summary: str
    rules_fingerprint: str
    rule_count: int
    techniques: tuple[str, ...]
    inputs: list[tuple[str, str]]
    holdout: Window
    development: SplitResult
    held_out: SplitResult
    later: int


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def evaluate(
    sessions: Sequence[Session],
    labels: Mapping[str, Label],
    ruleset: RuleSet,
    holdout: Window,
    *,
    inputs: Sequence[Path] = (),
) -> Evaluation:
    """Measure the rule set on the weeks before ``holdout`` and on ``holdout`` itself.

    Sessions starting after the window are counted but not evaluated: they
    belong to neither side of the split.
    """
    results = detect(sessions, ruleset)
    families = {s.id: session_family(s) for s in sessions}

    development = [s for s in sessions if s.start < holdout.start]
    held_out = [s for s in sessions if holdout.contains(s.start)]
    known_families = {families[s.id] for s in development}

    return Evaluation(
        generated_at=datetime.now(timezone.utc).replace(microsecond=0),
        rules_summary=ruleset.describe(),
        rules_fingerprint=ruleset.fingerprint,
        rule_count=len(ruleset),
        techniques=ruleset.techniques,
        inputs=[(str(path), file_digest(path)) for path in inputs],
        holdout=holdout,
        development=_measure(
            "development", None, development, labels, results, families, ruleset, None
        ),
        held_out=_measure(
            "held out", holdout, held_out, labels, results, families, ruleset, known_families
        ),
        later=sum(1 for s in sessions if s.start >= holdout.end),
    )


def _measure(
    name: str,
    window: Window | None,
    sessions: Sequence[Session],
    labels: Mapping[str, Label],
    results: Mapping[str, list[Alert]],
    families: Mapping[str, str],
    ruleset: RuleSet,
    known_families: set[str] | None,
) -> SplitResult:
    attack, benign, excluded, unlabelled = labelled_sessions(sessions, labels)

    outcomes = {
        rule.id: RuleOutcome(rule.id, rule.title, rule.techniques, rule.level) for rule in ruleset
    }
    for session in attack:
        fired = {alert.rule_id for alert in results[session.id]}
        for rule_id in fired:
            outcomes[rule_id].attack_sessions += 1
        if len(fired) == 1:
            outcomes[next(iter(fired))].sole_detector += 1
    for session in benign:
        for alert in results[session.id]:
            outcomes[alert.rule_id].benign_sessions += 1

    # A labelled technique counts towards a rule technique only when the two
    # identifiers match exactly. Folding a parent label into a sub-technique's
    # rules would charge those rules with sessions they were never written for.
    rules_per_technique = Counter(t for rule in ruleset for t in rule.techniques)
    techniques = {t: TechniqueOutcome(t, count) for t, count in sorted(rules_per_technique.items())}
    uncovered: Counter[str] = Counter()
    for session in attack:
        caught = {t for alert in results[session.id] for t in alert.techniques}
        for technique in labels[session.id].techniques:
            if technique in techniques:
                techniques[technique].labelled += 1
                techniques[technique].detected += technique in caught
            else:
                uncovered[technique] += 1

    detected_family: dict[str, bool] = {}
    for session in attack:
        family = families[session.id]
        detected_family[family] = detected_family.get(family, False) or bool(results[session.id])

    new_families = new_detected = None
    if known_families is not None:
        new = {f: hit for f, hit in detected_family.items() if f not in known_families}
        new_families, new_detected = len(new), sum(new.values())

    return SplitResult(
        name=name,
        window=window,
        sessions=len(sessions),
        attack=len(attack),
        detected=sum(1 for s in attack if results[s.id]),
        benign=len(benign),
        benign_alerted=sum(1 for s in benign if results[s.id]),
        false_alerts=sum(len(results[s.id]) for s in benign),
        excluded=excluded,
        unlabelled=unlabelled,
        families=len(detected_family),
        families_detected=sum(detected_family.values()),
        new_families=new_families,
        new_families_detected=new_detected,
        rules=list(outcomes.values()),
        techniques=list(techniques.values()),
        uncovered=dict(uncovered.most_common()),
        missed=[s for s in attack if not results[s.id]],
        false_positives=[(s, results[s.id]) for s in benign if results[s.id]],
    )


# ----------------------------------------------------------------- rendering


def to_markdown(evaluation: Evaluation, *, details: bool = False) -> str:
    """The evaluation as a report.

    Missed sessions and false alerts are listed for the development weeks,
    where they are what the next round of tuning works from. For the held-out
    window they appear only with ``details``: reading them invites tuning on the
    very week meant to stay unseen.
    """
    dev, held = evaluation.development, evaluation.held_out
    dev_fp, held_fp = dev.false_positive_rate, held.false_positive_rate
    # Names keep the table readable; the JSON report carries full paths, and the
    # digests identify each file exactly either way.
    inputs = (
        ", ".join(f"`{Path(path).name}` (`{digest[:12]}`)" for path, digest in evaluation.inputs)
        or "n/a"
    )

    lines = [
        "# Detection evaluation",
        "",
        "| | |",
        "| --- | --- |",
        f"| Rules | {evaluation.rules_summary}, rule set `{evaluation.rules_fingerprint[:12]}` |",
        f"| Held-out window | {evaluation.holdout.describe()} |",
        f"| Inputs | {inputs} |",
        f"| Generated | {iso(evaluation.generated_at)} |",
        "",
        "## Held-out result",
        "",
        held.headline()
        if held.attack or held.benign
        else "No labelled sessions fall in the held-out window.",
        "",
        "| Measure | Development weeks | Held-out window |",
        "| --- | ---: | ---: |",
        f"| Attack sessions detected | {dev.recall.describe()} | {held.recall.describe()} |",
        f"| 95% interval | {dev.recall.interval_text()} | {held.recall.interval_text()} |",
        f"| Benign sessions alerted | {dev_fp.describe()} | {held_fp.describe()} |",
        f"| 95% interval | {dev_fp.interval_text()} | {held_fp.interval_text()} |",
        f"| False alerts (rule × session) | {dev.false_alerts:,} | {held.false_alerts:,} |",
        f"| Attack families detected | {dev.family_recall.describe()} "
        f"| {held.family_recall.describe()} |",
        f"| Families first seen in the window | n/a | "
        f"{held.new_family_recall.describe() if held.new_family_recall else 'n/a'} |",
        f"| Precision at this class mix | {_percent(dev.precision)} | {_percent(held.precision)} |",
        f"| Excluded / unlabelled sessions | {dev.excluded:,} / {dev.unlabelled:,} "
        f"| {held.excluded:,} / {held.unlabelled:,} |",
        "",
    ]
    if held.unlabelled or dev.unlabelled:
        lines += [
            f"> {dev.unlabelled + held.unlabelled:,} sessions have no label and are not counted. "
            "Label them before reporting these figures.",
            "",
        ]
    if evaluation.later:
        lines += [
            f"{evaluation.later:,} sessions start after the window and are not evaluated.",
            "",
        ]

    lines += _technique_table(held)
    lines += _rule_table(held)

    lines += _error_sections(dev, "development weeks")
    if details:
        lines += _error_sections(held, "held-out window")

    return "\n".join(lines) + "\n"


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _technique_table(split: SplitResult) -> list[str]:
    lines = [
        f"## Techniques ({split.name})",
        "",
        "| Technique | Rules | Labelled attack sessions | Detected by its own rules |",
        "| --- | ---: | ---: | ---: |",
    ]
    for outcome in split.techniques:
        lines.append(
            f"| {outcome.technique} | {outcome.rules} | {outcome.labelled:,} | "
            f"{outcome.rate.describe() if outcome.labelled else 'n/a'} |"
        )
    lines.append("")
    if split.uncovered:
        listed = ", ".join(
            f"{t} ({n:,} session{'' if n == 1 else 's'})" for t, n in split.uncovered.items()
        )
        lines += [f"Labelled techniques no rule covers: {listed}.", ""]
    return lines


def _rule_table(split: SplitResult) -> list[str]:
    lines = [
        f"## Rules ({split.name})",
        "",
        "| Rule | Technique | Level | Attack sessions | Sole detector | Benign sessions |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for outcome in sorted(split.rules, key=lambda o: (-o.attack_sessions, o.title)):
        lines.append(
            f"| {outcome.title} | {', '.join(outcome.techniques)} | {outcome.level} "
            f"| {outcome.attack_sessions:,} | {outcome.sole_detector:,} "
            f"| {outcome.benign_sessions:,} |"
        )
    lines.append("")
    return lines


def _error_sections(split: SplitResult, label: str, limit: int = 50) -> list[str]:
    lines: list[str] = []
    if split.missed:
        lines += [
            f"## Missed attack sessions ({label})",
            "",
            "| Session | Start | Commands |",
            "| --- | --- | --- |",
        ]
        for session in split.missed[:limit]:
            commands = " ⏎ ".join(c.text for c in session.commands[:3])
            lines.append(
                f"| `{session.id}` | {iso(session.start)[:19]} | {markdown_cell(commands, 200)} |"
            )
        if len(split.missed) > limit:
            lines.append(f"| … {len(split.missed) - limit:,} more | | |")
        lines.append("")
    if split.false_positives:
        lines += [
            f"## False alerts ({label})",
            "",
            "| Session | Rule | Command |",
            "| --- | --- | --- |",
        ]
        for session, alerts in split.false_positives[:limit]:
            for alert in alerts:
                lines.append(
                    f"| `{session.id}` | {alert.rule_title} | {markdown_cell(alert.command, 200)} |"
                )
        lines.append("")
    return lines


def to_json(evaluation: Evaluation) -> str:
    def split(result: SplitResult) -> dict[str, Any]:
        return {
            "window": None
            if result.window is None
            else {"start": iso(result.window.start), "end": iso(result.window.end)},
            "sessions": result.sessions,
            "attack_detection": result.recall.to_dict(),
            "benign_alerted": result.false_positive_rate.to_dict(),
            "false_alerts": result.false_alerts,
            "family_detection": result.family_recall.to_dict(),
            "new_family_detection": result.new_family_recall.to_dict()
            if result.new_family_recall
            else None,
            "precision": result.precision,
            "excluded": result.excluded,
            "unlabelled": result.unlabelled,
            "techniques": [
                {"technique": t.technique, "rules": t.rules, **t.rate.to_dict()}
                for t in result.techniques
            ],
            "uncovered_techniques": result.uncovered,
            "rules": [
                {
                    "id": r.rule_id,
                    "title": r.title,
                    "techniques": list(r.techniques),
                    "level": r.level,
                    "attack_sessions": r.attack_sessions,
                    "sole_detector": r.sole_detector,
                    "benign_sessions": r.benign_sessions,
                }
                for r in result.rules
            ],
            "missed": [s.id for s in result.missed],
            "false_positives": [
                {"session": s.id, "rules": [a.rule_id for a in alerts]}
                for s, alerts in result.false_positives
            ],
        }

    return json.dumps(
        {
            "generated_at": iso(evaluation.generated_at),
            "rules": {
                "summary": evaluation.rules_summary,
                "fingerprint": evaluation.rules_fingerprint,
                "count": evaluation.rule_count,
                "techniques": list(evaluation.techniques),
            },
            "inputs": [{"path": path, "sha256": digest} for path, digest in evaluation.inputs],
            "holdout": {"start": iso(evaluation.holdout.start), "end": iso(evaluation.holdout.end)},
            "development": split(evaluation.development),
            "held_out": split(evaluation.held_out),
            "sessions_after_window": evaluation.later,
        },
        indent=2,
    )
