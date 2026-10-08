"""Running the Sigma rules over sessions.

Rules match single Cowrie events; a session is what an analyst triages. Each
command a session ran becomes one ``cowrie.command.input`` event, and a session
raises at most one alert per rule, at the first command that matched it: a bot
that runs the same download five times is one finding, not five.

Benign baselines imported from shell history are evaluated the same way. Their
commands are presented to the rules in Cowrie's event shape, so one rule set
reads honeypot sessions and an administrator's sessions without translation.

The fixture gate, the ``detect`` command and the held-out evaluation all call
:func:`detect`, so the rates the evaluation reports are the rates the gate
enforces.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from deception_shield.sessions import COMMAND_EVENT, Session, iso, markdown_cell
from deception_shield.sigma import RuleSet, SigmaRule

COWRIE_LOGSOURCE: dict[str, str] = {"product": "cowrie"}


@dataclass(frozen=True, slots=True)
class Alert:
    """One rule matching one session, at the first command it matched."""

    session_id: str
    rule_id: str
    rule_title: str
    level: str
    techniques: tuple[str, ...]
    command_index: int
    command: str
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "level": self.level,
            "techniques": list(self.techniques),
            "command_index": self.command_index,
            "command": self.command,
            "timestamp": iso(self.timestamp),
        }


def command_event(
    text: str,
    *,
    username: str | None = None,
    session_id: str | None = None,
    source_ip: str | None = None,
) -> dict[str, str]:
    """A command in the shape Cowrie logs it, which is the shape the rules read."""
    event = {"eventid": COMMAND_EVENT, "input": text}
    if username:
        event["username"] = username
    if session_id:
        event["session"] = session_id
    if source_ip:
        event["src_ip"] = source_ip
    return event


def detect_session(session: Session, rules: Sequence[SigmaRule]) -> list[Alert]:
    """Alerts for one session, in the order its commands raised them."""
    pending = list(rules)
    alerts: list[Alert] = []

    for index, command in enumerate(session.commands):
        if not pending:
            break
        event = command_event(
            command.text,
            username=session.username,
            session_id=session.id,
            source_ip=session.source_ip,
        )
        fired = [rule for rule in pending if rule.matches(event)]
        if not fired:
            continue
        alerts.extend(
            Alert(
                session_id=session.id,
                rule_id=rule.id,
                rule_title=rule.title,
                level=rule.level,
                techniques=rule.techniques,
                command_index=index,
                command=command.text,
                timestamp=command.timestamp,
            )
            for rule in fired
        )
        fired_ids = {rule.id for rule in fired}
        pending = [rule for rule in pending if rule.id not in fired_ids]

    return alerts


def detect(sessions: Iterable[Session], ruleset: RuleSet) -> dict[str, list[Alert]]:
    """Alerts for every session, keyed by session identifier."""
    rules = ruleset.applicable(COWRIE_LOGSOURCE)
    return {session.id: detect_session(session, rules) for session in sessions}


def detections_to_markdown(
    sessions: Sequence[Session],
    results: dict[str, list[Alert]],
    ruleset: RuleSet,
    *,
    limit: int = 200,
) -> str:
    """Which sessions alerted and on what, for a person to read."""
    alerted = [s for s in sessions if results.get(s.id)]
    counts = Counter(alert.rule_id for alerts in results.values() for alert in alerts)

    lines = [
        "# Detections",
        "",
        f"{ruleset.describe()}, rule set `{ruleset.fingerprint[:12]}`",
        "",
        f"**{len(alerted):,} of {len(sessions):,} sessions** raised at least one alert.",
        "",
        "| Rule | Technique | Level | Sessions |",
        "| --- | --- | --- | ---: |",
    ]
    for rule in ruleset:
        lines.append(
            f"| {rule.title} | {', '.join(rule.techniques)} | {rule.level} "
            f"| {counts.get(rule.id, 0):,} |"
        )

    if alerted:
        lines += [
            "",
            "## Alerted sessions",
            "",
            "| Session | Start | Source | Rules | First match |",
            "| --- | --- | --- | --- | --- |",
        ]
        for session in alerted[:limit]:
            alerts = results[session.id]
            lines.append(
                f"| `{session.id}` | {iso(session.start)[:19]} "
                f"| {session.source_ip or session.sensor} "
                f"| {'; '.join(a.rule_title for a in alerts)} "
                f"| {markdown_cell(alerts[0].command, 120)} |"
            )
        if len(alerted) > limit:
            lines.append(f"| … {len(alerted) - limit:,} more | | | | |")

    return "\n".join(lines) + "\n"


def detections_to_json(
    sessions: Sequence[Session], results: dict[str, list[Alert]], ruleset: RuleSet
) -> str:
    return json.dumps(
        {
            "ruleset": {"fingerprint": ruleset.fingerprint, "summary": ruleset.describe()},
            "sessions": len(sessions),
            "alerted": sum(1 for s in sessions if results.get(s.id)),
            "alerts": [alert.to_dict() for s in sessions for alert in results.get(s.id, [])],
        },
        indent=2,
    )
