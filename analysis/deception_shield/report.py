"""Turning analysis output into something a person reads.

Reports are generated in Markdown or JSON. Markdown is for the daily summary a
human skims; JSON is for feeding another tool. Both are built from the same
:class:`Findings` object so the two never drift.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from deception_shield.models import AttackPattern, Campaign, PayloadRecord, TriageBand
from deception_shield.patterns import (
    correlate_campaigns,
    derive_patterns,
    detect_sweeps,
    summarise_sources,
    technique_breakdown,
)


@dataclass(slots=True)
class Findings:
    """Everything an analysis run concluded."""

    generated_at: datetime
    window_start: datetime
    window_end: datetime
    total_records: int
    unique_sources: int
    patterns: list[AttackPattern] = field(default_factory=list)
    campaigns: list[Campaign] = field(default_factory=list)
    sweeps: list[dict[str, Any]] = field(default_factory=list)
    top_sources: list[dict[str, Any]] = field(default_factory=list)
    techniques: list[dict[str, Any]] = field(default_factory=list)
    triage_counts: dict[str, int] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return self.triage_counts.get(TriageBand.CRITICAL.value, 0)

    @property
    def actionable_count(self) -> int:
        """Records at or above the suspicious band.

        This is the number that matters operationally: everything below it is
        internet background radiation that needs no response.
        """
        return sum(
            self.triage_counts.get(band.value, 0)
            for band in (TriageBand.SUSPICIOUS, TriageBand.LIKELY_MALICIOUS, TriageBand.CRITICAL)
        )


def analyse(records: Sequence[PayloadRecord]) -> Findings:
    """Run the full analysis over a set of records."""
    now = datetime.now(timezone.utc)

    if not records:
        return Findings(
            generated_at=now,
            window_start=now,
            window_end=now,
            total_records=0,
            unique_sources=0,
        )

    timestamps = [r.timestamp for r in records]
    triage_counts: dict[str, int] = {}
    for record in records:
        key = record.triage.value
        triage_counts[key] = triage_counts.get(key, 0) + 1

    patterns = derive_patterns(records)

    return Findings(
        generated_at=now,
        window_start=min(timestamps),
        window_end=max(timestamps),
        total_records=len(records),
        unique_sources=len({r.source_ip for r in records}),
        patterns=patterns,
        campaigns=correlate_campaigns(records),
        sweeps=detect_sweeps(records),
        top_sources=summarise_sources(records),
        techniques=technique_breakdown(patterns),
        triage_counts=triage_counts,
    )


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def to_json(findings: Findings, *, indent: int = 2) -> str:
    """Serialise findings, converting datetimes to ISO 8601."""

    def encode(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, TriageBand):
            return obj.value
        raise TypeError(f"unserialisable: {type(obj).__name__}")

    payload = {
        "generated_at": findings.generated_at,
        "window": {"start": findings.window_start, "end": findings.window_end},
        "totals": {
            "records": findings.total_records,
            "unique_sources": findings.unique_sources,
            "actionable": findings.actionable_count,
            "critical": findings.critical_count,
        },
        "triage": findings.triage_counts,
        "patterns": [asdict(p) for p in findings.patterns],
        "campaigns": [asdict(c) for c in findings.campaigns],
        "sweeps": findings.sweeps,
        "top_sources": findings.top_sources,
        "techniques": findings.techniques,
    }
    return json.dumps(payload, indent=indent, default=encode)


def to_markdown(findings: Findings, *, title: str = "Deception Shield activity report") -> str:
    """Render findings as a Markdown briefing."""
    lines: list[str] = [
        f"# {title}",
        "",
        f"Window `{_iso(findings.window_start)}` to `{_iso(findings.window_end)}`  ",
        f"Generated `{_iso(findings.generated_at)}`",
        "",
        "## Summary",
        "",
        f"- Payload records analysed: **{findings.total_records:,}**",
        f"- Distinct source addresses: **{findings.unique_sources:,}**",
        f"- Records at suspicious or above: **{findings.actionable_count:,}**",
        f"- Records rated critical: **{findings.critical_count:,}**",
        f"- Correlated campaigns: **{len(findings.campaigns)}**",
        f"- Hosts sweeping ports: **{len(findings.sweeps)}**",
        "",
    ]

    if findings.triage_counts:
        lines += ["## Triage distribution", "", "| Band | Records |", "| --- | ---: |"]
        for band in TriageBand:
            count = findings.triage_counts.get(band.value, 0)
            if count:
                lines.append(f"| {band.value} | {count:,} |")
        lines.append("")

    if findings.patterns:
        lines += [
            "## Attack patterns",
            "",
            "| Pattern | Technique | Occurrences | Sources | Ports |",
            "| --- | --- | ---: | ---: | --- |",
        ]
        for pattern in findings.patterns[:15]:
            ports = ", ".join(str(p) for p in pattern.ports[:6])
            if len(pattern.ports) > 6:
                ports += f" (+{len(pattern.ports) - 6})"
            lines.append(
                f"| `{pattern.name}` | {pattern.technique} | {pattern.occurrences:,} "
                f"| {pattern.unique_sources:,} | {ports} |"
            )
        lines.append("")

    if findings.campaigns:
        lines += ["## Correlated campaigns", ""]
        for campaign in findings.campaigns[:10]:
            lines += [
                f"### {campaign.identifier}",
                "",
                f"- Confidence: **{campaign.confidence:.2f}**",
                f"- Participating sources: **{campaign.size}**",
                f"- Shared behaviour: {', '.join(f'`{p}`' for p in campaign.patterns) or 'none recorded'}",
                f"- Target ports: {', '.join(str(p) for p in campaign.target_ports[:12])}",
                f"- Active `{_iso(campaign.first_seen)}` to `{_iso(campaign.last_seen)}`",
                "",
                "<details><summary>Source addresses</summary>",
                "",
                "```",
                "\n".join(campaign.sources[:64]),
                "```",
                "",
                "</details>",
                "",
            ]

    if findings.sweeps:
        lines += [
            "## Port sweeps",
            "",
            "| Source | Ports touched | Duration (s) | Ports/sec |",
            "| --- | ---: | ---: | ---: |",
        ]
        for sweep in findings.sweeps[:15]:
            rate = sweep.get("rate")
            lines.append(
                f"| `{sweep['source_ip']}` | {sweep['port_count']} "
                f"| {sweep['duration_seconds']} | {rate if rate is not None else 'n/a'} |"
            )
        lines.append("")

    if findings.top_sources:
        lines += [
            "## Most active sources",
            "",
            "| Source | Network | Events | Peak score | Behaviour |",
            "| --- | --- | ---: | ---: | --- |",
        ]
        for row in findings.top_sources[:15]:
            behaviour = ", ".join(f"`{s}`" for s in row["signatures"][:3]) or "-"
            lines.append(
                f"| `{row['source_ip']}` | `{row['network']}` | {row['events']:,} "
                f"| {row['max_score']} | {behaviour} |"
            )
        lines.append("")

    if findings.techniques:
        lines += ["## ATT&CK techniques observed", "", "| Technique | Occurrences | Sources |", "| --- | ---: | ---: |"]
        for row in findings.techniques:
            lines.append(f"| {row['technique']} | {row['occurrences']:,} | {row['unique_sources']:,} |")
        lines.append("")

    return "\n".join(lines)
