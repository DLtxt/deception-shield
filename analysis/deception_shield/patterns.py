"""Attack pattern derivation and campaign correlation.

A honeypot's raw output is a long list of individual events, most of which are
untargeted internet background noise. The functions here compress that list into
the smaller set of statements worth acting on: which behaviours recur, which
sources are working together, and which hosts are sweeping rather than probing.

Every function takes plain records and returns plain dataclasses, so the
analysis runs identically against a live Elasticsearch query, a replayed capture
or a fixture in the test suite.
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta

from deception_shield.models import AttackPattern, Campaign, PayloadRecord
from deception_shield.scoring import SIGNATURES_BY_NAME

# Two sources are considered part of one effort when their behaviour overlaps by
# at least this much. Chosen so that sharing a single common signature is not
# enough on its own, but sharing two out of three is.
CAMPAIGN_SIMILARITY_THRESHOLD = 0.5

# Activity separated by more than this is treated as unrelated even when the
# behaviour matches, because reused tooling is not the same as a coordinated run.
CAMPAIGN_TIME_WINDOW = timedelta(hours=6)

# Distinct ports a single source must touch before its activity reads as a sweep
# rather than as interest in one service.
SWEEP_PORT_THRESHOLD = 15


def derive_patterns(records: Sequence[PayloadRecord]) -> list[AttackPattern]:
    """Group records by the behaviour they exhibit.

    One record can carry several signatures, and each is counted separately: a
    payload that both fetches a remote file and pipes it to a shell is evidence
    of both behaviours.
    """
    buckets: dict[str, list[PayloadRecord]] = defaultdict(list)
    for record in records:
        for name in record.signatures:
            buckets[name].append(record)

    patterns: list[AttackPattern] = []
    for name, matched in buckets.items():
        signature = SIGNATURES_BY_NAME.get(name)
        timestamps = [r.timestamp for r in matched]
        example = next((r.payload_text(240) for r in matched if r.payload), "")

        patterns.append(
            AttackPattern(
                name=name,
                technique=signature.technique if signature else "unmapped",
                occurrences=len(matched),
                unique_sources=len({r.source_ip for r in matched}),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                example=example,
                ports=sorted({r.destination_port for r in matched}),
            )
        )

    # Most frequent first, and for equal counts prefer the more widely
    # distributed behaviour, which is the more significant of the two.
    patterns.sort(key=lambda p: (p.occurrences, p.unique_sources), reverse=True)
    return patterns


def _behaviour_profile(records: Iterable[PayloadRecord]) -> frozenset[str]:
    """Describe what a source did, independent of when or how often.

    Ports join signatures in the profile because two hosts running the same tool
    against the same services are better evidence of coordination than either
    fact alone.
    """
    profile: set[str] = set()
    for record in records:
        profile.update(f"sig:{name}" for name in record.signatures)
        profile.add(f"port:{record.destination_port}")
    return frozenset(profile)


def jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    """Overlap between two behaviour profiles, from 0.0 to 1.0."""
    if not left or not right:
        return 0.0
    union = len(left | right)
    return len(left & right) / union if union else 0.0


def correlate_campaigns(
    records: Sequence[PayloadRecord],
    *,
    threshold: float = CAMPAIGN_SIMILARITY_THRESHOLD,
    window: timedelta = CAMPAIGN_TIME_WINDOW,
    min_sources: int = 2,
) -> list[Campaign]:
    """Group sources whose behaviour and timing suggest one coordinated effort.

    Sources are linked pairwise when they share at least one attack signature,
    their behaviour profiles overlap past ``threshold``, and their activity
    windows fall within ``window`` of each other. Linked sources are then merged
    transitively, so a chain of similar hosts forms a single campaign even when
    its two ends differ.

    Requiring a shared signature is what keeps the output meaningful: profiles
    include the ports a source touched, and without that requirement any two
    hosts that happened to probe the same port would correlate perfectly.
    """
    by_source: dict[str, list[PayloadRecord]] = defaultdict(list)
    for record in records:
        by_source[record.source_ip].append(record)

    if len(by_source) < min_sources:
        return []

    profiles = {ip: _behaviour_profile(rs) for ip, rs in by_source.items()}
    spans = {
        ip: (min(r.timestamp for r in rs), max(r.timestamp for r in rs))
        for ip, rs in by_source.items()
    }

    # Union-find keeps the merge transitive without building the full graph.
    parent: dict[str, str] = {ip: ip for ip in by_source}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(a: str, b: str) -> None:
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            parent[root_b] = root_a

    sources = sorted(by_source)
    for i, left in enumerate(sources):
        for right in sources[i + 1 :]:
            shared = profiles[left] & profiles[right]

            # Overlapping on ports alone is not coordination. Two unrelated
            # hosts that both touched 443 have identical profiles under a plain
            # similarity measure, so a shared signature is required before two
            # sources can be linked at all.
            if not any(token.startswith("sig:") for token in shared):
                continue

            if jaccard(profiles[left], profiles[right]) < threshold:
                continue
            # Compare the gap between activity windows, not their midpoints, so
            # two long running sources that overlap are not pushed apart.
            gap = max(
                spans[left][0] - spans[right][1],
                spans[right][0] - spans[left][1],
                timedelta(0),
            )
            if gap <= window:
                union(left, right)

    clusters: dict[str, list[str]] = defaultdict(list)
    for ip in sources:
        clusters[find(ip)].append(ip)

    campaigns: list[Campaign] = []
    for root, members in clusters.items():
        if len(members) < min_sources:
            continue

        member_records = [r for ip in members for r in by_source[ip]]
        signatures = sorted({s for r in member_records for s in r.signatures})
        starts = [spans[ip][0] for ip in members]
        ends = [spans[ip][1] for ip in members]

        campaigns.append(
            Campaign(
                identifier=f"campaign-{root.replace('.', '-').replace(':', '-')}",
                sources=sorted(members),
                patterns=signatures,
                first_seen=min(starts),
                last_seen=max(ends),
                target_ports=sorted({r.destination_port for r in member_records}),
                confidence=_campaign_confidence(members, profiles, signatures),
            )
        )

    campaigns.sort(key=lambda c: (c.confidence, c.size), reverse=True)
    return campaigns


def _campaign_confidence(
    members: Sequence[str],
    profiles: dict[str, frozenset[str]],
    signatures: Sequence[str],
) -> float:
    """Rate how strongly a cluster holds together, from 0.0 to 1.0.

    Three things raise confidence: members behaving alike, there being more of
    them, and the shared behaviour being specific rather than generic. Size
    contributes on a log scale so a hundred member cluster is not rated fifty
    times more confidently than a two member one.
    """
    if len(members) < 2:
        return 0.0

    pairs = [
        jaccard(profiles[a], profiles[b])
        for i, a in enumerate(members)
        for b in members[i + 1 :]
    ]
    cohesion = sum(pairs) / len(pairs) if pairs else 0.0

    size_factor = min(math.log(len(members) + 1) / math.log(20), 1.0)

    # A cluster held together only by a scanner banner is weaker evidence than
    # one sharing an exploitation attempt, so weight by signature specificity.
    weights = [SIGNATURES_BY_NAME[s].weight for s in signatures if s in SIGNATURES_BY_NAME]
    specificity = min(max(weights) / 45, 1.0) if weights else 0.3

    confidence = 0.5 * cohesion + 0.2 * size_factor + 0.3 * specificity
    return round(min(confidence, 1.0), 3)


def detect_sweeps(
    records: Sequence[PayloadRecord],
    *,
    port_threshold: int = SWEEP_PORT_THRESHOLD,
) -> list[dict[str, object]]:
    """Identify sources touching many ports rather than pursuing one service.

    Reported separately from campaigns because a sweep is reconnaissance: it
    says a host is enumerating, not that it has chosen a target.
    """
    by_source: dict[str, set[int]] = defaultdict(set)
    timing: dict[str, list[datetime]] = defaultdict(list)

    for record in records:
        by_source[record.source_ip].add(record.destination_port)
        timing[record.source_ip].append(record.timestamp)

    sweeps = []
    for ip, ports in by_source.items():
        if len(ports) < port_threshold:
            continue

        stamps = sorted(timing[ip])
        span = (stamps[-1] - stamps[0]).total_seconds()
        sweeps.append(
            {
                "source_ip": ip,
                "port_count": len(ports),
                "ports": sorted(ports),
                "duration_seconds": round(span, 2),
                # Ports per second separates an automated sweep from a person
                # working through services by hand.
                "rate": round(len(ports) / span, 3) if span > 0 else None,
                "first_seen": stamps[0].isoformat(),
                "last_seen": stamps[-1].isoformat(),
            }
        )

    sweeps.sort(key=lambda s: s["port_count"], reverse=True)
    return sweeps


def summarise_sources(records: Sequence[PayloadRecord], *, limit: int = 20) -> list[dict[str, object]]:
    """Rank sources by how much attention each one earned."""
    by_source: dict[str, list[PayloadRecord]] = defaultdict(list)
    for record in records:
        by_source[record.source_ip].append(record)

    rows = []
    for ip, matched in by_source.items():
        scores = [r.score for r in matched]
        rows.append(
            {
                "source_ip": ip,
                "network": _containing_network(ip),
                "events": len(matched),
                "max_score": max(scores),
                "mean_score": round(sum(scores) / len(scores), 1),
                "ports": sorted({r.destination_port for r in matched}),
                "signatures": sorted({s for r in matched for s in r.signatures}),
                "bytes": sum(r.payload_length for r in matched),
            }
        )

    # Peak severity leads, because one serious attempt matters more than a long
    # tail of harmless probes from a chatty host.
    rows.sort(key=lambda r: (r["max_score"], r["events"]), reverse=True)
    return rows[:limit]


def _containing_network(ip: str, prefix: int = 24) -> str:
    """Report the /24 (or /64 for IPv6) an address sits in.

    Botnet nodes frequently cluster inside one allocation, so the enclosing
    network is often the more useful unit when blocking.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"

    width = prefix if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{width}", strict=False))


def technique_breakdown(patterns: Sequence[AttackPattern]) -> list[dict[str, object]]:
    """Roll patterns up to the MITRE ATT&CK techniques they map to."""
    counter: Counter[str] = Counter()
    sources: dict[str, int] = defaultdict(int)

    for pattern in patterns:
        counter[pattern.technique] += pattern.occurrences
        sources[pattern.technique] += pattern.unique_sources

    return [
        {"technique": technique, "occurrences": count, "unique_sources": sources[technique]}
        for technique, count in counter.most_common()
    ]
