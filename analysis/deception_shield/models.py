"""Core data structures shared by the capture and analysis paths."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class TriageBand(str, enum.Enum):
    """How urgently a payload deserves a human look.

    The bands are ordered, so comparisons work directly and a caller can filter
    with ``band >= TriageBand.SUSPICIOUS`` without mapping to numbers first.

    Deriving from ``str`` rather than ``enum.StrEnum`` keeps the module working
    on Python 3.10, which is what Ubuntu 22.04 ships.
    """

    BENIGN = "benign"
    NOISE = "noise"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely-malicious"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _BAND_ORDER[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, TriageBand):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, TriageBand):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, TriageBand):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, TriageBand):
            return NotImplemented
        return self.rank >= other.rank

    @classmethod
    def from_score(cls, score: int) -> "TriageBand":
        if score <= 0:
            return cls.BENIGN
        if score < 20:
            return cls.NOISE
        if score < 50:
            return cls.SUSPICIOUS
        if score < 80:
            return cls.LIKELY_MALICIOUS
        return cls.CRITICAL


_BAND_ORDER: dict[TriageBand, int] = {
    TriageBand.BENIGN: 0,
    TriageBand.NOISE: 1,
    TriageBand.SUSPICIOUS: 2,
    TriageBand.LIKELY_MALICIOUS: 3,
    TriageBand.CRITICAL: 4,
}


@dataclass(slots=True)
class PayloadRecord:
    """One application layer payload lifted out of a capture by tshark.

    A record is a single direction of a single conversation at a point in time.
    Reassembly across frames is done by Wireshark before the record is built, so
    ``payload`` holds the bytes an application would have received.
    """

    timestamp: datetime
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    transport: str
    payload: bytes
    protocol: str | None = None
    stream_id: int | None = None
    sensor_id: str = "unknown"
    score: int = 0
    signatures: list[str] = field(default_factory=list)
    triage: TriageBand = TriageBand.BENIGN

    @property
    def payload_length(self) -> int:
        return len(self.payload)

    @property
    def printable_ratio(self) -> float:
        """Share of bytes that are printable ASCII.

        A low ratio on a port that speaks a text protocol usually means binary
        shellcode or a deliberately malformed probe.
        """
        if not self.payload:
            return 0.0
        printable = sum(1 for b in self.payload if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
        return printable / len(self.payload)

    def payload_text(self, limit: int = 4096) -> str:
        """Payload decoded leniently for display and pattern matching."""
        return self.payload[:limit].decode("utf-8", errors="replace")

    def to_document(self) -> dict[str, Any]:
        """Shape the record the way the Logstash pipeline expects it."""
        return {
            "frame_time": self.timestamp.isoformat(),
            "source": {"ip": self.source_ip, "port": self.source_port},
            "destination": {"ip": self.destination_ip, "port": self.destination_port},
            "network": {
                "transport": self.transport,
                "protocol": self.protocol,
                "bytes": self.payload_length,
            },
            "stream_id": self.stream_id,
            "observer": {"name": self.sensor_id},
            "payload_length": self.payload_length,
            "payload_ascii": self.payload_text(),
            "payload_hex": self.payload[:2048].hex(),
            "printable_ratio": round(self.printable_ratio, 4),
            "threat": {
                "payload_score": self.score,
                "payload_signatures": self.signatures,
                "triage": self.triage.value,
            },
        }


@dataclass(slots=True)
class AttackPattern:
    """A behaviour seen repeatedly across sessions or sources."""

    name: str
    technique: str
    occurrences: int
    unique_sources: int
    first_seen: datetime
    last_seen: datetime
    example: str = ""
    ports: list[int] = field(default_factory=list)

    @property
    def duration_hours(self) -> float:
        return max((self.last_seen - self.first_seen).total_seconds() / 3600.0, 0.0)

    @property
    def sources_per_occurrence(self) -> float:
        """Distinguishes distributed activity from a single noisy host.

        A value near 1.0 means many different hosts each tried the behaviour
        roughly once, which is the signature of a botnet sweeping a range. A
        value near 0 means one host repeated it many times.
        """
        if self.occurrences == 0:
            return 0.0
        return self.unique_sources / self.occurrences


@dataclass(slots=True)
class Campaign:
    """Sources acting alike closely enough in time to be treated as one effort."""

    identifier: str
    sources: list[str]
    patterns: list[str]
    first_seen: datetime
    last_seen: datetime
    target_ports: list[int] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def size(self) -> int:
        return len(self.sources)
