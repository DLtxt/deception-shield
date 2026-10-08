"""Honeypot sessions: assembling them, storing them, and grouping them.

Cowrie logs a session as a stream of small events (a connection, login attempts,
each command line, any file fetched, the disconnect) interleaved with every
other session the sensor is handling. Detection, labelling and evaluation all
work on whole sessions, so this module folds the stream back into one record per
session and keeps the sessions in which the intruder ran at least one command.

A corpus is stored as JSON lines, one session per line. It is built once from
weeks of logs and then labelled, evaluated and turned into fixtures without
going back to the sensor.

Benign baselines come from shell history on hosts an operator controls, split
into sessions at idle gaps and stored in the same shape. A honeypot sees almost
nothing but attack traffic, so false positives can only be measured against
activity like that.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

COMMAND_EVENT = "cowrie.command.input"

ORIGIN_COWRIE = "cowrie"
ORIGIN_HISTORY = "shell-history"

# A pause longer than this between two history entries starts a new session.
# Shell history records no logins or logouts, so the gap is the only boundary
# available; half an hour separates sittings without splitting one in two.
DEFAULT_IDLE_GAP = timedelta(minutes=30)

_FRACTION = re.compile(r"\.(\d+)")


def parse_timestamp(value: Any) -> datetime | None:
    """Parse the timestamps Cowrie, Elasticsearch and the corpus write.

    Cowrie writes microseconds, Elasticsearch returns milliseconds, and
    ``datetime.fromisoformat`` on Python 3.10 accepts neither a ``Z`` suffix nor
    a fraction of another length, so both are normalised first. A timestamp
    with no zone is taken as UTC, which is what every source here writes.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None

    text = value.strip()
    if text[-1] in "Zz":
        text = text[:-1] + "+00:00"
    match = _FRACTION.search(text)
    if match:
        digits = (match.group(1) + "000000")[:6]
        text = text[: match.start(1)] + digits + text[match.end(1) :]
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iso(moment: datetime) -> str:
    """UTC ISO 8601 with a ``Z`` suffix, the form every file here uses."""
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def printable(text: str, limit: int | None = None) -> str:
    """Session text made safe to display: control characters escaped, length capped.

    Commands are attacker controlled. An escape sequence printed raw to a
    terminal can move the cursor and rewrite what the analyst reads, so every
    control character is shown as its escape instead.
    """
    shown = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    if limit is not None and len(shown) > limit:
        shown = shown[: max(limit - 1, 0)] + "…"
    return shown


def markdown_cell(text: str, limit: int | None = None) -> str:
    """Session text for a Markdown table cell, inside a code span."""
    return "`" + printable(text, limit).replace("`", "'").replace("|", "\\|") + "`"


@dataclass(slots=True)
class Command:
    """One line typed into a shell."""

    timestamp: datetime
    text: str


@dataclass(slots=True)
class Session:
    """Everything one connection did, from login to disconnect.

    ``origin`` records where the session came from: the honeypot, or a benign
    baseline imported from shell history. Identifiers are globally unique by
    being prefixed with the sensor or host that recorded the session, because
    Cowrie's own session identifiers are only unique per sensor.
    """

    id: str
    origin: str
    sensor: str
    start: datetime
    end: datetime
    source_ip: str | None = None
    protocol: str | None = None
    username: str | None = None
    password: str | None = None
    login_success: bool = False
    client_version: str | None = None
    commands: list[Command] = field(default_factory=list)
    downloads: list[dict[str, str]] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return max((self.end - self.start).total_seconds(), 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "id": self.id,
            "origin": self.origin,
            "sensor": self.sensor,
            "start": iso(self.start),
            "end": iso(self.end),
            "source_ip": self.source_ip,
            "protocol": self.protocol,
            "username": self.username,
            "password": self.password,
            "login_success": self.login_success,
            "client_version": self.client_version,
            "commands": [{"t": iso(c.timestamp), "c": c.text} for c in self.commands],
            "downloads": self.downloads,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Session":
        """Rebuild a session from its stored form, rejecting anything incomplete."""
        schema = data.get("schema", SCHEMA_VERSION)
        if schema != SCHEMA_VERSION:
            raise ValueError(f"unsupported session schema {schema!r}")

        session_id = data.get("id")
        start = parse_timestamp(data.get("start"))
        end = parse_timestamp(data.get("end")) or start
        if not session_id or start is None or end is None:
            raise ValueError("a session needs an id and a start time")

        commands = []
        for item in data.get("commands") or []:
            moment = parse_timestamp(item.get("t")) or start
            commands.append(Command(moment, str(item.get("c", ""))))

        return cls(
            id=str(session_id),
            origin=str(data.get("origin") or ORIGIN_COWRIE),
            sensor=str(data.get("sensor") or "unknown"),
            start=start,
            end=end,
            source_ip=data.get("source_ip"),
            protocol=data.get("protocol"),
            username=data.get("username"),
            password=data.get("password"),
            login_success=bool(data.get("login_success")),
            client_version=data.get("client_version"),
            commands=commands,
            downloads=[dict(d) for d in data.get("downloads") or []],
        )


# ------------------------------------------------------------------- assembly


class CowrieSessionAssembler:
    """Folds Cowrie events into sessions.

    A session can start in one log file and end in the next, and a log may be
    read twice when an archived copy sits beside the original, so state is held
    per session until the stream ends and repeated commands are dropped.
    Sessions that close without running a command are discarded on close: most
    honeypot sessions are failed logins, and weeks of them would otherwise sit
    in memory for nothing.
    """

    def __init__(self, *, sensor_id: str | None = None) -> None:
        self.sensor_id = sensor_id
        self.events = 0
        self.skipped = 0
        self._open: dict[tuple[str, str], Session] = {}
        self._kept: dict[tuple[str, str], Session] = {}
        self._seen: dict[tuple[str, str], set[tuple[datetime, str]]] = defaultdict(set)

    def add(self, event: Mapping[str, Any]) -> None:
        cowrie_id = event.get("session")
        eventid = event.get("eventid")
        moment = parse_timestamp(event.get("timestamp"))
        if not cowrie_id or not isinstance(eventid, str) or moment is None:
            self.skipped += 1
            return

        sensor = self.sensor_id or str(event.get("sensor") or "unknown")
        key = (sensor, str(cowrie_id))
        session = self._kept.get(key) or self._open.get(key)
        if session is None:
            session = Session(
                id=f"{sensor}/{cowrie_id}",
                origin=ORIGIN_COWRIE,
                sensor=sensor,
                start=moment,
                end=moment,
            )
            self._open[key] = session

        self.events += 1
        session.start = min(session.start, moment)
        session.end = max(session.end, moment)
        if event.get("src_ip") and not session.source_ip:
            session.source_ip = str(event["src_ip"])

        if eventid == "cowrie.session.connect":
            session.protocol = event.get("protocol") or session.protocol
        elif eventid == "cowrie.login.success":
            session.username = event.get("username")
            session.password = event.get("password")
            session.login_success = True
        elif eventid == "cowrie.client.version":
            session.client_version = event.get("version")
        elif eventid == COMMAND_EVENT:
            text = event.get("input")
            if isinstance(text, str) and text.strip() and (moment, text) not in self._seen[key]:
                self._seen[key].add((moment, text))
                session.commands.append(Command(moment, text))
        elif eventid == "cowrie.session.file_download":
            download = {
                "url": str(event.get("url") or ""),
                "sha256": str(event.get("shasum") or ""),
            }
            if download not in session.downloads:
                session.downloads.append(download)
        elif eventid == "cowrie.session.closed":
            self._close(key)

    def _close(self, key: tuple[str, str]) -> None:
        session = self._open.pop(key, None)
        if session is None:
            return
        if session.commands:
            self._kept[key] = session
        else:
            self._seen.pop(key, None)

    def sessions(self) -> list[Session]:
        """Every session that ran a command, ordered by start time."""
        found = list(self._kept.values()) + [s for s in self._open.values() if s.commands]
        for session in found:
            session.commands.sort(key=lambda c: c.timestamp)
        return sorted(found, key=lambda s: (s.start, s.id))


def read_cowrie_events(path: Path) -> Iterator[dict[str, Any]]:
    """Events from one Cowrie JSON log, plain or gzipped.

    A log copied while Cowrie was writing it can end in half a line, and a
    honeypot log is written by software handling hostile input, so lines that
    do not parse are skipped rather than allowed to stop the build.
    """
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                log.debug("%s:%s is not JSON; skipped", path.name, number)
                continue
            if isinstance(event, dict):
                yield event


def cowrie_log_files(paths: Iterable[Path]) -> list[Path]:
    """Expand files and directories into Cowrie logs, oldest content first.

    Directories are searched for Cowrie's own names (``cowrie.json`` and its
    dated rotations) and for any ``.json`` or ``.json.gz`` file. Files are
    ordered by their first event, because rotation suffixes do not sort
    chronologically under every naming scheme.
    """
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(
                p
                for p in sorted(path.rglob("*"))
                if p.is_file()
                and (p.name.startswith("cowrie.json") or p.name.endswith((".json", ".json.gz")))
            )
        else:
            found.append(path)

    def first_event(path: Path) -> datetime:
        for event in read_cowrie_events(path):
            moment = parse_timestamp(event.get("timestamp"))
            if moment is not None:
                return moment
        return datetime.max.replace(tzinfo=timezone.utc)

    return sorted(dict.fromkeys(found), key=lambda p: (first_event(p), str(p)))


@dataclass(slots=True)
class Assembly:
    """The outcome of building sessions, with the figures worth reporting."""

    sessions: list[Session]
    files: int
    events: int
    skipped: int


def build_sessions(paths: Iterable[Path], *, sensor_id: str | None = None) -> Assembly:
    """Assemble command sessions from Cowrie logs."""
    assembler = CowrieSessionAssembler(sensor_id=sensor_id)
    files = cowrie_log_files(paths)
    for path in files:
        for event in read_cowrie_events(path):
            assembler.add(event)
    return Assembly(assembler.sessions(), len(files), assembler.events, assembler.skipped)


# ------------------------------------------------------------------- storage


def write_sessions(path: Path, sessions: Iterable[Session]) -> int:
    """Write a corpus atomically, so an interrupted build leaves the old one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    count = 0
    with temporary.open("w", encoding="utf-8") as handle:
        for session in sessions:
            handle.write(json.dumps(session.to_dict(), separators=(",", ":")) + "\n")
            count += 1
    os.replace(temporary, path)
    return count


def read_session_records(paths: Iterable[Path]) -> Iterator[tuple[Path, int, dict[str, Any]]]:
    """Raw session objects with where they came from, for callers that need extra keys."""
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{number}: not valid JSON: {exc}") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"{path}:{number}: expected a JSON object")
                yield path, number, record


def read_sessions(paths: Iterable[Path]) -> list[Session]:
    """Load one or more corpora.

    The same identifier appearing twice means the same corpus was passed twice
    or two corpora overlap, and either would count sessions twice in an
    evaluation, so it is an error rather than something to resolve quietly.
    """
    sessions: list[Session] = []
    seen: dict[str, str] = {}
    for path, number, record in read_session_records(paths):
        try:
            session = Session.from_dict(record)
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: {exc}") from exc
        if session.id in seen:
            raise ValueError(
                f"{path}:{number}: session {session.id} also appears in {seen[session.id]}"
            )
        seen[session.id] = f"{path}:{number}"
        sessions.append(session)
    return sessions


# ------------------------------------------------------------- shell history

_BASH_STAMP = re.compile(r"^#(\d{9,11})\s*$")
_ZSH_ENTRY = re.compile(r"^: (\d{9,11}):\d+;(.*)$", re.DOTALL)


def parse_shell_history(text: str) -> list[tuple[datetime, str]]:
    """Timestamped commands from a bash or zsh history file.

    Bash writes ``#<epoch>`` before each entry when ``HISTTIMEFORMAT`` is set,
    and zsh writes ``: <epoch>:<duration>;<command>`` with ``EXTENDED_HISTORY``.
    Entries before the first timestamp cannot be placed in time and are
    dropped. A file with no timestamps at all is an error, because sessions,
    and the split between tuning and held-out weeks, both depend on time.
    """
    lines = text.splitlines()
    entries: list[tuple[datetime, str]] = []
    stamp: datetime | None = None

    if any(_ZSH_ENTRY.match(line) for line in lines):
        command = ""
        for line in lines:
            # zsh stores a multi-line command with each newline escaped, so a
            # line after a trailing backslash continues the entry before it.
            continued = stamp is not None and command.endswith("\\")
            match = None if continued else _ZSH_ENTRY.match(line)
            if match:
                if stamp is not None:
                    entries.append((stamp, command))
                stamp = datetime.fromtimestamp(int(match.group(1)), tz=timezone.utc)
                command = match.group(2)
            elif continued:
                command = command[:-1] + "\n" + line
        if stamp is not None:
            entries.append((stamp, command))
    elif any(_BASH_STAMP.match(line) for line in lines):
        pending: list[str] = []
        for line in lines:
            match = _BASH_STAMP.match(line)
            if match:
                if stamp is not None and pending:
                    entries.append((stamp, "\n".join(pending)))
                stamp = datetime.fromtimestamp(int(match.group(1)), tz=timezone.utc)
                pending = []
            elif stamp is not None:
                pending.append(line)
        if stamp is not None and pending:
            entries.append((stamp, "\n".join(pending)))
    else:
        raise ValueError(
            "history has no timestamps; enable them before collecting a baseline "
            "(bash: export HISTTIMEFORMAT='%F %T '; zsh: setopt EXTENDED_HISTORY)"
        )

    return [(moment, command) for moment, command in entries if command.strip()]


def sessions_from_history(
    entries: Iterable[tuple[datetime, str]],
    *,
    host: str,
    user: str | None = None,
    idle: timedelta = DEFAULT_IDLE_GAP,
) -> list[Session]:
    """Split timestamped commands into sessions at idle gaps."""
    ordered = sorted(entries, key=lambda e: e[0])
    groups: list[list[Command]] = []
    for moment, text in ordered:
        if groups and moment - groups[-1][-1].timestamp <= idle:
            groups[-1].append(Command(moment, text))
        else:
            groups.append([Command(moment, text)])

    owner = f"{host}/{user}" if user else host
    return [
        Session(
            id=f"{owner}/{commands[0].timestamp:%Y%m%dT%H%M%SZ}",
            origin=ORIGIN_HISTORY,
            sensor=host,
            start=commands[0].timestamp,
            end=commands[-1].timestamp,
            username=user,
            commands=commands,
        )
        for commands in groups
    ]


def import_shell_history(
    paths: Iterable[Path],
    *,
    host: str,
    user: str | None = None,
    idle: timedelta = DEFAULT_IDLE_GAP,
) -> list[Session]:
    """Benign sessions from one host's history files, merged before splitting.

    Merging first means a bash and a zsh history from the same account produce
    one timeline, rather than two sets of sessions that overlap in time and
    collide on their identifiers.
    """
    entries: list[tuple[datetime, str]] = []
    for path in paths:
        entries.extend(parse_shell_history(path.read_text(encoding="utf-8", errors="replace")))
    return sessions_from_history(entries, host=host, user=user, idle=idle)


# ------------------------------------------------------------------ families

_NORMALISERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+)\s+AAAA[0-9A-Za-z+/]+=*(?:\s+[^\s'\"]+)?"
        ),
        "<sshkey>",
    ),
    (re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>|;&)]+", re.IGNORECASE), "<url>"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2})+"), "<bytes>"),
    (
        re.compile(
            r"(?<![A-Za-z0-9+/])(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*\d)"
            r"[A-Za-z0-9+/]{24,}={0,2}"
        ),
        "<base64>",
    ),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    # A random password or file name is sometimes all hex digits by chance, so
    # hashes and tokens share one placeholder rather than splitting a family.
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<token>"),
    (re.compile(r"\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{8,}\b"), "<token>"),
    (re.compile(r"\s+"), " "),
)


def normalise_command(text: str) -> str:
    """Reduce a command to its shape, discarding what varies between runs.

    Bots running one script differ only in the parts chosen per target: the
    download address, the random password, the key, the encoded blob. Replacing
    those with placeholders leaves the part that identifies the tool.
    """
    for pattern, replacement in _NORMALISERS:
        text = pattern.sub(replacement, text)
    return text.strip()


def session_family(session: Session) -> str:
    """Identifier shared by sessions that ran the same commands in the same order."""
    shape = "\n".join(normalise_command(c.text) for c in session.commands)
    return "f-" + hashlib.sha256(shape.encode("utf-8")).hexdigest()[:10]


def group_families(sessions: Iterable[Session]) -> dict[str, list[Session]]:
    """Sessions grouped by family, largest family first.

    Labelling a family at a time is what makes a month of honeypot sessions
    practical to label: a few dozen scripts account for most of them.
    """
    groups: dict[str, list[Session]] = defaultdict(list)
    for session in sessions:
        groups[session_family(session)].append(session)
    ordered = sorted(
        groups.items(), key=lambda item: (-len(item[1]), min(s.start for s in item[1]))
    )
    return dict(ordered)


# --------------------------------------------------------------------- stats


def iso_week(moment: datetime) -> str:
    year, week, _ = moment.astimezone(timezone.utc).isocalendar()
    return f"{year}-W{week:02d}"


def corpus_stats(sessions: Sequence[Session]) -> dict[str, Any]:
    """The figures that describe a corpus: how much, over how long, from where."""
    if not sessions:
        return {"sessions": 0}

    starts = sorted(s.start for s in sessions)
    return {
        "sessions": len(sessions),
        "commands": sum(len(s.commands) for s in sessions),
        "first_seen": iso(starts[0]),
        "last_seen": iso(starts[-1]),
        "span_days": round((starts[-1] - starts[0]).total_seconds() / 86400, 1),
        "weeks": dict(sorted(Counter(iso_week(s.start) for s in sessions).items())),
        "origins": dict(Counter(s.origin for s in sessions).most_common()),
        "sensors": dict(Counter(s.sensor for s in sessions).most_common()),
        "sources": len({s.source_ip for s in sessions if s.source_ip}),
        "families": len({session_family(s) for s in sessions}),
        "with_downloads": sum(1 for s in sessions if s.downloads),
    }


def stats_to_markdown(stats: Mapping[str, Any]) -> str:
    if not stats.get("sessions"):
        return "No sessions."

    lines = [
        f"**{stats['sessions']:,} command sessions** over {stats['span_days']} days "
        f"({stats['first_seen'][:10]} to {stats['last_seen'][:10]})",
        "",
        "| ISO week | Sessions |",
        "| --- | ---: |",
    ]
    lines += [f"| {week} | {count:,} |" for week, count in stats["weeks"].items()]
    lines += [
        "",
        f"- Commands: {stats['commands']:,}",
        f"- Distinct source addresses: {stats['sources']:,}",
        f"- Command families: {stats['families']:,}",
        f"- Sessions that downloaded a file: {stats['with_downloads']:,}",
        "- Origins: " + ", ".join(f"{name} {count:,}" for name, count in stats["origins"].items()),
        "- Sensors: " + ", ".join(f"{name} {count:,}" for name, count in stats["sensors"].items()),
    ]
    return "\n".join(lines)
