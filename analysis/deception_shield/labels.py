"""Labels: the human judgement every measurement here is made against.

A label says whether a session was an attack, benign, or should be left out of
measurement, and for an attack which ATT&CK techniques the labeller saw in it.
Labels live apart from sessions, in a CSV a person can read and correct, so
relabelling never means rebuilding the corpus. Rows are appended and the last
row for a session wins, which keeps a history of every decision.

Labelling goes one family at a time (sessions that ran the same commands in the
same order), which turns a month of honeypot sessions into a few dozen
decisions. The labeller is never shown what the rules made of a session: labels
judged with the rules' verdicts in view would measure the rules against
themselves.
"""

from __future__ import annotations

import csv
import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from deception_shield.sessions import Session, group_families, iso, printable

LABELS: tuple[str, ...] = ("attack", "benign", "exclude")
FIELDS: tuple[str, ...] = (
    "session_id",
    "label",
    "techniques",
    "family",
    "method",
    "labelled_at",
    "note",
)

_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Offered by the interactive labeller after the rule set's own techniques. The
# list leans on what SSH honeypots record, so a labeller can mark behaviour no
# rule covers yet; those gaps then show up in every evaluation.
TECHNIQUE_NAMES: dict[str, str] = {
    "T1098.004": "SSH Authorized Keys",
    "T1082": "System Information Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1059.004": "Unix Shell",
    "T1070.003": "Clear Command History",
    "T1053.003": "Cron",
    "T1098": "Account Manipulation",
    "T1496.001": "Compute Hijacking",
    "T1562.001": "Disable or Modify Tools",
    "T1222.002": "Linux and Mac File and Directory Permissions Modification",
    "T1057": "Process Discovery",
    "T1033": "System Owner/User Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1531": "Account Access Removal",
}


@dataclass(frozen=True, slots=True)
class Label:
    session_id: str
    label: str
    techniques: tuple[str, ...] = ()
    family: str = ""
    method: str = "manual"
    labelled_at: str = ""
    note: str = ""

    def to_row(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "label": self.label,
            "techniques": ";".join(self.techniques),
            "family": self.family,
            "method": self.method,
            "labelled_at": self.labelled_at,
            "note": self.note,
        }


def parse_techniques(text: str) -> tuple[str, ...]:
    """ATT&CK technique identifiers from free text, validated and de-duplicated."""
    items = [item.strip().upper() for item in re.split(r"[;,\s]+", text or "") if item.strip()]
    invalid = [item for item in items if not _TECHNIQUE.match(item)]
    if invalid:
        raise ValueError(f"not ATT&CK technique identifiers: {', '.join(invalid)}")
    return tuple(dict.fromkeys(items))


def read_labels(path: Path) -> dict[str, Label]:
    """Labels by session, the last row for a session taking precedence."""
    if not path.exists():
        return {}

    labels: dict[str, Label] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = {"session_id", "label"} - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing column {', '.join(sorted(missing))}")
        for number, row in enumerate(reader, start=2):
            session_id = (row.get("session_id") or "").strip()
            label = (row.get("label") or "").strip().lower()
            if not session_id:
                raise ValueError(f"{path}:{number}: session_id is empty")
            if label not in LABELS:
                raise ValueError(
                    f"{path}:{number}: label {label!r} is not one of {', '.join(LABELS)}"
                )
            try:
                techniques = parse_techniques(row.get("techniques") or "")
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: {exc}") from exc
            labels[session_id] = Label(
                session_id=session_id,
                label=label,
                techniques=techniques,
                family=(row.get("family") or "").strip(),
                method=(row.get("method") or "manual").strip(),
                labelled_at=(row.get("labelled_at") or "").strip(),
                note=(row.get("note") or "").strip(),
            )
    return labels


def append_labels(path: Path, labels: Iterable[Label]) -> int:
    """Append rows, writing the header for a new file.

    An existing file keeps its own column order, so a label file someone has
    reshaped in a spreadsheet is extended rather than corrupted.
    """
    rows = [label.to_row() for label in labels]
    if not rows:
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: Sequence[str] = FIELDS
    if path.exists() and path.stat().st_size:
        with path.open(newline="", encoding="utf-8") as handle:
            fieldnames = next(csv.reader(handle), None) or FIELDS

    new_file = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
        if new_file:
            writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def _now() -> str:
    return iso(datetime.now(timezone.utc).replace(microsecond=0))


def label_all(
    sessions: Iterable[Session],
    path: Path,
    label: str,
    *,
    techniques: Sequence[str] = (),
    note: str = "",
) -> int:
    """Give every unlabelled session the same label.

    Meant for benign baselines, which are benign by construction: they come from
    hosts the operator controls, not from a judgement about each session.
    """
    if label not in LABELS:
        raise ValueError(f"label must be one of {', '.join(LABELS)}")
    existing = read_labels(path)
    stamp = _now()
    pending = [
        Label(s.id, label, tuple(techniques), method="bulk", labelled_at=stamp, note=note)
        for s in sessions
        if s.id not in existing
    ]
    return append_labels(path, pending)


def label_interactively(
    sessions: Sequence[Session],
    path: Path,
    *,
    techniques: Sequence[str] = (),
    ask: Callable[[str], str] = input,
    out: TextIO | None = None,
    example_lines: int = 15,
) -> int:
    """Walk the unlabelled families, largest first, and record each decision.

    Every decision is written as soon as it is made, so quitting part way and
    resuming later loses nothing. ``techniques`` lists the identifiers offered
    by number, normally the rule set's own; any other identifier can be typed.
    """
    out = out or sys.stdout
    existing = read_labels(path)
    families = group_families(sessions)
    pending = {
        family: [s for s in members if s.id not in existing] for family, members in families.items()
    }
    pending = {family: members for family, members in pending.items() if members}

    menu = list(dict.fromkeys([*techniques, *TECHNIQUE_NAMES]))
    remaining = sum(len(members) for members in pending.values())
    out.write(
        f"{len(families)} families, {len(sessions)} sessions: "
        f"{len(sessions) - remaining} labelled, {remaining} to go\n"
    )
    if pending:
        _show_menu(out, menu)

    labelled = 0
    for position, (family, members) in enumerate(pending.items(), start=1):
        example = 0
        while True:
            _show_family(out, position, len(pending), family, members, example, example_lines)
            try:
                answer = ask(
                    "label: [a]ttack [b]enign e[x]clude, [n]ext example, [s]kip, [q]uit > "
                )
            except EOFError:
                return labelled
            answer = answer.strip().lower()

            if answer in ("q", "quit"):
                return labelled
            if answer in ("s", "skip"):
                break
            if answer in ("n", "next"):
                example = (example + 1) % len(members)
                continue
            choice = {"a": "attack", "b": "benign", "x": "exclude"}.get(answer[:1])
            if choice is None:
                continue

            chosen: tuple[str, ...] = ()
            if choice == "attack":
                try:
                    chosen = _ask_techniques(ask, out, menu)
                except EOFError:
                    return labelled

            stamp = _now()
            labelled += append_labels(
                path,
                [
                    Label(s.id, choice, chosen, family=family, method="family", labelled_at=stamp)
                    for s in members
                ],
            )
            suffix = f" ({', '.join(chosen)})" if chosen else ""
            out.write(f"  labelled {len(members)} session(s) {choice}{suffix}\n\n")
            break

    out.write("every family is labelled\n")
    return labelled


def _show_family(
    out: TextIO,
    position: int,
    total: int,
    family: str,
    members: Sequence[Session],
    example: int,
    example_lines: int,
) -> None:
    sources = {s.source_ip for s in members if s.source_ip}
    first = min(s.start for s in members)
    last = max(s.start for s in members)
    session = members[example]
    who = ", ".join(
        printable(part)
        for part in (session.source_ip, session.protocol, session.username, session.client_version)
        if part
    )

    out.write(
        f"[{position}/{total}] family {family}: "
        f"{len(members)} session(s) from {len(sources)} source(s), "
        f"{iso(first)[:10]} to {iso(last)[:10]}\n"
        f"  example {example + 1} of {len(members)}: "
        f"{printable(session.id)} ({who or session.origin})\n"
    )
    for index, command in enumerate(session.commands[:example_lines], start=1):
        out.write(f"  {index:>4}  {printable(command.text, 400)}\n")
    if len(session.commands) > example_lines:
        out.write(f"        … {len(session.commands) - example_lines} more command(s)\n")


def _show_menu(out: TextIO, menu: Sequence[str]) -> None:
    out.write("techniques, by number or ATT&CK ID:\n")
    for number, technique in enumerate(menu, start=1):
        out.write(f"  {number:>2} {technique:<10} {TECHNIQUE_NAMES.get(technique, '')}\n")
    out.write("\n")


def _ask_techniques(ask: Callable[[str], str], out: TextIO, menu: Sequence[str]) -> tuple[str, ...]:
    while True:
        answer = ask("  techniques seen (comma separated, blank for none, ? to list) > ")
        if answer.strip() == "?":
            _show_menu(out, menu)
            continue
        chosen: list[str] = []
        try:
            for item in re.split(r"[;,\s]+", answer.strip()):
                if not item:
                    continue
                if item.isdigit() and 1 <= int(item) <= len(menu):
                    chosen.append(menu[int(item) - 1])
                else:
                    chosen.extend(parse_techniques(item))
        except ValueError as exc:
            out.write(f"  {exc}\n")
            continue
        return tuple(dict.fromkeys(chosen))


def labelled_sessions(
    sessions: Iterable[Session], labels: Mapping[str, Label]
) -> tuple[list[Session], list[Session], int, int]:
    """Split sessions by label: attack, benign, excluded count, unlabelled count."""
    attack: list[Session] = []
    benign: list[Session] = []
    excluded = unlabelled = 0
    for session in sessions:
        label = labels.get(session.id)
        if label is None:
            unlabelled += 1
        elif label.label == "attack":
            attack.append(session)
        elif label.label == "benign":
            benign.append(session)
        else:
            excluded += 1
    return attack, benign, excluded, unlabelled
