"""Capture dissection via tshark.

Wireshark's command line engine does the protocol work. Running it rather than
parsing frames in Python means the sensor gets Wireshark's reassembly and its
full dissector table: a payload split across five TCP segments arrives here as
one record, and application protocols are identified by dissection rather than
by port number.

The subprocess boundary is kept narrow on purpose. :func:`build_command` and
:func:`parse_field_line` are pure, so the parsing logic is tested without tshark
installed, and :func:`extract_records` is the only function that shells out.
"""

from __future__ import annotations

import gzip
import logging
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from deception_shield.models import PayloadRecord
from deception_shield.scoring import score_payload

log = logging.getLogger(__name__)

# Order matters: the parser indexes into the output by position, so this tuple
# is the single definition of the record layout.
TSHARK_FIELDS: tuple[str, ...] = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "_ws.col.Protocol",
    "tcp.payload",
    "data.data",
)

# Frames with no application payload describe the conversation but carry nothing
# to inspect, so they are filtered inside tshark rather than discarded later.
DEFAULT_DISPLAY_FILTER = "tcp.len > 0 or udp.length > 8"

FIELD_SEPARATOR = "\t"


class TsharkNotAvailable(RuntimeError):
    """Raised when tshark is not installed or not on PATH."""


def tshark_path() -> str:
    """Locate the tshark binary."""
    found = shutil.which("tshark")
    if not found:
        raise TsharkNotAvailable(
            "tshark was not found on PATH. Install the wireshark command line "
            "tools (apt-get install tshark) to dissect captures."
        )
    return found


def build_command(
    capture: Path,
    *,
    display_filter: str = DEFAULT_DISPLAY_FILTER,
    fields: tuple[str, ...] = TSHARK_FIELDS,
    executable: str = "tshark",
) -> list[str]:
    """Assemble the tshark invocation for one capture file.

    ``occurrence=f`` keeps one value per field per frame. Without it a frame
    carrying tunnelled traffic emits several comma joined values and the columns
    stop lining up with the layout above.
    """
    command = [
        executable,
        "-r", str(capture),
        "-Y", display_filter,
        "-T", "fields",
        "-E", f"separator={FIELD_SEPARATOR}",
        "-E", "occurrence=f",
        "-E", "quote=n",
        # Reassembly is what makes a record correspond to an application message
        # rather than to a single frame.
        "-o", "tcp.desegment_tcp_streams:TRUE",
        "-o", "tcp.reassemble_out_of_order:TRUE",
        "-n",
    ]
    for field in fields:
        command += ["-e", field]
    return command


def _decode_hex(value: str) -> bytes:
    """Decode a tshark hex field.

    Output format varies by version: some emit ``48:54:54:50`` and others
    ``48545450``. Both appear in the wild, so both are accepted.
    """
    if not value:
        return b""
    cleaned = value.replace(":", "").replace(" ", "").strip()
    if not cleaned:
        return b""
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        log.debug("undecodable payload field: %.40s", value)
        return b""


def parse_field_line(line: str, *, sensor_id: str = "unknown") -> PayloadRecord | None:
    """Turn one tab separated tshark row into a record.

    Returns ``None`` for rows that cannot form a record: malformed lines, frames
    without an IP layer, and frames whose payload decoded to nothing.
    """
    if not line.strip():
        return None

    parts = line.rstrip("\n").split(FIELD_SEPARATOR)
    if len(parts) < len(TSHARK_FIELDS):
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))

    (
        epoch,
        src_ip,
        dst_ip,
        tcp_sport,
        tcp_dport,
        udp_sport,
        udp_dport,
        stream,
        protocol,
        tcp_payload,
        udp_payload,
    ) = parts[: len(TSHARK_FIELDS)]

    if not src_ip or not dst_ip:
        return None

    try:
        timestamp = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None

    if tcp_sport:
        transport, sport, dport = "tcp", tcp_sport, tcp_dport
    elif udp_sport:
        transport, sport, dport = "udp", udp_sport, udp_dport
    else:
        return None

    try:
        source_port, destination_port = int(sport), int(dport)
    except ValueError:
        return None

    payload = _decode_hex(tcp_payload) or _decode_hex(udp_payload)
    if not payload:
        return None

    record = PayloadRecord(
        timestamp=timestamp,
        source_ip=src_ip,
        source_port=source_port,
        destination_ip=dst_ip,
        destination_port=destination_port,
        transport=transport,
        payload=payload,
        protocol=protocol or None,
        stream_id=int(stream) if stream.isdigit() else None,
        sensor_id=sensor_id,
    )

    verdict = score_payload(record.payload, printable_ratio=record.printable_ratio)
    record.score = verdict.score
    record.signatures = verdict.signatures
    record.triage = verdict.triage
    return record


def _materialise(capture: Path) -> tuple[Path, Path | None]:
    """Give tshark a plain file to read.

    Rotated captures are gzipped by tcpdump's post-rotate hook. tshark cannot
    read those directly, so a compressed capture is expanded into a temporary
    file whose path is returned alongside the original for cleanup.
    """
    if capture.suffix != ".gz":
        return capture, None

    handle = tempfile.NamedTemporaryFile(prefix="ds-capture-", suffix=".pcap", delete=False)
    temporary = Path(handle.name)
    try:
        with gzip.open(capture, "rb") as compressed:
            shutil.copyfileobj(compressed, handle)
    finally:
        handle.close()
    return temporary, temporary


def extract_records(
    capture: Path,
    *,
    sensor_id: str = "unknown",
    display_filter: str = DEFAULT_DISPLAY_FILTER,
    timeout: int = 900,
) -> Iterator[PayloadRecord]:
    """Dissect a capture and yield one record per application payload.

    Records stream as tshark produces them, so a multi gigabyte capture is
    processed without being held in memory.
    """
    target, temporary = _materialise(capture)

    try:
        command = build_command(target, display_filter=display_filter, executable=tshark_path())
        log.info("dissecting %s", capture.name)

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        assert process.stdout is not None
        try:
            for line in process.stdout:
                record = parse_field_line(line, sensor_id=sensor_id)
                if record is not None:
                    yield record

            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            log.error("tshark exceeded %ss on %s", timeout, capture.name)
            raise
        finally:
            if process.poll() is None:
                process.kill()

        if process.returncode not in (0, None):
            stderr = process.stderr.read() if process.stderr else ""
            log.warning("tshark exited %s on %s: %s", process.returncode, capture.name, stderr.strip())
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def capture_summary(records: list[PayloadRecord]) -> dict[str, object]:
    """Condense a dissected capture into the figures worth logging per file."""
    if not records:
        return {"records": 0, "sources": 0, "bytes": 0, "max_score": 0}

    return {
        "records": len(records),
        "sources": len({r.source_ip for r in records}),
        "ports": sorted({r.destination_port for r in records}),
        "bytes": sum(r.payload_length for r in records),
        "max_score": max(r.score for r in records),
        "flagged": sum(1 for r in records if r.score >= 20),
        "window": [
            min(r.timestamp for r in records).isoformat(),
            max(r.timestamp for r in records).isoformat(),
        ],
    }
