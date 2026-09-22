"""Extraction service behaviour that does not require tshark or a network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from deception_shield.extractor import (
    CaptureArchiver,
    ExtractorService,
    LogstashShipper,
)


class RecordingShipper(LogstashShipper):
    """Captures documents instead of sending them."""

    def __init__(self) -> None:
        super().__init__("unused", 0)
        self.sent: list[dict] = []

    def send(self, document: dict) -> bool:
        self.sent.append(document)
        return True

    def close(self) -> None:
        pass


@pytest.fixture
def service(tmp_path: Path) -> ExtractorService:
    capture_dir = tmp_path / "pcap"
    output_dir = tmp_path / "extracted"
    capture_dir.mkdir()
    output_dir.mkdir()
    return ExtractorService(
        capture_dir,
        output_dir,
        RecordingShipper(),
        CaptureArchiver(None, sensor_id="test"),
        sensor_id="test",
        poll_interval=1,
    )


class TestSettledCaptureDetection:
    def test_a_growing_capture_is_skipped(self, service: ExtractorService) -> None:
        """tcpdump writes the active capture in place; dissecting it would truncate."""
        capture = service.capture_dir / "sensor-20260920-120000.pcap"
        capture.write_bytes(b"\x00" * 100)

        assert service._settled_captures() == []  # first sighting, size unknown

        capture.write_bytes(b"\x00" * 200)
        assert service._settled_captures() == []  # size changed, still writing

    def test_a_stable_capture_is_returned(self, service: ExtractorService) -> None:
        capture = service.capture_dir / "sensor-20260920-120000.pcap"
        capture.write_bytes(b"\x00" * 100)

        service._settled_captures()
        assert service._settled_captures() == [capture]

    def test_empty_captures_are_ignored(self, service: ExtractorService) -> None:
        (service.capture_dir / "sensor-20260920-120000.pcap").touch()
        service._settled_captures()
        assert service._settled_captures() == []

    def test_unrelated_files_are_ignored(self, service: ExtractorService) -> None:
        (service.capture_dir / "notes.txt").write_bytes(b"x" * 50)
        service._settled_captures()
        assert service._settled_captures() == []

    def test_gzipped_rotations_are_picked_up(self, service: ExtractorService) -> None:
        capture = service.capture_dir / "sensor-20260920-120000.pcap.gz"
        capture.write_bytes(b"\x1f\x8b" + b"\x00" * 50)
        service._settled_captures()
        assert service._settled_captures() == [capture]


class TestProcessedState:
    def test_state_survives_a_restart(self, service: ExtractorService, tmp_path: Path) -> None:
        """A restart must not re-ship records already sent."""
        service._processed.add("sensor-20260920-120000.pcap")
        service._save_state()

        revived = ExtractorService(
            service.capture_dir,
            service.output_dir,
            RecordingShipper(),
            CaptureArchiver(None, sensor_id="test"),
        )
        assert "sensor-20260920-120000.pcap" in revived._processed

    def test_already_processed_captures_are_skipped(self, service: ExtractorService) -> None:
        capture = service.capture_dir / "sensor-20260920-120000.pcap"
        capture.write_bytes(b"\x00" * 100)
        service._processed.add(capture.name)

        service._settled_captures()
        assert service._settled_captures() == []

    def test_corrupt_state_file_is_tolerated(self, service: ExtractorService) -> None:
        (service.output_dir / ".processed.json").write_text("{not json")
        revived = ExtractorService(
            service.capture_dir,
            service.output_dir,
            RecordingShipper(),
            CaptureArchiver(None, sensor_id="test"),
        )
        assert revived._processed == set()

    def test_state_is_bounded(self, service: ExtractorService) -> None:
        """The file must not grow without limit on a long running sensor."""
        service._processed = {f"sensor-{i:06d}.pcap" for i in range(6000)}
        service._save_state()
        stored = json.loads((service.output_dir / ".processed.json").read_text())
        assert len(stored["processed"]) == 5000


class TestArchiver:
    def test_archiving_is_skipped_without_a_bucket(self, tmp_path: Path) -> None:
        """Offline analysis must work with no AWS configuration present."""
        assert CaptureArchiver(None, sensor_id="s").archive(tmp_path / "a.pcap") is False


class TestShutdown:
    def test_stop_clears_the_running_flag(self, service: ExtractorService) -> None:
        assert service._running is True
        service.stop()
        assert service._running is False
