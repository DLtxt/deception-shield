"""The capture extraction service.

Runs continuously on the sensor. tcpdump rotates captures into a directory; this
watches for completed rotations, hands each one to tshark, ships the resulting
records to Logstash, and archives the capture to S3.

Only closed files are processed. tcpdump writes the active capture in place, so
a file is considered complete when its size has stopped changing between polls,
which avoids dissecting a capture that is still being written.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import time
from pathlib import Path
from typing import Any

from deception_shield.pcap import (
    TsharkNotAvailable,
    capture_summary,
    extract_records,
)

log = logging.getLogger("deception_shield.extractor")

STATE_FILENAME = ".processed.json"


class LogstashShipper:
    """Line delimited JSON over TCP to the Logstash input.

    The connection is reopened on failure rather than held open indefinitely,
    because Logstash restarts during stack upgrades and a stale socket would
    silently discard records.
    """

    def __init__(self, host: str, port: int, *, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._socket: socket.socket | None = None

    def _connect(self) -> socket.socket:
        if self._socket is not None:
            return self._socket
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        self._socket = sock
        log.info("connected to logstash at %s:%s", self.host, self.port)
        return sock

    def send(self, document: dict[str, Any]) -> bool:
        payload = (json.dumps(document, separators=(",", ":")) + "\n").encode("utf-8")
        for attempt in (1, 2):
            try:
                self._connect().sendall(payload)
                return True
            except (OSError, socket.timeout) as exc:
                log.warning("logstash send failed (attempt %s): %s", attempt, exc)
                self.close()
                if attempt == 2:
                    return False
                time.sleep(1.0)
        return False

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None

    def __enter__(self) -> "LogstashShipper":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class CaptureArchiver:
    """Copies processed captures to S3 and removes the local copy.

    The sensor's data volume is sized for a working set, not for retention, so
    a capture that has been dissected and archived is deleted locally. boto3 is
    imported lazily to keep the package usable for offline analysis on a machine
    with no AWS credentials.
    """

    def __init__(self, bucket: str | None, *, sensor_id: str, region: str | None = None) -> None:
        self.bucket = bucket
        self.sensor_id = sensor_id
        self._client = None
        self._region = region

    def _get_client(self):
        if self._client is None:
            import boto3

            self._client = boto3.client("s3", region_name=self._region)
        return self._client

    def archive(self, capture: Path) -> bool:
        if not self.bucket:
            return False

        key = f"pcap/{self.sensor_id}/{capture.name}"
        try:
            self._get_client().upload_file(str(capture), self.bucket, key)
            log.info("archived %s to s3://%s/%s", capture.name, self.bucket, key)
            return True
        except Exception as exc:  # noqa: BLE001 - archival must never stop capture
            log.error("archive failed for %s: %s", capture.name, exc)
            return False


class ExtractorService:
    """Polls a capture directory and processes each completed rotation."""

    def __init__(
        self,
        capture_dir: Path,
        output_dir: Path,
        shipper: LogstashShipper,
        archiver: CaptureArchiver,
        *,
        sensor_id: str = "unknown",
        poll_interval: int = 60,
        delete_after_archive: bool = True,
    ) -> None:
        self.capture_dir = capture_dir
        self.output_dir = output_dir
        self.shipper = shipper
        self.archiver = archiver
        self.sensor_id = sensor_id
        self.poll_interval = poll_interval
        self.delete_after_archive = delete_after_archive

        self._running = True
        self._sizes: dict[Path, int] = {}
        self._state_path = output_dir / STATE_FILENAME
        self._processed: set[str] = self._load_state()

    def _load_state(self) -> set[str]:
        """Remember what has been handled so a restart does not re-ship records."""
        try:
            return set(json.loads(self._state_path.read_text())["processed"])
        except (OSError, ValueError, KeyError):
            return set()

    def _save_state(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Keep the file bounded: older entries cannot recur because the capture
        # filenames carry a timestamp.
        recent = sorted(self._processed)[-5000:]
        self._state_path.write_text(json.dumps({"processed": recent}, indent=0))
        self._processed = set(recent)

    def stop(self, *_: object) -> None:
        log.info("shutdown requested")
        self._running = False

    def _settled_captures(self) -> list[Path]:
        """Return captures whose size has stopped changing since the last poll."""
        settled: list[Path] = []
        current: dict[Path, int] = {}

        for path in sorted(self.capture_dir.glob("sensor-*.pcap*")):
            try:
                size = path.stat().st_size
            except OSError:
                continue

            current[path] = size
            if path.name in self._processed or size == 0:
                continue
            if self._sizes.get(path) == size:
                settled.append(path)

        self._sizes = current
        return settled

    def process(self, capture: Path) -> dict[str, Any]:
        """Dissect one capture, ship its records, and archive the file."""
        records = []
        shipped = 0

        try:
            for record in extract_records(capture, sensor_id=self.sensor_id):
                records.append(record)
                if self.shipper.send(record.to_document()):
                    shipped += 1
        except TsharkNotAvailable:
            raise
        except Exception as exc:  # noqa: BLE001 - one bad capture must not stop the service
            log.error("dissection failed for %s: %s", capture.name, exc)

        summary = capture_summary(records)
        summary["shipped"] = shipped
        summary["capture"] = capture.name

        log.info(
            "%s: %s records, %s sources, %s flagged, max score %s",
            capture.name,
            summary.get("records", 0),
            summary.get("sources", 0),
            summary.get("flagged", 0),
            summary.get("max_score", 0),
        )

        if self.archiver.archive(capture) and self.delete_after_archive:
            capture.unlink(missing_ok=True)

        self._processed.add(capture.name)
        self._save_state()
        return summary

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)

        self.output_dir.mkdir(parents=True, exist_ok=True)
        log.info(
            "watching %s every %ss as sensor %s",
            self.capture_dir,
            self.poll_interval,
            self.sensor_id,
        )

        while self._running:
            try:
                for capture in self._settled_captures():
                    if not self._running:
                        break
                    self.process(capture)
            except Exception as exc:  # noqa: BLE001 - the loop must survive anything
                log.exception("poll cycle failed: %s", exc)

            # Sleep in short slices so a stop signal is honoured promptly.
            for _ in range(self.poll_interval):
                if not self._running:
                    break
                time.sleep(1)

        self.shipper.close()
        log.info("extractor stopped")


def build_from_environment() -> ExtractorService:
    """Construct the service from the container environment."""
    capture_dir = Path(os.environ.get("CAPTURE_DIR", "/pcap"))
    output_dir = Path(os.environ.get("OUTPUT_DIR", "/extracted"))
    sensor_id = os.environ.get("SENSOR_ID", "unknown")

    shipper = LogstashShipper(
        os.environ.get("LOGSTASH_HOST", "logstash"),
        int(os.environ.get("LOGSTASH_PORT", "5400")),
    )
    archiver = CaptureArchiver(
        os.environ.get("CAPTURE_BUCKET") or None,
        sensor_id=sensor_id,
        region=os.environ.get("AWS_DEFAULT_REGION"),
    )

    return ExtractorService(
        capture_dir,
        output_dir,
        shipper,
        archiver,
        sensor_id=sensor_id,
        poll_interval=int(os.environ.get("POLL_INTERVAL", "60")),
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )
    build_from_environment().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
