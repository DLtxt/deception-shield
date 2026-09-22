"""Reading attack telemetry back out of Elasticsearch.

The analysis functions operate on :class:`PayloadRecord` objects regardless of
where those came from, so this module's job is narrow: run the query and rebuild
records from the documents the Logstash pipeline wrote.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

from deception_shield.models import PayloadRecord, TriageBand

log = logging.getLogger(__name__)

DEFAULT_INDEX = "logs-*-deception"

# Elasticsearch caps a plain search at 10,000 hits, so anything that may exceed
# that pages with search_after instead.
PAGE_SIZE = 1000


class TelemetryStore:
    """Query wrapper over the deception data streams."""

    def __init__(self, hosts: str | list[str] = "http://localhost:9200", **client_kwargs: Any) -> None:
        self.hosts = hosts
        self._client_kwargs = client_kwargs
        self._client = None

    def _get_client(self):
        if self._client is None:
            from elasticsearch import Elasticsearch

            self._client = Elasticsearch(self.hosts, **self._client_kwargs)
        return self._client

    def ping(self) -> bool:
        try:
            return bool(self._get_client().ping())
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as False
            log.error("elasticsearch unreachable: %s", exc)
            return False

    def fetch_payloads(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        index: str = DEFAULT_INDEX,
        min_score: int = 0,
        sensor_id: str | None = None,
        limit: int | None = None,
    ) -> list[PayloadRecord]:
        """Retrieve payload records for a time range."""
        since = since or datetime.now(timezone.utc) - timedelta(days=1)
        until = until or datetime.now(timezone.utc)

        must: list[dict[str, Any]] = [
            {"range": {"@timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}},
            {"term": {"event.dataset": "pcap.payload"}},
        ]
        if min_score > 0:
            must.append({"range": {"threat.payload_score": {"gte": min_score}}})
        if sensor_id:
            must.append({"term": {"observer.name": sensor_id}})

        query = {"bool": {"must": must}}
        records: list[PayloadRecord] = []

        for document in self._scan(index, query, limit=limit):
            record = document_to_record(document)
            if record is not None:
                records.append(record)

        log.info("retrieved %s payload records", len(records))
        return records

    def _scan(self, index: str, query: dict[str, Any], *, limit: int | None) -> Iterator[dict[str, Any]]:
        """Page through matches in stable order using search_after."""
        client = self._get_client()
        search_after: list[Any] | None = None
        returned = 0

        while True:
            size = PAGE_SIZE if limit is None else min(PAGE_SIZE, limit - returned)
            if size <= 0:
                return

            body: dict[str, Any] = {
                "query": query,
                "size": size,
                "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
            }
            if search_after:
                body["search_after"] = search_after

            response = client.search(index=index, body=body)
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                return

            for hit in hits:
                yield hit["_source"]
                returned += 1
                if limit is not None and returned >= limit:
                    return

            search_after = hits[-1]["sort"]

    def top_sources(
        self,
        *,
        since: datetime | None = None,
        index: str = DEFAULT_INDEX,
        size: int = 20,
    ) -> list[dict[str, Any]]:
        """Aggregate the busiest sources without pulling their documents."""
        since = since or datetime.now(timezone.utc) - timedelta(days=1)

        response = self._get_client().search(
            index=index,
            body={
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": since.isoformat()}}},
                "aggs": {
                    "sources": {
                        "terms": {"field": "source.ip", "size": size, "order": {"peak": "desc"}},
                        "aggs": {
                            "peak": {"max": {"field": "threat.payload_score"}},
                            "ports": {"cardinality": {"field": "destination.port"}},
                            "country": {"terms": {"field": "source.geo.country_name", "size": 1}},
                        },
                    }
                },
            },
        )

        buckets = response.get("aggregations", {}).get("sources", {}).get("buckets", [])
        return [
            {
                "source_ip": bucket["key"],
                "events": bucket["doc_count"],
                "peak_score": int(bucket["peak"]["value"] or 0),
                "distinct_ports": int(bucket["ports"]["value"] or 0),
                "country": next(
                    (c["key"] for c in bucket.get("country", {}).get("buckets", [])), "unknown"
                ),
            }
            for bucket in buckets
        ]


def document_to_record(document: dict[str, Any]) -> PayloadRecord | None:
    """Rebuild a record from an indexed document.

    Documents that predate a field, or that were written by a different
    pipeline version, return ``None`` rather than raising, so one malformed
    document cannot abort an entire analysis run.
    """
    try:
        source = document.get("source", {})
        destination = document.get("destination", {})
        network = document.get("network", {})
        threat = document.get("threat", {})

        raw_time = document.get("@timestamp") or document.get("frame_time")
        if not raw_time:
            return None
        timestamp = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))

        payload_hex = document.get("payload_hex") or ""
        if payload_hex:
            payload = bytes.fromhex(payload_hex)
        else:
            payload = str(document.get("payload_ascii", "")).encode("utf-8", errors="replace")

        record = PayloadRecord(
            timestamp=timestamp,
            source_ip=source.get("ip", ""),
            source_port=int(source.get("port") or 0),
            destination_ip=destination.get("ip", ""),
            destination_port=int(destination.get("port") or 0),
            transport=network.get("transport", "tcp"),
            payload=payload,
            protocol=network.get("protocol"),
            sensor_id=document.get("observer", {}).get("name", "unknown"),
            score=int(threat.get("payload_score") or 0),
            signatures=list(threat.get("payload_signatures") or []),
        )

        band = threat.get("triage")
        record.triage = TriageBand(band) if band else TriageBand.from_score(record.score)
        return record
    except (ValueError, TypeError, AttributeError) as exc:
        log.debug("skipping malformed document: %s", exc)
        return None
