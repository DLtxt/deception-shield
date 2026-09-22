"""Payload scoring.

This mirrors the Ruby filter that runs inside Logstash. Scoring exists in both
places deliberately: Logstash scores events as they stream in, and this module
scores captures replayed offline, where Logstash is not in the path. The weights
and names are kept identical so a payload receives the same verdict either way.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

from deception_shield.models import TriageBand

MAX_SCORE = 100


@dataclass(frozen=True, slots=True)
class Signature:
    """A recognisable attack shape and what its presence is worth."""

    name: str
    weight: int
    pattern: re.Pattern[str]
    technique: str


def _c(expr: str) -> re.Pattern[str]:
    return re.compile(expr, re.IGNORECASE)


# Weights reflect how rarely each shape appears in benign traffic. Piping a
# download into an interpreter is close to conclusive; a traversal string is
# routine in untargeted scanning and scores low on its own.
SIGNATURES: tuple[Signature, ...] = (
    Signature("shell_pipe_execution", 40, _c(r"\|\s*(?:ba)?sh\b|\|\s*python[23]?\b"), "T1059"),
    Signature("remote_payload_fetch", 30, _c(r"\b(?:wget|curl)\s+[^\s;|]*https?://"), "T1105"),
    Signature("reverse_shell", 40, _c(r"(?:nc|ncat|netcat)\s+(?:-[a-z]*e[a-z]*\s|\S+\s+\d+\s*-e)|/dev/tcp/"), "T1059"),
    Signature("sql_injection", 25, _c(r"union\s+(?:all\s+)?select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d+\)|benchmark\("), "T1190"),
    Signature("path_traversal", 15, _c(r"(?:\.\.[/\\]){2,}|%2e%2e(?:%2f|%5c)"), "T1083"),
    Signature("command_injection", 30, _c(r"[;&`]\s*(?:cat|ls|id|whoami|uname)\b|\$\([^)]*\)"), "T1059"),
    Signature("log4shell", 45, _c(r"\$\{jndi:(?:ldaps?|rmi|dns|iiop):"), "T1190"),
    Signature("webshell_upload", 35, _c(r"<\?php|eval\s*\(\s*(?:base64_decode|\$_(?:POST|GET|REQUEST))"), "T1505.003"),
    Signature("credential_probe", 20, _c(r"/etc/(?:passwd|shadow)|\bwin\.ini\b|\bboot\.ini\b"), "T1003"),
    Signature("iot_botnet_dropper", 40, _c(r"\b(?:mirai|mozi|gafgyt|tsunami)\b|busybox\s+(?:wget|tftp)"), "T1105"),
    Signature("cve_probe_struts", 35, _c(r"%\{\(#_?=|ognl|struts\.valueStack"), "T1190"),
    Signature("xxe_attempt", 30, _c(r"<!ENTITY\s+\S+\s+SYSTEM"), "T1190"),
    Signature("encoded_powershell", 35, _c(r"powershell(?:\.exe)?\s+.*-e(?:nc|ncoded)?[a-z]*\s+[A-Za-z0-9+/]{40,}"), "T1059.001"),
    Signature("scanner_fingerprint", 5, _c(r"\b(?:zgrab|masscan|nmap|nuclei|zmap|censys)\b"), "T1595"),
)

SIGNATURES_BY_NAME = {s.name: s for s in SIGNATURES}


@dataclass(slots=True)
class ScoreResult:
    """Outcome of scoring one payload."""

    score: int
    signatures: list[str]
    triage: TriageBand
    techniques: list[str]


def _expand(text: str) -> str:
    """Append a percent decoded copy so rules need no encoded variant.

    Both forms are kept because an attacker may encode only part of a payload,
    and a rule anchored on the raw form should still match the part that was
    left alone.
    """
    try:
        decoded = urllib.parse.unquote(text, errors="replace")
    except (UnicodeDecodeError, ValueError):
        return text
    return text if decoded == text else f"{text}\n{decoded}"


def score_payload(payload: bytes | str, *, printable_ratio: float | None = None) -> ScoreResult:
    """Score one payload and explain the verdict.

    ``printable_ratio`` lets the caller pass a ratio already computed over the
    full payload. When a payload matches no signature but is largely
    unprintable, it is still surfaced for inspection: binary shellcode and
    malformed protocol probes look like nothing in particular to a text rule.
    """
    if isinstance(payload, bytes):
        text = payload.decode("utf-8", errors="replace")
        raw = payload
    else:
        text = payload
        raw = payload.encode("utf-8", errors="replace")

    if not text:
        return ScoreResult(0, [], TriageBand.BENIGN, [])

    candidate = _expand(text)

    score = 0
    names: list[str] = []
    techniques: list[str] = []

    for sig in SIGNATURES:
        if sig.pattern.search(candidate):
            score += sig.weight
            names.append(sig.name)
            if sig.technique not in techniques:
                techniques.append(sig.technique)

    score = min(score, MAX_SCORE)
    band = TriageBand.from_score(score)

    if not names:
        if printable_ratio is None:
            printable = sum(1 for b in raw if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
            printable_ratio = printable / len(raw) if raw else 0.0
        if printable_ratio < 0.6:
            return ScoreResult(0, ["non_printable_payload"], TriageBand.SUSPICIOUS, [])

    return ScoreResult(score, names, band, techniques)
