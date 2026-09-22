"""Deception Shield analysis toolkit.

Turns rotated packet captures and honeypot logs into structured attack
telemetry, and reads that telemetry back out of Elasticsearch to describe what
the sensor network observed.
"""

__version__ = "1.0.0"

from deception_shield.models import (
    AttackPattern,
    Campaign,
    PayloadRecord,
    TriageBand,
)

__all__ = [
    "__version__",
    "AttackPattern",
    "Campaign",
    "PayloadRecord",
    "TriageBand",
]
