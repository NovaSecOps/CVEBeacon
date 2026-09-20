"""Pure parser helpers for source adapters."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ..models import HealthStatus, SourceHealth

CVE_PATTERN = re.compile(r"^CVE-(1999|2\d{3})-\d{4,}$", re.IGNORECASE)


def cve_id(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if CVE_PATTERN.fullmatch(text) else None


def as_float(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def now_health(source: str, status: HealthStatus, message: str) -> SourceHealth:
    return SourceHealth(source, status, datetime.now(timezone.utc), message)
