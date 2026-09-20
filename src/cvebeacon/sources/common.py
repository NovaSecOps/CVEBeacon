"""Pure parser helpers for source adapters."""

from __future__ import annotations

import re
import math
from functools import wraps
from datetime import datetime, timezone
from typing import Any

from ..models import HealthStatus, SourceHealth

CVE_PATTERN = re.compile(r"^CVE-(1999|2\d{3})-\d{4,}$", re.IGNORECASE)


def cve_id(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if CVE_PATTERN.fullmatch(text) else None


def as_float(value: Any) -> float | None:
    try:
        number = float(value) if value not in (None, "") else None
        return number if number is not None and math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def source_payload(source: str):
    """Translate invalid nested upstream data into an isolated source failure."""
    def decorate(function):
        @wraps(function)
        def checked(*args, **kwargs):
            from ..errors import SourceError
            try:
                return function(*args, **kwargs)
            except (AttributeError, TypeError, ValueError, KeyError, IndexError) as exc:
                raise SourceError(source, "source returned malformed structured data") from exc
        return checked
    return decorate


def now_health(source: str, status: HealthStatus, message: str) -> SourceHealth:
    return SourceHealth(source, status, datetime.now(timezone.utc), message)
