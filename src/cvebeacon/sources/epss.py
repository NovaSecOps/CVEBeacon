"""FIRST EPSS adapter with request-size bounded batching."""

from __future__ import annotations

from datetime import date
from typing import Iterable

from ..http import HttpClient
from ..errors import SourceError
from .common import as_float, cve_id

EPSS_URL = "https://api.first.org/data/v1/epss"


def batches(values: Iterable[str], max_chars: int = 2000) -> list[list[str]]:
    output: list[list[str]] = []
    current: list[str] = []
    length = 0
    for raw in sorted(set(values)):
        value = cve_id(raw)
        if not value:
            continue
        added = len(value) + (1 if current else 0)
        if current and length + added > max_chars:
            output.append(current)
            current, length = [], 0
            added = len(value)
        current.append(value)
        length += added
    if current:
        output.append(current)
    return output


class EPSSSource:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    def scores(self, identifiers: Iterable[str]) -> dict[str, tuple[float, float, date]]:
        output: dict[str, tuple[float, float, date]] = {}
        for batch in batches(identifiers):
            payload = self.http.get_json(EPSS_URL, source="epss", params={"cve": ",".join(batch)})
            if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
                raise SourceError("epss", "source returned an invalid response envelope")
            for item in payload["data"]:
                if not isinstance(item, dict):
                    raise SourceError("epss", "source returned a non-object score entry")
                identifier = cve_id(item.get("cve"))
                score, percentile = as_float(item.get("epss")), as_float(item.get("percentile"))
                try:
                    score_date = date.fromisoformat(str(item.get("date")))
                except ValueError:
                    continue
                if identifier and score is not None and percentile is not None:
                    output[identifier] = (score, percentile, score_date)
        return output
