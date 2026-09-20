"""FIRST EPSS adapter with request-size bounded batching."""

from __future__ import annotations

from datetime import date
from typing import Iterable

from ..http import HttpClient
from ..errors import SourceError
from .common import as_float, cve_id, source_payload

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

    @source_payload("epss")
    def scores(self, identifiers: Iterable[str]) -> dict[str, tuple[float, float, date]]:
        output: dict[str, tuple[float, float, date]] = {}
        for batch in batches(identifiers):
            payload = self.http.get_json(EPSS_URL, source="epss", params={"cve": ",".join(batch), "limit": len(batch)})
            if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
                raise SourceError("epss", "source returned an invalid response envelope")
            if payload.get("status", "OK") != "OK" or ("total" in payload and payload["total"] != len(payload["data"])):
                raise SourceError("epss", "source returned an incomplete score response")
            for item in payload["data"]:
                if not isinstance(item, dict):
                    raise SourceError("epss", "source returned a non-object score entry")
                identifier = cve_id(item.get("cve"))
                score, percentile = as_float(item.get("epss")), as_float(item.get("percentile"))
                try:
                    score_date = date.fromisoformat(str(item.get("date")))
                except ValueError:
                    raise SourceError("epss", "score entry has an invalid date")
                if identifier in batch and score is not None and percentile is not None and 0 <= score <= 1 and 0 <= percentile <= 1:
                    output[identifier] = (score, percentile, score_date)
                else:
                    raise SourceError("epss", "source returned an invalid probability or identifier")
        return output
