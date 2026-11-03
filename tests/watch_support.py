from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import httpx

from cvebeacon.config import AppConfig, HttpConfig, load_config
from cvebeacon.http import HttpClient

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def write_config(
    tmp_path: Path,
    *,
    sources: tuple[str, ...] = ("nvd",),
    initial: str = "baseline",
    enabled: bool = True,
    backfill_days: int = 7,
    overlap_minutes: int = 15,
    epss_floor: float = 0.1,
    extra: str = "",
) -> AppConfig:
    names = ", ".join(f'"{name}"' for name in sources)
    path = tmp_path / "config.toml"
    path.write_text(
        f"""
[inventory]
path = "missing-inventory.csv"

[state]
database = "state.db"

[output]
directory = "reports"

[http]
retries = 0

[watch]
enabled = {str(enabled).lower()}
database = "watch.db"
sources = [{names}]
initial = "{initial}"
backfill_days = {backfill_days}
overlap_minutes = {overlap_minutes}
epss_floor = {epss_floor}
{extra}
""",
        encoding="utf-8",
    )
    return load_config(path)


def mock_client(handler) -> HttpClient:
    return HttpClient(
        HttpConfig(retries=0),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _: None,
    )


def nvd_cve(identifier: str = "CVE-2026-0001", **overrides) -> dict:
    value = {
        "id": identifier,
        "sourceIdentifier": "security@example.com",
        "published": "2026-11-01T00:00:00.000",
        "lastModified": "2026-11-02T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ]
        },
    }
    value.update(overrides)
    return value


def nvd_page(
    vulnerabilities: list[dict],
    *,
    start: int = 0,
    total: int | None = None,
    count: int | None = None,
) -> dict:
    size = len(vulnerabilities) if count is None else count
    return {
        "resultsPerPage": size,
        "startIndex": start,
        "totalResults": len(vulnerabilities) if total is None else total,
        "vulnerabilities": [{"cve": item} for item in vulnerabilities],
    }
