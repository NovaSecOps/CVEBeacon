"""Canonical models shared by the CLI and optional interfaces."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from enum import StrEnum
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Applicability(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    NEEDS_REVIEW = "needs_review"
    COVERAGE_UNKNOWN = "coverage_unknown"


class HealthStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class Asset:
    asset_id: str
    vendor: str
    product: str
    version: str

    @property
    def target_key(self) -> tuple[str, str, str]:
        return (
            self.vendor.casefold().strip(),
            self.product.casefold().strip(),
            self.version.casefold().strip(),
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    source: str
    role: str
    statement: str
    source_url: str | None = None
    source_timestamp: str | None = None
    retrieved_at: datetime = field(default_factory=utc_now)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Vulnerability:
    cve_id: str
    summary: str | None = None
    published: str | None = None
    modified: str | None = None
    rejected: bool = False
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: date | None = None
    cisa_kev: bool = False
    eu_kev: bool = False
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    asset: Asset
    vulnerability: Vulnerability
    applicability: Applicability
    confidence: str
    reason: str
    evidence: tuple[Evidence, ...] = ()
    conflicts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["applicability"] = self.applicability.value
        if self.vulnerability.epss_date:
            value["vulnerability"]["epss_date"] = self.vulnerability.epss_date.isoformat()
        for item in value["evidence"]:
            item["retrieved_at"] = item["retrieved_at"].isoformat()
        return value


@dataclass(frozen=True, slots=True)
class SourceHealth:
    source: str
    status: HealthStatus
    checked_at: datetime
    message: str
    freshness_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class QueryResult:
    asset: Asset
    findings: tuple[Finding, ...]
    source_health: tuple[SourceHealth, ...]
    coverage: Applicability | None = None
    coverage_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": asdict(self.asset),
            "findings": [finding.to_dict() for finding in self.findings],
            "source_health": [
                {
                    **asdict(health),
                    "status": health.status.value,
                    "checked_at": health.checked_at.isoformat(),
                    "freshness_at": (
                        health.freshness_at.isoformat() if health.freshness_at else None
                    ),
                }
                for health in self.source_health
            ],
            "coverage": self.coverage.value if self.coverage else None,
            "coverage_reason": self.coverage_reason,
        }
