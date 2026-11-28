"""Post-processing for the optional VulnCheck KEV and Shodan CVEDB sources.

The core scan path is authoritative and is completed before this module runs.
Optional sources may add evidence, metadata and clearly-labelled CVEDB-only
findings, but they never take part in a core lookup, reconciliation, coverage
decision or material fingerprint. When both sources are inactive the completed
result is returned unchanged.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Iterable

from .applicability import exact_cpe_version, identity_text
from .errors import SourceError
from .models import (
    Applicability,
    Asset,
    Evidence,
    Finding,
    HealthStatus,
    QueryResult,
    SourceHealth,
    Vulnerability,
)
from .sources.common import cve_id, now_health
from .sources.shodan_cvedb import CVE_URL as CVEDB_CVE_URL
from .sources.shodan_cvedb import ShodanCVEDBSource
from .sources.vulncheck import VulnCheckSource

if TYPE_CHECKING:
    from .engine import QueryEngine

CVEDB_ONLY_REASON = "reported by Shodan CVEDB only; confirm applicability"

VULNCHECK_FIELDS = (
    "vulncheck_kev",
    "vulncheck_date_added",
    "vulncheck_ransomware",
    "vulncheck_reported_exploits",
    "vulncheck_exploit_references",
)
CVEDB_FIELDS = ("shodan_cvedb_kev", "shodan_cvedb_ransomware")
OPTIONAL_SOURCES = frozenset({"vulncheck", "shodan_cvedb"})


@dataclass(slots=True)
class OptionalContext:
    """Optional-source caches and request counters for one scan call."""

    vulncheck: VulnCheckSource
    cvedb: ShodanCVEDBSource
    vulncheck_catalog: dict[str, Evidence] | SourceError | None = None


def vulncheck_active(config: Any) -> bool:
    accessor = getattr(config, "vulncheck_active", None)
    return bool(accessor()) if callable(accessor) else False


def cvedb_active(config: Any) -> bool:
    accessor = getattr(config, "cvedb_active", None)
    return bool(accessor()) if callable(accessor) else False


def new_context(engine: "QueryEngine") -> OptionalContext:
    """Create empty optional-source state for one scan call."""
    return OptionalContext(
        VulnCheckSource(engine.http),
        ShodanCVEDBSource(engine.http),
    )


def _catalog(engine: "QueryEngine", state: OptionalContext) -> dict[str, Evidence]:
    if state.vulncheck_catalog is None:
        token = engine.config.vulncheck_api_key()
        try:
            if not token:
                raise SourceError("vulncheck", "no API token")
            state.vulncheck_catalog = state.vulncheck.kev(token)
        except SourceError as exc:
            state.vulncheck_catalog = exc
    if isinstance(state.vulncheck_catalog, SourceError):
        raise state.vulncheck_catalog
    return state.vulncheck_catalog


def is_cvedb_only(payload: dict[str, Any]) -> bool:
    """A prior CVEDB-only row is corroboration, never an authoritative target."""
    return (
        payload.get("reason") == CVEDB_ONLY_REASON
        and payload.get("applicability") == Applicability.NEEDS_REVIEW.value
    )


def _identifiers(vulnerability: Vulnerability) -> tuple[str, ...]:
    return tuple(sorted({identifier for identifier in vulnerability.identifiers if cve_id(identifier)}))


def _exact_cpe(config: Any, asset: Asset) -> str | None:
    if asset.identity_path in {"purl", "ecosystem", "commit"}:
        return None
    configured = asset.cpe or None
    if configured is None:
        for mapping in getattr(config, "product_mappings", ()):
            if (
                identity_text(mapping.vendor) == identity_text(asset.vendor)
                and identity_text(mapping.product) == identity_text(asset.product)
            ):
                configured = mapping.cpe
                break
    if not configured:
        return None
    try:
        return exact_cpe_version(configured, asset.version)
    except ValueError:
        return None


def _evidence(
    record: Any,
    *,
    cisa: bool,
    eu: bool,
    epss_score: float | None,
) -> Evidence:
    details = {
        "cve_id": record.cve_id,
        "kev": record.kev,
        "ransomware": record.ransomware,
        "epss": record.epss,
        "epss_percentile": record.epss_percentile,
        "cisa_kev": cisa,
        "eu_kev": eu,
    }
    if record.kev is True and not cisa and not eu:
        details["kev_disagreement"] = True
    if (
        record.epss is not None
        and epss_score is not None
        and abs(record.epss - epss_score) >= 0.01
    ):
        details["epss_difference"] = True
    return Evidence(
        "shodan_cvedb",
        "independent_enrichment",
        "Shodan CVEDB cross-check for KEV, EPSS and ransomware evidence",
        CVEDB_CVE_URL.format(identifier=record.cve_id),
        record.published,
        details=details,
    )


def _merged_flag(records: Iterable[Any], field: str) -> bool | None:
    values = [getattr(record, field) for record in records]
    if any(value is True for value in values):
        return True
    if any(value is False for value in values):
        return False
    return None


def _vulncheck(
    engine: "QueryEngine",
    state: OptionalContext,
    findings: list[Finding],
    health: list[SourceHealth],
) -> tuple[list[Finding], list[SourceHealth]]:
    if not findings:
        health.append(now_health("vulncheck", HealthStatus.OK, "on; not requested; no discovered CVEs"))
        return findings, health
    try:
        catalog = _catalog(engine, state)
    except SourceError as exc:
        health.append(now_health("vulncheck", HealthStatus.FAILED, f"on; {exc}"))
        return findings, health
    updated: list[Finding] = []
    for finding in findings:
        identifiers = _identifiers(finding.vulnerability)
        matched = next((identifier for identifier in identifiers if identifier in catalog), None)
        vulnerability = replace(
            finding.vulnerability,
            vulncheck_kev=(matched is not None) if identifiers else None,
        )
        evidence = finding.evidence
        if matched is not None:
            details = catalog[matched].details
            vulnerability = replace(
                vulnerability,
                vulncheck_date_added=details.get("date_added"),
                vulncheck_ransomware=details.get("ransomware"),
                vulncheck_reported_exploits=details.get("reported_exploited"),
                vulncheck_exploit_references=len(details.get("exploit_references") or ()),
            )
            evidence = evidence + (catalog[matched],)
        updated.append(replace(finding, vulnerability=vulnerability, evidence=evidence))
    health.append(now_health("vulncheck", HealthStatus.OK, f"on; catalog loaded; {len(catalog)} CVEs"))
    return updated, health


def _cvedb(
    engine: "QueryEngine",
    state: OptionalContext,
    asset: Asset,
    findings: list[Finding],
    health: list[SourceHealth],
) -> tuple[list[Finding], list[SourceHealth]]:
    source = state.cvedb
    records: dict[str, Any] = {}
    messages: list[str] = []
    failed = False
    truncated = False

    cpe = _exact_cpe(engine.config, asset)
    discovered: dict[str, Any] = {}
    if cpe:
        try:
            discovery = source.discover(cpe)
        except SourceError as exc:
            failed = True
            messages.append(str(exc))
        else:
            discovered = discovery.records
            truncated = discovery.degraded
            records.update(discovered)
            for record in discovered.values():
                source.remember(record)
            messages.append(f"{len(discovered)} CVE results for the exact CPE")
            if discovery.message:
                messages.append(discovery.message)
    elif asset.identity_path not in {"purl", "ecosystem", "commit"}:
        messages.append("not requested; no resolved CPE")

    existing_ids = {
        identifier
        for finding in findings
        for identifier in _identifiers(finding.vulnerability)
    }
    pending = sorted(existing_ids - records.keys())
    completed = lookup_failures = 0
    for identifier in pending:
        try:
            record = source.lookup(identifier)
        except SourceError:
            lookup_failures += 1
            continue
        completed += 1
        if record is not None:
            records[identifier] = record
    if pending:
        messages.append(f"{completed}/{len(pending)} CVE lookups completed")
    if lookup_failures:
        messages.append(f"{lookup_failures} CVE lookups failed")
        failed = True
    if source.cap_reached:
        messages.append("lookup cap reached")
        failed = True

    enriched: list[Finding] = []
    for finding in findings:
        identifiers = _identifiers(finding.vulnerability)
        matched = [identifier for identifier in identifiers if identifier in records]
        if not matched:
            enriched.append(finding)
            continue
        metadata = [records[identifier] for identifier in matched]
        vulnerability = replace(
            finding.vulnerability,
            shodan_cvedb_kev=_merged_flag(metadata, "kev"),
            shodan_cvedb_ransomware=_merged_flag(metadata, "ransomware"),
        )
        evidence = finding.evidence + tuple(
            _evidence(
                records[identifier],
                cisa=finding.vulnerability.cisa_kev is True,
                eu=finding.vulnerability.eu_kev is True,
                epss_score=finding.vulnerability.epss_score,
            )
            for identifier in matched
        )
        enriched.append(replace(finding, vulnerability=vulnerability, evidence=evidence))

    for identifier, record in sorted(discovered.items()):
        if identifier in existing_ids:
            continue
        vulnerability = Vulnerability(
            record.cve_id,
            record.summary,
            record.published,
            cvss_score=record.cvss_score,
            cvss_vector=record.cvss_vector,
            cvss_version=record.cvss_version,
            epss_score=record.epss,
            epss_percentile=record.epss_percentile,
            shodan_cvedb_kev=record.kev,
            shodan_cvedb_ransomware=record.ransomware,
            references=record.references,
        )
        enriched.append(
            Finding(
                asset,
                vulnerability,
                Applicability.NEEDS_REVIEW,
                "limited",
                CVEDB_ONLY_REASON,
                (_evidence(record, cisa=False, eu=False, epss_score=None),),
            )
        )

    if failed:
        status = HealthStatus.DEGRADED if records else HealthStatus.FAILED
    elif truncated:
        status = HealthStatus.DEGRADED
    else:
        status = HealthStatus.OK
    health.append(
        now_health(
            "shodan_cvedb",
            status,
            "on" + ("; " + "; ".join(messages) if messages else ""),
        )
    )
    return enriched, health


def apply(
    engine: "QueryEngine",
    asset: Asset,
    result: QueryResult,
    state: OptionalContext | None = None,
) -> QueryResult:
    """Enrich one completed core result with the optional sources that are on."""
    config = getattr(engine, "config", None)
    if config is None:
        return result
    vulncheck = vulncheck_active(config)
    cvedb = cvedb_active(config)
    if not vulncheck and not cvedb:
        return result
    if state is None:
        state = new_context(engine)
    findings = list(result.findings)
    health = list(result.source_health)
    if vulncheck:
        findings, health = _vulncheck(engine, state, findings, health)
    if cvedb:
        findings, health = _cvedb(engine, state, asset, findings, health)
    return replace(
        result,
        findings=tuple(findings),
        source_health=tuple(health),
    )


def filter_payload(
    payload: dict[str, Any],
    *,
    vulncheck: bool,
    cvedb: bool,
) -> dict[str, Any]:
    """Return a deep copy without disabled-source metadata or evidence."""
    value = copy.deepcopy(payload)
    vulnerability = value.get("vulnerability")
    if isinstance(vulnerability, dict):
        if not vulncheck:
            for key in VULNCHECK_FIELDS:
                vulnerability.pop(key, None)
        if not cvedb:
            for key in CVEDB_FIELDS:
                vulnerability.pop(key, None)
    if not vulncheck or not cvedb:
        hidden = set()
        if not vulncheck:
            hidden.add("vulncheck")
        if not cvedb:
            hidden.add("shodan_cvedb")
        evidence = value.get("evidence")
        if isinstance(evidence, (list, tuple)):
            value["evidence"] = [
                item
                for item in evidence
                if not (isinstance(item, dict) and item.get("source") in hidden)
            ]
    return value


def filter_result_payload(
    payload: dict[str, Any],
    *,
    vulncheck: bool,
    cvedb: bool,
) -> dict[str, Any]:
    """Filter every finding and source-health row in a query-result payload."""
    value = copy.deepcopy(payload)
    value["findings"] = [
        filter_payload(finding, vulncheck=vulncheck, cvedb=cvedb)
        for finding in value.get("findings", ())
        if isinstance(finding, dict)
    ]
    value["source_health"] = filter_health(
        value.get("source_health", ()), vulncheck=vulncheck, cvedb=cvedb
    )
    return value


def source_visible(source: str, *, vulncheck: bool, cvedb: bool) -> bool:
    return (vulncheck or source != "vulncheck") and (cvedb or source != "shodan_cvedb")


def filter_health(
    rows: Iterable[dict[str, Any]],
    *,
    vulncheck: bool,
    cvedb: bool,
) -> list[dict[str, Any]]:
    hidden = set()
    if not vulncheck:
        hidden.add("vulncheck")
    if not cvedb:
        hidden.add("shodan_cvedb")
    return [row for row in rows if row.get("source") not in hidden]


def off_health_rows(config: Any) -> list[dict[str, Any]]:
    """Effective off states for the dedicated Sources view."""
    rows: list[dict[str, Any]] = []
    if not vulncheck_active(config):
        message = "off: no token" if config.sources.vulncheck_enabled else "off: disabled"
        rows.append(_off_row("vulncheck", message))
    if not cvedb_active(config):
        rows.append(_off_row("shodan_cvedb", "off: disabled"))
    return rows


def _off_row(source: str, message: str) -> dict[str, Any]:
    return {
        "asset_id": "",
        "source": source,
        "status": HealthStatus.DISABLED.value,
        "checked_at": None,
        "message": message,
        "freshness_at": None,
        "freshness": "configured",
    }
