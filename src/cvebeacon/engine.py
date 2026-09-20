"""Reusable scan engine with per-run target deduplication and degraded-source handling."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from typing import Iterable

from .applicability import Decision, evaluate_cve_evidence, evaluate_nvd_evidence, exact_cpe_version, identity_text
from .config import AppConfig
from .errors import SourceError
from .http import HttpClient
from .identity import identity_conflict, normalize_asset
from .models import Applicability, Asset, Evidence, HealthStatus, QueryResult, SourceHealth, Vulnerability
from .reconcile import merge_vulnerabilities, reconcile
from .sources import CVEListSource, EPSSSource, EUVDSource, KEVSource, NVDSource
from .sources.common import now_health, as_float
from .sources.epss import EPSS_URL
from .sources.osv import OSVSource, OSVResult


class QueryEngine:
    def __init__(self, config: AppConfig, http: HttpClient | None = None) -> None:
        self.config = config
        self.http = http or HttpClient(config.http)
        self._owned = http is None
        api_key = config.secret(config.sources.nvd_api_key_env)
        self.nvd = NVDSource(self.http, api_key=api_key, interval=config.sources.minimum_request_interval)
        self.cve = CVEListSource(self.http)
        self.euvd = EUVDSource(self.http)
        self.kev = KEVSource(self.http)
        self.epss = EPSSSource(self.http)
        self.osv = OSVSource(self.http)
        self._catalogs: dict[str, dict[str, Evidence] | SourceError] = {}
        self._cve_records: dict[str, tuple[Evidence, ...] | SourceError] = {}

    def close(self) -> None:
        if self._owned:
            self.http.close()

    def __enter__(self) -> "QueryEngine":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _configured_cpe(self, asset: Asset) -> str | None:
        if asset.cpe:
            return asset.cpe
        for mapping in self.config.product_mappings:
            if identity_text(mapping.vendor) == identity_text(asset.vendor) and identity_text(mapping.product) == identity_text(asset.product):
                return mapping.cpe
        return None

    def _resolve_cpe(self, asset: Asset) -> tuple[str | None, str]:
        configured = self._configured_cpe(asset)
        if configured:
            try:
                return exact_cpe_version(configured, asset.version), "configured product mapping"
            except ValueError as exc:
                return None, str(exc)
        candidates = self.nvd.resolve_cpes(asset)
        exact = [
            item for item in candidates
            if identity_text(item.vendor.replace("_", " ")) == identity_text(asset.vendor)
            and identity_text(item.product.replace("_", " ")) == identity_text(asset.product)
        ]
        identities = {(item.part, item.vendor.casefold(), item.product.casefold()) for item in exact}
        if len(identities) != 1:
            return None, "no unambiguous exact CPE identity" if not identities else "multiple exact CPE identities require an explicit product mapping"
        try:
            # Automatic resolution establishes product identity only. Qualifiers
            # remain unknown and must be checked against each configuration.
            from .sources.nvd import split_cpe23
            fields = split_cpe23(exact[0].name)
            if any(field != "*" for field in fields[4:]):
                return None, "CPE edition or platform requires an explicit product mapping"
            return exact_cpe_version(exact[0].name, asset.version), "unique exact NVD CPE identity"
        except ValueError as exc:
            return None, str(exc)

    def _catalog(self, name: str) -> dict[str, Evidence]:
        cached = self._catalogs.get(name)
        if cached is None:
            try:
                cached = self.kev.cisa() if name == "cisa_kev" else self.kev.eu()
            except SourceError as exc:
                cached = exc
            self._catalogs[name] = cached
        if isinstance(cached, SourceError):
            raise cached
        return cached

    def _official_evidence(self, identifier: str) -> tuple[Evidence, ...]:
        cached = self._cve_records.get(identifier)
        if cached is None:
            try:
                cached = self.cve.evidence(self.cve.record(identifier))
            except SourceError as exc:
                cached = exc
            self._cve_records[identifier] = cached
        if isinstance(cached, SourceError):
            raise cached
        return cached

    def query_asset(self, asset: Asset) -> QueryResult:
        asset = normalize_asset(asset)
        if identity_conflict(asset):
            return QueryResult(asset, (), (), Applicability.NEEDS_REVIEW, "explicit identity systems require authoritative equivalence evidence")
        if asset.identity_path in {"purl", "ecosystem", "commit"}:
            if not self.config.sources.osv_enabled:
                return QueryResult(asset, (), (now_health("osv", HealthStatus.DISABLED, "disabled by configuration"),),
                                   Applicability.COVERAGE_UNKNOWN, "required package source OSV is disabled")
            from .package_query import query_package
            data = getattr(self, "_osv_results", {}).get(asset.target_key)
            if data is None:
                data = self.osv.query_many([asset])[asset.target_key]
            records = {record["id"]: record for record in data.records}
            error = data.error
            for identifier in getattr(self, "_known_package_ids", {}).get(asset.target_key, ()):
                if identifier not in records:
                    try:
                        records[identifier] = self.osv.record(identifier)
                    except SourceError as exc:
                        error = str(exc)
            return query_package(self, asset, OSVResult(tuple(records.values()), error, data.matched_ids))
        health: list[SourceHealth] = []
        claims: dict[str, list[Vulnerability]] = defaultdict(list)
        evidence: dict[str, list[Evidence]] = defaultdict(list)
        decisions: dict[str, list[Decision]] = defaultdict(list)
        nvd_ids: set[str] = set()
        cpe: str | None = None
        for identifier in getattr(self, "_known_targets", {}).get(asset.target_key, ()):
            claims[identifier].append(Vulnerability(identifier))
        if self.config.sources.nvd_enabled:
            try:
                cpe, resolution = self._resolve_cpe(asset)
                if cpe:
                    for vuln, item in self.nvd.vulnerabilities(cpe_name=cpe):
                        claims[vuln.cve_id].append(vuln)
                        evidence[vuln.cve_id].append(item)
                        decisions[vuln.cve_id].append(evaluate_nvd_evidence(cpe, item))
                        nvd_ids.add(vuln.cve_id)
                    health.append(now_health("nvd", HealthStatus.OK, f"{resolution}; {len(nvd_ids)} exact-version matches"))
                else:
                    health.append(now_health("nvd", HealthStatus.DEGRADED, resolution))
            except SourceError as exc:
                health.append(now_health("nvd", HealthStatus.FAILED, str(exc)))
        else:
            health.append(now_health("nvd", HealthStatus.DISABLED, "disabled by configuration"))

        if self.config.sources.euvd_enabled:
            try:
                values = self.euvd.search(asset.vendor, asset.product)
                for vuln, item in values:
                    claims[vuln.cve_id].append(vuln)
                    evidence[vuln.cve_id].append(item)
                status = HealthStatus.OK if values else HealthStatus.DEGRADED
                health.append(now_health("euvd", status, f"{len(values)} product search results" + ("; independent discovery coverage is unconfirmed" if not values else "")))
            except SourceError as exc:
                health.append(now_health("euvd", HealthStatus.FAILED, str(exc)))
        else:
            health.append(now_health("euvd", HealthStatus.DISABLED, "disabled by configuration"))

        identifiers = sorted(claims)
        if self.config.sources.cve_enabled:
            failures = 0
            for identifier in identifiers:
                try:
                    for item in self._official_evidence(identifier):
                        evidence[identifier].append(item)
                        metrics = item.details.get("metrics", [])
                        for metric in metrics if isinstance(metrics, list) else []:
                            if not isinstance(metric, dict):
                                continue
                            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                                data = metric.get(key)
                                if isinstance(data, dict):
                                    claims[identifier].append(Vulnerability(identifier, cvss_score=as_float(data.get("baseScore")), cvss_vector=data.get("vectorString"), cvss_version=data.get("version")))
                        references = item.details.get("references", [])
                        claims[identifier].append(Vulnerability(identifier, references=tuple(ref["url"] for ref in references if isinstance(ref, dict) and isinstance(ref.get("url"), str))))
                        decisions[identifier].append(evaluate_cve_evidence(asset, item))
                        if item.details.get("state") == "REJECTED":
                            claims[identifier] = [replace(vuln, rejected=True) for vuln in claims[identifier]]
                except (SourceError, ValueError):
                    failures += 1
                    decisions[identifier].append(Decision(Applicability.NEEDS_REVIEW, "official CVE applicability record could not be retrieved or parsed"))
            status = HealthStatus.OK if failures == 0 else HealthStatus.DEGRADED
            health.append(now_health("cve_list", status, f"{len(identifiers) - failures}/{len(identifiers)} records retrieved"))
        else:
            health.append(now_health("cve_list", HealthStatus.DISABLED, "disabled by configuration"))

        cisa: dict[str, Evidence] = {}
        eu: dict[str, Evidence] = {}
        for enabled, source, name in [
            (self.config.sources.cisa_kev_enabled, lambda: self._catalog("cisa_kev"), "cisa_kev"),
            (self.config.sources.eu_kev_enabled, lambda: self._catalog("eu_kev"), "eu_kev"),
        ]:
            if not enabled:
                health.append(now_health(name, HealthStatus.DISABLED, "disabled by configuration"))
                continue
            if not identifiers:
                health.append(now_health(name, HealthStatus.OK, "not requested; no discovered CVEs"))
                continue
            try:
                loaded = source()
                if name == "cisa_kev": cisa = loaded
                else: eu = loaded
                health.append(now_health(name, HealthStatus.OK, f"catalog loaded; {len(loaded)} CVEs"))
            except SourceError as exc:
                health.append(now_health(name, HealthStatus.FAILED, str(exc)))

        scores = {}
        if self.config.sources.epss_enabled and identifiers:
            try:
                scores = self.epss.scores(identifiers)
                health.append(now_health("epss", HealthStatus.OK, f"{len(scores)}/{len(identifiers)} scores returned"))
            except SourceError as exc:
                health.append(now_health("epss", HealthStatus.FAILED, str(exc)))
        elif not self.config.sources.epss_enabled:
            health.append(now_health("epss", HealthStatus.DISABLED, "disabled by configuration"))
        else:
            health.append(now_health("epss", HealthStatus.OK, "not requested; no discovered CVEs"))

        findings = []
        for identifier in identifiers:
            vuln = merge_vulnerabilities(claims[identifier])
            vuln = replace(vuln,
                cisa_kev=(identifier in cisa) if any(h.source == "cisa_kev" and h.status == HealthStatus.OK for h in health) else None,
                eu_kev=(identifier in eu) if any(h.source == "eu_kev" and h.status == HealthStatus.OK for h in health) else None)
            if identifier in cisa:
                vuln = replace(vuln, cisa_kev=True)
                evidence[identifier].append(cisa[identifier])
            if identifier in eu:
                vuln = replace(vuln, eu_kev=True)
                evidence[identifier].append(eu[identifier])
            if identifier in scores:
                score, percentile, score_date = scores[identifier]
                vuln = replace(vuln, epss_score=score, epss_percentile=percentile, epss_date=score_date)
                evidence[identifier].append(Evidence(
                    "epss", "predictive_enrichment", "FIRST EPSS probability and percentile",
                    EPSS_URL, score_date.isoformat(),
                    details={"score": score, "percentile": percentile, "score_date": score_date.isoformat()},
                ))
            if any(item.source in {"nvd", "cve_list", "euvd"} and item.status in {HealthStatus.FAILED, HealthStatus.DEGRADED} for item in health):
                decisions[identifier].append(Decision(Applicability.NEEDS_REVIEW, "core applicability sources are incomplete"))
            finding = reconcile(asset, vuln, evidence[identifier], decisions[identifier])
            severities = {(value.cvss_score, value.cvss_vector, value.cvss_version) for value in claims[identifier] if value.cvss_score is not None}
            if len(severities) > 1:
                finding = replace(finding, conflicts=finding.conflicts + ("CVSS claims differ; the highest reported base score is displayed; see source evidence",))
            findings.append(finding)
        findings.sort(key=lambda item: (not item.vulnerability.cisa_kev, not item.vulnerability.eu_kev, -(item.vulnerability.cvss_score or -1), item.vulnerability.cve_id))
        any_failed = any(item.status in {HealthStatus.FAILED, HealthStatus.DEGRADED} or (item.source in {"nvd", "cve_list", "euvd"} and item.status == HealthStatus.DISABLED) for item in health)
        if not cpe:
            coverage, reason = Applicability.COVERAGE_UNKNOWN, "product identity could not be resolved unambiguously"
        elif any_failed:
            coverage, reason = Applicability.COVERAGE_UNKNOWN, "one or more authoritative sources were unavailable or incomplete"
        elif not findings:
            coverage, reason = Applicability.COVERAGE_UNKNOWN, "no results is not proof of complete vulnerability coverage"
        else:
            coverage, reason = None, None
        return QueryResult(asset, tuple(findings), tuple(health), coverage, reason)

    def scan(self, assets: Iterable[Asset], *, known_findings: Iterable[dict] = ()) -> list[QueryResult]:
        assets = [normalize_asset(asset) for asset in assets]
        self._known_targets: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self._known_package_ids = defaultdict(set)
        for item in known_findings:
            previous_asset = Asset(**item["asset"])
            if previous_asset.identity_path in {"purl", "ecosystem", "commit"}:
                self._known_package_ids[previous_asset.target_key].update(item["vulnerability"].get("source_ids", ()))
            else:
                self._known_targets[previous_asset.target_key].add(item["vulnerability"]["cve_id"])
        package_assets = {asset.target_key: asset for asset in assets if asset.identity_path in {"purl", "ecosystem", "commit"} and not identity_conflict(asset)}
        self._osv_results = self.osv.query_many(list(package_assets.values())) if package_assets and self.config.sources.osv_enabled else {}
        cached: dict[tuple[str, str, str], QueryResult] = {}
        output: list[QueryResult] = []
        for asset in assets:
            if asset.target_key not in cached:
                cached[asset.target_key] = self.query_asset(asset)
            shared = cached[asset.target_key]
            output.append(QueryResult(
                asset,
                tuple(replace(finding, asset=asset) for finding in shared.findings),
                shared.source_health, shared.coverage, shared.coverage_reason,
            ))
        return output
