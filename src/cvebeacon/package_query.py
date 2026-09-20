"""Package-native applicability with CVE metadata enrichment where available."""

from dataclasses import replace

from .applicability import Decision
from .errors import SourceError
from .models import Applicability as A, Evidence, HealthStatus as H, QueryResult, Vulnerability
from .osv_applicability import evaluate_osv
from .reconcile import merge_vulnerabilities, reconcile
from .sources.common import as_float, cve_id, now_health
from .sources.osv import BASE_URL
from .identity import name_key


def fixed_versions(asset, record):
    values = set()
    for item in record.get("affected", []):
        package = item.get("package", {})
        if not isinstance(package, dict) or package.get("ecosystem") != asset.ecosystem or not isinstance(package.get("name"), str) or name_key(asset.ecosystem, package["name"]) != name_key(asset.ecosystem, asset.product):
            continue
        ranges = item.get("ranges", [])
        for value in ranges if isinstance(ranges, list) else []:
            if not isinstance(value, dict) or not isinstance(value.get("events", []), list):
                continue
            values.update(event["fixed"] for event in value.get("events", []) if isinstance(event, dict) and isinstance(event.get("fixed"), str))
    return tuple(sorted(values))


def alias_groups(records):
    """Union only explicit authoritative aliases; never related IDs or prose."""
    groups = []
    for record in records:
        identifiers = {record["id"], *record.get("aliases", [])}
        selected = [group for group in groups if identifiers & group[0]]
        members = [record]
        for group in selected:
            identifiers.update(group[0]); members.extend(group[1]); groups.remove(group)
        groups.append((identifiers, members))
    return groups


def query_package(engine, asset, data):
    health = [now_health("osv", H.DEGRADED if data.error and data.records else H.FAILED if data.error else H.OK,
                         data.error or f"{len(data.records)} package advisory records retrieved")]
    findings = []
    for identifiers, records in alias_groups(data.records):
        cves = sorted(identifier for identifier in identifiers if cve_id(identifier))
        primary = cves[0] if cves else min(record["id"] for record in records)
        claims, evidence, decisions = [], [], []
        for record in records:
            try:
                decision = evaluate_osv(asset, record, commit_match=record["id"] in data.matched_ids)
            except (ValueError, TypeError, AttributeError, KeyError):
                decision = Decision(A.NEEDS_REVIEW, "OSV applicability data is malformed or unsupported")
            decisions.append(decision)
            fixed = fixed_versions(asset, record) if decision.state != A.COVERAGE_UNKNOWN else ()
            refs = record.get("references", [])
            if not isinstance(refs, list):
                refs = []
            claims.append(Vulnerability(cves[0] if cves else None, record.get("summary") or record.get("details"),
                record.get("published"), record.get("modified"), bool(record.get("withdrawn")),
                references=tuple(ref["url"] for ref in refs if isinstance(ref, dict) and isinstance(ref.get("url"), str)),
                advisory_id=primary, aliases=tuple(sorted(identifiers - {primary})),
                source_ids=tuple(sorted(item["id"] for item in records)), fixed_versions=tuple(sorted(fixed))))
            evidence.append(Evidence("osv", "package_applicability", decision.reason,
                f"{BASE_URL}/vulns/{record['id']}", record.get("modified"),
                details={"id": record["id"], "aliases": record.get("aliases", []), "state": "withdrawn" if record.get("withdrawn") else "published",
                         "affected": record.get("affected", []), "severity": record.get("severity", []),
                         "database_specific": record.get("database_specific", {})}))
        if data.error:
            decisions.append(Decision(A.NEEDS_REVIEW, "required OSV discovery or record retrieval is incomplete"))
        findings.append(reconcile(asset, merge_vulnerabilities(claims), evidence, decisions))

    # Refresh only actionable aliases; excluded package advisories already have
    # their affirmative package evidence and need no broad CPE discovery.
    active_ids = sorted({identifier for finding in findings if finding.applicability != A.NOT_AFFECTED
                         for identifier in finding.vulnerability.identifiers if cve_id(identifier)})
    metadata, extra = {}, {}
    for source, enabled in (("nvd", engine.config.sources.nvd_enabled), ("euvd", engine.config.sources.euvd_enabled), ("cve_list", engine.config.sources.cve_enabled)):
        if not enabled:
            health.append(now_health(source, H.DISABLED, "disabled by configuration")); continue
        failures = 0
        for identifier in active_ids:
            try:
                if source == "nvd":
                    values = engine.nvd.by_id(identifier)
                elif source == "euvd":
                    values = engine.euvd.search("", "", identifier=identifier)
                else:
                    values = []
                    for item in engine._official_evidence(identifier):
                        metrics = []
                        for metric in item.details.get("metrics", []):
                            if isinstance(metric, dict):
                                metrics.extend(value for key, value in metric.items() if key.startswith("cvss") and isinstance(value, dict))
                        metric = max(metrics, key=lambda value: as_float(value.get("baseScore")) or -1, default={})
                        values.append((Vulnerability(identifier, rejected=item.details.get("state") == "REJECTED",
                            cvss_score=as_float(metric.get("baseScore")), cvss_vector=metric.get("vectorString"), cvss_version=metric.get("version")),
                            replace(item, role="cve_enrichment", statement="Official CVE alias metadata; package applicability is assessed separately")))
                for vuln, item in values:
                    metadata.setdefault(identifier, []).append(vuln)
                    extra.setdefault(identifier, []).append(item)
            except (SourceError, ValueError, TypeError):
                failures += 1
        health.append(now_health(source, H.DEGRADED if failures else H.OK,
            f"{len(active_ids) - failures}/{len(active_ids)} CVE metadata lookups completed; package applicability uses OSV"))
    catalogs = {}
    for source, enabled in (("cisa_kev", engine.config.sources.cisa_kev_enabled), ("eu_kev", engine.config.sources.eu_kev_enabled)):
        try:
            if enabled and active_ids:
                catalogs[source] = engine._catalog(source)
            health.append(now_health(source, H.OK if enabled else H.DISABLED, "catalog loaded" if source in catalogs else "not requested; no actionable CVE aliases" if enabled else "disabled by configuration"))
        except SourceError as exc:
            health.append(now_health(source, H.FAILED, str(exc)))
    scores = {}
    try:
        if engine.config.sources.epss_enabled and active_ids:
            scores = engine.epss.scores(active_ids)
        health.append(now_health("epss", H.OK if engine.config.sources.epss_enabled else H.DISABLED, f"{len(scores)} alias scores retrieved" if engine.config.sources.epss_enabled else "disabled by configuration"))
    except SourceError as exc:
        health.append(now_health("epss", H.FAILED, str(exc)))
    enriched = []
    for finding in findings:
        original = finding.vulnerability
        cves = [identifier for identifier in original.identifiers if cve_id(identifier)]
        claims = [original] + [value for identifier in cves for value in metadata.get(identifier, [])]
        vuln = replace(merge_vulnerabilities(claims), cve_id=original.cve_id, advisory_id=original.primary_id)
        evidence = list(finding.evidence) + [item for identifier in cves for item in extra.get(identifier, [])]
        for source, catalog in catalogs.items():
            if cves and finding.applicability != A.NOT_AFFECTED:
                vuln = replace(vuln, **{source: any(identifier in catalog for identifier in cves)})
                evidence.extend(catalog[identifier] for identifier in cves if identifier in catalog)
        matching_scores = [(identifier, scores[identifier]) for identifier in cves if identifier in scores]
        if matching_scores:
            identifier, (score, percentile, date) = max(matching_scores, key=lambda item: item[1][0])
            vuln = replace(vuln, epss_score=score, epss_percentile=percentile, epss_date=date)
            evidence.append(Evidence("epss", "predictive_enrichment", "Highest FIRST EPSS among authoritative CVE aliases",
                details={"cve_id": identifier, "score": score, "percentile": percentile, "score_date": date.isoformat()}))
        enriched.append(replace(finding, vulnerability=vuln, evidence=tuple(evidence),
            applicability=A.NEEDS_REVIEW if vuln.rejected else finding.applicability,
            reason="An authoritative advisory or CVE alias was withdrawn/rejected" if vuln.rejected else finding.reason))
    uncertain = any(f.applicability in {A.COVERAGE_UNKNOWN, A.NEEDS_REVIEW} for f in enriched)
    coverage = A.COVERAGE_UNKNOWN if data.error or not enriched or any(f.applicability == A.COVERAGE_UNKNOWN for f in enriched) else A.NEEDS_REVIEW if uncertain else None
    reason = "required package source is incomplete" if data.error else "no results is not proof of complete vulnerability coverage" if not enriched else "one or more package assessments require review" if uncertain else None
    return QueryResult(asset, tuple(sorted(enriched, key=lambda f: f.vulnerability.primary_id)), tuple(health), coverage, reason)
