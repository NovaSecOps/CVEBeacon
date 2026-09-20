from types import SimpleNamespace

import pytest

from cvebeacon.applicability import evaluate_nvd_evidence
from cvebeacon.errors import SourceError
from cvebeacon.models import Applicability as A, Evidence
from cvebeacon.sources.nvd import NVDSource
from cvebeacon.sources.euvd import EUVDSource
from cvebeacon.sources.epss import EPSSSource
from cvebeacon.sources.kev import KEVSource
from cvebeacon.reconcile import merge_vulnerabilities
from cvebeacon.models import Vulnerability


CPE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"


def nvd_decision(operator="OR", negate=False, platform=False):
    criterion = {"vulnerable": True, "criteria": CPE}
    matches = [criterion]
    if platform:
        matches.append({"vulnerable": False, "criteria": "cpe:2.3:o:other:os:1:*:*:*:*:*:*:*"})
    item = Evidence("nvd", "applicability", "test", details={"configurations": [{"nodes": [{"operator": operator, "negate": negate, "cpeMatch": matches}]}]})
    return evaluate_nvd_evidence(CPE, item)


def test_nvd_simple_exact_match():
    assert nvd_decision().state == A.AFFECTED


@pytest.mark.parametrize("kwargs", [{"operator": "AND", "platform": True}, {"negate": True}, {"platform": True}])
def test_nvd_environment_conditions_are_not_flattened(kwargs):
    assert nvd_decision(**kwargs).state == A.NEEDS_REVIEW


def test_nvd_missing_configuration_is_not_exact_proof():
    assert evaluate_nvd_evidence(CPE, Evidence("nvd", "applicability", "test")).state == A.NEEDS_REVIEW


@pytest.mark.parametrize("payload", [
    {"startIndex": 0, "resultsPerPage": 1, "totalResults": 2, "vulnerabilities": []},
    {"startIndex": 0, "resultsPerPage": 0, "totalResults": 2, "vulnerabilities": []},
    {"startIndex": 1, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []},
    {"startIndex": 0, "resultsPerPage": "bad", "totalResults": 2, "vulnerabilities": []},
    {"startIndex": 0, "resultsPerPage": 1, "totalResults": 1, "vulnerabilities": [{"cve": None}]},
])
def test_nvd_invalid_or_incomplete_pages_fail(payload):
    http = SimpleNamespace(get_json=lambda *a, **kw: payload)
    with pytest.raises(SourceError):
        NVDSource(http, interval=0).vulnerabilities(cpe_name=CPE)


@pytest.mark.parametrize("payload", [{"items": [], "total": 1}, {"items": []}, {"items": [], "total": -1}])
def test_euvd_incomplete_pages_fail(payload):
    with pytest.raises(SourceError):
        EUVDSource(SimpleNamespace(get_json=lambda *a, **kw: payload)).search("Acme", "Widget")


def test_second_nvd_page_failure_does_not_return_partial_success():
    def get(*args, **kwargs):
        if kwargs["params"]["startIndex"]:
            raise SourceError("nvd", "503")
        return {"startIndex": 0, "resultsPerPage": 1, "totalResults": 2, "vulnerabilities": [{"cve": {"id": "CVE-2026-1234"}}]}
    with pytest.raises(SourceError):
        NVDSource(SimpleNamespace(get_json=get), interval=0).vulnerabilities(cpe_name=CPE)


def test_euvd_retains_each_alias_and_duplicate_source_evidence():
    item = {"id": "EUVD-2026-1234", "aliases": "CVE-2026-1234 CVE-2026-1235"}
    source = EUVDSource(SimpleNamespace(get_json=lambda *a, **kw: {"items": [item, item], "total": 2}))
    values = source.search("Acme", "Widget")
    assert [v.cve_id for v, _ in values] == ["CVE-2026-1234", "CVE-2026-1235"] * 2


def test_epss_requests_more_than_default_hundred_without_truncation():
    identifiers = [f"CVE-2026-{1000 + n}" for n in range(120)]
    def get(*args, **kwargs):
        params = kwargs["params"]
        assert params["limit"] == 120
        return {"total": 120, "data": [{"cve": value, "epss": "0.2", "percentile": "0.8", "date": "2026-01-01"} for value in params["cve"].split(",")]}
    assert len(EPSSSource(SimpleNamespace(get_json=get)).scores(identifiers)) == 120


def test_cvss_selection_keeps_score_vector_and_version_together():
    low = Vulnerability("CVE-2026-1234", cvss_score=5, cvss_vector="low", cvss_version="3.1")
    high = Vulnerability("CVE-2026-1234", cvss_score=9, cvss_vector=None, cvss_version="4.0")
    left = merge_vulnerabilities([low, high]); right = merge_vulnerabilities([high, low])
    assert left == right
    assert (left.cvss_score, left.cvss_vector, left.cvss_version) == (9, None, "4.0")


@pytest.mark.parametrize("item", [
    {"cveId": "CVE-2026-1234", "sources": "eukev_kev"},
    {"cveId": "invalid", "sources": ["eukev_kev"]},
    {"cveId": "CVE-2026-1234"},
])
def test_malformed_eu_kev_entry_cannot_be_healthy_nonmembership(item):
    with pytest.raises(SourceError):
        KEVSource(SimpleNamespace(get_json=lambda *a, **kw: [item])).eu()
