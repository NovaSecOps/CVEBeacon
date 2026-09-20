from __future__ import annotations

import httpx
import pytest

from cvebeacon.config import HttpConfig
from cvebeacon.errors import SourceError
from cvebeacon.http import HttpClient
from cvebeacon.sources.cve_list import CVEListSource, record_url
from cvebeacon.sources.epss import EPSSSource, batches
from cvebeacon.sources.euvd import EUVDSource
from cvebeacon.sources.kev import KEVSource
from cvebeacon.sources.nvd import NVDSource, split_cpe23


def test_http_retries_retryable_status_then_succeeds():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(429 if len(calls) == 1 else 200, headers={"Retry-After": "0"}, json={"ok": True})
    raw = httpx.Client(transport=httpx.MockTransport(handler))
    client = HttpClient(HttpConfig(retries=1), client=raw, sleep=lambda _: None)
    assert client.get_json("https://example.test", source="test") == {"ok": True}
    assert len(calls) == 2


def test_http_does_not_retry_non_retryable_status():
    raw = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(400, json={})))
    with pytest.raises(SourceError): HttpClient(HttpConfig(retries=3), client=raw).get_json("https://example.test", source="test")


@pytest.mark.parametrize("first", ["timeout", "503"])
def test_http_retries_timeout_and_temporary_server_failure(first):
    calls = []
    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            if first == "timeout": raise httpx.ReadTimeout("slow", request=request)
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})
    client = HttpClient(HttpConfig(retries=1), client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)
    assert client.get_json("https://example.test", source="test") == {"ok": True}
    assert len(calls) == 2


def test_cve_record_bucket_and_rejected_evidence():
    assert "/2021/44xxx/CVE-2021-44228.json" in record_url("CVE-2021-44228")
    assert "/2024/0xxx/CVE-2024-0001.json" in record_url("CVE-2024-0001")
    record = {"cveMetadata": {"cveId": "CVE-2026-1234", "state": "REJECTED"}, "containers": {"cna": {"rejectedReasons": [{"lang": "en", "value": "duplicate"}]}}}
    item = CVEListSource.evidence(record)[0]
    assert item.details["state"] == "REJECTED"


def test_nvd_parser_and_cpe_escaping():
    assert split_cpe23(r"cpe:2.3:a:acme:widget\:pro:1.0:*:*:*:*:*:*:*")[2] == "widget:pro"
    parsed = NVDSource.parse_cve({"id": "CVE-2026-1234", "descriptions": [{"lang": "en", "value": "summary"}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "version": "3.1", "vectorString": "CVSS:3.1/X"}}]}})
    assert parsed[0].cvss_score == 9.8


def test_euvd_parser_keeps_human_ranges_as_evidence():
    parsed = EUVDSource.parse_item({"aliases": ["CVE-2026-1234"], "description": "x", "enisaIdProduct": [{"product": "Widget", "version": "1 <2"}]})
    assert parsed[1].details["products"][0]["version"] == "1 <2"


def test_epss_batches_obey_character_limit():
    values = [f"CVE-2026-{1000 + x}" for x in range(100)]
    groups = batches(values, max_chars=80)
    assert all(len(",".join(group)) <= 80 for group in groups)
    assert sum(map(len, groups)) == len(values)


def test_nvd_pagination_uses_reported_offsets():
    class FakeHttp:
        def __init__(self): self.starts = []
        def get_json(self, url, **kwargs):
            start = kwargs["params"]["startIndex"]; self.starts.append(start)
            identifier = "CVE-2026-0001" if start == 0 else "CVE-2026-0002"
            return {"startIndex": start, "resultsPerPage": 1, "totalResults": 2, "vulnerabilities": [{"cve": {"id": identifier}}]}
    http = FakeHttp(); source = NVDSource(http, interval=0)
    assert len(source.vulnerabilities(cpe_name="cpe:2.3:a:a:b:1:*:*:*:*:*:*:*")) == 2
    assert http.starts == [0, 1]


def test_malformed_success_response_is_a_source_failure():
    class FakeHttp:
        def get_json(self, url, **kwargs): return {"unexpected": []}
    with pytest.raises(SourceError): NVDSource(FakeHttp(), interval=0).vulnerabilities(cpe_name="cpe:2.3:a:a:b:1:*:*:*:*:*:*:*")
    with pytest.raises(SourceError): KEVSource(FakeHttp()).cisa()


def test_kev_parsers_preserve_eu_provenance():
    class FakeHttp:
        def get_json(self, url, **kwargs):
            if "enisa" in url:
                return [{"cveId": "CVE-2026-0001", "dateAdded": "2026-01-01", "sources": ["cisa_kev", "eukev_kev"]}]
            return {"dateReleased": "2026-01-01", "vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
    source = KEVSource(FakeHttp())
    assert source.cisa()["CVE-2026-0001"].source == "cisa_kev"
    assert source.eu()["CVE-2026-0001"].details["sources"] == ["cisa_kev", "eukev_kev"]


@pytest.mark.parametrize("version", ["5.0", "5.1", "5.1.1", "5.2"])
def test_cve_list_accepts_current_json5_versions(version):
    class FakeHttp:
        def get_json(self, url, **kwargs):
            return {"dataVersion": version, "cveMetadata": {"cveId": "CVE-2026-0001", "state": "PUBLISHED"}, "containers": {"cna": {"affected": []}}}
    assert CVEListSource(FakeHttp()).record("CVE-2026-0001")["dataVersion"] == version


def test_epss_parser_keeps_score_percentile_and_date():
    class FakeHttp:
        def get_json(self, url, **kwargs):
            return {"data": [{"cve": "CVE-2026-0001", "epss": "0.25", "percentile": "0.75", "date": "2026-01-02"}]}
    score, percentile, score_date = EPSSSource(FakeHttp()).scores(["CVE-2026-0001"])["CVE-2026-0001"]
    assert (score, percentile, score_date.isoformat()) == (0.25, 0.75, "2026-01-02")
