import gzip
import json

import httpx
import pytest

from cvebeacon.config import HttpConfig
from cvebeacon.errors import SourceError
from cvebeacon.http import HttpClient
from cvebeacon.sources.shodan_cvedb import ShodanCVEDBSource
from cvebeacon.sources.vulncheck import VulnCheckSource

CPE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"


def make_http(handler) -> HttpClient:
    return HttpClient(
        HttpConfig(retries=0),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _: None,
    )


def test_default_stream_keeps_caller_headers_and_accepts_encoded_reply():
    seen = {}
    body = b'{"ok": true}'

    def handler(request):
        seen["headers"] = dict(request.headers)
        return httpx.Response(
            200,
            content=gzip.compress(body),
            headers={"Content-Encoding": "gzip"},
        )

    http = make_http(handler)
    chunks = b"".join(http.stream_bytes(
        "https://example.test/data",
        source="test",
        byte_cap=1024,
        headers={"X-Test": "kept", "Accept-Encoding": "gzip"},
    ))
    assert chunks == body
    assert seen["headers"]["x-test"] == "kept"
    assert seen["headers"]["accept-encoding"] == "gzip"


@pytest.mark.parametrize("header", ["Accept-Encoding", "accept-encoding", "AcCePt-EnCoDiNg"])
def test_identity_only_forces_identity_and_rejects_encoded_reply(header):
    seen = {}

    def handler(request):
        seen["headers"] = dict(request.headers)
        return httpx.Response(
            200,
            content=gzip.compress(b'{"ok": true}'),
            headers={"Content-Encoding": "gzip"},
        )

    http = make_http(handler)
    with pytest.raises(SourceError, match="unsupported content encoding"):
        list(http.stream_bytes(
            "https://example.test/data",
            source="test",
            byte_cap=1024,
            headers={header: "gzip"},
            identity_only=True,
        ))
    assert seen["headers"]["accept-encoding"] == "identity"


class RecordingHttp:
    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.calls = []

    def stream_bytes(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return iter([json.dumps(self.payloads.pop(0)).encode("utf-8")])


def test_optional_sources_request_identity_encoding():
    vulncheck = RecordingHttp([{
        "data": [{
            "cve": ["CVE-2026-0001"],
            "date_added": "2026-01-02",
            "knownRansomwareCampaignUse": "Known",
        }],
        "_meta": {"limit": 100, "total_documents": 1},
    }])
    VulnCheckSource(vulncheck).kev("SYNTHETIC-TOKEN")
    assert vulncheck.calls[0][1]["identity_only"] is True

    cvedb = RecordingHttp([{"total": 0}])
    ShodanCVEDBSource(cvedb).discover(CPE)
    assert cvedb.calls[0][1]["identity_only"] is True

    detail = RecordingHttp([{"cve_id": "CVE-2026-0001"}])
    assert ShodanCVEDBSource(detail).lookup("CVE-2026-0001") is not None
    assert detail.calls[0][1]["identity_only"] is True
