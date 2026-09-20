import httpx

from cvebeacon.config import HttpConfig
from cvebeacon.http import HttpClient
from cvebeacon.models import Asset
from cvebeacon.sources.nvd import NVDSource, CPE_URL
from cvebeacon.sources.euvd import EUVDSource


def test_generic_public_requests_exclude_operational_metadata():
    asset = Asset("internal-asset-marker", "PublicVendor", "PublicProduct", "1.0.0",
                  category="private-category-marker", system_id="internal-host-marker")
    observed = []
    def handler(request):
        observed.append(request)
        if str(request.url).startswith(CPE_URL):
            return httpx.Response(200, json={"products": [], "totalResults": 0, "startIndex": 0, "resultsPerPage": 0})
        if "nvd.nist.gov" in request.url.host:
            return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0, "startIndex": 0, "resultsPerPage": 0})
        return httpx.Response(200, json={"items": [], "total": 0})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with HttpClient(HttpConfig(retries=0), client=client) as http:
            nvd = NVDSource(http, interval=0)
            nvd.resolve_cpes(asset)
            nvd.vulnerabilities(cpe_name="cpe:2.3:a:publicvendor:publicproduct:1.0.0:*:*:*:*:*:*:*")
            EUVDSource(http).search(asset.vendor, asset.product)
    assert len(observed) == 3
    wire = " ".join(str(request.url) + request.content.decode() + str(request.headers) for request in observed)
    assert all(value not in wire for value in (asset.asset_id, asset.category, asset.system_id, "asset_id", "system_id", "category"))
    assert all("authorization" not in request.headers and "apikey" not in request.headers for request in observed)
