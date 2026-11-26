"""The shared interface between the web fetcher and the detection rules."""

from cvebeacon.identity import normalize_asset
from cvebeacon.models import Asset
from cvebeacon_extensions.webrules import Resource, package_url, page_from


def test_package_url_encodes_npm_scopes_and_rejects_other_ecosystems():
    assert package_url("npm", "core-js", "3.30.2") == "pkg:npm/core-js@3.30.2"
    assert package_url("npm", "@popperjs/core", "2.11.8") == "pkg:npm/%40popperjs/core@2.11.8"
    assert package_url("npm", "core-js", "") == ""
    assert package_url("pypi", "django", "4.2") == ""
    asset = normalize_asset(Asset("a", "popperjs", "@popperjs/core", "2.11.8", ecosystem="npm",
                                  purl=package_url("npm", "@popperjs/core", "2.11.8")))
    assert asset.purl.startswith("pkg:npm/")


def test_page_keeps_fetched_resources_by_kind():
    page = page_from({}, "<html></html>", resources=[Resource("https://a.example/app.js", "script", "x")])
    assert page.resources == (Resource("https://a.example/app.js", "script", "x"),)
