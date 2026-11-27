"""One entry per technology across identity schemes, path versions and Google tag parity."""

from datetime import datetime, timezone
import os
import re
import time

import pytest

from cvebeacon_extensions import web, webfingerprints as wf, webrules
from cvebeacon_extensions.webrules import Detection, Evidence, detect, page_from

BIG = 10 * 1024 * 1024
BOUND = 15.0
BOOTSTRAP_CPE = "cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*"


def npm(name, package, *, versions=(), evidence=()):
    return Detection("twbs", package, "js-library", "", "high", versions, ("html",), name=name,
                     ecosystem="npm", package=package, evidence=evidence)


def external(name, *, cpe="", versions=(), category="application", evidence=(), vendor=None,
             product=None):
    slug = re.sub(r"[^a-z0-9]+", "_", name.casefold())
    return Detection(vendor or slug, product or slug, category, cpe, "medium", versions,
                     ("url",), name=name, name_only=not cpe, evidence=evidence)


def ev(kind, source, excerpt):
    return Evidence(kind, source, excerpt)


def observe(detections):
    merged = {}
    web._merge_detections(merged, detections)
    endpoint = web.Endpoint("https", "example.invalid", 443, "/")
    asset = web.WebAsset(endpoint, "Test", datetime(2026, 11, 1, tzinfo=timezone.utc),
                         None, True, 0, False)
    return web._observation_result(asset, "Acme", datetime(2026, 11, 1, tzinfo=timezone.utc),
                                   merged, [], set())


def test_npm_and_cpe_bootstrap_become_one_product():
    banner = npm("Bootstrap", "bootstrap", versions=("5.3.2",),
                 evidence=(ev("html", "page", "Bootstrap v5.3.2"),))
    collection = external("Bootstrap", cpe=BOOTSTRAP_CPE, category="css-library",
                          evidence=(ev("url", "page", "bootstrap.min.css"),))
    for order in ((banner, collection), (collection, banner)):
        result = observe(order)
        product, = result.products
        assert (product["ecosystem"], product["package"]) == ("npm", "bootstrap")
        assert product["category"] == "js-library"
        assert product["versions"] == ["5.3.2"]
        assert len(product["evidence"]) == 2
        row, = result.rows
        assert row["purl"] == "pkg:npm/bootstrap@5.3.2" and row["cpe"] == ""
    alone = observe((banner,))
    assert result.rows[0]["asset_id"] == alone.rows[0]["asset_id"]


def test_name_only_bootstrap_icons_merges_into_the_npm_detection():
    icons = npm("Bootstrap Icons", "bootstrap-icons", versions=("1.11.3",))
    other = external("Bootstrap Icons", category="css-library")
    result = observe((icons, other))
    product, = result.products
    assert product["package"] == "bootstrap-icons" and product["versions"] == ["1.11.3"]


def test_slug_and_package_name_match():
    package = npm("Moment.js", "moment")
    assert len(observe((package, external("Moment"))).products) == 1
    assert len(observe((package, external("moment.js"))).products) == 1
    assert len(observe((package, external("Momentum"))).products) == 2


def test_name_matching_two_npm_detections_is_not_merged():
    first = npm("Chart", "chart.js")
    second = npm("Chart", "chart")
    result = observe((first, second, external("Chart")))
    assert len(result.products) == 3


@pytest.mark.parametrize("cpe", [
    "cpe:2.3:o:getbootstrap:bootstrap:*:*:*:*:*:*:*:*",
    "cpe:2.3:h:getbootstrap:bootstrap:*:*:*:*:*:*:*:*",
])
def test_os_and_hardware_cpes_never_merge(cpe):
    result = observe((npm("Bootstrap", "bootstrap", versions=("5.3.2",)),
                      external("Bootstrap", cpe=cpe)))
    assert len(result.products) == 2


def test_application_is_replaced_by_a_specific_category():
    generic = web._detection_summary(external("Thing", vendor="v", product="p"))
    specific = web._detection_summary(external("Thing", vendor="v", product="p", category="js-library"))
    for first, second in ((generic, specific), (specific, generic)):
        combined = web._combine_detections(first, second)
        assert combined.category == "js-library"
        assert "application" not in combined.categories
    only = web._combine_detections(generic, generic)
    assert only.categories == ("application",)


@pytest.mark.skipif(os.name == "nt", reason="external fingerprint collections are POSIX-only")
@pytest.mark.parametrize("name,category", [
    ("UI frameworks", "css-library"), ("Font scripts", "css-library"),
    ("JavaScript graphics", "js-library"), ("Maps", "js-library"),
    ("Rich text editors", "js-library"), ("Video players", "js-library"),
    ("Static site generator", "framework"), ("Analytics", "analytics"),
    ("Tag managers", "analytics"), ("Something unlisted", "application"),
])
def test_collection_category_aliases(name, category):
    assert wf._category_name(name) == category


def _google(*snippets):
    html = "".join(snippets)
    return {item.name: item for item in detect(page_from({}, html))}


def test_google_analytics_is_one_product_with_fixed_versions():
    gtag = '<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC1234567"></script>'
    classic = '<script src="https://www.google-analytics.com/analytics.js"></script>'
    assert _google(gtag)["Google Analytics"].versions == ("GA4",)
    assert _google(classic)["Google Analytics"].versions == ("UA",)
    both = _google(gtag, classic)
    assert both["Google Analytics"].versions == ("GA4", "UA")
    assert both["Google Analytics"].category == "analytics"
    assert not any("ga4" in item.product for item in webrules.detect(page_from({}, gtag)))
    assert not any(rule.product == "google-analytics-ga4" for rule in webrules.RULES)


def test_collection_google_analytics_merges_with_the_rule_product():
    rule = detect(page_from({}, '<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC1234567"></script>'))
    ga = next(item for item in rule if item.name == "Google Analytics")
    result = observe((ga, external("Google Analytics", category="analytics")))
    product, = result.products
    assert product["versions"] == ["GA4"] and product["category"] == "analytics"
    # A display label is never an inventory version.
    assert result.rows == []


def test_fixed_version_is_validated():
    with pytest.raises(ValueError):
        webrules._rule("x", "v", "p", "analytics", "url", "x", fixed_version="not valid!")
    assert webrules._rule("x", "v", "p", "analytics", "url", "x", fixed_version="GA4").fixed_version == "GA4"


def test_tag_manager_from_the_google_tag_is_medium_and_other_markers_are_high():
    gtag = '<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC1234567"></script>'
    manager = _google(gtag)["Google Tag Manager"]
    assert manager.confidence == "medium" and manager.category == "analytics"
    for html in ('<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABCD"></iframe></noscript>',
                 "<!-- Google Tag Manager -->", "<!-- End Google Tag Manager -->",
                 "<script>dataLayer.push({'gtm.id':'GTM-ABCD'})</script>"):
        assert _google(html)["Google Tag Manager"].confidence == "high", html
    combined = _google(gtag, "<!-- Google Tag Manager -->")
    assert combined["Google Tag Manager"].confidence == "high"
    assert [item.name for item in detect(page_from({}, gtag + "<!-- Google Tag Manager -->"))
            ].count("Google Tag Manager") == 1


def _path(url, **fields):
    detection = web._detection_summary(Detection(
        "twbs", "bootstrap", "js-library", "", "medium", (), ("url",), name="Bootstrap",
        evidence=(ev("url", url, "x"),), **fields))
    return web._path_versions(detection)


@pytest.mark.parametrize("url,expected", [
    ("https://cdn.example.com/bootstrap@5.3.2/dist/css/bootstrap.min.css", ("5.3.2",)),
    ("https://example.com/libs/bootstrap/5.3.2/css/x.css", ("5.3.2",)),
    ("https://example.com/css/bootstrap-5.3.2.min.css", ("5.3.2",)),
    ("https://example.com/css/bootstrap.min.css", ()),
    ("https://example.com/bootstrap/5/x.css", ()),
    ("https://example.com/xbootstrap-5.3.2.css", ()),
])
def test_versions_from_file_paths(url, expected):
    assert _path(url) == expected


def test_conflicting_path_versions_are_kept():
    detection = web._detection_summary(Detection(
        "twbs", "bootstrap", "js-library", "", "medium", (), ("url",), name="Bootstrap",
        evidence=(ev("url", "https://e.example/bootstrap@4.6.0/a.css", ""),
                  ev("url", "https://e.example/bootstrap@5.3.2/a.css", ""))))
    assert web._path_versions(detection) == ("4.6.0", "5.3.2")


def test_path_version_gives_a_collection_detection_a_version_and_a_row():
    url = "https://cdn.example.com/lib/example-widget@2.4.1/dist/widget.css"
    found = external("Example Widget", cpe="cpe:2.3:a:example:example_widget:*:*:*:*:*:*:*:*",
                     evidence=(ev("url", url, "widget.css"),))
    result = observe((found,))
    product, = result.products
    assert product["versions"] == ["2.4.1"]
    row, = result.rows
    assert row["version"] == "2.4.1" and product["inventory"] is True


def test_path_versions_skip_implied_only_and_generic_detections():
    url = "https://cdn.example.com/bootstrap@5.3.2/a.css"
    banner = Detection("banner", "bootstrap", "js-library", "", "low", (), ("url",), name="Bootstrap",
                       evidence=(ev("url", url, ""),))
    assert observe((banner,)).rows == []
    implied = Detection("twbs", "bootstrap", "js-library", "", "low", (), ("implied",),
                        name="Bootstrap", implied_by=("Other",), evidence=(ev("url", url, ""),))
    assert observe((implied,)).products[0]["versions"] == []


@pytest.mark.parametrize("unit", [
    "/bootstrap@", "/bootstrap-1.", "bootstrap/1.2.3.4.5.", "/bootstrap/1.1.1.1.1.1",
])
def test_path_version_scan_is_linear(unit):
    long_source = "https://e.example/" + unit * (BIG // len(unit))
    # Built directly: the scan must stay bounded even if an oversized source reaches it.
    record = web._EvidenceRecord("url", long_source, long_source)
    detection = web._DetectionSummary(
        "twbs", "bootstrap", "js-library", "", "medium", (), ("url",), "Bootstrap",
        evidence=(record,) * 30)
    start = time.perf_counter()
    web._path_versions(detection)
    assert time.perf_counter() - start < BOUND


@pytest.mark.parametrize("unit", [
    "googletagmanager.com/gtag/js", "googletagmanager.com/ns.htm", "<!-- ", "<!--  End Google Tag Manager ",
    "GTM-ABC", "GTM-", "<!--" + " " * 7,
])
def test_tag_manager_patterns_are_linear(unit):
    start = time.perf_counter()
    detect(page_from({}, "<script>" + unit * (BIG // len(unit)) + "</script>"))
    assert time.perf_counter() - start < BOUND
