"""Broader detection with honest confidence: Leaflet, banners and file names."""

import time

import pytest

from cvebeacon_extensions import webrules
from cvebeacon_extensions.webrules import Resource, detect, page_from

BOUND = 4.0
BIG = 4 * 1024 * 1024


def _res(kind, text, url=None):
    return Resource(url or f"https://example.invalid/a.{'js' if kind == 'script' else 'css'}", kind, text)


def _page(*resources, html=""):
    return page_from({}, html, tuple(resources))


def _find(page, name):
    return next((item for item in detect(page) if item.name == name), None)


def _generic(page):
    return [item for item in detect(page) if item.vendor in {"banner", "file-name"}]


def test_leaflet_banner_versions():
    for text in ("/* @preserve\n * Leaflet 1.3.1, a JS library for interactive maps */",
                 "/* Leaflet 1.3.1+Detached: 0123abcd.0123abcd, a JS library for interactive maps */"):
        leaflet = _find(_page(_res("script", text)), "Leaflet")
        assert leaflet.versions == ("1.3.1",)
        assert (leaflet.ecosystem, leaflet.package, leaflet.confidence) == ("npm", "leaflet", "high")


def test_leaflet_version_assignment_near_marker():
    near = 'var Leaflet={};' + "x=1;" * 100 + 'var version = "1.3.1";'
    leaflet = _find(_page(_res("script", near)), "Leaflet")
    assert leaflet.versions == ("1.3.1",) and leaflet.confidence == "low"
    explicit = _find(_page(_res("script", 'L.version = "1.9.4"; // leaflet')), "Leaflet")
    assert explicit.versions == ("1.9.4",) and explicit.confidence == "medium"
    far = 'var version = "1.3.1";' + "x=1;" * 3000 + "leaflet"
    assert _find(_page(_res("script", far)), "Leaflet") is None
    assert _find(_page(_res("script", 'var version = "1.3.1";')), "Leaflet") is None


def test_leaflet_style_has_no_version_and_medium_confidence():
    leaflet = _find(_page(_res("style", ".leaflet-container{overflow:hidden}")), "Leaflet")
    assert leaflet.versions == () and leaflet.confidence == "medium"


def test_leaflet_cdn_link_gives_version():
    page = page_from({}, '<script src="https://unpkg.com/leaflet@1.3.1/dist/leaflet.js"></script>')
    assert _find(page, "Leaflet").versions == ("1.3.1",)


@pytest.mark.parametrize("kind,text,name,version", [
    ("script", "/*! Swiperish 8.4.5 | MIT */", "Swiperish", "8.4.5"),
    ("script", "/*! lightgallery - v2.7.1 - 2022-09-21 */", "lightgallery", "2.7.1"),
    ("script", "/*! Gallery UI - v1.13.2 */", "Gallery UI", "1.13.2"),
    ("script", "/** @license Zeta v1.2 */", "Zeta", "1.2"),
    ("style", "/*!\n * Frobnicate v3.4.5\n */", "Frobnicate", "3.4.5"),
])
def test_generic_banners_are_low_review_only(kind, text, name, version):
    found = _generic(_page(_res(kind, text)))
    assert len(found) == 1
    item = found[0]
    assert item.name == name and item.confidence == "low"
    assert item.versions == (version,) and (item.ecosystem, item.package, item.cpe) == ("", "", "")
    assert item.category == ("css-library" if kind == "style" else "js-library")
    assert item.evidence_types == (kind,)


def test_react_banner_stays_low_alone_and_merges_with_the_rule():
    alone = _generic(_page(_res("script", "/** @license React v17.0.2 */")))
    assert [(i.name, i.confidence) for i in alone] == [("React", "low")] or alone == []
    both = detect(_page(_res("script", "/** @license React v17.0.2\n * react.production.min.js */")))
    assert len([i for i in both if i.name == "React"]) == 1


@pytest.mark.parametrize("text", [
    "/*! Copyright 2020 Acme */",
    "/*! License v1.2.3 */",
    "/*! Build 2.0.1 */",
    "/*! core 1.2.3 */",
    "/*! 1.2.3 */",
    "/* plain comment Foo 1.2.3 */",
])
def test_generic_banner_negatives(text):
    assert _generic(_page(_res("script", text))) == []


def test_banner_limit_is_fifty():
    text = "".join(f"/*! Lib{chr(97 + i // 26)}{chr(97 + i % 26)} 1.0.{i} */\n" for i in range(60))
    assert len(_generic(_page(_res("script", text)))) == 50


def test_reviewed_package_banner_gets_package_identity_and_a_row_version():
    # Banners the specific rules already know add no generic duplicate.
    for text, name in (("/*! Swiper 8.4.5 | MIT */", "Swiper"), ("/*! jQuery UI - v1.13.2 */", "jQuery UI")):
        page = _page(_res("script", text))
        assert _generic(page) == []
        assert len([i for i in detect(page) if i.name == name]) <= 1
    reviewed = next(p for p in sorted(webrules.REVIEWED_PACKAGES) if p.isalpha() and len(p) > 4
                    and p not in {"react", "jquery", "bootstrap", "angular"})
    found = detect(_page(_res("script", f"/*! {reviewed} 4.5.6 */")))
    match = next(i for i in found if i.package == reviewed)
    assert match.versions == ("4.5.6",) and match.confidence == "low"


def test_bootstrap_banner_gives_one_bootstrap():
    text = "/*!\n * Bootstrap v5.3.0 (https://getbootstrap.com/)\n * Licensed under MIT\n */"
    found = detect(_page(_res("script", text)))
    assert len([i for i in found if i.name.startswith("Bootstrap")]) == 1
    assert _generic(_page(_res("script", text))) == []


def test_file_name_versions():
    page = page_from({}, '<script src="/js/flatpickr-4.6.13.min.js?x=1"></script>'
                         '<link rel="stylesheet" href="/css/select2.4.0.13.min.css">'
                         '<script src="/lib/chosen/1.8.7/chosen.min.js"></script>')
    found = {i.name: i for i in _generic(page)}
    assert set(found) == {"flatpickr", "select2", "chosen"}
    assert all(i.confidence == "low" and not i.package for i in found.values())
    assert {n: i.versions for n, i in found.items()} == {
        "flatpickr": ("4.6.13",), "select2": ("4.0.13",), "chosen": ("1.8.7",)}
    assert found["select2"].category == "css-library"
    assert found["flatpickr"].evidence_types == ("url",)


@pytest.mark.parametrize("name", [
    "main.91fe0a.js", "chunk-ABC123.js", "vendor-1.2.3.js", "styles.8f2a1c.css", "runtime-2.0.js",
    "app.1.2.js", "deadbeefcafe-1.2.3.js",
])
def test_file_name_negatives(name):
    assert _generic(page_from({}, f'<script src="/static/{name}"></script>')) == []


def test_file_name_does_not_duplicate_a_specific_detection():
    page = page_from({}, '<script src="/js/jquery-3.6.0.min.js"></script>')
    assert [i.name for i in detect(page) if i.name.lower() == "jquery"] == ["jQuery"]
    assert _generic(page) == []


def test_generic_results_never_become_inventory_rows():
    from cvebeacon_extensions.web import _preferred_version  # noqa: F401
    found = _generic(_page(_res("script", "/*! Swiperish 8.4.5 */")))
    assert found and all(i.versions and not i.package and not i.cpe for i in found)
    assert all(i.vendor in webrules.REVIEW_ONLY_VENDORS for i in found)


def test_other_versions_of_a_generic_library_merge_into_one_detection():
    page = _page(_res("script", "/*! Swiperish 8.4.5 */"), _res("script", "/*! Swiperish 8.4.6 */",
                                                               "https://example.invalid/b.js"))
    found = _generic(page)
    assert len(found) == 1 and found[0].versions == ("8.4.5", "8.4.6")


def _timed(page):
    start = time.perf_counter()
    detect(page)
    assert time.perf_counter() - start < BOUND


@pytest.mark.parametrize("unit", [
    "/*! a ", "/*!", "/*", "/** @license ", "@license ", "/*! aaaa 1.", "/*! " + "a" * 39 + " ",
    "Leaflet 1.2.3+", 'var version = "1.2.3";', "leaflet ",
])
def test_banner_and_leaflet_scans_are_linear(unit):
    _timed(_page(_res("script", unit * (BIG // len(unit)))))
    _timed(_page(_res("style", unit * (BIG // len(unit)))))


@pytest.mark.parametrize("unit", [
    "aaaa-", "a.a.a.a.a.", "a_1.2.", "/a/1.2/", "a-1.2.3.min", "abc.",
])
def test_file_name_scans_are_linear(unit):
    base = "/" + unit * (90 // len(unit))
    urls = "".join(f'<script src="{base}{i}.js"></script>' for i in range(20000))
    _timed(page_from({}, urls))
    _timed(page_from({}, f'<script src="/{unit * (BIG // len(unit))}"></script>'))
