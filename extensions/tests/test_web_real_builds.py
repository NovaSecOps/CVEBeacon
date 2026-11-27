"""Detection of Angular, core-js, GA4 and Priority Hints in production builds."""

import json
import os
from pathlib import Path
import re
import time

import pytest

from cvebeacon_extensions import webrules
from cvebeacon_extensions.webrules import Resource, detect, page_from

from test_web_resource_fetching import asset, response, run

# Optional directory of official minified Angular core builds, for example
# "angular_core@16.2.12__core.min.mjs". The test skips when it is not set.
CORPUS = Path(os.environ["CVEBEACON_ANGULAR_BUILDS"]) if os.environ.get("CVEBEACON_ANGULAR_BUILDS") else None
BOUND = 15.0  # Quadratic forms take hours on these inputs; leave room for slow CI runners.
BIG = 4 * 1024 * 1024


def _script_page(text, url="https://example.invalid/main.js"):
    return page_from({}, "", (Resource(url, "script", text),))


def _wrap(code):
    return "(self.webpackChunkapp=self.webpackChunkapp||[]).push([[179],{4:(e,n,t)=>{" + code + "}}]);"


def _find(page, name):
    return next((item for item in detect(page) if item.name == name), None)


@pytest.mark.parametrize("code,version", [
    ('Wu=new qu("16.2.12");function f(){if(o)Qe(e,n,["ng-version",Wu.full]);else{x()}}', "16.2.12"),
    ('Ol=new Sl("14.3.0");if(o)Qe(e,n,["ng-version",Ol.full]);', "14.3.0"),
    ('if(o)Ft(e,n,["ng-version","17.3.12"]);else{x()}', "17.3.12"),
    ('Ft(e,n,["ng-version",new Xq("18.0.1").full]);', "18.0.1"),
])
def test_angular_without_banner(code, version):
    page = _script_page(_wrap(code))
    angular = _find(page, "Angular")
    assert angular is not None and angular.versions == (version,)
    assert (angular.ecosystem, angular.package) == ("npm", "@angular/core")
    assert angular.confidence == "high"
    typescript = _find(page, "TypeScript")
    assert typescript is not None and typescript.implied_by == ("Angular",)


@pytest.mark.parametrize("code", [
    'new Set(["ngh","ng-version","ng-server-context"]);',
    'Qe(e,n,["ng-version",Wu.full]);',
    'Qe(e,n,["ng-version",""]);',
])
def test_angular_without_version_is_not_reported(code):
    assert _find(_script_page(_wrap(code)), "Angular") is None


def test_angular_unbannered_rejects_out_of_range_majors():
    helper = webrules._angular_unbannered_versions
    for version in ("1.0.0", "100.1.0", "0.9.9"):
        assert helper(f'["ng-version","{version}"]', deadline=None, clock=time.monotonic) == []
    assert helper('["ng-version","2.4.10"]', deadline=None, clock=time.monotonic)[0][0] == "2.4.10"


_COMMENT = re.compile(r"/\*!.*?\*/|/\*\*[^*]*?@license.*?\*/", re.S)


@pytest.mark.parametrize("name,version", [
    ("14.3.0", "14.3.0"), ("15.2.10", "15.2.10"), ("16.2.12", "16.2.12"), ("17.3.12", "17.3.12"),
])
def test_angular_real_builds_when_available(name, version):
    candidates = sorted(CORPUS.glob(f"*{name}*")) if CORPUS is not None and CORPUS.is_dir() else []
    candidates = [path for path in candidates if path.is_file()]
    if not candidates:
        pytest.skip("corpus not available")
    text = _COMMENT.sub("", candidates[0].read_text(encoding="utf-8", errors="replace"))
    angular = _find(_script_page(_wrap(text)), "Angular")
    assert angular is not None and version in angular.versions


def test_corejs_3_record_far_from_the_shared_store():
    record = ('(t.exports=function(e,n){return i[e]||(i[e]=void 0!==n?n:{})})("versions",[]).push('
              '{version:"3.29.0",mode:o?"pure":"global",copyright:"\\xa9 2014-2023 Denis Pushkarev (zloirock.ru)",'
              'license:"https://x",source:"https://github.com/zloirock/core-js"});')
    text = "var s=r.__core-js_shared__;" + ("a=1;" * 4000) + record
    assert text.index("push") - text.index("__core-js_shared__") > 10000
    core = _find(_script_page(_wrap(text)), "core-js")
    assert core is not None and core.versions == ("3.29.0",)
    plain = record.replace("\\xa9", "©")
    assert _find(_script_page(_wrap(plain)), "core-js").versions == ("3.29.0",)


@pytest.mark.parametrize("text", [
    'var r=t.exports={version:"2.6.12"};"number"==typeof __e&&(__e=r)',
    "var core = module.exports = { version: '2.6.12' };\nif (typeof __e == 'number') __e = core;",
])
def test_corejs_2_core(text):
    core = _find(_script_page(text), "core-js")
    assert core is not None and core.versions == ("2.6.12",)


def test_corejs_record_without_copyright_is_not_reported():
    text = '("versions",[]).push({version:"1.0.0",mode:"global",name:"thing"});'
    assert _find(_script_page(_wrap(text)), "core-js") is None


def test_ga4_inline_and_url_have_no_version():
    inline = page_from({}, "<script>gtag('config','G-ABC1234567');</script>")
    url = page_from({}, '<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC1234567"></script>')
    url2 = page_from({}, '<script src="https://www.googletagmanager.com/gtag/js?l=dl&id=G-ABC1234567"></script>')
    for page in (inline, url, url2):
        ga4 = _find(page, "Google Analytics (GA4)")
        assert ga4 is not None and ga4.versions == ()
        assert _find(page, "Google Analytics") is None
    classic = page_from({}, '<script src="https://www.google-analytics.com/analytics.js"></script>')
    assert _find(classic, "Google Analytics").versions == ()
    assert _find(classic, "Google Analytics (GA4)") is None


def test_priority_hints_set_from_inline_script():
    page = page_from({}, '<script>img.setAttribute("fetchpriority","high");</script>')
    assert _find(page, "Priority Hints") is not None
    bundled = _script_page('var a="fetchpriority";e.setAttribute("fetchpriority",t)')
    assert _find(bundled, "Priority Hints") is None


def test_manifest_without_content_type_is_accepted_when_json(tmp_path, monkeypatch):
    html = ('<link rel="manifest" href="/app.webmanifest">'
            '<script>navigator.serviceWorker.register("/sw.js");</script>')
    observed = []
    original = webrules.detect

    def recording(page):
        observed.extend((r.kind, r.text) for r in page.resources)
        return original(page)

    monkeypatch.setattr(webrules, "detect", recording)
    files = [response(content_type="", body=b'{"name":"demo"}')]
    detail, _, _, _ = run(tmp_path, [asset()], html, files)
    assert ("manifest", '{"name":"demo"}') in observed
    assert "PWA" in json.dumps(detail)


@pytest.mark.parametrize("body", [b"<!doctype html><html></html>", b'["list"]', b"not json"])
def test_manifest_without_content_type_is_refused_otherwise(tmp_path, monkeypatch, body):
    observed = []
    original = webrules.detect
    monkeypatch.setattr(webrules, "detect", lambda page: (
        observed.extend(r.kind for r in page.resources), original(page))[1])
    run(tmp_path, [asset()], '<link rel="manifest" href="/app.webmanifest">',
        [response(content_type="", body=body)])
    assert "manifest" not in observed


def _timed(page):
    start = time.perf_counter()
    detect(page)
    assert time.perf_counter() - start < BOUND


@pytest.mark.parametrize("unit", [
    '"ng-version",', '"ng-version",A.full', '"ng-version",new A("1.2.3"', '"ng-version","1.2.3"',
    'A=new B("', 'A=new B(" ',
])
def test_angular_patterns_are_linear(unit):
    _timed(_script_page((unit + " ") * (BIG // (len(unit) + 1))))
    _timed(_script_page(('"ng-version",A.full;' * 40) + ("A " * (BIG // 2))))


@pytest.mark.parametrize("unit", [
    '.push({version:"1.2.3",mode:', '.push({version:"1.2.3",mode:x,copyright:"', '{version:"2.1.1"};',
    '{version:"2.1.1"};"number"==typeof ', '"versions",[]).push({version:"3.0.0",mode:"',
])
def test_corejs_patterns_are_linear(unit):
    _timed(_script_page(unit * (BIG // len(unit))))


@pytest.mark.parametrize("unit", [
    "gtag('config','G-", "googletagmanager.com/gtag/js?", "googletagmanager.com/gtag/js?&&&a&",
    'setAttribute("fetchpriority" ,',
])
def test_ga4_and_priority_patterns_are_linear(unit):
    _timed(page_from({}, "<script>" + unit * (BIG // len(unit)) + "</script>"))
