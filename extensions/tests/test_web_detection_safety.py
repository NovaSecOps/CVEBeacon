"""Regression checks for published web builds and bounded offline matching."""

import hashlib
import importlib.util
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cvebeacon.identity import normalize_asset
from cvebeacon.models import Asset
from cvebeacon_extensions import retirejs, webrules
from cvebeacon_extensions.web import Allowlist, Endpoint, WebAsset, _FetchSuccess, _Response, _merge_detections, _observe
from cvebeacon_extensions.webrules import Detection, Resource, detect, page_from


def _resource(text, kind="script"):
    suffix = "js" if kind == "script" else "css"
    return page_from({}, "", (Resource(f"https://assets.example.invalid/app.{suffix}", kind, text),))


@pytest.mark.parametrize("kind,text,package,excerpt_version", [
    # react@18.3.1, MIT. Exact 236-byte license banner from the published file.
    ("script", "/**\n * @license React\n * react.production.min.js\n *\n * Copyright (c) Facebook, Inc. and its affiliates.\n *\n * This source code is licensed under the MIT license found in the\n * LICENSE file in the root directory of this source tree.\n */",
     "react", ""),
    # lodash@4.18.1, MIT. Exact 95-byte license banner from the published file.
    ("script", "/**\n * @license\n * Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE\n */",
     "lodash", ""),
    # bulma@1.0.4, MIT. Exact 61-byte minified stylesheet banner excerpt.
    ("style", "*! bulma.io v1.0.4 | MIT License | github.com/jgthms/bulma */",
     "bulma", "1.0.4"),
    # htmx.org@2.0.11, 0BSD. Synthetic fixture because this licence is outside
    # the permitted excerpt licences; it retains the published root marker.
    ("script", "var htmx=function(){/* synthetic excerpt */}", "htmx.org", ""),
    # handlebars@4.7.10, MIT. Exact 77-byte published license excerpt.
    ("script", "/**!\n\n @license\n handlebars v4.7.10\n\nCopyright (C) 2011-2019 by Yehuda Katz\n\n",
     "handlebars", "4.7.10"),
    # backbone@1.6.1, MIT. Exact 294-byte minified UMD and VERSION excerpt.
    ("script", '(t,e,i){n.Backbone=r(n,i,t,e)})}else if(typeof exports!=="undefined"){var t=require("underscore"),e;try{e=require("jquery")}catch(t){}r(n,exports,t,e)}else{n.Backbone=r(n,{},n._,n.jQuery||n.Zepto||n.ender||n.$)}})(function(t,h,x,e){var i=t.Backbone;var a=Array.prototype.slice;h.VERSION="1.6.1"',
     "backbone", "1.6.1"),
    # underscore@1.13.8, MIT. Exact 239-byte banner excerpt distinguishes it
    # from the Underscore.js notice embedded in Lodash.
    ("script", '//     Underscore.js 1.13.8\n//     https://underscorejs.org\n//     (c) 2009-2026 Jeremy Ashkenas, Julian Gonggrijp, and DocumentCloud and Investigative Reporters & Editors\n//     Underscore may be freely distributed under the MIT license.\n',
     "underscore", "1.13.8"),
    # animate.css@4.1.1, non-MIT licence. Synthetic positive fixture as required.
    ("style", "/*! animate.css - Version 4.1.1 */", "animate.css", "4.1.1"),
])
def test_published_and_synthetic_excerpts_detect_expected_package_and_version(
        kind, text, package, excerpt_version):
    assert len(text.encode("utf-8")) <= 300
    found = detect(_resource(text, kind))
    match = next(item for item in found if item.package == package)
    assert match.versions == ((excerpt_version,) if excerpt_version else ())


def test_core_js_requires_the_version_record_and_copyright_marker():
    shared_key_only = _resource('var key="__core-js_shared__"; var probe=shared[key];')
    assert not any(item.package == "core-js" for item in detect(shared_key_only))

    # core-js-bundle@3.51.0, MIT. Exact 181-byte published version record,
    # including the required copyright field.
    excerpt = ('__core-js_shared__",u=t.exports=o[a]||i(a,{});'
               '(u.versions||(u.versions=[])).push({version:"3.51.0",mode:n?"pure":"global",'
               'copyright:"© 2013–2025 Denis Pushkarev (zloirock.ru), 20')
    assert len(excerpt.encode("utf-8")) <= 300
    found = detect(_resource(excerpt))
    core_js = next(item for item in found if item.package == "core-js")
    assert core_js.versions == ("3.51.0",)


def test_lodash_and_handlebars_shared_key_probes_do_not_detect_core_js():
    lodash = _resource('Lodash lodash.com/license __core-js_shared__')
    handlebars = _resource('@license\n handlebars v4.7.10 __core-js_shared__')
    assert not any(item.package == "core-js" for item in detect(lodash))
    assert not any(item.package == "core-js" for item in detect(handlebars))
    assert not any(item.name == "Underscore.js" for item in detect(lodash))


def test_react_dom_next_marker_normalizes_to_the_registry_release():
    signature = retirejs._compile_pattern(
        "react-dom", "filecontent", 0,
        r'version:"(§§version§§)[a-z0-9\-]*"[\s,]*rendererPackageName:"react-dom"',
        {"npmname": "react-dom"},
    )
    assert signature is not None and signature.package == "react-dom"
    result = retirejs._matches(
        signature, 'version:"18.3.1-next-f1338f8080-20240426",rendererPackageName:"react-dom"',
    )
    assert result is not None and result[1] == "18.3.1"


def test_version_capture_is_bounded_before_normalization():
    assert webrules.normalize_version("1.2.3" + "a" * 64) == ""
    assert webrules.normalize_version(" 1.2.3 ") == "1.2.3"


@pytest.mark.parametrize("index,value", [
    (0, "o"), (0, "h"), (4, "sp1"), (5, "enterprise"), (6, "en-us"),
    (7, "professional"), (8, "linux"), (9, "x64"), (10, r"\*"),
])
def test_incompatible_cpe_fields_keep_versions_separate(index, value):
    base = ["a", "f5", "nginx", "*", "*", "*", "*", "*", "*", "*", "*"]
    distinct = base.copy()
    distinct[1] = "nginx"
    distinct[index] = value
    merged = {}
    _merge_detections(merged, (
        Detection("f5", "nginx", "web-server", "cpe:2.3:" + ":".join(base), "high", ("1.2.3",)),
        Detection("nginx", "nginx", "web-server", "cpe:2.3:" + ":".join(distinct), "high", ("2.0",)),
    ))
    assert {item.versions for item in merged.values()} == {("1.2.3",), ("2.0",)}


def test_builtin_rules_do_not_combine_incompatible_cpes(monkeypatch):
    compiled = tuple(
        webrules._CompiledRule(webrules.Rule(
            part, "fixture", "server", "web-server", "html", part,
            cpe=f"cpe:2.3:{part}:fixture:server:*:*:*:*:*:*:*:*",
        ), re.compile(part), None)
        for part in ("a", "o")
    )
    monkeypatch.setattr(webrules, "_rule_index", lambda: compiled)
    assert {item.cpe for item in detect(page_from({}, "ao"))} == {
        "cpe:2.3:a:fixture:server:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:fixture:server:*:*:*:*:*:*:*:*",
    }


@pytest.mark.parametrize("url", [
    "https://cdnjs.cloudflare.com/ajax/libs/fixture%2fpath/1.2.3/app.js",
    "https://cdnjs.cloudflare.com/ajax/libs/fixture%5cpath/1.2.3/app.js",
    "https://cdnjs.cloudflare.com/ajax/libs/fixture%00name/1.2.3/app.js",
    "https://cdnjs.cloudflare.com/ajax/libs/https%3a%2f%2fhost/1.2.3/app.js",
])
def test_cdnjs_rejects_decoded_separators_controls_and_url_like_names(url):
    found = detect(page_from({}, f'<script src="{url}"></script>'))
    assert not any(item.vendor == "cdnjs" for item in found)


def test_unknown_cdnjs_without_a_public_version_stays_unidentified_review_evidence():
    url = "https://cdnjs.cloudflare.com/ajax/libs/private-widget/latest/widget.js"
    found = detect(page_from({}, f'<script src="{url}"></script>'))
    review = next(item for item in found if item.vendor == "cdnjs")
    assert not review.product and not review.ecosystem and not review.package and not review.versions


def test_unknown_cdnjs_stays_private_when_inventory_rows_are_normalized():
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    asset = WebAsset(Endpoint("https", "example.invalid", 443, "/"), "Fixture", now,
                     None, True, 0, False)
    allowlist = Allowlist("Fixture", None, (asset,))
    body = (
        b'<script src="https://cdn.jsdelivr.net/npm/react@18.3.1/umd/react.production.min.js"></script>'
        b'<script src="https://cdnjs.cloudflare.com/ajax/libs/unknown-widget/2.4.1/widget.js"></script>'
        b'<script src="https://unpkg.com/@scope/widget@2.4.1/dist/widget.js"></script>'
        b'<script src="https://cdn.jsdelivr.net/npm/unreviewed-widget@3.4.5/widget.js"></script>'
        b'<script src="https://unpkg.com/dompurify@3.2.0/dist/purify.min.js"></script>'
    )

    class Fetcher:
        @staticmethod
        def _clock():
            return 0.0

        @staticmethod
        def fetch(*args, **kwargs):
            return _FetchSuccess(_Response(200, {"content-type": ("text/html",)}, body), (), now)

    result = _observe(asset, allowlist, Fetcher(), run_deadline=10.0)
    rows = [normalize_asset(Asset(
        asset_id=row["asset_id"], vendor=row["vendor"], product=row["product"],
        version=row["version"], system_id=row["system_id"], ecosystem=row["ecosystem"],
        purl=row["purl"], cpe=row["cpe"], client=row["client"],
    )) for row in result.rows]
    assert {row.purl for row in rows} == {"pkg:npm/react@18.3.1", "pkg:npm/dompurify@3.2.0"}

    cdnjs = next(item for item in result.products if item["vendor"] == "cdnjs")
    assert cdnjs["product"] == ""
    assert cdnjs["name"] == "Unidentified cdnjs library"
    assert "ecosystem" not in cdnjs and "package" not in cdnjs
    assert cdnjs["evidence"][0]["kind"] == "url"
    assert "unknown-widget" in cdnjs["evidence"][0]["excerpt"]
    assert any(item.get("reason") == "version-unknown" and item.get("product") == "cdnjs/"
               for item in result.reviews)
    for vendor, excerpt in (("unpkg", "@scope/widget@2.4.1"), ("jsdelivr", "unreviewed-widget@3.4.5")):
        item = next(item for item in result.products if item["vendor"] == vendor)
        assert item["product"] == "" and item["versions"] == []
        assert "ecosystem" not in item and "package" not in item
        assert excerpt in item["evidence"][0]["excerpt"]


def test_every_builtin_rule_has_a_display_name_and_identity_keys_are_stable():
    assert all(rule.name for rule in webrules.RULES)
    package = Detection("npm", "react", "js-library", "", "high", ("18.3.1",),
                        ecosystem="npm", package="react")
    apache = Detection("apache", "http_server", "web-server",
                       "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "high", ())
    equivalent = Detection("apache_http_server", "apache_http_server", "web-server", "",
                           "high", (), name="Apache HTTP Server")
    invalid_package = Detection("npm", "../react", "js-library", "", "high", (),
                                ecosystem="npm", package="@../react")
    assert webrules.identity_key(package) == ("npm", "react")
    assert webrules.identity_key(apache) == ("product", "apache", "http_server")
    assert webrules.identity_key(equivalent) == webrules.identity_key(apache)
    assert webrules.identity_key(invalid_package) == ("product", "npm", "../react")
    assert webrules.EVIDENCE_KINDS == frozenset({
        "header", "cookie", "meta", "url", "html", "script", "style", "manifest",
        "robots", "icon", "implied", "dom", "text",
    })
    assert webrules.REVIEWED_ALIASES[("php_language", "php")] == ("php", "php")
    assert webrules.REVIEWED_ALIASES[("wordpress", "wordpress_cms")] == ("wordpress", "wordpress")


def test_deadline_returns_matches_completed_before_expiry():
    calls = iter((0.0, 0.0, 0.0, 2.0))
    found = detect(page_from({"x-powered-by": ["PHP/8.2.0"]}, ""), deadline=1.0,
                   clock=lambda: next(calls, 2.0))
    php = next(item for item in found if item.product == "php")
    assert php.versions == ("8.2.0",)

    stopped = retirejs.detect(
        _resource("/*! jQuery v3.7.1 */"), deadline=1.0, clock=lambda: 2.0,
    )
    assert stopped == ()


def test_deadline_stops_between_patterns_and_keeps_completed_page_result(monkeypatch):
    now = [0.0]
    original = next(item for item in webrules.COMPILED_RULES if item.rule.key == "php-header")

    class Match:
        @staticmethod
        def group(index=0):
            return "PHP/8.2.0"

    class SlowMatcher:
        @staticmethod
        def search(value):
            now[0] = 2.0
            return Match()

    compiled = webrules._CompiledRule(original.rule, SlowMatcher(), None)
    monkeypatch.setattr(webrules, "_rule_index", lambda: (compiled,))
    found = detect(page_from({"x-powered-by": ["PHP/8.2.0"]}, ""), deadline=1.0,
                   clock=lambda: now[0])
    php = next(item for item in found if item.product == "php")
    assert php.evidence_types == ("header",)


@pytest.mark.parametrize("kind", ["html", "url", "script", "style", "retirejs"])
def test_ten_mib_adversarial_input_stays_bounded(kind):
    payload = "<" + "x" * (10 * 1024 * 1024 - 1)
    started = time.monotonic()
    if kind == "html":
        page = page_from({}, payload)
    elif kind == "url":
        page = page_from({}, f'<script src="{payload}"></script>')
    else:
        resource_kind = "style" if kind == "style" else "script"
        page = _resource(payload, resource_kind)
    detect(page)
    assert time.monotonic() - started < 10.0
    assert len(page.html) <= webrules.MAX_ANALYSIS_TEXT
    assert all(len(resource.text) <= webrules.MAX_ANALYSIS_TEXT for resource in page.resources)


def test_versionless_published_builds_have_reviewed_exact_digest_fingerprints():
    expected = {
        # zone.js@0.16.3, MIT. The minified artifact has no literal version.
        "4ee0b2fe4733702f3ff1bc453ef5547effdc08e62551904946d2058bdd811ada":
            ("zone.js", "0.16.3", "script"),
        # rxjs@7.8.1, Apache-2.0. The minified artifact has no literal version.
        "6508e15edacb9eb2c00b8d3fb8fe3022bef1ca1cdb705519524093d4659b3c23":
            ("rxjs", "7.8.1", "script"),
        # foundation-sites@6.9.0, MIT. The minified stylesheet has no version.
        "c500decbe33468e54180f1b6238850d810e85dcdfbea7f87f56bcb17051a51e4":
            ("foundation-sites", "6.9.0", "style"),
    }
    actual = {digest: (entry[5], entry[6], entry[7])
              for digest, entry in webrules.BUILT_ARTIFACT_HASHES.items()}
    assert actual == expected


def test_artifact_digest_lookup_uses_exact_resource_text(monkeypatch):
    sample = 'var key="__Zone_symbol_prefix";'
    digest = hashlib.sha256(sample.encode("utf-8")).hexdigest()
    monkeypatch.setattr(webrules, "BUILT_ARTIFACT_HASHES", {
        digest: ("example", "published-build", "js-library", "Example", "npm", "example",
                 "1.2.3", "script"),
    })
    found = detect(_resource(sample))
    assert any(item.package == "example" and item.versions == ("1.2.3",) for item in found)
    assert webrules.BUILT_ARTIFACT_HASHES != {}


def test_artifact_digest_lookup_verifies_embedded_bytes(monkeypatch):
    sample = b'var marker="fixture only";'
    marker = b'fixture only'
    digest = hashlib.sha256(sample).hexdigest()
    monkeypatch.setattr(webrules, "BUILT_ARTIFACT_HASHES", {
        digest: ("example", "published-build", "Example", "js-library", "npm", "example",
                 "1.2.3", "script"),
    })
    monkeypatch.setattr(webrules, "_EMBEDDED_ARTIFACTS", {
        digest: (marker, sample.index(marker), len(sample)),
    }, raising=False)
    bundle = b'/* prefix fixture only */\n' + sample + b'\n/* suffix */'
    found = detect(_resource(bundle.decode()))
    assert [(item.package, item.versions) for item in found] == [("example", ("1.2.3",))]
    modified = bundle.replace(b'var marker', b'let marker')
    assert not detect(_resource(modified.decode()))


def test_detection_rejects_non_scalar_input_text():
    malformed = page_from({}, "<div>\ud800</div>")
    assert not detect(malformed)
    bad_name = Detection("vendor", "product", "language", "", "high", (), name="\ud800")
    bad_evidence = Detection(
        "vendor", "product", "language", "", "high", (),
        evidence=(webrules.Evidence("text", "page", "\ud800"),),
    )
    assert not webrules._valid_detection(bad_name)
    assert not webrules._valid_detection(bad_evidence)


def test_corpus_maintainer_script_checks_local_builds_without_network(tmp_path):
    tool_path = Path(__file__).resolve().parents[2] / "tools" / "web_detection_corpus.py"
    spec = importlib.util.spec_from_file_location("web_detection_corpus", tool_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # handlebars@4.7.10, MIT. Exact published banner excerpt under 300 bytes.
    excerpt = "/**!\n\n @license\n handlebars v4.7.10\n\nCopyright (C) 2011-2019 by Yehuda Katz\n\n"
    source = tmp_path / "handlebars.js"
    source.write_text(excerpt, encoding="utf-8", newline="\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([{
        "package": "handlebars", "version": "4.7.10", "kind": "script", "file": source.name,
    }]), encoding="utf-8", newline="\n")

    results = module.run(manifest, tmp_path / "checked", offline=True)
    assert results[0]["status"] == "OK"
    assert results[0]["unexpected"] == []
