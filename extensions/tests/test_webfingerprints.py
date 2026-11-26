import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from cvebeacon_extensions import webfingerprints as wf, webrules
from cvebeacon_extensions.webrules import Resource, page_from


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8", newline="\n")


def make_collection(tmp_path, technologies=None, *, categories=None, groups=None):
    root = tmp_path / "src"
    tech_dir = root / "technologies"
    tech_dir.mkdir(parents=True)
    write_json(root / "categories.json", categories or {
        "1": {"name": "CMS"},
        "2": {"name": "JavaScript libraries"},
        "3": {"name": "Programming languages"},
        "4": {"name": "JavaScript frameworks"},
    })
    if groups is not None:
        write_json(root / "groups.json", groups)
    bundle = {}
    for name, document in (technologies or {}).items():
        technology = dict(document)
        for field in ("cats", "groups", "requiresCategory"):
            values = technology.get(field)
            if isinstance(values, list):
                technology[field] = [int(value) if isinstance(value, str) and value.isdigit() else value for value in values]
        for kind in ("scriptSrc", "scripts", "css", "html", "text", "url", "robots", "xhr"):
            if isinstance(technology.get(kind), str):
                technology[kind] = [technology[kind]]
        if isinstance(technology.get("cookies"), list):
            technology["cookies"] = {value: "" for value in technology["cookies"]}
        bundle[name] = technology
    if bundle:
        write_json(tech_dir / "SyntheticCollection.json", bundle)
    return root, tech_dir


def detect(tmp_path, technologies, page, *, page_url="https://synthetic.invalid/"):
    root, _ = make_collection(tmp_path, technologies)
    fingerprints = wf.load_fingerprints(root)
    return wf.detect_external(page, fingerprints, page_url=page_url), fingerprints


def names(detections):
    return {item.name: item for item in detections}


def test_loading_accepts_published_root_and_technologies_directory(tmp_path):
    root, tech_dir = make_collection(tmp_path, {
        "Demo": {"cats": ["1"], "html": "demo-marker"},
    }, groups={"1": {"name": "Example group"}})

    from_root = wf.load_fingerprints(root)
    from_technologies = wf.load_fingerprints(tech_dir)

    assert from_root is from_technologies
    assert from_root.stats.technologies_loaded == 1
    assert from_root.technologies[0].category == "cms"
    assert from_root.groups["1"] == "Example group"
    with pytest.raises((AttributeError, TypeError)):
        from_root.technologies = ()


def test_loading_skips_malformed_and_oversize_inputs_with_counts(tmp_path):
    root, tech_dir = make_collection(tmp_path, {
        "Good": {"cats": ["2"], "html": "good-marker"},
    })
    (tech_dir / "Broken.json").write_text("{not json", encoding="utf-8", newline="\n")
    write_json(tech_dir / "WrongShape.json", {"WrongShape": {"cats": "not-a-list"}})
    (tech_dir / "Huge.json").write_text("x" * (wf.MAX_FILE_BYTES + 1), encoding="utf-8", newline="\n")
    write_json(root / "groups.json", 42)
    page = page_from({}, "<p>good-marker</p>")

    fingerprints = wf.load_fingerprints(root)
    detections = wf.detect_external(page, fingerprints)
    skipped = dict(fingerprints.stats.skipped_technologies)

    assert fingerprints.stats.technologies_loaded == 1
    assert skipped["malformed technology"] >= 1
    assert skipped["malformed technology file"] >= 1
    assert skipped["technology file too large"] == 1
    assert skipped["malformed groups file"] == 1
    assert {item.name for item in detections} == {"Good"}


def test_loading_cache_tracks_file_stamps_and_skips_pattern_and_string_limits(tmp_path):
    root, tech_dir = make_collection(tmp_path, {
        "ChangeMe": {"cats": ["2"], "html": "first-marker"},
        "TooManyPatterns": {"cats": ["2"], "html": ["x"] * (wf.MAX_PATTERNS_PER_TECHNOLOGY + 1)},
        "TooLong": {"cats": ["2"], "html": "x" * (wf.MAX_STRING_LENGTH + 1)},
    })
    first = wf.load_fingerprints(root)
    change_file = tech_dir / "SyntheticCollection.json"
    write_json(change_file, {
        "ChangeMe": {"cats": [2], "html": ["second-marker-with-different-size"]},
        "TooManyPatterns": {"cats": [2], "html": ["x"] * (wf.MAX_PATTERNS_PER_TECHNOLOGY + 1)},
        "TooLong": {"cats": [2], "html": ["x" * (wf.MAX_STRING_LENGTH + 1)]},
    })
    second = wf.load_fingerprints(root)

    assert second is not first
    assert dict(second.stats.skipped_technologies)["technology pattern count limit"] == 1
    assert "malformed pattern collection" in dict(second.stats.skipped_patterns)
    page = page_from({}, "first-marker second-marker-with-different-size")
    assert {item.name for item in wf.detect_external(page, second)} == {"ChangeMe"}


def test_supported_pattern_kinds_and_tags_match_bounded_page_data(tmp_path):
    technologies = {
        "HeaderDemo": {"cats": ["2"], "headers": {
            "x-demo": r"HeaderDemo/([0-9.]+)\;version:\1\;confidence:75",
        }},
        "CookieDemo": {"cats": ["2"], "cookies": {r"session_demo\;confidence:40": ""}},
        "MetaDemo": {"cats": ["2"], "meta": {
            "application-name": r"MetaDemo ([0-9.]+)\;version:\1",
        }},
        "ScriptUrlDemo": {"cats": ["2"], "scriptSrc": r"script-demo/([0-9.]+)\.js\;version:\1"},
        "ScriptTextDemo": {"cats": ["2"], "scripts": r"ScriptTextDemo/([0-9.]+)\;version:\1"},
        "CssDemo": {"cats": ["2"], "css": r"css-demo-([0-9.]+)\;version:\1"},
        "HtmlDemo": {"cats": ["2"], "html": r"html-demo-([0-9.]+)\;version:\1"},
        "TextDemo": {"cats": ["2"], "text": r"Visible Demo ([0-9.]+)\;version:\1"},
        "UrlDemo": {"cats": ["2"], "url": r"synthetic\.invalid/app/([0-9.]+)\;version:\1"},
        "RobotsDemo": {"cats": ["2"], "robots": r"RobotsDemo/([0-9.]+)\;version:\1"},
    }
    page = page_from(
        {"X-Demo": ["HeaderDemo/1.2.3"], "Set-Cookie": ["session_demo=secret; Path=/"]},
        '<html><head><meta name="application-name" content="MetaDemo 2.4.0"></head>'
        '<body><script src="/assets/script-demo/3.1.0.js"></script>'
        '<script>window.x="ScriptTextDemo/4.2.0";</script>'
        '<style>/* css-demo-5.6.0 */</style><p>Visible Demo 6.7.0</p>'
        '<p>html-demo-7.8.0</p></body></html>',
        resources=(
            Resource("/synthetic/script-demo.js", "script", 'window.r="ScriptTextDemo/4.2.0"'),
            Resource("/synthetic/style.css", "style", ".css-demo-5.6.0{}"),
            Resource("/robots.txt", "robots", "User-agent: *\n# RobotsDemo/8.9.0"),
        ),
    )
    detections, fingerprints = detect(tmp_path, technologies, page, page_url="https://synthetic.invalid/app/9.1.0")
    found = names(detections)

    assert set(found) == set(technologies)
    expected_versions = {
        "HeaderDemo": "1.2.3", "MetaDemo": "2.4.0", "ScriptUrlDemo": "3.1.0",
        "ScriptTextDemo": "4.2.0", "CssDemo": "5.6.0", "TextDemo": "6.7.0",
        "HtmlDemo": "7.8.0", "UrlDemo": "9.1.0", "RobotsDemo": "8.9.0",
    }
    for name, version in expected_versions.items():
        assert found[name].versions == (version,)
    assert found["HeaderDemo"].confidence == "medium"
    assert found["CookieDemo"].confidence == "low"
    expected_kinds = {
        "HeaderDemo": "header", "CookieDemo": "cookie", "MetaDemo": "meta",
        "ScriptUrlDemo": "url", "ScriptTextDemo": "script", "CssDemo": "style",
        "HtmlDemo": "html", "TextDemo": "text", "UrlDemo": "url", "RobotsDemo": "robots",
    }
    for name, kind in expected_kinds.items():
        assert found[name].evidence_types == (kind,)
    assert dict(fingerprints.stats.skipped_patterns) == {}


def test_meta_parser_reads_tags_other_than_generator(tmp_path):
    technologies = {"MetaApp": {"cats": ["1"], "meta": {"application-name": "Synthetic App"}}}
    page = page_from({}, '<meta name="application-name" content="Synthetic App">')

    detections, _ = detect(tmp_path, technologies, page)

    assert [item.name for item in detections] == ["MetaApp"]


def test_version_ternary_confidence_and_javascript_regex_translation(tmp_path):
    technologies = {
        "NamedVersion": {"cats": ["2"], "url": r"/vendor\/script/(?<ver>\d+\.\d+)/i\;version:\k<ver>"},
        "TernaryPresent": {"cats": ["2"], "html": r'data-major="(\d+)"\;version:\1?3.0:0.0\;confidence:40'},
        "TernaryFallback": {"cats": ["2"], "html": r'data-flag="(x)?yes"\;version:\1?3.0:2.0'},
        "BadRegex": {"cats": ["2"], "html": "("},
    }
    page = page_from({}, '<div data-major="3" data-flag="yes"></div>')
    detections, fingerprints = detect(tmp_path, technologies, page, page_url="https://synthetic.invalid/vendor/script/2.7")
    found = names(detections)

    assert found["NamedVersion"].versions == ("2.7",)
    assert found["TernaryPresent"].versions == ("3.0",)
    assert found["TernaryPresent"].confidence == "low"
    assert found["TernaryFallback"].versions == ("2.0",)
    assert "BadRegex" not in found
    assert dict(fingerprints.stats.skipped_patterns)["invalid or unsafe regular expression"] == 1


def test_relationships_implies_excludes_requires_and_requires_category(tmp_path):
    technologies = {
        "FrameworkDemo": {
            "cats": ["4"], "html": "framework-marker",
            "implies": [r"TypeScript\;confidence:80"], "excludes": ["ExcludedDemo"],
        },
        "TypeScript": {"cats": ["3"]},
        "ExcludedDemo": {"cats": ["1"], "html": "excluded-marker"},
        "NeedsMissing": {"cats": ["1"], "html": "needs-missing-marker", "requires": ["MissingDemo"]},
        "NeedsPresent": {"cats": ["1"], "html": "needs-present-marker", "requires": ["PresentDemo"]},
        "PresentDemo": {"cats": ["1"], "html": "present-marker"},
        "NeedsLanguage": {"cats": ["1"], "html": "needs-language-marker", "requiresCategory": ["3"]},
        "InvalidFramework": {
            "cats": ["4"], "html": "invalid-framework-marker",
            "implies": ["InvalidChild"], "requires": ["MissingDemo"],
        },
        "InvalidChild": {"cats": ["3"]},
    }
    page = page_from({}, "framework-marker excluded-marker needs-missing-marker needs-present-marker present-marker needs-language-marker invalid-framework-marker")
    detections, _ = detect(tmp_path, technologies, page)
    found = names(detections)

    assert set(found) == {"FrameworkDemo", "TypeScript", "NeedsPresent", "PresentDemo", "NeedsLanguage"}
    assert found["TypeScript"].implied_by == ("FrameworkDemo",)
    assert found["TypeScript"].evidence_types == ("implied",)
    assert found["TypeScript"].confidence == "medium"


def test_dom_selector_subset_and_unsupported_forms(tmp_path):
    selectors = {
        "DomTag": ("article", {}),
        "DomId": ("#root", {"exists": True}),
        "DomClass": (".panel", {}),
        "DomAttr": ("[data-code]", {}),
        "DomEquals": ("[data-state=ready]", {}),
        "DomContains": ("[data-code*=c12]", {}),
        "DomPrefix": ("[data-code^=abc]", {}),
        "DomSuffix": ("[data-code$=123]", {}),
        "DomCompound": ("article#root.panel[data-state=ready]", {}),
        "DomAttributes": ("article", {"attributes": {"data-code": r"abc([0-9]+)\;version:\1"}}),
        "DomText": ("article", {"text": "ContentToken"}),
    }
    document = {name: {"cats": ["2"], "dom": {selector: descriptor}} for name, (selector, descriptor) in selectors.items()}
    document.update({
        "UnsupportedCombinator": {"cats": ["2"], "dom": {"article > span": {"exists": True}}},
        "UnsupportedPseudo": {"cats": ["2"], "dom": {"article:first-child": {"exists": True}}},
        "UnsupportedProperties": {"cats": ["2"], "dom": {"article": {"properties": {"x": "y"}}}},
    })
    page = page_from({}, '<article id="root" class="panel selected" data-state="ready" data-code="abc123">ContentToken</article>')
    detections, fingerprints = detect(tmp_path, document, page)

    assert set(names(detections)) == set(selectors)
    assert names(detections)["DomAttributes"].versions == ("123",)
    skipped = dict(fingerprints.stats.skipped_patterns)
    assert skipped["unsupported DOM selector"] == 2
    assert skipped["DOM properties require a JavaScript runtime"] == 1


def test_unsupported_kinds_are_counted_and_never_matched(tmp_path):
    technology = {
        "cats": [2],
        "js": {"window": "synthetic-marker"},
        "xhr": ["synthetic-marker"],
        "dns": {"synthetic.invalid": ["synthetic-marker"]},
        "certIssuer": "synthetic-marker",
        "probe": {"selector": "synthetic-marker"},
    }
    root, _ = make_collection(tmp_path, {"Unsupported": technology})
    fingerprints = wf.load_fingerprints(root)
    page = page_from({}, "synthetic-marker", resources=(Resource("/synthetic", "script", "synthetic-marker"),))

    detections = wf.detect_external(page, fingerprints)

    assert tuple(detections) == ()
    assert set(dict(detections.stats.unsupported_kinds)) == wf.UNSUPPORTED_KINDS
    assert len(dict(fingerprints.stats.unsupported_kinds)) == len(wf.UNSUPPORTED_KINDS)


def test_cpe_identity_and_unknown_category_fallback(tmp_path):
    technologies = {
        "Human Name": {
            "cats": ["999"], "html": "identity-marker",
            "cpe": "cpe:2.3:a:Example_Vendor:ExampleProduct:*:*:*:*:*:*:*:*",
        },
    }
    detections, _ = detect(tmp_path, technologies, page_from({}, "identity-marker"))
    found = detections[0]

    assert (found.vendor, found.product) == ("example_vendor", "exampleproduct")
    assert found.category == "application"
    assert found.cpe == technologies["Human Name"]["cpe"]


def test_literal_prefilter_preserves_matches_and_text_bounds_apply(tmp_path):
    root, _ = make_collection(tmp_path, {
        "Literal": {"cats": ["2"], "html": "wanted-marker"},
        "Regex": {"cats": ["2"], "html": r".*wanted-marker.*"},
        "TooFarText": {"cats": ["2"], "text": "outside-visible-text-bound"},
        "TooFarScript": {"cats": ["2"], "scripts": "outside-script-bound"},
    })
    fingerprints = wf.load_fingerprints(root)
    page = page_from({}, "wanted-marker " + ("x" * (wf.MAX_TEXT_LENGTH + 8)) + " outside-visible-text-bound",
                     resources=(Resource("/synthetic/bundle.js", "script",
                                         "x" * (wf.MAX_RESOURCE_LENGTH + 4) + "outside-script-bound"),))

    detections = wf.detect_external(page, fingerprints)

    assert {item.name for item in detections} == {"Literal", "Regex"}


def test_deadline_is_counted_with_fake_clock(tmp_path, monkeypatch):
    root, _ = make_collection(tmp_path, {"Demo": {"cats": ["2"], "html": "match-me"}})
    fingerprints = wf.load_fingerprints(root)
    clock = iter((0.0, 21.0, 21.0, 21.0, 21.0))
    monkeypatch.setattr(wf.time, "monotonic", lambda: next(clock, 21.0))

    detections = wf.detect_external(page_from({}, "match-me"), fingerprints)

    assert tuple(detections) == ()
    assert detections.stats.stopped_at_time_limit == 1


def test_optional_evidence_is_filled_when_the_web_rules_type_is_available(tmp_path, monkeypatch):
    @dataclass(frozen=True)
    class Evidence:
        kind: str
        source: str
        excerpt: str

    @dataclass(frozen=True)
    class Detection:
        vendor: str
        product: str
        category: str
        cpe: str
        confidence: str
        versions: tuple[str, ...]
        evidence_types: tuple[str, ...]
        name: str
        ecosystem: str
        package: str
        implied_by: tuple[str, ...]
        evidence: tuple[Evidence, ...] = ()

    monkeypatch.setattr(webrules, "Evidence", Evidence, raising=False)
    monkeypatch.setattr(webrules, "Detection", Detection)
    root, _ = make_collection(tmp_path, {"EvidenceDemo": {"cats": ["2"], "html": "evidence-marker"}})
    fingerprints = wf.load_fingerprints(root)

    detections = wf.detect_external(page_from({}, "evidence-marker"), fingerprints)

    assert detections[0].evidence
    assert detections[0].evidence[0].kind == "html"
    assert detections[0].evidence[0].source == "page HTML"


def test_owner_angular_style_synthetic_page_detects_expected_technologies(tmp_path):
    technologies = {
        "Angular": {"cats": ["2"], "html": r'ng-version="([0-9.]+)"\;version:\1',
                    "implies": [r"TypeScript\;confidence:80"]},
        "zone.js": {"cats": ["2"], "scriptSrc": r"/zone\.js(?:\?|$)"},
        "core-js": {"cats": ["2"], "scripts": "core-js/modules/"},
        "webpack": {"cats": ["2"], "scripts": "webpackJsonp"},
        "Bootstrap": {"cats": ["2"], "html": "bootstrap.min.css"},
        "Google Maps": {"cats": ["2"], "scriptSrc": "maps.googleapis.com/maps/api/js"},
        "Google Font API": {"cats": ["2"], "html": "fonts.googleapis.com/css"},
        "TypeScript": {"cats": ["3"]},
    }
    html = (
        '<app-root ng-version="18.2.0"></app-root>'
        '<script src="/zone.js"></script>'
        '<script src="https://maps.googleapis.com/maps/api/js"></script>'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Demo">'
        '<link rel="stylesheet" href="/bootstrap.min.css">'
    )
    resources = (
        Resource("/polyfills.js", "script", 'import "core-js/modules/";'),
        Resource("/main.js", "script", "webpackJsonp([1], {});"),
        Resource("/styles.css", "style", ".synthetic{}"),
    )
    detections, _ = detect(tmp_path, technologies, page_from({}, html, resources))

    found = names(detections)
    assert {"Angular", "zone.js", "core-js", "webpack", "Bootstrap", "Google Maps", "Google Font API", "TypeScript"} <= set(found)
    assert found["TypeScript"].implied_by == ("Angular",)


def test_performance_3000_synthetic_technologies_against_16mb(tmp_path):
    tech_dir = tmp_path / "src" / "technologies"
    tech_dir.mkdir(parents=True)
    write_json(tmp_path / "src" / "categories.json", {"1": {"name": "JavaScript libraries"}})
    count = 3000
    markers = []
    batch_size = 1500
    for batch_start in range(0, count, batch_size):
        bundle = {}
        for index in range(batch_start, min(count, batch_start + batch_size)):
            marker = f"module_{index:04d}"
            markers.append(marker)
            bundle[f"Synthetic{index:04d}"] = {
                "cats": [1],
                "scriptSrc": [rf"/assets/chunk-{index:04d}\.js(?:\?|$)"],
                "scripts": [rf"window\.{marker}(?:=|\s)"],
                "css": [rf"\.theme-{index:04d}\s*\{{"],
                "html": [rf"data-module=[\"']{index:04d}[\"']"],
            }
        write_json(tech_dir / f"SyntheticBatch{batch_start:04d}.json", bundle)
    per_chunk = [markers[position:position + count // 4] for position in range(0, count, count // 4)]
    resources = []
    chunk_size = wf.MAX_RESOURCE_LENGTH
    for index, chunk_markers in enumerate(per_chunk):
        suffix = ";".join(f"window.{marker}=1" for marker in chunk_markers)
        filler_length = chunk_size - len(suffix)
        text = "x" * filler_length + suffix
        resources.append(Resource(f"/synthetic/chunk-{index}.js", "script", text))
    page = page_from({}, "<html><body></body></html>", tuple(resources))

    started = time.perf_counter()
    fingerprints = wf.load_fingerprints(tmp_path / "src")
    assert fingerprints.stats.technologies_loaded == count
    detections = wf.detect_external(page, fingerprints)
    elapsed = time.perf_counter() - started

    assert len(detections) == count
    assert elapsed < 30.0
    # Keep timing visible in test output for the task report when run with -s.
    print(f"synthetic fingerprint benchmark: load plus detect, {count} technologies, 16 MiB text, {elapsed:.3f}s")


def test_real_published_schema_accepts_many_technologies_and_informational_fields(tmp_path):
    root, tech_dir = make_collection(tmp_path)
    write_json(tech_dir / "Bundle.json", {
        "BundleAlpha": {
            "cats": [2], "description": "Synthetic description", "oss": True,
            "website": "https://synthetic.invalid/", "html": ["alpha-marker"],
        },
        "BundleBeta": {
            "cats": [2], "icon": "synthetic.svg", "pricing": ["free"], "saas": False,
            "dom": ["main#feature"], "html": ["beta-marker"],
        },
    })

    fingerprints = wf.load_fingerprints(root)
    detections = wf.detect_external(page_from({}, '<main id="feature">alpha-marker beta-marker</main>'), fingerprints)

    assert fingerprints.stats.technologies_loaded == 2
    assert {item.name for item in detections} == {"BundleAlpha", "BundleBeta"}


def test_invalid_unicode_technology_is_quarantined_without_losing_valid_entries(tmp_path):
    root, tech_dir = make_collection(tmp_path)
    write_json(tech_dir / "Invalid.json", {"Invalid\ud800": {"cats": [2], "html": "invalid-marker"}})
    write_json(tech_dir / "Valid.json", {"Valid": {"cats": [2], "html": "valid-marker"}})

    fingerprints = wf.load_fingerprints(root)
    detections = wf.detect_external(page_from({}, "invalid-marker valid-marker"), fingerprints)

    assert fingerprints.stats.technologies_loaded == 1
    assert dict(fingerprints.stats.skipped_technologies)["invalid Unicode scalar value"] == 1
    assert {item.name for item in detections} == {"Valid"}


def test_version_capture_longer_than_64_characters_is_not_emitted(tmp_path):
    value = "v" * 65
    technologies = {"LongVersion": {"cats": [2], "html": r"version=([a-z]+)\;version:\1"}}
    detections, _ = detect(tmp_path, technologies, page_from({}, f"version={value}"))

    assert detections[0].versions == ()


def test_regex_backreferences_and_adjacent_unbounded_repeats_are_skipped(tmp_path):
    technologies = {
        "Risky": {
            "cats": [2],
            "html": [r"(a+)\1b", "a*a*synthetic-marker", r"(a+)+b", r"(?:a|aa)+b"],
        },
        "SafeNested": {"cats": [2], "html": r"(?:a+)+b"},
    }
    detections, fingerprints = detect(tmp_path, technologies, page_from({}, "aaaab"))

    assert dict(fingerprints.stats.skipped_patterns)["invalid or unsafe regular expression"] == 4
    assert {item.name for item in detections} == {"SafeNested"}
    _, rewritten = wf._compile_regex(r".*synthetic-marker.*")
    assert rewritten == "synthetic-marker"


def test_adversarial_10_mib_page_stays_bounded(tmp_path):
    technologies = {"Risky": {"cats": [2], "html": r"(a+)\1b"}}
    root, _ = make_collection(tmp_path, technologies)
    fingerprints = wf.load_fingerprints(root)
    page = page_from({}, "a" * (10 * 1024 * 1024) + "!")

    started = time.perf_counter()
    detections = wf.detect_external(page, fingerprints)
    elapsed = time.perf_counter() - started

    assert tuple(detections) == ()
    assert dict(fingerprints.stats.skipped_patterns)["invalid or unsafe regular expression"] == 1
    assert elapsed < 10.0


def test_dom_text_cache_obeys_total_utf8_byte_budget(monkeypatch):
    monkeypatch.setattr(wf, "MAX_DOM_TEXT_CACHE_BYTES", 96, raising=False)
    parser = wf._PageParser("<main>" + ("é" * 40) + "<span>" + ("x" * 40) + "</span></main>")

    parent = parser.node_text(0)
    child = parser.node_text(1)

    assert parent.startswith("é") and child == "x" * 40
    cache_bytes = sum(len(value.encode("utf-8")) for value in parser._node_text_cache.values())
    assert cache_bytes == parser._node_text_cache_bytes
    assert cache_bytes <= 96


def test_external_session_resolves_relations_across_page_and_resource(tmp_path):
    technologies = {
        "SessionFramework": {"cats": [2], "html": "framework-marker", "requires": ["SessionRuntime"]},
        "SessionRuntime": {"cats": [2], "scripts": "runtime-marker"},
    }
    root, _ = make_collection(tmp_path, technologies)
    fingerprints = wf.load_fingerprints(root)
    session = wf.ExternalSession(fingerprints, deadline=20.0, clock=lambda: 0.0)

    session.add_page(page_from({}, "framework-marker"), "https://synthetic.invalid/")
    session.add_resource(Resource("/runtime.js", "script", "runtime-marker"))
    detections, stats = session.finish()

    assert {item.name for item in detections} == {"SessionFramework", "SessionRuntime"}
    assert stats["stopped"] is False


def test_external_session_uses_callers_absolute_deadline_and_keeps_matches(tmp_path):
    technologies = {
        "BeforeDeadline": {"cats": [2], "html": "before-marker", "requires": ["AfterDeadline"]},
        "AfterDeadline": {"cats": [2], "scripts": "after-marker"},
    }
    root, _ = make_collection(tmp_path, technologies)
    fingerprints = wf.load_fingerprints(root)
    now = [0.0]
    session = wf.ExternalSession(fingerprints, deadline=5.0, clock=lambda: now[0])

    session.add_page(page_from({}, "before-marker"), "https://synthetic.invalid/")
    now[0] = 6.0
    session.add_resource(Resource("/late.js", "script", "after-marker"))
    detections, stats = session.finish()

    assert tuple(detections) == ()
    assert stats["stopped"] is True


def test_loader_rejects_world_writable_supported_directory(tmp_path):
    root, _ = make_collection(tmp_path, {"Demo": {"cats": [2], "html": "demo-marker"}})
    root.chmod(0o777)
    if not root.stat().st_mode & stat.S_IWOTH:
        pytest.skip("platform does not expose POSIX world-write mode bits")

    fingerprints = wf.load_fingerprints(root)

    assert fingerprints.stats.technologies_loaded == 0
    assert dict(fingerprints.stats.skipped_technologies)["untrusted fingerprint layout"] >= 1


def test_loader_rejects_symlinked_technology_files(tmp_path):
    root, tech_dir = make_collection(tmp_path)
    target = tmp_path / "outside.json"
    write_json(target, {"Outside": {"cats": [2], "html": "outside-marker"}})
    try:
        (tech_dir / "Linked.json").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")

    fingerprints = wf.load_fingerprints(root)

    assert fingerprints.stats.technologies_loaded == 0
    assert dict(fingerprints.stats.skipped_technologies)["technology file is not a regular file"] == 1


def test_loader_rejects_world_writable_technology_files(tmp_path):
    root, tech_dir = make_collection(tmp_path, {"Demo": {"cats": [2], "html": "demo-marker"}})
    technology_file = tech_dir / "SyntheticCollection.json"
    technology_file.chmod(0o666)
    if not technology_file.stat().st_mode & stat.S_IWOTH:
        pytest.skip("platform does not expose POSIX world-write mode bits")

    fingerprints = wf.load_fingerprints(root)

    assert fingerprints.stats.technologies_loaded == 0


def test_loader_detects_file_replacement_between_lstat_and_open(tmp_path, monkeypatch):
    root, tech_dir = make_collection(tmp_path, {"Original": {"cats": [2], "html": "original-marker"}})
    filename = tech_dir / "SyntheticCollection.json"
    original_open = os.open
    swapped = False

    def replace_then_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and Path(path).name == filename.name:
            filename.rename(tech_dir / "Original.hold")
            write_json(filename, {"Replacement": {"cats": [2], "html": ["replacement-marker"]}})
            swapped = True
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(wf.os, "open", replace_then_open)

    fingerprints = wf.load_fingerprints(root)

    assert swapped
    assert fingerprints.stats.technologies_loaded == 0
    assert dict(fingerprints.stats.skipped_technologies)["technology file changed during loading"] == 1


def test_cpe_less_detection_keeps_display_name_and_slug_identity(tmp_path):
    detections, _ = detect(
        tmp_path,
        {
            "Readable Product Name": {
                "cats": [2], "html": "identity-marker",
                "cpe": "cpe:2.3:a:Example_Vendor:*:*:*:*:*:*:*:*:*",
            },
        },
        page_from({}, "identity-marker"),
    )

    detection = detections[0]
    assert detection.name == "Readable Product Name"
    assert (detection.vendor, detection.product, detection.cpe) == ("readable_product_name", "readable_product_name", "")
