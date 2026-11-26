import json
import time
from dataclasses import dataclass

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
    for name, document in (technologies or {}).items():
        write_json(tech_dir / f"{name}.json", {name: document})
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
    write_json(tech_dir / "WrongShape.json", {"one": {"cats": []}, "two": {"cats": []}})
    (tech_dir / "Huge.json").write_text("x" * (wf.MAX_FILE_BYTES + 1), encoding="utf-8", newline="\n")
    write_json(root / "groups.json", 42)
    page = page_from({}, "<p>good-marker</p>")

    fingerprints = wf.load_fingerprints(root)
    detections = wf.detect_external(page, fingerprints)
    skipped = dict(fingerprints.stats.skipped_technologies)

    assert fingerprints.stats.technologies_loaded == 1
    assert skipped["malformed technology"] >= 2
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
    change_file = tech_dir / "ChangeMe.json"
    write_json(change_file, {"ChangeMe": {"cats": ["2"], "html": "second-marker-with-different-size"}})
    second = wf.load_fingerprints(root)

    assert second is not first
    assert dict(second.stats.skipped_technologies)["malformed technology"] == 1
    assert "malformed pattern collection" in dict(second.stats.skipped_patterns)
    page = page_from({}, "first-marker second-marker-with-different-size")
    assert {item.name for item in wf.detect_external(page, second)} == {"ChangeMe"}


def test_supported_pattern_kinds_and_tags_match_bounded_page_data(tmp_path):
    technologies = {
        "HeaderDemo": {"cats": ["2"], "headers": {
            "x-demo": r"HeaderDemo/([0-9.]+)\;version:\1\;confidence:75",
        }},
        "CookieDemo": {"cats": ["2"], "cookies": [r"session_demo\;confidence:40"]},
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
    assert found["ScriptUrlDemo"].evidence_types == ("scriptSrc",)
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
    }
    page = page_from({}, "framework-marker excluded-marker needs-missing-marker needs-present-marker present-marker needs-language-marker")
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
    technology = {"cats": ["2"], **{kind: "synthetic-marker" for kind in wf.UNSUPPORTED_KINDS}}
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
    for index in range(count):
        marker = f"module_{index:04d}"
        markers.append(marker)
        write_json(tech_dir / f"Synthetic{index:04d}.json", {
            f"Synthetic{index:04d}": {
                "cats": ["1"],
                "scriptSrc": rf"/assets/chunk-{index:04d}\.js(?:\?|$)",
                "scripts": rf"window\.{marker}(?:=|\s)",
                "css": rf"\.theme-{index:04d}\s*\{{",
                "html": rf"data-module=[\"']{index:04d}[\"']",
            },
        })
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
