"""Offline checks for the bundled, Apache-2.0 Retire.js signatures."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from cvebeacon_extensions.webrules import Evidence, Resource, detect, page_from
from cvebeacon_extensions import retirejs


def _load_update_tool():
    path = Path(__file__).resolve().parents[2] / "tools" / "update_retirejs.py"
    spec = importlib.util.spec_from_file_location("update_retirejs", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _named(items, name):
    return next(item for item in items if item.name == name)


def test_bundled_signatures_have_pinned_source_and_license():
    data = Path(retirejs.__file__).parent / "data" / "retirejs"
    source = (data / "SOURCE.md").read_text(encoding="utf-8")
    license_text = (data / "LICENSE.md").read_text(encoding="utf-8")
    payload = (data / "jsrepository-master.json").read_bytes()
    assert "da66c52a5a5a60f949d19adc04c0bd8ea38a24b9" in source
    assert hashlib.sha256(payload).hexdigest() == (
        "654e9d00dae2ac6cdb5a01ce637463b57d3bb3e77b11bf4a12b979aa3f490f73")
    assert "Apache License" in license_text and "Version 2.0" in license_text
    assert retirejs.SIGNATURES
    assert not any(item.extractor in {"func", "filecontentreplace"} for item in retirejs.SIGNATURES)


def test_uri_extractor_reads_page_links_as_text_only():
    page = page_from({}, '<script src="https://cdn.example.invalid/3.7.1/jquery.js"></script>')
    item = _named(retirejs.detect(page), "jQuery")
    assert item.versions == ("3.7.1",)
    assert item.ecosystem == "npm" and item.package == "jquery"
    assert item.evidence == (Evidence("url", "page", "/3.7.1/jquery.js"),)


def test_uri_extractor_checks_resource_urls_including_third_party():
    page = page_from({}, "", [Resource(
        "https://cdn.example.invalid/assets/jquery-3.7.1.min.js", "script", "",
    )])
    item = _named(retirejs.detect(page), "jQuery")
    assert item.versions == ("3.7.1",)
    assert item.evidence[0].source == "https://cdn.example.invalid/assets/jquery-3.7.1.min.js"


def test_filename_extractor_reads_resource_basenames():
    page = page_from({}, "", [Resource("https://assets.example.invalid/jquery-3.7.1.min.js",
                                         "script", "unrelated content")])
    item = _named(retirejs.detect(page), "jQuery")
    assert item.versions == ("3.7.1",)
    assert item.evidence[0].source == "https://assets.example.invalid/jquery-3.7.1.min.js"
    assert item.evidence[0].excerpt == "jquery-3.7.1.min.js"


def test_filecontent_extractor_matches_script_text():
    page = page_from({}, "", [Resource("https://assets.example.invalid/jquery.js", "script",
                                         "/*! jQuery v3.7.1 */")])
    item = _named(retirejs.detect(page), "jQuery")
    assert item.versions == ("3.7.1",)
    assert item.evidence[0].kind == "script"
    assert item.evidence[0].source == "https://assets.example.invalid/jquery.js"
    assert "jQuery v3.7.1" in item.evidence[0].excerpt


def test_hash_extractor_uses_sha1_of_utf8_script_text(monkeypatch):
    text = "synthetic script π"
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
    signature = retirejs._Signature(
        "synthetic:hashes", "synthetic", "npm", "synthetic-package", "Synthetic package",
        "npm", "synthetic-package", "js-library", "hashes", digest=digest,
        hash_version="1.2.3",
    )
    monkeypatch.setattr(retirejs, "SIGNATURES", (*retirejs.SIGNATURES, signature))
    page = page_from({}, "", [Resource("https://assets.example.invalid/synthetic.js", "script", text)])
    item = _named(retirejs.detect(page), "Synthetic package")
    assert item.versions == ("1.2.3",)
    assert item.evidence == (Evidence("script", "https://assets.example.invalid/synthetic.js", digest),)


def test_unsupported_func_and_filecontentreplace_extractors_are_not_executed():
    page = page_from({}, "", [Resource(
        "https://assets.example.invalid/retire-example.js", "script",
        "retire.VERSION='9.9.9'; var jquery='3.7.1';",
    )])
    assert not any(item.name == "Retire Example" for item in retirejs.detect(page))


def test_regex_compilation_skips_invalid_and_nested_unbounded_patterns():
    assert retirejs._compile_pattern("demo", "filecontent", 0, "(?<bad>", {}) is None
    assert retirejs._compile_pattern("demo", "filecontent", 1, r"(a+)+$", {}) is None
    compiled = retirejs._compile_pattern("demo", "filecontent", 2,
                                         r"Demo version §§version§§", {})
    assert compiled is not None and compiled.versioned


def test_webrules_merges_retirejs_evidence_and_limits_excerpt_and_count():
    text = "/*! @license React v18.2.0 */" + "x" * 300 + "/*! @license React v18.2.0 */"
    page = page_from({}, "", [Resource("https://assets.example.invalid/react.js", "script", text)])
    item = _named(detect(page), "React")
    assert item.ecosystem == "npm" and item.package == "react"
    assert item.versions == ("18.2.0",)
    assert 1 <= len(item.evidence) <= 20
    assert all(len(evidence.excerpt) <= 160 for evidence in item.evidence)
    assert all(evidence.source == "https://assets.example.invalid/react.js" for evidence in item.evidence)


def test_known_retire_component_alias_merges_with_own_npm_detection():
    page = page_from({}, "", [Resource(
        "https://assets.example.invalid/ember.js", "script", 'Ember.VERSION = "5.12.0";',
    )])
    matches = [item for item in detect(page) if item.name == "Ember"]
    assert len(matches) == 1
    assert matches[0].versions == ("5.12.0",)
    assert (matches[0].ecosystem, matches[0].package) == ("npm", "ember-source")
    assert matches[0].evidence_types == ("script",)


def test_update_script_uses_injected_downloads_and_writes_verified_source(tmp_path):
    tool = _load_update_tool()
    commit = "a" * 40
    json_bytes = json.dumps({"demo": {"extractors": {"uri": ["/demo"]}}}).encode("utf-8")
    license_bytes = b"Apache License\nVersion 2.0\n"
    calls = []

    def download(given_commit, filename):
        calls.append((given_commit, filename))
        return {"jsrepository-master.json": json_bytes, "LICENSE.md": license_bytes}[filename]

    digest = tool.update(commit, destination=tmp_path, download=download, bundled_date="2026-11-26")
    assert digest == hashlib.sha256(json_bytes).hexdigest()
    assert calls == [(commit, "jsrepository-master.json"), (commit, "LICENSE.md")]
    assert (tmp_path / "jsrepository-master.json").read_bytes() == json_bytes
    assert (tmp_path / "LICENSE.md").read_bytes() == license_bytes
    source = (tmp_path / "SOURCE.md").read_text(encoding="utf-8")
    assert f"`{commit}`" in source and f"`{digest}`" in source


def test_update_script_rejects_invalid_json_without_writing(tmp_path):
    tool = _load_update_tool()

    def download(commit, filename):
        return b"not json" if filename.endswith(".json") else b"Apache License Version 2.0"

    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        tool.update("b" * 40, destination=tmp_path, download=download)
    assert not list(tmp_path.iterdir())


def test_resource_kinds_support_robots_and_manifest_text():
    page = page_from({}, "", [
        Resource("https://example.invalid/robots.txt", "robots", "Disallow: /wp-admin/"),
        Resource("https://example.invalid/site.webmanifest", "manifest", '{"name":"Sample"}'),
    ])
    item = _named(detect(page), "WordPress")
    assert item.evidence_types == ("robots",)
    assert item.evidence[0].source == "https://example.invalid/robots.txt"
