"""Regressions for the release review: private query text, partial collections,
browser path resolution and stable scoped row IDs."""

import dataclasses
import json

import pytest

from cvebeacon_extensions import contract, web, webfingerprints, webrules
from cvebeacon_extensions.contract import read_snapshot

from test_web_resource_fetching import NOW, Transport, asset, response, run
from test_webfingerprints import make_collection


@pytest.fixture(autouse=True)
def snapshot_clock(monkeypatch):
    monkeypatch.setattr(contract, "utc_now", lambda: NOW)


def _display(kind, source, excerpt):
    return web._display_evidence(web._EvidenceRecord(kind, source, excerpt))


@pytest.mark.parametrize("kind,source,excerpt", [
    ("url", "page", "key=SYNTHETIC-PRIVATE&callback=initMap"),
    ("url", "page", "maps.googleapis.com/maps/api/js?key=SYNTHETIC-PRIVATE"),
    ("dom", "page", '<a href="/download?token=SYNTHETIC-PRIVATE">'),
    ("html", "page", "src=/x.js?session=SYNTHETIC-PRIVATE"),
])
def test_url_bearing_evidence_never_keeps_query_values(kind, source, excerpt):
    shown_source, shown = _display(kind, source, excerpt)
    assert "SYNTHETIC-PRIVATE" not in shown and "SYNTHETIC-PRIVATE" not in shown_source
    assert shown


def test_quoted_markup_attributes_are_kept():
    assert _display("html", "page", 'ng-version="17.3.8"')[1] == 'ng-version="17.3.8"'
    assert _display("url", "page", "maps.googleapis.com/maps/api/js")[1] == "maps.googleapis.com/maps/api/js"


@pytest.mark.parametrize("reference,expected", [
    ("assets//vendor.js", "https://origin.invalid/app/assets//vendor.js"),
    ("../x.js", "https://origin.invalid/x.js"),
    ("./a/../b.js", "https://origin.invalid/app/b.js"),
    ("?v=1", "https://origin.invalid/app/index.html?v=1"),
    ("//cdn.invalid/x.js", "https://cdn.invalid/x.js"),
    ("/abs/y.css", "https://origin.invalid/abs/y.css"),
    ("../../../../z.js", "https://origin.invalid/z.js"),
])
def test_references_resolve_like_a_browser(reference, expected):
    assert web._resolve_reference("https://origin.invalid/app/index.html", reference) == expected


def test_empty_path_segments_are_requested_as_written(tmp_path):
    html = '<script src="assets//vendor.js"></script>'
    detail, transport, _, _ = run(tmp_path, [asset()], html, [
        response(content_type="text/javascript", body=b"/* fixture */"),
    ])
    assert "/app/assets//vendor.js" in [call[0].path for call in transport.calls]
    assert "/app/assets/vendor.js" not in [call[0].path for call in transport.calls]


def test_an_unreadable_collection_file_makes_the_result_partial(tmp_path, monkeypatch):
    class Partial:
        technology_count = 1
        incomplete = True
    monkeypatch.setattr(webfingerprints, "load_fingerprints", lambda directory: Partial())
    loaded, count, error = web._load_external_fingerprints(tmp_path)
    assert loaded is not None and count == 1 and error is True


def test_incomplete_collection_loads_are_not_cached(tmp_path, monkeypatch):
    root, _ = make_collection(tmp_path, {"Alpha": {"cats": [2], "html": ["alpha-marker"]}})
    real = webfingerprints._load_uncached
    calls = []

    def flaky(snapshot):
        loaded = real(snapshot)
        calls.append(1)
        stats = webfingerprints.FingerprintStats(
            technologies_loaded=loaded.stats.technologies_loaded,
            skipped_technologies=(("technology file unavailable", 1),))
        return dataclasses.replace(loaded, stats=stats)
    monkeypatch.setattr(webfingerprints, "_load_uncached", flaky)
    first = webfingerprints.load_fingerprints(root)
    second = webfingerprints.load_fingerprints(root)
    assert first.incomplete and second.incomplete
    assert len(calls) == 2


def _scoped(part):
    return webrules.Detection("acme", "widget", "application",
                              f"cpe:2.3:{part}:acme:widget:*:*:*:*:*:*:*:*", "high", ("1.0",))


@pytest.mark.parametrize("order", [("a", "o"), ("o", "a")])
def test_scoped_cpe_rows_keep_their_ids_whatever_the_order(tmp_path, monkeypatch, order):
    class Session:
        def __init__(self, fingerprints, *, deadline, clock):
            pass
        def add_page(self, page, page_url):
            pass
        def add_resource(self, resource):
            pass
        def finish(self):
            return tuple(_scoped(part) for part in order), {"stopped": False}
    monkeypatch.setattr(webfingerprints, "ExternalSession", Session, raising=False)
    monkeypatch.setattr(web, "_load_external_fingerprints", lambda _: (object(), 1, False))
    _, _, output, _ = run(tmp_path, [asset()], "<html></html>", transport=Transport([
        response(body=b"<html></html>")]))
    rows = {row["cpe"].split(":")[2]: row["asset_id"]
            for row in read_snapshot(output, allow_partial=True, now=NOW).records if row["cpe"]}
    plain = web._asset_id("acme", web.Endpoint("https", "origin.invalid", 443, "/app/index.html"),
                          "acme", "widget")
    assert rows["a"] == plain
    assert rows["o"] != plain
    (tmp_path / "order").write_text(json.dumps(rows), encoding="utf-8", newline="\n")
