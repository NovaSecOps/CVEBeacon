"""Offline regressions for request policy, discovery and publication."""

from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import threading
import weakref

import pytest

from cvebeacon_extensions import contract, web, webfingerprints, webrules
from cvebeacon_extensions.contract import read_snapshot

from test_web_resource_fetching import (
    NOW, Clock, Resolver, Transport, _paths, asset, response, run, write_allowlist,
)


@pytest.fixture(autouse=True)
def snapshot_clock(monkeypatch):
    monkeypatch.setattr(contract, "utc_now", lambda: NOW)


@pytest.mark.parametrize("start_private,target_private", [(True, False), (False, True)])
def test_redirect_requires_both_private_address_permissions(tmp_path, start_private, target_private):
    path = write_allowlist(tmp_path, [
        asset(allow_private_address=start_private),
        asset("target.invalid", "/", allow_private_address=target_private),
    ])
    allowed = web.load_allowlist(path, client="acme", now=NOW)
    transport = Transport([response(302, "", location="https://target.invalid/next"), response()])
    fetcher = web.Fetcher(
        resolver=Resolver({"target.invalid": ("127.0.0.1",)}),
        transport=transport, now=lambda: NOW, host_interval=0,
    )
    try:
        with pytest.raises(web._BlockedFailure, match="non-global address"):
            fetcher.fetch(allowed.assets[0], allowed)
    finally:
        fetcher.close()
    assert _paths(transport) == ["/app/index.html"]


def test_referer_is_computed_per_hop_and_mixed_content_never_reaches_transport(tmp_path):
    html = ('<script src="/first.js"></script>'
            '<script src="http://clear.invalid/insecure.js"></script>')
    class RecordingTransport(Transport):
        def fetch(self, endpoint, *args, **kwargs):
            result = super().fetch(endpoint, *args, **kwargs)
            if endpoint.path in {"/insecure.js", "/downgrade.js"}:
                pytest.fail("a downgrade reached transport")
            return result

    clock = Clock()
    transport = RecordingTransport([
        response(302, "", location="/landing?private=query"),
        response(body=html.encode()),
        response(302, "", location="https://cdn.invalid/second.js"),
        response(302, "", location="http://clear.invalid/downgrade.js"),
        response(), response(),
    ], clock)
    detail, _, _, _ = run(tmp_path, [
        asset(), asset("cdn.invalid", "/"), asset("clear.invalid", "/", scheme="http"),
    ], html, clock=clock, transport=transport)
    headers = {call[0].path: call[5]["request_headers"] for call in transport.calls
               if call[0].path in {"/first.js", "/second.js"}}
    assert headers == {
        "/first.js": {"Accept": "*/*", "Referer": "https://origin.invalid/landing?private=query"},
        "/second.js": {"Accept": "*/*", "Referer": "https://origin.invalid/"},
    }
    assert detail["run"]["resources_skipped_by_reason"]["redirect-blocked"] == 2


@pytest.mark.parametrize("failure", ["retry", "compressed"])
def test_partial_reads_debit_budget_before_retry_or_next_resource(tmp_path, monkeypatch, failure):
    import zlib

    monkeypatch.setattr(web, "RESOURCE_SITE_LIMIT", 8)
    html = '<script src="/first.js"></script><script src="/second.js"></script>'
    clock = Clock()
    class Reader:
        blocks = iter(())
        def read(self, size):
            block = next(self.blocks, b"")
            if block is None:
                raise web._ConnectionFailure("fixture read failed")
            return block

    class StreamingTransport(Transport):
        def fetch(self, endpoint, *args, **kwargs):
            if endpoint.path in {"/app/index.html", "/favicon.ico", "/robots.txt"}:
                return super().fetch(endpoint, *args, **kwargs)
            attempt = sum(call[0] == endpoint for call in self.calls)
            self.calls.append((endpoint, *args, kwargs))
            reader = Reader()
            if endpoint.path == "/first.js" and not attempt:
                if failure == "retry":
                    reader.blocks = iter([b"1234", None])
                    encoding = ""
                else:
                    compressor = zlib.compressobj(wbits=31)
                    reader.blocks = iter([compressor.compress(b"1234") + compressor.flush(zlib.Z_SYNC_FLUSH),
                                          b"invalid compressed data"])
                    encoding = "gzip"
            else:
                reader.blocks = iter([b"1234"])
                encoding = ""
            accounting = {"on_decoded": kwargs["on_decoded"]} if "on_decoded" in kwargs else {}
            body = web.read_body(reader, encoding, limit=kwargs["body_limit"], **accounting)
            return web._Response(200, {"content-type": ("text/javascript",)}, body)

    transport = StreamingTransport([response(body=html.encode())], clock)
    detail, _, _, _ = run(tmp_path, [asset()], html, clock=clock, transport=transport)
    streamed = [(call[0].path, call[-1]["body_limit"]) for call in transport.calls
                if call[0].path in {"/first.js", "/second.js"}]
    following = "/first.js" if failure == "retry" else "/second.js"
    assert streamed == [("/first.js", 8), (following, 4)]
    assert detail["run"]["resources_fetched"] == 1
    assert detail["run"]["resources_skipped_by_reason"]["site-limit"] >= 2


@pytest.mark.parametrize("stage", ["pacing", "retry", "redirect"])
def test_request_authorisation_is_rechecked_after_wait(tmp_path, stage):
    clock = Clock()
    expired = (NOW + timedelta(seconds=0.25)).isoformat()
    allowed = web.load_allowlist(write_allowlist(tmp_path, [
        asset(expires_at=expired if stage != "redirect" else asset()["expires_at"]),
        asset("target.invalid", "/", expires_at=expired),
    ]), client="acme", now=NOW)
    class ExpiringTransport(Transport):
        def fetch(self, endpoint, *args, **kwargs):
            result = super().fetch(endpoint, *args, **kwargs)
            if stage == "retry":
                raise web._ConnectionFailure("fixture retry")
            if stage == "redirect":
                clock.sleep(1)
            return result

    transport = ExpiringTransport([
        response(302, "", location="https://target.invalid/next") if stage == "redirect" else response(),
        response(), response(), response(),
    ], clock)
    fetcher = web.Fetcher(resolver=Resolver(), transport=transport, sleep=clock.sleep,
                          clock=clock.monotonic, now=lambda: NOW + timedelta(seconds=clock.value),
                          host_interval=1)
    try:
        if stage == "pacing":
            fetcher._pacer.wait("origin.invalid")
        with pytest.raises(web._FetchFailure, match="^authorisation expired$") as failure_info:
            fetcher.fetch(allowed.assets[0], allowed)
        assert failure_info.value.reason == "authorisation expired"
    finally:
        fetcher.close()
    assert _paths(transport) == ([] if stage == "pacing" else ["/app/index.html"])


def test_expired_page_preserves_other_sites_in_a_partial_snapshot(tmp_path):
    clock = Clock()
    expiring = (NOW + timedelta(seconds=0.05)).isoformat()
    path = write_allowlist(tmp_path, [asset(), asset("target.invalid", "/", expires_at=expiring)])
    output = tmp_path / "snapshot.json"
    transport = Transport([response(server="Apache/2.4.62"), response()], clock)
    manifest = web.detect_web(path, output, client="acme", source_id="acme-web",
                              allow_partial=True, resolver=Resolver(), transport=transport,
                              clock=clock.monotonic, now=lambda: NOW + timedelta(seconds=clock.value),
                              sleep=clock.sleep, host_interval=0, max_workers=1)
    review = json.loads(output.with_name(output.name + ".review.json").read_bytes())
    assert [item["reason"] for item in review["reviews"]] == ["authorisation expired"]
    assert manifest["omissions"] == ["authorisation-expired"]
    assert _paths(transport) == ["/app/index.html", "/favicon.ico", "/robots.txt"]
    assert read_snapshot(output, allow_partial=True, now=NOW).records[0]["product"] == "http_server"


def test_shared_file_cannot_replay_page_or_response_header_evidence(tmp_path):
    html = '<script src="/shared.js"></script>'
    detail, transport, output, _ = run(tmp_path, [asset(path="/one"), asset(path="/two")], html,
        transport=Transport([
            response(body=html.encode(), server="Apache/2.4.62"),
            response(content_type="text/javascript", body=b"", server="nginx/1.26.2"),
            response(body=html.encode(), server="Caddy/2.8.4"),
        ]))
    assert _paths(transport).count("/shared.js") == 1
    assert [product["product"] for product in detail["products"]] == ["http_server", "caddy"]
    assert len(read_snapshot(output, allow_partial=True, now=NOW).records) == 2


def test_redirected_bases_and_only_browser_resolvable_references(tmp_path, monkeypatch):
    html = ('<script type="module" src="/old/main.js"></script>'
            '<link rel="stylesheet" href="/old/main.css">'
            '<div style="@import &quot;/inline.css&quot;;"></div>'
            '<style type="text/plain">@import "/not-css.css";</style>'
            '<script src="/tab&#9;name.js"></script><script src="/bad\\path.js"></script>'
            '<script src="' + "x" * 5000 + '"></script>')
    module = (b'import "./module.js"; import "some-package"; const display = "inert.js";\n'
              b'const runtime = __webpack_require__; __webpack_require__.u = '
              b'id => ({1:"chunk.js"})[id];')
    css = b'@import /* theme */ url("theme.css"); body { content: "@import phantom.css"; } @import "late.css";'
    tokenised = []
    original_tokens = web._js_tokens

    def track_tokens(text, *args, **kwargs):
        tokenised.append(text)
        return original_tokens(text, *args, **kwargs)

    monkeypatch.setattr(web, "_js_tokens", track_tokens)
    class Routes(Transport):
        def fetch(self, endpoint, *args, **kwargs):
            self.calls.append((endpoint, *args, kwargs))
            routes = {
                "/app/index.html": response(body=html.encode()),
                "/old/main.js": response(302, "", location="/new/main.js"),
                "/old/main.css": response(302, "", location="/new/main.css"),
                "/new/main.js": response(content_type="text/javascript", body=module),
                "/new/main.css": response(content_type="text/css", body=css),
                "/new/chunk.js": response(content_type="text/javascript", body=b""),
                "/new/module.js": response(content_type="text/javascript", body=b""),
                "/new/theme.css": response(content_type="text/css", body=b""),
                "/favicon.ico": response(content_type="image/x-icon", body=b"icon"),
                "/robots.txt": response(content_type="text/plain", body=b""),
            }
            return web._Response(*routes.get(endpoint.path, response(404, "", b"")))
    _, transport, _, _ = run(tmp_path, [asset()], html, transport=Routes([]))
    assert set(_paths(transport)) == {
        "/app/index.html", "/old/main.js", "/old/main.css", "/new/main.js", "/new/main.css",
        "/new/module.js", "/new/chunk.js", "/new/theme.css", "/favicon.ico", "/robots.txt",
    }
    assert tokenised.count(module.decode()) == 1


def test_discovery_retention_and_origin_cache_lifetime(tmp_path, monkeypatch):
    count = 4000
    html = "".join(f'<script src="/file-{index}.js"></script>' for index in range(count))
    peak = []
    parsed = []
    origins = {}
    original = web._resource_candidate
    def track(*args, **kwargs):
        result = original(*args, **kwargs)
        state = args[4]
        peak.append(len(state.seen_urls))
        if hasattr(state, "__weakref__"):
            origins.setdefault(id(state), weakref.ref(state))
        return result
    monkeypatch.setattr(web, "_resource_candidate", track)
    original_references = web._resource_references
    def track_parser(*args, **kwargs):
        result = original_references(*args, **kwargs)
        parser = result[0] if isinstance(result, tuple) else result
        parsed.append(len(parser.links))
        return result
    monkeypatch.setattr(web, "_resource_references", track_parser)
    detail, transport, _, _ = run(tmp_path, [asset()], html, [
        response(content_type="text/javascript", body=b"// fixture") for _ in range(300)
    ])
    assert max(peak) == web.RESOURCE_MAX_FILES
    assert parsed == [web.RESOURCE_MAX_REFERENCES]
    assert len(origins) == 1 and all(ref() is None for ref in origins.values())
    assert len(transport.calls) == detail["run"]["request_count"] == 301


def test_module_streams_tokens_once():
    import inspect
    assert inspect.isgenerator(web._js_tokens(";" * 100_000))


def test_analysis_deadline_stops_new_work_and_retains_page(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(web, "RUN_TIMEOUT", 30)
    def load(_):
        clock.sleep(20)
        return None, 0, False
    monkeypatch.setattr(web, "_load_external_fingerprints", load)
    original_detect = webrules.detect
    deadlines = []
    def slow(page, *, deadline=None, clock=clock.monotonic):
        deadlines.append(deadline)
        result = original_detect(page)
        slow_clock.sleep(5)
        return result
    slow_clock = clock
    monkeypatch.setattr(web, "detect", slow)
    monkeypatch.setattr(webrules, "detect", slow)
    html = '<script src="/too-late.js"></script>'
    detail, transport, output, _ = run(tmp_path, [asset(path="/one"), asset(path="/two")], html,
        clock=clock, transport=Transport([response(body=html.encode(), server="Apache/2.4.62")], clock))
    assert deadlines == [25]
    assert _paths(transport) == ["/one"]
    assert detail["run"]["duration_seconds"] == 25
    assert read_snapshot(output, allow_partial=True, now=NOW).records[0]["product"] == "http_server"


@pytest.mark.parametrize("stage", ["next-page", "resource"])
def test_run_publishes_completed_pages_while_a_matcher_is_still_waiting(tmp_path, monkeypatch, stage):
    clock = Clock()
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    original_detect = webrules.detect
    monkeypatch.setattr(web, "RUN_TIMEOUT", 0.3)
    monkeypatch.setattr(web, "RESOURCE_RUN_DEADLINE_GUARD", 0.1)

    def slow(page, *, deadline=None, clock=clock.monotonic):
        blocked = (page.headers.get("server") == ("Caddy/2.8.4",) if stage == "next-page"
                   else any(resource.url.endswith("/slow.js") for resource in page.resources))
        if blocked:
            fake_clock.value = deadline if deadline is not None else 0.2
            entered.set()
            release.wait(timeout=4)
            finished.set()
        return original_detect(page)

    fake_clock = clock
    monkeypatch.setattr(webrules, "detect", slow)
    monkeypatch.setattr(web, "detect", slow)
    if stage == "next-page":
        assets = [asset(path="/one"), asset(path="/two")]
        responses = [response(server="Apache/2.4.62"), response(server="Caddy/2.8.4")]
        expected_paths = ["/one", "/favicon.ico", "/robots.txt", "/two"]
    else:
        assets = [asset(path="/one")]
        responses = [
            response(body=b'<script src="/slow.js"></script>', server="Apache/2.4.62"),
            response(content_type="text/javascript", body=b""),
        ]
        expected_paths = ["/one", "/slow.js"]
    transport = Transport(responses, clock)
    try:
        detail, _, output, _ = run(tmp_path, assets, "", transport=transport, clock=clock)
        assert entered.is_set() and not finished.is_set()
        assert _paths(transport) == expected_paths
        assert detail["run"]["fetched_count"] == 1
        assert [row["product"] for row in read_snapshot(output, now=NOW, allow_partial=True).records] == [
            "http_server"]
    finally:
        release.set()
        assert finished.wait(timeout=2)


def detection(product, *, name="", version="1.2", evidence=()):
    return webrules.Detection("fixture", product, "js-library", "", "high", (version,),
                              tuple(item.kind for item in evidence), name=name, evidence=evidence)


def test_external_session_finishes_once_and_keeps_long_url_metadata(tmp_path, monkeypatch):
    resource_url = "https://origin.invalid/" + "x" * 650 + ".js"
    html = f'<script src="{resource_url}"></script>'
    events = []
    clock = Clock()
    class Session:
        def __init__(self, fingerprints, *, deadline, clock):
            events.append(("start", deadline, clock()))
        def add_page(self, page, page_url):
            events.append(("page", page_url))
        def add_resource(self, resource):
            events.append(("resource", resource.url))
        def finish(self):
            events.append(("finish",))
            evidence = webrules.Evidence("dom", resource_url, "fixture")
            return (detection("external", evidence=(evidence,)),), {"stopped": True}
    monkeypatch.setattr(webfingerprints, "ExternalSession", Session, raising=False)
    monkeypatch.setattr(web, "_load_external_fingerprints", lambda _: (object(), 1, False))
    detail, _, _, _ = run(tmp_path, [asset()], html, [
        response(content_type="text/javascript", body=b"fixture resource"),
    ], clock=clock)
    assert events == [
        ("start", 180, 0), ("page", "https://origin.invalid/app/index.html"),
        ("resource", resource_url), ("resource", "https://origin.invalid/favicon.ico"),
        ("resource", "https://origin.invalid/robots.txt"), ("finish",),
    ]
    assert detail["run"]["fingerprint_stopped"] == 1
    evidence = detail["products"][0]["evidence"][0]
    assert evidence["kind"] == "dom"
    assert evidence["sha256"] == hashlib.sha256(b"fixture resource").hexdigest()
    assert evidence["bytes"] == len(b"fixture resource")


def test_each_observation_replays_a_shared_resource_and_its_children_once(tmp_path, monkeypatch):
    html = '<script type="module" src="/shared.js"></script>' * 900
    sessions = []

    class Session:
        def __init__(self, fingerprints, *, deadline, clock):
            self.urls = []
            sessions.append(self.urls)

        def add_page(self, page, page_url):
            pass

        def add_resource(self, resource):
            self.urls.append(resource.url)

        def finish(self):
            return (), {}

    monkeypatch.setattr(webfingerprints, "ExternalSession", Session, raising=False)
    monkeypatch.setattr(web, "_load_external_fingerprints", lambda _: (object(), 1, False))
    transport = Transport([
        response(body=html.encode()),
        response(content_type="text/javascript", body=b'import "./child.js";'),
        response(content_type="text/javascript", body=b""),
        response(body=html.encode()),
    ])
    detail, _, _, _ = run(tmp_path, [asset(path="/one"), asset(path="/two")], html, transport=transport)
    assert len(transport.calls) == detail["run"]["request_count"] == 6
    assert len(sessions) == 2
    for urls in sessions:
        assert sorted(urls) == ["https://origin.invalid" + path for path in (
            "/child.js", "/favicon.ico", "/robots.txt", "/shared.js")]


def test_legacy_evidence_uses_the_full_resource_url_for_hashes(tmp_path, monkeypatch):
    prefix = "https://origin.invalid/" + "x" * 600
    urls = [prefix + f"/{index}.js" for index in range(2)]
    html = "".join(f'<script src="{url}"></script>' for url in urls)
    monkeypatch.setattr(web, "_load_external_fingerprints", lambda _: (object(), 1, False))

    def legacy(page, fingerprints, *, page_url=""):
        if page.resources and page.resources[0].url in urls:
            resource = page.resources[0]
            evidence = webrules.Evidence("scripts", resource.url[:512], "fixture")
            return (detection("legacy", evidence=(evidence,)),)
        return ()

    monkeypatch.setattr(webfingerprints, "detect_external", legacy)
    detail, _, _, _ = run(tmp_path, [asset()], html, [
        response(content_type="text/javascript", body=b"one"),
        response(content_type="text/javascript", body=b"two"),
    ])
    evidence = detail["products"][0]["evidence"]
    assert [item["kind"] for item in evidence] == ["scripts", "scripts"]
    assert [item["sha256"] for item in evidence] == [
        hashlib.sha256(body).hexdigest() for body in (b"one", b"two")]


def test_merge_uses_canonical_keys_and_keeps_ambiguous_display_names(monkeypatch):
    monkeypatch.setattr(webrules, "identity_key", lambda value: (
        "alias", "canonical") if value.product in {"one", "one-alias"} else ("product", value.product),
        raising=False)
    merged = {}
    web._merge_detections(merged, [
        detection("one", name="Shared"), detection("one-alias", name="Different"),
        detection("unrelated", name="Shared"),
    ])
    assert list(merged) == [("alias", "canonical"), ("product", "unrelated")]


@pytest.mark.parametrize("bad", [
    detection("surrogate", name="\ud800"), detection("oversized", version="1" * 8202),
    replace(detection("invalid-cpe"), cpe="invalid"),
    replace(detection("oversized-purl", version="á" * 2000), ecosystem="npm", package="fixture"),
], ids=["surrogate", "version", "cpe", "purl"])
def test_invalid_optional_detection_is_quarantined(tmp_path, monkeypatch, bad):
    monkeypatch.setattr(web, "_load_external_fingerprints", lambda _: (object(), 1, False))
    monkeypatch.setattr(webfingerprints, "detect_external", lambda page, *args, **kwargs:
                        (bad,) if page.html else ())
    detail, _, output, _ = run(tmp_path, [asset()], "<html></html>", transport=Transport([
        response(body=b"<html></html>", server="Apache/2.4.62"),
    ]))
    assert [item["product"] for item in detail["products"]] == ["http_server"]
    assert [item["reason"] for item in detail["reviews"]] == ["invalid-detection"]
    assert [row["product"] for row in read_snapshot(output, allow_partial=True, now=NOW).records] == ["http_server"]


def test_optional_review_size_limit_does_not_block_publication(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "MAX_BYTES", 4000)
    monkeypatch.setattr(web, "_load_external_fingerprints", lambda _: (object(), 1, False))
    extras = tuple(detection(f"extra-{index}", version="") for index in range(50))
    monkeypatch.setattr(webfingerprints, "detect_external", lambda page, *args, **kwargs:
                        extras if page.html else ())
    detail, _, output, _ = run(tmp_path, [asset()], "<html></html>", transport=Transport([
        response(body=b"<html></html>", server="Apache/2.4.62"),
    ]))
    assert detail["run"]["review_truncated"] is True
    assert output.with_name(output.name + ".review.json").stat().st_size <= 4000
    assert read_snapshot(output, allow_partial=True, now=NOW).records[0]["product"] == "http_server"
