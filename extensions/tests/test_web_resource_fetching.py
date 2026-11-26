"""Bounded, allowlist-only fetches for browser-referenced resources."""

from datetime import datetime, timezone
import hashlib
import json
import re
import threading
import time
from types import SimpleNamespace

from cvebeacon_extensions import contract, webrules
from cvebeacon_extensions.contract import read_snapshot
from cvebeacon_extensions import web as web_module
from cvebeacon_extensions.web import detect_web
from cvebeacon_extensions.webrules import Rule

RESOURCE_FILE_LIMIT = getattr(web_module, "RESOURCE_FILE_LIMIT", 5 * 1024 * 1024)
RESOURCE_MAX_FILES = getattr(web_module, "RESOURCE_MAX_FILES", 24)
RESOURCE_MIN_HOST_INTERVAL = getattr(web_module, "RESOURCE_MIN_HOST_INTERVAL", 0.25)

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
PUBLIC = "93.184.216.34"
PAGE_URL = "https://origin.invalid/app/index.html"


def asset(hostname="origin.invalid", path="/app/index.html", **extra):
    return {
        "hostname": hostname,
        "path": path,
        "authorized_by": "Security Team",
        "authorized_at": "2026-11-01T00:00:00Z",
        "expires_at": "2027-11-01T00:00:00Z",
        **extra,
    }


def write_allowlist(tmp_path, assets):
    path = tmp_path / "assets.json"
    path.write_text(json.dumps({"client": "acme", "assets": assets}),
                    encoding="utf-8", newline="\n")
    return path


def response(status=200, content_type="text/html", body=b"<html></html>", **headers):
    values = {"content-type": content_type} if content_type else {}
    values.update({key.casefold(): value for key, value in headers.items()})
    normalized = {key: (tuple(value) if isinstance(value, (list, tuple)) else (value,))
                  for key, value in values.items()}
    return status, normalized, body


class Resolver:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}

    def resolve(self, hostname, port):
        return tuple(self.mapping.get(hostname, (PUBLIC,)))


class Clock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def sleep(self, duration):
        self.value += duration


class SizedBody(bytes):
    def __new__(cls, data, reported_size):
        value = super().__new__(cls, data)
        value.reported_size = reported_size
        return value

    def __len__(self):
        return self.reported_size


class Transport:
    def __init__(self, responses, clock=None):
        self.responses = list(responses)
        self.calls = []
        self.clock = clock

    def fetch(self, endpoint, address, *, ca_bundle, deadline, user_agent, **kwargs):
        now = self.clock.monotonic() if self.clock else 0.0
        self.calls.append((endpoint, address, ca_bundle, deadline, user_agent, kwargs, now))
        if endpoint.path == "/favicon.ico":
            status, headers, body = response(content_type="image/x-icon", body=b"icon")
        elif endpoint.path == "/robots.txt":
            status, headers, body = response(content_type="text/plain", body=b"User-agent: *\n")
        else:
            status, headers, body = self.responses.pop(0)
        return type("Response", (), {"status": status, "headers": headers, "body": body})()


def run(tmp_path, assets, html, files=(), *, resolver=None, transport=None,
        clock=None, host_interval=0, max_workers=1):
    path = write_allowlist(tmp_path, assets)
    clock = clock or Clock()
    transport = transport or Transport([response(body=html.encode()), *files], clock)
    output = tmp_path / "snapshot.json"
    detect_web(path, output, client="acme", source_id="acme-web", allow_partial=True,
               resolver=resolver or Resolver(), transport=transport,
               now=lambda: NOW, clock=clock.monotonic, sleep=clock.sleep,
               host_interval=host_interval, max_workers=max_workers)
    detail = json.loads((tmp_path / "snapshot.json.review.json").read_text(encoding="utf-8"))
    return detail, transport, output, clock


def _paths(transport):
    return [call[0].path for call in transport.calls]


def test_collects_browser_resource_kinds_base_and_deduplicates(tmp_path):
    html = """
    <base href="/assets/">
    <script src="main.js"></script>
    <link rel="stylesheet" href="site.css">
    <link rel="modulepreload" href="module.js">
    <link rel="preload" as="script" href="preloaded.js">
    <link rel="preload" as="style" href="preloaded.css">
    <script src="main.js#again"></script>
    <script src="source-map.js.map"></script>
    <script type="application/json" src="state.json"></script>
    <script type="text/x-template" src="template.js"></script>
    <template><script src="inert-template.js"></script></template>
    <noscript><script src="inert-noscript.js"></script></noscript>
    <link rel="preload" as="image" href="hero.png">
    """
    files = [
        response(content_type="text/javascript", body=b"main"),
        response(content_type="text/css", body=b"css"),
        response(content_type="text/plain", body=b"module"),
        response(content_type="application/octet-stream", body=b"preload"),
        response(content_type="text/plain", body=b"style"),
    ]
    detail, transport, _, _ = run(tmp_path, [asset()], html, files)
    assert _paths(transport) == ["/app/index.html", "/assets/main.js", "/assets/site.css",
                                "/assets/module.js", "/assets/preloaded.js",
                                "/assets/preloaded.css", "/favicon.ico", "/robots.txt"]
    assert detail["run"]["resources_fetched"] == 7
    assert detail["run"]["resources_skipped"] == 2
    assert detail["run"]["resources_skipped_by_reason"] == {"duplicate": 1, "source-map": 1}


def test_external_data_and_javascript_urls_are_never_fetched(tmp_path):
    html = (
        '<script src="https://cdn-marker.invalid/lib.js"></script>'
        '<script src="data:text/javascript,marker"></script>'
        '<script src="javascript:alert(1)"></script>'
        '<script src="https://user:password@origin.invalid/private.js"></script>'
    )
    detail, transport, _, _ = run(tmp_path, [asset()], html)
    assert _paths(transport) == ["/app/index.html", "/favicon.ico", "/robots.txt"]
    assert detail["run"]["resources_fetched"] == 2
    assert detail["run"]["resources_skipped"] == 4
    assert detail["run"]["resources_skipped_by_reason"] == {
        "credentials": 1, "external-origin": 1, "unsupported-scheme": 2,
    }


def test_other_authorized_host_of_same_client_can_serve_resource(tmp_path):
    html = '<script src="https://assets.invalid/lib.js"></script>'
    files = [response(content_type="text/javascript", body=b"library"),
             response(body=b"<html></html>")]
    detail, transport, _, _ = run(
        tmp_path, [asset(), asset("assets.invalid", "/")], html, files)
    selected = [(call[0].hostname, call[0].path) for call in transport.calls
                if call[0].path not in {"/favicon.ico", "/robots.txt"}]
    assert selected == [("origin.invalid", "/app/index.html"),
                        ("assets.invalid", "/lib.js"), ("assets.invalid", "/")]
    assert detail["run"]["resources_fetched"] == 5


def test_resource_redirect_off_allowlist_is_refused_and_counted(tmp_path):
    html = '<script src="/assets/app.js"></script>'
    files = [response(302, "", b"redirect body",
                      location="https://redirect-marker.invalid/private.js")]
    detail, transport, _, _ = run(tmp_path, [asset()], html, files)
    assert _paths(transport) == ["/app/index.html", "/assets/app.js", "/favicon.ico", "/robots.txt"]
    assert detail["run"]["resources_fetched"] == 2
    assert detail["run"]["resources_skipped_by_reason"] == {"redirect-blocked": 1}


def test_resource_redirect_to_private_address_is_refused_and_counted(tmp_path):
    html = '<script src="/assets/app.js"></script>'
    files = [response(302, "", location="/private-target.js")]

    class RebindingResolver:
        def __init__(self):
            self.calls = 0

        def resolve(self, hostname, port):
            self.calls += 1
            return ("127.0.0.1",) if self.calls == 3 else (PUBLIC,)

    detail, transport, _, _ = run(tmp_path, [asset()], html, files,
                                  resolver=RebindingResolver())
    assert len(transport.calls) == 4
    assert detail["run"]["resources_skipped_by_reason"] == {"blocked": 1}


def test_html_non_200_wrong_type_and_oversized_files_are_skipped(tmp_path):
    html = "".join(f'<script src="/{name}.js"></script>'
                   for name in ("html", "status", "type", "large"))
    files = [
        response(content_type="text/html", body=b"single-page application fallback"),
        response(404, "text/javascript", b"missing"),
        response(content_type="application/json", body=b"{}"),
        response(content_type="text/javascript",
                 body=SizedBody(b"x", RESOURCE_FILE_LIMIT + 1)),
    ]
    detail, transport, _, _ = run(tmp_path, [asset()], html, files)
    assert len(transport.calls) == 7
    assert detail["run"]["resources_fetched"] == 2
    assert detail["run"]["resources_skipped"] == 4
    assert detail["run"]["resources_skipped_by_reason"] == {
        "html-response": 1, "http-status": 1, "too-large": 1,
        "wrong-content-type": 1,
    }


def test_file_limit_is_300_per_site(tmp_path):
    names = [f"file-{index}.js" for index in range(301)]
    html = "".join(f'<script src="/{name}"></script>' for name in names)
    files = [
        response(content_type="text/javascript", body=b"x") for _ in range(300)
    ]
    detail, transport, _, _ = run(tmp_path, [asset()], html, files)
    assert len(transport.calls) == 301  # the page plus 300 files
    assert _paths(transport)[-1] == "/file-299.js"
    assert detail["run"]["resources_fetched"] == 300
    assert detail["run"]["resources_skipped"] == 3
    assert detail["run"]["resources_skipped_by_reason"] == {"file-limit": 3}


def test_site_decoded_byte_limit_is_96_mib(tmp_path):
    names = [f"file-{index}.js" for index in range(13)]
    html = "".join(f'<script src="/{name}"></script>' for name in names)
    files = [response(content_type="text/javascript",
                       body=SizedBody(b"x", 8 * 1024 * 1024)) for _ in range(12)]
    detail, transport, _, _ = run(tmp_path, [asset()], html, files)
    assert len(transport.calls) == 13  # the thirteenth file hits the site limit
    assert detail["run"]["resources_fetched"] == 12
    assert detail["run"]["resources_skipped_by_reason"] == {"site-limit": 3}


def test_site_time_budget_and_same_host_pacing_use_fake_clock(tmp_path):
    html = "".join(f'<script src="/file-{index}.js"></script>' for index in range(12))
    clock = Clock()

    class SlowTransport(Transport):
        def fetch(self, endpoint, address, *, ca_bundle, deadline, user_agent, **kwargs):
            if endpoint.path not in {"/app/index.html", "/favicon.ico", "/robots.txt"}:
                if self.clock.monotonic() + 19 > deadline:
                    self.clock.value = deadline
                    self.calls.append((endpoint, address, ca_bundle, deadline, user_agent, kwargs,
                                       self.clock.monotonic()))
                    from cvebeacon_extensions.web import _TimeoutFailure
                    raise _TimeoutFailure("fake resource deadline")
                self.clock.value += 19
            return super().fetch(endpoint, address, ca_bundle=ca_bundle, deadline=deadline,
                                 user_agent=user_agent, **kwargs)

    transport = SlowTransport([response(body=html.encode()), *[
        response(content_type="text/javascript", body=b"x") for _ in range(12)
    ]], clock)
    detail, transport, _, clock = run(tmp_path, [asset()], html, clock=clock,
                                      transport=transport, host_interval=0)
    assert len(transport.calls) == 11  # page, nine files, then the timed out tenth file
    times = [call[-1] for call in transport.calls]
    assert times[1] - times[0] >= RESOURCE_MIN_HOST_INTERVAL
    assert times[2] - times[1] >= RESOURCE_MIN_HOST_INTERVAL
    assert detail["run"]["resources_fetched"] == 9
    assert detail["run"]["resources_skipped"] == 5
    assert detail["run"]["resources_skipped_by_reason"] == {
        "site-time-budget": 5,
    }


def test_resource_headers_referer_and_no_cookie(tmp_path):
    html = '<script src="/assets/main.js"></script><link rel="stylesheet" href="/site.css">'
    files = [response(content_type="text/javascript", body=b"js"),
             response(content_type="text/css", body=b"css")]
    _, transport, _, _ = run(tmp_path, [asset()], html, files)
    requests = [call[5].get("request_headers", {}) for call in transport.calls[1:]
                if call[0].path not in {"/favicon.ico", "/robots.txt"}]
    assert requests == [
        {"Accept": "*/*", "Referer": PAGE_URL},
        {"Accept": "text/css,*/*;q=0.1", "Referer": PAGE_URL},
    ]
    assert all("Cookie" not in headers and "cookie" not in headers for headers in requests)


def test_referer_uses_final_page_url_after_redirect(tmp_path):
    html = '<script src="/runtime.js"></script>'
    clock = Clock()
    transport = Transport([
        response(302, "", location="/final/index.html"),
        response(body=html.encode()),
        response(content_type="text/javascript", body=b"runtime"),
    ], clock)
    _, transport, _, _ = run(tmp_path, [asset()], html, clock=clock, transport=transport)
    assert [call[0].path for call in transport.calls[:3]] == [
        "/app/index.html", "/final/index.html", "/runtime.js"]
    assert transport.calls[2][5]["request_headers"]["Referer"] == (
        "https://origin.invalid/final/index.html")


def test_test_only_script_rule_detects_only_fetched_resource(tmp_path, monkeypatch):
    import cvebeacon_extensions.webrules as rules

    rule = Rule("test-runtime", "fixture", "runtime", "js-library", "script",
                r"fixture-runtime/(\d+\.\d+\.\d+)",
                version_pattern=r"fixture-runtime/(\d+\.\d+\.\d+)")
    compiled = rules._CompiledRule(rule, re.compile(rule.pattern, re.IGNORECASE),
                                   re.compile(rule.version_pattern, re.IGNORECASE))
    monkeypatch.setattr(rules, "COMPILED_RULES", (compiled,))
    monkeypatch.setattr(contract, "utc_now", lambda: NOW)
    rules._rule_index.cache_clear()
    try:
        html = '<script src="/runtime.js"></script>'
        files = [response(content_type="text/javascript", body=b"fixture-runtime/4.2.0")]
        detail, _, output, _ = run(tmp_path, [asset()], html, files)
        assert detail["products"][0]["product"] == "runtime"
        assert detail["products"][0]["versions"] == ["4.2.0"]
        assert detail["products"][0]["evidence_types"] == ["script"]
        assert read_snapshot(output, now=NOW).records[0]["product"] == "runtime"
    finally:
        rules._rule_index.cache_clear()


def test_resource_urls_paths_hostnames_and_bodies_never_enter_messages_or_review(
        tmp_path, capsys):
    html = '<script src="/resource-path-marker.js"></script>'
    files = [response(302, "", b"response-body-marker",
                      location="https://resource-host-marker.invalid/private-path-marker.js")]
    detail, _, _, _ = run(tmp_path, [asset()], html, files)
    assert detail["run"]["resources_skipped"] == 1
    message = capsys.readouterr().out
    review = json.dumps(detail)
    for marker in ("resource-path-marker.js", "resource-host-marker.invalid",
                   "private-path-marker.js", "response-body-marker"):
        assert marker not in message
        assert marker not in review


def test_resource_metadata_counts_successes_and_skips(tmp_path):
    html = '<script src="/good.js"></script><script src="https://cdn.invalid/ext.js"></script>'
    files = [response(content_type="text/javascript", body=b"ok")]
    detail, _, _, _ = run(tmp_path, [asset()], html, files)
    assert detail["run"]["resources_fetched"] == 3
    assert detail["run"]["resources_skipped"] == 1
    assert detail["run"]["resources_skipped_by_reason"] == {"external-origin": 1}


def test_css_imports_are_fetched_relative_to_the_stylesheet(tmp_path):
    html = '<link rel="stylesheet" href="/css/main.css">'
    files = [response(content_type="text/css", body=b'@import "./theme.css";'),
             response(content_type="text/css", body=b"body { color: black }")]
    detail, transport, _, _ = run(tmp_path, [asset()], html, files)
    assert "/css/main.css" in _paths(transport)
    assert "/css/theme.css" in _paths(transport)
    assert detail["run"]["resources_fetched"] == 4  # two styles, the icon and robots.txt


def test_static_module_imports_and_literal_dynamic_imports_are_fetched(tmp_path):
    html = '<script type="module" src="/modules/main.js"></script>'
    source = (
        'import value from "./dep.js"; import("./lazy.js"); '
        'export {other} from "../shared.js";'
    )
    files = [response(content_type="text/javascript", body=source.encode())] + [
        response(content_type="text/javascript", body=b"module") for _ in range(3)
    ]
    _, transport, _, _ = run(tmp_path, [asset()], html, files)
    paths = set(_paths(transport))
    assert {"/modules/main.js", "/modules/dep.js", "/modules/lazy.js", "/shared.js"} <= paths


def test_only_literal_webpack_and_vite_chunk_map_paths_are_fetched(tmp_path):
    html = '<script src="/runtime.js"></script>'
    source = (
        '__webpack_require__.u = id => ({"one": "/chunks/one.js"})[id]; '
        'const __vite__mapDeps = ["/chunks/two.js", "./styles/lazy.css"]; '
        'const guessed = "" + chunkId + ".js";'
    )
    files = [response(content_type="text/javascript", body=source.encode()),
             response(content_type="text/javascript", body=b"chunk"),
             response(content_type="text/javascript", body=b"chunk"),
             response(content_type="text/css", body=b"css")]
    _, transport, _, _ = run(tmp_path, [asset()], html, files)
    paths = set(_paths(transport))
    assert {"/runtime.js", "/chunks/one.js", "/chunks/two.js", "/styles/lazy.css"} <= paths
    assert "/app/chunkId.js" not in paths
    assert "/.js" not in paths


def test_manifest_icon_and_robots_are_fetched_with_resource_kinds(tmp_path, monkeypatch):
    html = ('<link rel="manifest" href="/app.webmanifest">'
            '<link rel="icon" href="/favicon.ico">')
    files = [response(content_type="application/manifest+json", body=b'{"name":"demo"}')]
    observed = []
    original_detect = webrules.detect

    def recording_detect(page):
        if page.resources:
            assert not page.html and not page.headers
        observed.extend((resource.kind, resource.text) for resource in page.resources)
        return original_detect(page)

    monkeypatch.setattr(webrules, "detect", recording_detect)
    detail, transport, _, _ = run(tmp_path, [asset()], html, files)
    assert {"/app.webmanifest", "/favicon.ico", "/robots.txt"} <= set(_paths(transport))
    assert ("manifest", '{"name":"demo"}') in observed
    assert ("icon", "") in observed
    assert any(kind == "robots" and text.startswith("User-agent:") for kind, text in observed)
    assert detail["run"]["resources_fetched"] == 3


def test_review_evidence_is_excerpt_limited_file_hashed_and_capped(tmp_path, monkeypatch):
    html = '<link rel="icon" href="/favicon.ico">' + "".join(
        f'<script src="/bundle-{index}.js"></script>' for index in range(25))
    files = [response(content_type="text/javascript", body=f"bundle-{index}".encode())
             for index in range(25)]
    contract_now = contract.utc_now
    monkeypatch.setattr(contract, "utc_now", lambda: NOW)

    def patched_detect(page):
        if not page.resources:
            return ()
        resource = page.resources[0]
        if resource.kind not in {"script", "icon"}:
            return ()
        evidence_kind = "url" if resource.kind == "icon" else "script"
        evidence = SimpleNamespace(kind=evidence_kind, source=resource.url, excerpt="e" * 200)
        return (SimpleNamespace(
            vendor="fixture", product="bundle", category="js-library", cpe="",
            confidence="high", versions=("1.2.3",), evidence_types=(evidence_kind,),
            name="", ecosystem="", package="", implied_by=(), evidence=(evidence,),
        ),)

    monkeypatch.setattr(webrules, "detect", patched_detect)
    try:
        detail, _, _, _ = run(tmp_path, [asset()], html, files)
    finally:
        monkeypatch.setattr(contract, "utc_now", contract_now)
    evidence = detail["products"][0]["evidence"]
    assert len(evidence) == 20
    assert all(set(item) == {"kind", "source", "excerpt", "sha256", "bytes"} for item in evidence)
    assert all(len(item["excerpt"]) == 160 for item in evidence)
    first_script = next(item for item in evidence if item["source"].endswith("bundle-0.js"))
    body = b"bundle-0"
    assert first_script["sha256"] == hashlib.sha256(body).hexdigest()
    assert first_script["bytes"] == len(body)
    icon = next(item for item in evidence if item["source"].endswith("favicon.ico"))
    assert icon["sha256"] == hashlib.sha256(b"icon").hexdigest()
    assert icon["bytes"] == len(b"icon")


def test_run_deadline_margin_stops_resources_but_keeps_page_result(tmp_path, monkeypatch):
    import cvebeacon_extensions.web as web_module

    monkeypatch.setattr(web_module, "RUN_TIMEOUT", 30.0)
    clock = Clock()
    original_detect = webrules.detect

    def recorded_page(page, *, deadline, clock):
        result = original_detect(page)
        assert deadline - clock() == 25
        fake_clock.sleep(25)
        return result

    fake_clock = clock
    monkeypatch.setattr(webrules, "detect", recorded_page)
    html = '<script src="/slow.js"></script>'
    detail, transport, _, _ = run(tmp_path, [asset()], html, clock=clock)
    assert _paths(transport) == ["/app/index.html"]
    assert detail["run"]["fetched_count"] == 1
    assert detail["run"]["resources_skipped_by_reason"] == {"run-deadline": 1}


def test_resource_limits_and_run_deadline_are_named_constants():
    assert getattr(web_module, "RESOURCE_MAX_FILES", None) == 300
    assert getattr(web_module, "RESOURCE_FILE_LIMIT", None) == 10 * 1024 * 1024
    assert getattr(web_module, "RESOURCE_WIRE_LIMIT", None) == 20 * 1024 * 1024
    assert getattr(web_module, "RESOURCE_SITE_LIMIT", None) == 96 * 1024 * 1024
    assert getattr(web_module, "RESOURCE_SITE_TIMEOUT", None) == 180.0
    assert getattr(web_module, "RESOURCE_MIN_HOST_INTERVAL", None) == 0.1
    assert getattr(web_module, "RUN_TIMEOUT", None) == 60 * 60


def test_requests_to_one_host_do_not_overlap_across_site_workers(tmp_path):
    html = "<html></html>"
    clock = Clock()

    class OverlapTransport(Transport):
        def __init__(self, responses, clock):
            super().__init__(responses, clock)
            self.guard = threading.Lock()
            self.active = 0
            self.maximum_active = 0

        def fetch(self, endpoint, address, *, ca_bundle, deadline, user_agent, **kwargs):
            with self.guard:
                self.active += 1
                self.maximum_active = max(self.maximum_active, self.active)
            try:
                time.sleep(0.01)
                return super().fetch(endpoint, address, ca_bundle=ca_bundle, deadline=deadline,
                                     user_agent=user_agent, **kwargs)
            finally:
                with self.guard:
                    self.active -= 1

    transport = OverlapTransport([response(body=html.encode()), response(body=html.encode())], clock)
    run(tmp_path, [asset(path="/one"), asset(path="/two", port=444)], html, clock=clock,
        transport=transport, host_interval=0, max_workers=2)
    assert transport.maximum_active == 1
