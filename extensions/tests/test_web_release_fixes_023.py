"""Linear-time scans and private skip details for the web detector."""

import json
import time

from cvebeacon_extensions import webrules
from cvebeacon_extensions.webrules import MAX_ANALYSIS_TEXT, _inline_script_text

from test_web_resource_fetching import asset, response, run

BOUND = 4.0  # The quadratic forms take far longer; keep slow CI runners from flaking.


def _og_matches(text):
    for compiled in webrules._rule_index():
        if compiled.rule.key == "expanded-open-graph":
            return compiled.evidence.search(text)
    raise AssertionError("rule missing")


def test_open_graph_scan_is_linear():
    text = ("<meta " * (MAX_ANALYSIS_TEXT // 6))[:MAX_ANALYSIS_TEXT]
    started = time.perf_counter()
    assert _og_matches(text) is None
    assert time.perf_counter() - started < BOUND


def test_open_graph_still_detected():
    assert _og_matches('<meta property="og:title" content="x">')
    assert not _og_matches('<meta name="title" content="x">')


def test_inline_extraction_is_linear():
    for text in (("<script " * (MAX_ANALYSIS_TEXT // 8))[:MAX_ANALYSIS_TEXT],
                 "<script>" * 500000):
        started = time.perf_counter()
        assert _inline_script_text(text) == ""
        assert time.perf_counter() - started < BOUND


def test_inline_extraction_behaviour():
    html = ('<script>var a=1;</script><script src="/x.js">no()</script>'
            '<script type="application/ld+json">{"a":1}</script>'
            '<SCRIPT type="module">var b=2;</script >')
    assert _inline_script_text(html) == "var a=1;\nvar b=2;"


def test_inline_extraction_respects_deadline():
    html = "<script>var a=1;</script>" * 5
    assert _inline_script_text(html, deadline=0.0, clock=lambda: 1.0) == ""
    assert _inline_script_text(html, deadline=10.0, clock=lambda: 1.0).count("var a=1;") == 5


def _skips(tmp_path, count):
    html = '<meta name="generator" content="WordPress 6.4.2">' + "".join(f'<script src="/f{i}.js?q=secret#frag"></script>' for i in range(count))
    files = [response(content_type="application/json", body=b"{}") for _ in range(count)]
    detail, _, output, _ = run(tmp_path, [asset()], html, files)
    return detail, output


def test_skip_details_in_private_review_only(tmp_path):
    detail, output = _skips(tmp_path, 1)
    assert detail["resources_skipped_truncated"] == 0
    assert detail["resources_skipped"] == [dict(
        kind="script", reason="wrong-content-type", content_type="application/json",
        bytes=2, path="https://origin.invalid/f0.js")]
    assert detail["run"]["resources_skipped"] == 1
    assert "f0.js" not in json.dumps(detail["run"])
    assert "f0.js" not in output.read_text(encoding="utf-8")
    assert "secret" not in json.dumps(detail)


def test_skip_details_are_bounded(tmp_path):
    detail, output = _skips(tmp_path, 60)
    assert len(detail["resources_skipped"]) == 50
    assert detail["resources_skipped_truncated"] == 10
    assert detail["run"]["resources_skipped"] == 60
    assert "f0.js" not in output.read_text(encoding="utf-8")
