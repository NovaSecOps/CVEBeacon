"""Headless browser checks for the Products page's progressive enhancement.

The pages are rendered by the Flask test app, with the stylesheet and scripts
inlined the same way as the screenshot fixture, then loaded from a local file.
These tests skip when no Chromium-family browser is installed.
"""
import html
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from cvebeacon import dashboard_web, web_assets
from cvebeacon.web_assets import paths

from test_dashboard import setup  # noqa: F401
from test_dashboard_accounts import accounts, csrf  # noqa: F401
from test_dashboard_web import save, web  # noqa: F401

BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "msedge")


def browser_path():
    for name in BROWSERS:
        found = shutil.which(name)
        if found:
            return found
    pytest.skip("no Chromium-family browser is installed")


def seed(config, products):
    _, output = paths(config, "Acme")
    detail = {"client": "Acme", "products": products, "reviews": []}
    web_assets.replace_bytes(Path(str(output) + ".review.json"),
                             json.dumps(detail).encode("utf-8"))


def product(asset_id, hostname, name, category="framework", confidence="high", versions=("1.0",)):
    return {"asset_id": asset_id, "hostname": hostname, "vendor": name.casefold(),
            "product": name.casefold(), "name": name, "category": category,
            "categories": [category], "confidence": confidence, "versions": list(versions),
            "evidence_types": ["header"]}


def render_page(tmp_path, client, query, harness, fragment="", *, path="/web-assets/products",
                name="browser-page.html", harness_name="browser-harness.js", return_path=False):
    response = client.get(path, query_string={"client": "Acme", **query})
    assert response.status_code == 200, response.text
    static = Path(dashboard_web.__file__).parent / "static"
    text = response.text
    text = re.sub(r'<link rel="stylesheet" href="[^"]*dashboard\.css">',
                  lambda match: "<style>\n" + (static / "dashboard.css").read_text(encoding="utf-8")
                  + "\n</style>", text, count=1)
    text = re.sub(r'<script src="[^"]*ui\.js"></script>',
                  lambda match: "<script>\n" + (static / "ui.js").read_text(encoding="utf-8")
                  + "\n</script>", text, count=1)
    text = re.sub(r'<script src="[^"]*web-assets\.js" defer></script>',
                  lambda match: "<script defer>\n"
                  + (static / "web-assets.js").read_text(encoding="utf-8")
                  + "\n</script>", text, count=1)
    harness_path = tmp_path / harness_name
    harness_path.write_text(harness, encoding="utf-8", newline="\n")
    text = text.replace("</body>", '<script src="' + harness_name + '"></script></body>', 1)
    page_path = tmp_path / name
    page_path.write_text(text, encoding="utf-8", newline="\n")
    url = page_path.as_uri() + fragment
    return (page_path, url) if return_path else url


def dump_dom(url, *, width, height):
    result = subprocess.run(
        [browser_path(), "--headless=new", "--no-sandbox", "--disable-gpu",
         "--disable-dev-shm-usage", "--hide-scrollbars", "--force-device-scale-factor=1",
         f"--window-size={width},{height}", "--virtual-time-budget=5000", "--dump-dom", url],
        capture_output=True, text=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout


def report(dom):
    match = re.search(r'<pre id="browser-check">(.*?)</pre>', dom, re.S)
    assert match, dom[-2000:]
    return json.loads(html.unescape(match.group(1)))


def finish_script(body):
    return ("(function () {\n"
            "  function finish(value) {\n"
            "    var pre = document.createElement('pre');\n"
            "    pre.id = 'browser-check';\n"
            "    pre.textContent = JSON.stringify(value);\n"
            "    document.body.appendChild(pre);\n"
            "  }\n"
            + body + "\n})();\n")


BULK_HARNESS = finish_script("""
  function state() {
    var form = document.querySelector('form[data-bulk-form]');
    var picks = Array.prototype.slice.call(form.querySelectorAll('input[name="pick"]'));
    var submitted = new FormData(form).getAll('pick');
    var count = form.querySelector('[data-bulk-count]').textContent.trim();
    return {count: count, submitted: submitted.length,
      closedChecked: picks.filter(function (box) {
        var group = box.closest('details.product-group');
        return Boolean(group) && !group.open && box.checked;
      }).length};
  }
  document.addEventListener('DOMContentLoaded', function () {
    var form = document.querySelector('form[data-bulk-form]');
    var choose = form.querySelector('[data-bulk-select-all]');
    var clear = form.querySelector('[data-bulk-clear]');
    var groups = document.querySelectorAll('details.product-group');
    var out = {initial: state()};
    choose.click();
    out.closed = state();
    groups[0].open = true;
    choose.click();
    out.open = state();
    groups[0].open = false;
    clear.click();
    out.clearedClosed = state();
    groups[1].open = true;
    clear.click();
    out.clearedOpen = state();
    var disabled = document.createElement('input');
    disabled.type = 'checkbox';
    disabled.name = 'pick';
    disabled.value = 'disabled';
    disabled.disabled = true;
    disabled.checked = true;
    groups[1].querySelector('tbody').appendChild(disabled);
    var hidden = document.createElement('input');
    hidden.type = 'checkbox';
    hidden.name = 'pick';
    hidden.value = 'hidden';
    hidden.style.display = 'none';
    groups[1].querySelector('tbody').appendChild(hidden);
    choose.click();
    out.extra = state();
    out.disabledChecked = disabled.checked;
    out.hiddenChecked = hidden.checked;
    clear.click();
    out.extraClear = state();
    out.disabledAfterClear = disabled.checked;
    finish(out);
  });
""")


def test_select_all_and_clear_only_change_visible_enabled_picks(tmp_path, web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed(config, [
        product("web-a1", "a.example", "Alpha"),
        product("web-a2", "a.example", "Beta"),
        product("web-b1", "b.example", "Gamma"),
        product("web-b2", "b.example", "Delta"),
    ])
    dom = dump_dom(render_page(tmp_path, client, {}, BULK_HARNESS), width=1400, height=900)
    result = report(dom)
    assert 'data-bulk-ready="true"' in dom
    assert result["initial"] == {"count": "0 selected", "submitted": 0, "closedChecked": 0}
    # Two closed site groups: Select all must not pick rows the user cannot see
    # and the count must match the submitted picks (none).
    assert result["closed"] == {"count": "0 selected", "submitted": 0, "closedChecked": 0}
    # One group open: Select all picks its two rows, never the closed group.
    assert result["open"] == {"count": "2 selected", "submitted": 2, "closedChecked": 0}
    # Closing the group keeps its selections; Clear leaves them and the count
    # still matches what the form would submit.
    assert result["clearedClosed"] == {"count": "2 selected", "submitted": 2, "closedChecked": 2}
    assert result["clearedOpen"] == {"count": "2 selected", "submitted": 2, "closedChecked": 2}
    # A disabled checked pick is not submitted and not counted; a layout-hidden
    # pick is not selected by Select all.
    assert result["extra"] == {"count": "4 selected", "submitted": 4, "closedChecked": 2}
    assert result["disabledChecked"] is True
    assert result["hiddenChecked"] is False
    assert result["extraClear"] == {"count": "2 selected", "submitted": 2, "closedChecked": 2}
    assert result["disabledAfterClear"] is True


ANCHOR_HARNESS = finish_script("""
  function metrics() {
    var target = document.getElementById('product-w-target');
    var group = target.closest('details.product-group');
    var others = Array.prototype.filter.call(
      document.querySelectorAll('details.product-group'),
      function (item) { return item !== group; });
    var rect = target.getBoundingClientRect();
    return {open: group.open,
            otherOpen: others.filter(function (item) { return item.open; }).length,
            scrollY: window.scrollY,
            inView: rect.top >= 0 && rect.bottom <= window.innerHeight};
  }
  document.addEventListener('DOMContentLoaded', function () {
    window.addEventListener('hashchange', function () {
      setTimeout(function () { finish(metrics()); }, 50);
    });
    window.location.hash = '#product-w-target';
  });
""")


def anchor_products():
    products = [product(f"web-a{index:02d}", "a.example", f"A{index:02d}") for index in range(25)]
    products.extend(product(f"web-b{index:02d}", "b.example", f"B{index:02d}") for index in range(12))
    products.append(product("w-target", "b.example", "ZTarget"))
    return products


def test_a_product_link_opens_only_its_closed_group_on_load(tmp_path, web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed(config, anchor_products())
    load_harness = finish_script("""
      document.addEventListener('DOMContentLoaded', function () {
        var target = document.getElementById('product-w-target');
        var group = target.closest('details.product-group');
        var others = Array.prototype.filter.call(
          document.querySelectorAll('details.product-group'),
          function (item) { return item !== group; });
        var rect = target.getBoundingClientRect();
        finish({open: group.open,
                otherOpen: others.filter(function (item) { return item.open; }).length,
                scrollY: window.scrollY,
                inView: rect.top >= 0 && rect.bottom <= window.innerHeight});
      });
    """)
    url = render_page(tmp_path, client, {}, load_harness, fragment="#product-w-target")
    result = report(dump_dom(url, width=1400, height=900))
    assert result["open"] is True
    assert result["otherOpen"] == 0
    assert result["scrollY"] > 0
    assert result["inView"] is True


def test_a_product_link_opens_its_group_after_hashchange(tmp_path, web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed(config, anchor_products())
    url = render_page(tmp_path, client, {}, ANCHOR_HARNESS)
    result = report(dump_dom(url, width=1400, height=900))
    assert result["open"] is True
    assert result["otherOpen"] == 0
    assert result["scrollY"] > 0
    assert result["inView"] is True


STICKY_HARNESS = finish_script("""
  document.addEventListener('DOMContentLoaded', function () {
    var panel = document.querySelector('details[data-filter-panel]');
    Array.prototype.forEach.call(document.querySelectorAll('details.product-group'), function (group) {
      group.open = true;
    });
    var out = {open: panel.open,
               position: getComputedStyle(panel).position,
               cssTop: getComputedStyle(panel).top,
               zIndex: getComputedStyle(panel).zIndex,
               pageHeight: document.documentElement.scrollHeight};
    window.scrollTo(0, 700);
    out.scrollY = window.scrollY;
    out.stickyTop = panel.getBoundingClientRect().top;
    finish(out);
  });
""")


def sticky_products():
    products = []
    for site in ("a.example", "b.example"):
        for index in range(12):
            products.append(product(f"web-{site[0]}{index:02d}", site, f"{site[0].upper()}Tech{index:02d}"))
    return products


def test_filter_panel_is_sticky_on_desktop_and_static_on_mobile(tmp_path, web):
    config, _, _, client = web
    assert save(client).status_code == 303
    seed(config, sticky_products())
    desktop = report(dump_dom(render_page(tmp_path, client, {}, STICKY_HARNESS),
                              width=1400, height=900))
    assert desktop["open"] is True
    assert desktop["position"] == "sticky"
    assert desktop["zIndex"] == "20"
    assert desktop["scrollY"] > 0
    assert desktop["stickyTop"] == float(desktop["cssTop"].removesuffix("px"))
    assert desktop["stickyTop"] == 56
    mobile = report(dump_dom(render_page(tmp_path, client, {}, STICKY_HARNESS),
                             width=380, height=800))
    assert mobile["open"] is False
    assert mobile["position"] == "static"
    active = report(dump_dom(render_page(tmp_path, client, {"tech": "ATech00"}, STICKY_HARNESS),
                             width=380, height=800))
    assert active["open"] is True
    assert active["position"] == "static"


def test_legacy_inventory_sync_bookmark_opens_changes(tmp_path, web):
    _, _, _, client = web
    assert save(client).status_code == 303
    assert client.post("/web-assets/inventory/sync", data={
        "csrf": csrf(client), "client": "Acme", "action": "mode", "mode": "review",
        "auto_remove": "default",
    }).status_code == 303
    changes = client.get("/web-assets/changes", query_string={"client": "Acme"})
    assert changes.status_code == 200
    (tmp_path / "changes-target.html").write_text(changes.text, encoding="utf-8", newline="\n")

    page_path, url = render_page(
        tmp_path, client, {}, "", fragment="#inventory-sync", path="/web-assets",
        name="overview-page.html", harness_name="overview-harness.js", return_path=True)
    text = page_path.read_text(encoding="utf-8")
    assert 'href="/web-assets/changes?client=Acme" data-inventory-sync-link' in text
    text = re.sub(r'(<a[^>]*data-inventory-sync-link[^>]*>)',
                  lambda match: re.sub(r'href="[^"]*"', 'href="changes-target.html"', match.group(1)),
                  text, count=1)
    page_path.write_text(text, encoding="utf-8", newline="\n")
    dom = dump_dom(url, width=1400, height=900)
    assert "Changes since the last scan" in dom
    assert "Mode: Review (client override)" in dom

    other = render_page(
        tmp_path, client, {}, "", fragment="#inventory-sync-extra", path="/web-assets",
        name="overview-other.html", harness_name="overview-other-harness.js")
    dom = dump_dom(other, width=1400, height=900)
    assert "Next steps" in dom
    assert "Changes since the last scan" not in dom
