"""Add by filters and confidence, and per-technology "Reported" marks on Web assets."""
import html
import json
import re

import pytest

from cvebeacon import web_assets, web_reported
from cvebeacon.managed_inventory import client_key, read_inventory
from cvebeacon.web_assets import paths

from test_dashboard_accounts import PASSWORD, csrf, login
from test_web_assets_inventory import (build, confirmation, page, preview, products_card, row, seed)


def wid(number):
    return "web-%016x" % number


def item(number, host, name, *, confidence="high", category="framework", versions=("1.0",), **extra):
    return dict(asset_id=wid(number), hostname=host, vendor=name.lower(), product=name.lower(), name=name,
                category=category, categories=[category], confidence=confidence, versions=list(versions),
                evidence_types=["header"], inventory=bool(versions), **extra)


PRODUCTS = [
    item(1, "a.example", "Alpha", confidence="high", category="framework"),
    item(2, "b.example", "Alpha", confidence="low", category="framework"),
    item(3, "a.example", "Beta", confidence="medium", category="cms", versions=("2.0",)),
    item(4, "b.example", "Gamma", confidence="low", category="js-library", versions=("3.0",)),
    item(5, "b.example", "Delta", confidence="high", category="js-library", versions=("4.0",)),
    item(6, "a.example", "Epsilon", confidence="high", category="cms", versions=()),
]


@pytest.fixture
def web(tmp_path):
    yield from build(tmp_path)


def reseed(env, products):
    """Replace the saved detection results, as a later scan would."""
    output = paths(env[0], "Acme")[1]
    detail = {"client": "Acme", "products": [dict(entry) for entry in products], "reviews": []}
    web_assets.replace_bytes(output.with_name(output.name + ".review.json"), json.dumps(detail).encode())


def inventory_names(config):
    path = config.inventory_directory / f"{client_key('Acme')}.json"
    return sorted(asset.product for asset in read_inventory(path.read_bytes()))


def add_filtered(client, **fields):
    data = {"csrf": csrf(client), "client": "Acme", "action": "filtered", **fields}
    return client.post("/web-assets/inventory/preview", data=data)


def previewed(response):
    return sorted(re.findall(r"<td>([A-Za-z]+)</td><td>[\d.]+</td>", response.text))


def mark(client, picks, action="mark", **extra):
    return client.post("/web-assets/reported", data={
        "csrf": csrf(client), "client": "Acme", "action": action, "pick": list(picks), **extra})


def marks_file(config):
    return web_reported.marks_path(paths(config, "Acme")[1])


def stored(config):
    return json.loads(marks_file(config).read_text(encoding="utf-8"))["marks"]


# R2 ---------------------------------------------------------------------------------


def test_add_all_shown_uses_the_filters(web):
    client = seed(web, PRODUCTS)
    assert previewed(add_filtered(client, conf="high")) == ["Alpha", "Delta"]
    assert previewed(add_filtered(client, conf=["high", "medium"])) == ["Alpha", "Beta", "Delta"]
    assert previewed(add_filtered(client, conf=["high", "medium"], category="cms")) == ["Beta"]
    assert previewed(add_filtered(client, site="b.example")) == ["Alpha", "Delta", "Gamma"]
    assert previewed(add_filtered(client, tech="gam")) == ["Gamma"]
    assert previewed(add_filtered(client)) == ["Alpha", "Alpha", "Beta", "Delta", "Gamma"]


def test_forged_filter_values_are_ignored_like_on_the_page(web):
    client = seed(web, PRODUCTS)
    everything = ["Alpha", "Alpha", "Beta", "Delta", "Gamma"]
    for fields in ({"category": "no-such"}, {"site": "nowhere.example"}, {"tech": "x" * 500},
                   {"conf": "bogus"}, {"version": "x", "inv": "y", "rep": "z"}):
        assert previewed(add_filtered(client, **fields)) == everything, fields
    for fields in ({"conf": "high"}, {"tech": "gam"}):
        # Epsilon has no version, so it is shown on the page but is not ready to add.
        on_page = set(re.findall(r"<strong>([A-Za-z]+)</strong>", products_card(page(client, **fields))))
        on_page.discard("Epsilon")
        assert on_page == set(previewed(add_filtered(client, **fields))), fields


def test_filtered_plan_never_trusts_posted_rows(web):
    client = seed(web, PRODUCTS)
    forged = add_filtered(client, conf="high", pick=[wid(4)], **{"v-" + wid(4): "9"})
    assert previewed(forged) == ["Alpha", "Delta"]
    empty = add_filtered(client, conf="high", tech="nothing-matches")
    assert empty.status_code == 400 and "No ready products match those filters" in empty.text


def test_confirmation_names_the_filter_and_saves_the_same_list(web):
    config = web[0]
    client = seed(web, PRODUCTS)
    response = add_filtered(client, conf=["high", "medium"])
    assert "Ready products with High or Medium confidence" in response.text
    assert "Ready products with High confidence" in add_filtered(client, conf="high").text
    text = add_filtered(client, conf="high", category="js-library", site="b.example").text
    assert "High confidence, category js-library, site b.example" in text
    data = confirmation(response)
    saved = client.post("/web-assets/inventory/save", data={"csrf": csrf(client), **data})
    assert saved.status_code == 303
    assert inventory_names(config) == ["alpha", "beta", "delta"]


def test_quick_actions_show_counts_and_hide_at_zero(web):
    client = seed(web, PRODUCTS)
    for view in ("site", "tech"):
        text = page(client, view=view)
        assert "Add all High confidence ready products (2)" in text
        assert "Add all except Low confidence (3)" in text
        assert "Add all 5 ready products" in text
        assert "ready products shown" not in text
    shown = page(client, conf="medium")
    assert "Add all 1 ready products shown" in shown
    assert "Add all 1 ready products shown" in page(client, conf="medium", view="tech")
    assert "ready products shown" not in page(client, conf="medium", inv="review")
    lows = [dict(product, confidence="low") for product in PRODUCTS]
    reseed(web, lows)
    text = page(client)
    assert "Add all High confidence" not in text and "Add all except Low" not in text
    assert "Add all 5 ready products" in text


def test_quick_action_adds_through_the_confirmation_page(web):
    config = web[0]
    client = seed(web, PRODUCTS)
    response = add_filtered(client, conf="high")
    assert previewed(response) == ["Alpha", "Delta"]
    client.post("/web-assets/inventory/save", data={"csrf": csrf(client), **confirmation(response)})
    assert inventory_names(config) == ["alpha", "delta"]
    text = page(client)
    assert "Add all High confidence" not in text and "Add all except Low confidence (1)" in text


def test_monitored_and_service_picks_are_skipped_not_errors(web):
    config = web[0]
    client = seed(web, PRODUCTS)
    done = add_filtered(client, conf="high")
    client.post("/web-assets/inventory/save", data={"csrf": csrf(client), **confirmation(done)})
    response = preview(client, [wid(1), wid(3)])
    assert response.status_code == 200 and "Already monitored" in response.text
    assert previewed(response) == ["Beta"]
    assert config


# R4 ---------------------------------------------------------------------------------


def test_mark_and_withdraw_round_trip(web):
    config, users, _, client = web
    seed(web, PRODUCTS)
    response = mark(client, [wid(1), wid(3)], note="Nov 2026 monthly report")
    assert response.status_code == 303 and "marked=2" in response.headers["Location"]
    notice = client.get(response.headers["Location"]).text
    assert "Marked 2 technologies as reported" in notice
    marks = stored(config)
    assert set(marks) == {wid(1), wid(3)}
    assert marks[wid(1)]["note"] == "Nov 2026 monthly report" and marks[wid(1)]["by"] == "admin"
    assert marks[wid(1)]["version"] == "1.0" and marks[wid(1)]["reported_at"].endswith("+00:00")
    text = page(client)
    assert "Nov 2026 monthly report" in row(products_card(text), "Beta") and "by admin" in text
    assert "Not reported" in row(products_card(text), "Gamma")
    response = mark(client, [wid(1), wid(4)], action="withdraw")
    assert response.status_code == 303 and "withdrawn=1" in response.headers["Location"]
    assert "Withdrew 1 report mark." in client.get(response.headers["Location"]).text
    assert set(stored(config)) == {wid(3)}
    assert not users.verify_audit()


def test_unknown_picks_are_ignored_and_too_many_are_refused(web):
    config = web[0]
    client = seed(web, PRODUCTS)
    assert mark(client, [wid(1), wid(99), "bogus", "web-" + "g" * 16]).status_code == 303
    assert set(stored(config)) == {wid(1)}
    nothing = mark(client, [wid(99)])
    assert nothing.status_code == 400 and "None of the selected products" in nothing.text
    assert mark(client, []).status_code == 400
    many = mark(client, [f"id-{index}" for index in range(2001)])
    assert many.status_code == 400 and "Select at most 2,000" in many.text
    assert set(stored(config)) == {wid(1)}
    assert mark(client, [wid(1)], note="x" * 201).status_code == 400


def test_reported_needs_the_report_permission_and_csrf(web):
    config, users, app, client = web
    seed(web, PRODUCTS)
    assert client.post("/web-assets/reported", data={
        "client": "Acme", "action": "mark", "pick": [wid(1)]}).status_code == 400
    assert client.post("/web-assets/reported", data={
        "csrf": "0" * 64, "client": "Acme", "action": "mark", "pick": [wid(1)]}).status_code == 400
    limited = app.test_client()
    login(limited, "webonly")
    text = limited.get("/web-assets?client=Acme").text
    assert "Reported</th>" in text and "Not reported" in text
    assert "Mark selected as reported" not in text and "Withdraw report mark" not in text
    assert limited.post("/web-assets/reported", data={
        "csrf": csrf(limited), "client": "Acme", "action": "mark", "pick": [wid(1)]}).status_code == 403
    assert not marks_file(config).exists()
    assert "Mark selected as reported" in page(client)


def test_monitored_products_can_be_marked(web):
    config = web[0]
    client = seed(web, PRODUCTS)
    done = add_filtered(client, conf="high")
    client.post("/web-assets/inventory/save", data={"csrf": csrf(client), **confirmation(done)})
    text = page(client)
    assert f'name="pick" value="{wid(1)}"' in text
    assert mark(client, [wid(1)]).status_code == 303 and set(stored(config)) == {wid(1)}


def test_invalid_or_oversized_marks_file_warns_and_never_crashes(web):
    config = web[0]
    client = seed(web, PRODUCTS)
    good = {"version": "1.0", "reported_at": "2026-11-01T00:00:00+00:00", "by": "admin", "note": ""}
    bad_files = [
        b"not json",
        json.dumps({"client": "Acme", "marks": {"w-nope": good}}).encode(),
        json.dumps({"client": "Other", "marks": {}}).encode(),
        json.dumps({"client": "Acme", "marks": {wid(1): dict(good, note="x" * 201)}}).encode(),
        json.dumps({"client": "Acme", "marks": {wid(1): dict(good, version="v" * 101)}}).encode(),
        json.dumps({"client": "Acme", "marks": {wid(1): dict(good, note="a\x01b")}}).encode(),
        json.dumps({"client": "Acme", "marks": {"web-%016x" % n: good for n in range(20_001)}}).encode(),
    ]
    for data in bad_files:
        web_assets.replace_bytes(marks_file(config), data)
        text = page(client)
        assert "Report marks unavailable" in text and "Not reported" in text, data[:40]
        assert "Alpha" in text
        assert mark(client, [wid(1)]).status_code == 400
        assert marks_file(config).read_bytes() == data


def test_changed_since_reported_appears_when_the_version_changes(web):
    config = web[0]
    client = seed(web, PRODUCTS)
    mark(client, [wid(1), wid(3)])
    assert "Changed since reported</span>" not in page(client)
    reseed(web, [dict(PRODUCTS[0], versions=["1.1"])] + PRODUCTS[1:])
    text = page(client)
    changed = row(products_card(text), "Alpha")
    assert "Changed since reported" in changed and "Reported with 1.0" in changed
    assert text.count("Changed since reported</span>") == 1
    assert "Changed since reported: 1" in text and "Reported: 1" in text
    assert "Changed since reported" in page(client, view="tech")
    assert config


def test_reported_filter_values_and_chips(web):
    client = seed(web, PRODUCTS)
    mark(client, [wid(1), wid(3), wid(4)])
    reseed(web, [dict(PRODUCTS[0], versions=["1.1"])] + PRODUCTS[1:])

    def names(**query):
        return sorted(re.findall(r"<strong>([A-Za-z]+)</strong>", products_card(page(client, **query))))
    assert names(rep="reported") == ["Beta", "Gamma"]
    assert names(rep="changed") == ["Alpha"]
    assert names(rep="not") == ["Alpha", "Delta", "Epsilon"]
    assert names(rep="any") == names(rep="bogus") == names()
    text = page(client)
    assert "Reported: 2" in text and "Not reported: 3" in text and "Changed since reported: 1" in text
    assert 'name="rep" value="changed"' not in text and 'id="f-rep"' in text
    assert re.search(r'<option value="changed" selected>', page(client, rep="changed"))
    assert 'rep=reported' in page(client, rep="reported") and 'rep=not' in page(client)
    switch = page(client, rep="not", conf="high")
    assert re.search(r'view=tech[^"]*rep=not', html.unescape(switch))
    clear = re.search(r'<a href="([^"]+)">Clear filters</a>', page(client, rep="not"))[1]
    assert "rep=" not in clear


def test_technology_view_shows_reported_sites(web):
    client = seed(web, PRODUCTS)
    mark(client, [wid(1)])
    text = page(client, view="tech")
    assert "1 of 2 sites" in row(text, "Alpha") and "Latest" in row(text, "Alpha")
    assert "0 of 1 site" in row(text, "Beta") and "Not reported" in row(text, "Beta")
    assert "Not reported: 5" in text


def test_audit_records_the_action_without_the_note(web):
    config, users, _, client = web
    seed(web, PRODUCTS)
    mark(client, [wid(1), wid(2)], note="private wording")
    mark(client, [wid(1)], action="withdraw")
    entries = [entry.action for entry in users.audit_entries() if entry.action.startswith("web_report_")]
    assert len(entries) == 2
    first = json.loads(entries[0].split(":", 1)[1])
    assert entries[0].startswith("web_report_mark:")
    assert first == {"client": "Acme", "action": "mark", "count": 2, "user": "admin"}
    assert entries[1].startswith("web_report_withdraw:") and json.loads(entries[1].split(":", 1)[1])["count"] == 1
    assert all("private wording" not in entry for entry in entries)
    assert not users.verify_audit()


def test_remove_all_assets_removes_the_marks_file(web):
    config = web[0]
    client = seed(web, PRODUCTS)
    mark(client, [wid(1)])
    assert marks_file(config).exists()
    version = re.search(r'name="version" value="([^"]+)"', client.get("/web-assets/sites?client=Acme").text)[1]
    response = client.post("/web-assets/save", data={
        "csrf": csrf(client), "client": "Acme", "action": "remove-all", "version": version,
        "confirm": "yes"})
    assert response.status_code == 303
    assert not marks_file(config).exists()


def test_marks_file_is_not_read_as_a_web_snapshot(web, caplog):
    from cvebeacon.web_inventory import append_snapshots
    config = web[0]
    client = seed(web, PRODUCTS)
    mark(client, [wid(1)])
    with caplog.at_level("WARNING", logger="cvebeacon"):
        append_snapshots([], marks_file(config).parent)
    assert "Skipping invalid web snapshot" not in caplog.text


def test_markup_has_no_inline_code_and_forms_are_not_nested(web):
    client = seed(web, PRODUCTS)
    mark(client, [wid(1)], note="n")
    for text in (page(client), page(client, view="tech"), page(client, conf="high"),
                 add_filtered(client, conf="high").text):
        assert not re.search(r"(?i)\sstyle\s*=", text)
        assert not re.search(r"(?is)<style\b", text)
        assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)[^>]*>", text)
        assert " title=" not in text.split("<main", 1)[1]
        depth = 0
        for tag in re.findall(r"(?i)</?form\b", text):
            depth += -1 if tag.startswith("</") else 1
            assert depth in (0, 1)


def test_new_column_widths_come_from_header_classes(web):
    from pathlib import Path
    from cvebeacon import dashboard_web
    client = seed(web, PRODUCTS)
    css = (Path(dashboard_web.__file__).parent / "static" / "dashboard.css").read_text(encoding="utf-8")
    for view, table in (("site", "web-products-table"), ("tech", "web-tech-table")):
        head = page(client, view=view).split(f'class="{table}"', 1)[1].split("</thead>", 1)[0]
        assert '<th class="web-reported-cell" scope="col">Reported</th>' in head
        assert f".{table} thead th.web-reported-cell {{ width:" in css
        widths = [int(w) for w in re.findall(rf"\.{table} thead th\.web-[a-z]+-cell \{{ width: (\d+)%", css)]
        assert sum(widths) == 100, (table, widths)
