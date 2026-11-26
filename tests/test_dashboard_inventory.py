"""The account dashboard guides and protects client inventory management."""

import csv
import io
import json
import os
import re

from openpyxl import Workbook
import pytest

from cvebeacon import dashboard_inventory, inventory_journal, managed_inventory
from cvebeacon.dashboard import create_app
from cvebeacon.inventory import load_inventory
from cvebeacon.inventory_preview import FIELDS, preview_upload
from cvebeacon.private_storage import private_directory, private_file
from cvebeacon.web_assets import client_key
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from test_dashboard_watch import PASSWORD, csrf, login
from watch_support import write_config


@pytest.fixture
def deployment(tmp_path):
    config = write_config(tmp_path, inventory=False)
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("inventory", {"view", "manage_inventory"}, authorization=admin)
    users.add("manager", password=PASSWORD, role="inventory")
    users.add("reader", password=PASSWORD, role="viewer")
    app = create_app(config)
    browser = app.test_client()
    login(browser, "manager")
    return config, users, app, browser


ADD = "/watch/clients/add"
CSV = b"asset_id,vendor,wrong_title,version,client\nprivate-asset,Example,Widget,1,Untrusted client\n"
MAX_PASTE_BYTES = 100_000


def add(browser, name="Example client"):
    result = browser.post(ADD, data={
        "csrf": csrf(browser, ADD), "name": name,
        "contact": "private-contact@example.test", "notes": "private-notes-marker",
    })
    assert result.status_code == 303
    return result.location


def path_for(detail, action):
    path, marker, query = detail.partition("?")
    return f"{path}/{action}{marker}{query}"


def upload(browser, detail, data=CSV, filename="example.csv"):
    return browser.post(path_for(detail, "upload"), data={
        "csrf": csrf(browser, detail), "inventory": (io.BytesIO(data), filename),
        "pasted_rows": "", "paste_format": "csv",
    })


def paste_upload(browser, detail, text, format="csv", *, file=None):
    data = {
        "csrf": csrf(browser, detail), "pasted_rows": text, "paste_format": format,
        "inventory": (io.BytesIO(b""), ""),
    }
    if file is not None:
        data["inventory"] = (io.BytesIO(file), "example.csv")
    return browser.post(path_for(detail, "upload"), data=data, content_type="multipart/form-data")


def submit(browser, detail, preview, *, action="save", mode="replace", product="2", **options):
    fields = {
        "csrf": re.search(r'name="csrf" value="([^"]+)"', preview.text)[1],
        "token": re.search(r'name="token" value="([^"]+)"', preview.text)[1],
        "asset_id": "0", "vendor": "1", "product": product, "version": "3",
        "action": action, "mode": mode, "page": "1",
    }
    fields.update(options)
    return browser.post(path_for(detail, "review"), data=fields)


def current(browser, detail):
    response = browser.get(detail.split("?")[0] + "/download")
    assert response.status_code == 200
    assert response.headers["Content-Disposition"] == "attachment; filename=inventory.json"
    return json.loads(response.data)


def change(browser, detail, action, *, version=None, confirm=""):
    text = browser.get(detail).text
    revision = re.search(r'name="revision" value="([^"]+)"', text)[1]
    fields = {"csrf": csrf(browser, detail), "revision": revision, "action": action, "confirm": confirm}
    if version is not None:
        fields["version"] = version
    return browser.post(detail.split("?")[0] + "/inventory", data=fields)


def test_guided_upload_to_watch_only_with_permissions_and_audit(deployment):
    config, users, app, manager = deployment
    assert config.effective_inventory is None
    clients_page = manager.get("/watch/clients").text
    assert '<a class="btn" href="/watch/clients/add">Add client</a>' in clients_page
    assert clients_page.count("<h1>") == 1
    assert manager.post(ADD, data={"name": "Example client"}).status_code == 400
    invalid = manager.post(ADD, data={"name": "bad\u200fname", "csrf": csrf(manager, ADD)})
    assert invalid.status_code == 400
    assert "control or format characters" in invalid.text

    detail = add(manager)
    path = config.inventory_directory / f"{client_key('Example client')}.json"
    assert not path.exists()
    assert "Example client" in manager.get("/watch/clients").text
    client_page = manager.get(detail).text
    assert "private-notes-marker" in client_page
    assert 'href="/watch/clients" aria-current="page"' in client_page
    assert 'aria-current="step">Choose a file' in client_page
    assert client_page.count("<h1>") == 1
    preview = upload(manager, detail)
    assert preview.status_code == 200
    assert "wrong_title" in preview.text and "Product is missing" in preview.text
    assert 'aria-current="step">Review and save' in preview.text
    assert 'aria-label="Inventory row validation" tabindex="0"' in preview.text
    assert 'name="action" value="save" disabled' in preview.text
    assert not path.exists()
    mapping = submit(manager, detail, preview, action="preview")
    assert mapping.status_code == 200 and "Ready to import" in mapping.text
    assert '<option value="2" selected>wrong_title</option>' in mapping.text
    assert not path.exists()

    other_session = app.test_client()
    login(other_session, "manager")
    assert submit(other_session, detail, mapping, csrf=csrf(other_session, detail)).status_code == 409
    assert submit(manager, detail, mapping, csrf="a" * 64).status_code == 400
    saved = submit(manager, detail, mapping)
    assert saved.status_code == 303
    saved_page = manager.get(saved.location)
    assert "Inventory saved." in saved_page.text
    assert "Last inventory change" in saved_page.text and "by manager" in saved_page.text
    assert "Run a scan now" not in saved_page.text
    assert "Run a scan now" in _admin(app).get(detail).text
    row, = current(manager, detail)
    assert row["client"] == "Example client" and row["product"] == "Widget"
    assert load_inventory(config.effective_inventory)[0].asset_id == "private-asset"
    assert "private-asset" in manager.get("/assets").text
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700

    reader = app.test_client()
    login(reader, "reader")
    assert reader.get(ADD).status_code == 403
    assert "Upload inventory" not in reader.get(detail).text
    assert upload(reader, detail).status_code == 403
    assert reader.post(path_for(detail, "inventory"), data={
        "csrf": csrf(reader, detail), "action": "remove", "confirm": "remove",
    }).status_code == 403
    assert current(reader, detail)[0]["asset_id"] == "private-asset"
    audits = [entry for entry in users.audit_entries() if entry.action.startswith(("inventory_", "client_added:"))]
    assert len(audits) == 2 and all(entry.actor == "manager" for entry in audits)
    assert '"row_count":1,"mode":"replace"' in audits[1].action
    assert all(marker not in repr(audits) for marker in (
        "private-asset", "private-notes-marker", "private-contact", "wrong_title", "Untrusted client",
    ))


def test_preview_defaults_to_add_and_replace_explains_removed_assets(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    preview = upload(browser, detail)
    assert preview.status_code == 200
    assert re.search(r'name="mode" value="add" checked', preview.text)
    assert not re.search(r'name="mode" value="replace" checked', preview.text)
    assert "Replace this client's inventory. Assets not in this file are removed." in preview.text


def test_inventory_template_download_has_canonical_fields_and_requires_view(deployment):
    _, users, app, browser = deployment
    response = browser.get("/watch/clients/inventory-template")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/csv; charset=utf-8"
    assert response.headers["Content-Disposition"] == "attachment; filename=inventory-template.csv"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert rows[0] == list(FIELDS)
    preview = preview_upload(response.data, ".csv", "Example client")
    asset, = preview.assets
    assert preview.errors == preview.warnings == 0
    assert asset.asset_id == "example-asset-001"
    assert asset.vendor == "Example Vendor" and asset.product == "Example Product"

    viewer = app.test_client()
    login(viewer, "reader")
    assert viewer.get("/watch/clients/inventory-template").status_code == 200

    admin = users.authenticate("admin", PASSWORD)
    users.save_role("inventory-no-view", {"manage_inventory"}, authorization=admin)
    users.add("inventory-no-view", password=PASSWORD, role="inventory-no-view")
    limited = app.test_client()
    login(limited, "inventory-no-view")
    assert limited.get("/watch/clients/inventory-template").status_code == 403


def test_upload_form_offers_paste_and_a_csv_template(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    page = browser.get(detail).text
    assert "Download a CSV template" in page
    assert 'label for="pasted-rows">Or paste rows</label>' in page
    assert 'name="paste_format"' in page
    assert 'option value="csv"' in page and 'option value="json"' in page and 'option value="yaml"' in page
    assert "Paste up to 100 KB, or upload a file for larger inventories." in page


def test_pasted_csv_uses_the_preview_and_save_flow(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    preview = paste_upload(
        browser, detail,
        "asset_id,vendor,product,version\npasted-asset,Example Vendor,Example Product,1.0.0\n",
    )
    assert preview.status_code == 200
    assert "Example Product" in preview.text and "Ready to import." in preview.text
    assert re.search(r'name="mode" value="add" checked', preview.text)
    saved = submit(browser, detail, preview, mode="add")
    assert saved.status_code == 303
    row, = current(browser, detail)
    assert row["asset_id"] == "pasted-asset" and row["product"] == "Example Product"


@pytest.mark.parametrize(("format", "text"), (
    ("json", '[{"asset_id":"pasted-json","vendor":"Example","product":"Widget","version":"1.0"}]'),
    ("yaml", "- asset_id: pasted-yaml\n  vendor: Example\n  product: Widget\n  version: '1.0'\n"),
))
def test_pasted_json_and_yaml_use_the_inventory_preview(deployment, format, text):
    _, _, _, browser = deployment
    detail = add(browser)
    response = paste_upload(browser, detail, text, format)
    assert response.status_code == 200
    assert "Ready to import." in response.text
    assert f"pasted-{format}" in response.text


@pytest.mark.parametrize("format", ["xml", "", "csv,json"])
def test_paste_with_an_unknown_format_is_refused_not_parsed_as_csv(deployment, format):
    _, _, _, browser = deployment
    detail = add(browser)
    response = paste_upload(
        browser, detail,
        "asset_id,vendor,product,version\npasted-asset,Example Vendor,Example Product,1.0.0\n",
        format,
    )
    assert response.status_code == 400
    assert "Choose CSV, JSON or YAML for pasted rows." in response.text
    assert "Ready to import." not in response.text


def test_paste_requires_exactly_one_source(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    neither = paste_upload(browser, detail, "")
    assert neither.status_code == 400 and "Choose a file or paste rows." in neither.text
    marker = "BOTH-SOURCES-MARKER <keep>&"
    both = paste_upload(
        browser, detail,
        f"asset_id,vendor,product,version\npasted-asset,Example,Widget,1.0\n{marker}",
        "json", file=CSV,
    )
    assert both.status_code == 400 and "Choose a file or paste rows, not both." in both.text
    assert "BOTH-SOURCES-MARKER &lt;keep&gt;&amp;" in both.text
    assert 'option value="json" selected' in both.text


def test_safe_parse_error_keeps_paste_and_format_escaped(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    marker = "SAFE-PASTE-MARKER <tag>&"
    text = f'["{marker}",]'
    response = paste_upload(browser, detail, text, "json")
    assert response.status_code == 400
    assert "SAFE-PASTE-MARKER &lt;tag&gt;&amp;" in response.text
    assert "<tag>" not in response.text
    assert 'option value="json" selected' in response.text


def test_paste_over_100_kb_is_rejected_with_guidance(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    marker = "OVER-LIMIT-PASTE-MARKER"
    text = "é" * (MAX_PASTE_BYTES // 2) + marker
    assert len(text.encode("utf-8")) > MAX_PASTE_BYTES
    oversized = paste_upload(browser, detail, text)
    assert oversized.status_code == 400
    assert "Your pasted text was not kept because it is over 100 KB. Paste less, or upload a file." in oversized.text
    assert marker not in oversized.text


def test_largest_allowed_paste_fits_multipart_limits_and_previews(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    rows = io.StringIO()
    writer = csv.writer(rows, lineterminator="\n")
    writer.writerow(FIELDS)
    writer.writerow(["example-asset-001", "Example Vendor", "Example Product", "1.0.0", *([""] * (len(FIELDS) - 4))])
    payload = rows.getvalue() + "\n" * (MAX_PASTE_BYTES - len(rows.getvalue().encode("utf-8")))
    assert len(payload.encode("utf-8")) == MAX_PASTE_BYTES

    response = paste_upload(browser, detail, payload)
    multipart_size = response.request.content_length
    assert multipart_size > MAX_PASTE_BYTES
    assert multipart_size <= 128 * 1024
    assert multipart_size <= dashboard_inventory.UPLOAD_REQUEST_BYTES
    assert response.status_code == 200 and "Example Product" in response.text


def test_upload_accepts_eight_parts_and_rejects_nine(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    path = path_for(detail, "upload")
    token = csrf(browser, detail)

    def fields():
        # A fresh file object per request: the test client closes it after sending.
        return {
            "csrf": token, "inventory": (io.BytesIO(CSV), "example.csv"),
            "pasted_rows": "", "paste_format": "csv",
        }

    six_parts = browser.post(path, data={**fields(), "harmless_a": "one", "harmless_b": "two"},
                             content_type="multipart/form-data")
    assert six_parts.status_code == 200 and "private-asset" in six_parts.text

    nine_parts = browser.post(path, data={
        **fields(), "harmless_a": "one", "harmless_b": "two", "harmless_c": "three",
        "harmless_d": "four", "harmless_e": "five",
    }, content_type="multipart/form-data")
    assert nine_parts.status_code == 413


def test_file_upload_still_previews_after_paste_support(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    response = upload(browser, detail)
    assert response.status_code == 200
    assert "private-asset" in response.text and "Widget" in response.text


def _admin(app):
    browser = app.test_client()
    login(browser)
    return browser


def test_add_replace_version_retention_restore_and_remove(deployment):
    config, users, _, browser = deployment
    detail = add(browser)
    assert submit(browser, detail, upload(browser, detail)).status_code == 303
    same_id = submit(browser, detail, upload(browser, detail), mode="add")
    assert same_id.status_code == 400 and "already in this client" in same_id.text
    extra = CSV.replace(b"private-asset", b"extra")
    assert submit(browser, detail, upload(browser, detail, extra), mode="add").status_code == 303
    assert [row["asset_id"] for row in current(browser, detail)] == ["private-asset", "extra"]
    for index in range(6):
        data = CSV.replace(b"private-asset", f"asset-{index}".encode())
        assert submit(browser, detail, upload(browser, detail, data)).status_code == 303
    history = re.findall(r'name="version" value="([0-9TZ]+)"', browser.get(detail).text)
    assert len(history) == 5
    assert len(list(config.inventory_directory.glob("*.*.json"))) == 5
    assert [row["asset_id"] for row in current(browser, detail)] == ["asset-5"]
    assert change(browser, detail, "restore", version=history[0]).status_code == 303
    assert [row["asset_id"] for row in current(browser, detail)] == ["asset-4"]
    assert change(browser, detail, "remove").status_code == 409
    assert change(browser, detail, "remove", confirm="remove").status_code == 303
    assert config.effective_inventory is None
    assert "No inventory has been uploaded" in browser.get(detail).text
    assert any('"mode":"add"' in row.action for row in users.audit_entries())
    assert any('"mode":"restore"' in row.action for row in users.audit_entries())
    assert any(row.action.startswith("inventory_removed:") for row in users.audit_entries())


def test_bad_files_sizes_collisions_and_paths_are_safe(deployment, tmp_path, monkeypatch):
    config, users, _, browser = deployment
    first = add(browser, "Client A")
    second = add(browser, "../Client B")
    assert submit(browser, first, upload(browser, first)).status_code == 303
    collision = submit(browser, second, upload(browser, second))
    assert collision.status_code == 400
    assert "Client A" in collision.text and "../Client B" in collision.text
    assert "An asset ID is shared" in collision.text
    assert not (config.inventory_directory / f"{client_key('../Client B')}.json").exists()
    malformed = upload(browser, second, b"SENSITIVE-MARKER: [", "sensitive-malformed.yaml")
    assert malformed.status_code == 400
    assert "The file could not be read" in malformed.text
    assert "SENSITIVE-MARKER" not in malformed.text and "sensitive-malformed" not in malformed.text
    assert "Choose a CSV" in upload(browser, second, filename="inventory.exe").text

    monkeypatch.setattr(dashboard_inventory, "MAX_BYTES", len(CSV) - 1)
    assert "too large" in upload(browser, second).text
    monkeypatch.setattr(dashboard_inventory, "MAX_BYTES", 32 * 1024 * 1024)
    oversized = b"x" * dashboard_inventory.UPLOAD_REQUEST_BYTES
    rejected = upload(browser, second, oversized)
    assert rejected.status_code == 413
    assert "This request could not be completed" in rejected.text
    assert "choose an inventory file up to 32 MiB" in rejected.text
    if os.name == "posix":
        target = tmp_path / "untouched.json"
        target.write_text("untouched", encoding="utf-8")
        path = config.inventory_directory / f"{client_key('../Client B')}.json"
        path.symlink_to(target)
        assert upload(browser, second).status_code == 503
        assert target.read_text(encoding="utf-8") == "untouched"
    assert browser.get("/watch/clients/%2e%2e/download").status_code == 404
    assert all("SENSITIVE-MARKER" not in row.action for row in users.audit_entries())


@pytest.mark.parametrize("suffix", (".csv", ".json", ".yaml", ".yml", ".xlsx"))
def test_dashboard_preview_formats(suffix):
    row = {"asset_id": "a1", "vendor": "example", "product": "widget", "version": "1.0"}
    if suffix == ".csv":
        data = b"asset_id,vendor,product,version\na1,example,widget,1.0\n"
    elif suffix == ".json":
        data = json.dumps({"assets": [row]}).encode()
    elif suffix == ".xlsx":
        workbook = Workbook()
        workbook.active.append(list(row))
        workbook.active.append(list(row.values()))
        stream = io.BytesIO()
        workbook.save(stream)
        data = stream.getvalue()
    else:
        data = b"- asset_id: a1\n  vendor: example\n  product: widget\n  version: '1.0'\n"
    preview = preview_upload(data, suffix, "Example client")
    assert preview.errors == preview.warnings == 0
    asset, = preview.assets
    assert asset.asset_id == "a1" and asset.version == "1.0" and asset.client == "Example client"


def test_mapped_xlsx_formulas_and_numeric_versions_are_blocked():
    workbook = Workbook()
    workbook.active.append(["asset_id", "vendor", "product", "release"])
    workbook.active.append(["a1", "example", "widget", "=PRIVATE_FORMULA()"])
    workbook.active.append(["a2", "example", "widget", 3.0])
    stream = io.BytesIO()
    workbook.save(stream)
    preview = preview_upload(stream.getvalue(), ".xlsx", "Example", {"version": "3"})
    assert preview.errors == 2
    assert "formula" in preview.validation[0][2]
    assert "stored as text" in preview.validation[1][2]
    assert "PRIVATE_FORMULA" not in repr(preview)


def test_stale_preview_cannot_replace_a_newer_save(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    stale = upload(browser, detail)
    newest = upload(browser, detail, CSV.replace(b"private-asset", b"newer-asset"))
    assert submit(browser, detail, newest).status_code == 303
    assert submit(browser, detail, stale).status_code == 409
    assert current(browser, detail)[0]["asset_id"] == "newer-asset"


def test_multiline_notes_and_safe_field_error(deployment):
    _, _, _, browser = deployment
    fields = {"csrf": csrf(browser, ADD), "name": "Example", "notes": "First\r\nSecond\rThird"}
    response = browser.post(ADD, data=fields)
    assert response.status_code == 303
    assert "First\nSecond\nThird" in browser.get(response.location).text
    response = browser.post(ADD, data={**fields, "name": "Another", "notes": "bad\x07"})
    assert response.status_code == 400 and "Notes contain an unsupported character" in response.text


def test_restore_after_removing_the_only_inventory_and_restarting(tmp_path):
    config = write_config(tmp_path, inventory=False, enabled=False, extra="[inventory]\nmanaged=true\n")
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    browser = _admin(create_app(config))
    detail = add(browser)
    assert submit(browser, detail, upload(browser, detail)).status_code == 303
    assert change(browser, detail, "remove", confirm="remove").status_code == 303
    from cvebeacon.config import load_config
    restarted = _admin(create_app(load_config(config.config_path)))
    selected = re.search(r'name="version" value="([0-9TZ]+)"', restarted.get(detail).text)[1]
    assert change(restarted, detail, "restore", version=selected).status_code == 303
    assert current(restarted, detail)[0]["asset_id"] == "private-asset"


def test_corrupt_version_gives_recovery_guidance(deployment):
    config, _, _, browser = deployment
    detail = add(browser)
    assert submit(browser, detail, upload(browser, detail)).status_code == 303
    assert submit(browser, detail, upload(browser, detail)).status_code == 303
    archived, = config.inventory_directory.glob("*.*.json")
    archived.write_text("private-corrupt-version", encoding="utf-8")
    response = change(browser, detail, "restore", version=archived.name.split(".")[1])
    assert response.status_code == 409
    assert "Choose another version" in response.text
    assert "private-corrupt-version" not in response.text


@pytest.mark.parametrize("installed", ("watch", "none", "both"))
def test_client_page_explains_the_installed_schedule(deployment, monkeypatch, installed):
    from types import SimpleNamespace
    from cvebeacon import scheduling

    config, _, app, browser = deployment
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")
    if installed == "none":
        output = b""
    else:
        plan = scheduling.make_plan(config.config_path, 4, system="linux", command=installed)
        expected = ["watch", "run"] if installed == "watch" else ["run"]
        assert plan.command[-len(expected):] == expected
        lines = [scheduling.CRON_BEGIN, *scheduling._cron_lines(plan), scheduling.CRON_END]
        output = "\n".join(lines).encode()

    def fake_scheduler(argv, **kwargs):
        assert argv == ["crontab", "-l"]
        return SimpleNamespace(returncode=0, stdout=output, stderr=b"")

    app.extensions["dashboard_schedule_runner"] = fake_scheduler
    detail = add(browser)
    page = browser.get(submit(browser, detail, upload(browser, detail)).location)
    if installed == "both":
        assert "Your next scheduled scan will include this inventory." in page.text
    else:
        assert "runs watch jobs only" in page.text if installed == "watch" else "no installed native schedule" in page.text
        assert 'href="/operations/schedule">Schedule</a>' in page.text
        assert "Your next scheduled scan" not in page.text


def test_scan_submission_respects_run_permission(deployment, monkeypatch):
    from types import SimpleNamespace

    _, _, app, manager = deployment
    detail = add(manager)
    assert submit(manager, detail, upload(manager, detail)).status_code == 303
    submitted = []

    def fake_submit(operation, **kwargs):
        submitted.append((operation, kwargs["started_by"]))
        return SimpleNamespace(id=42)

    monkeypatch.setattr(app.extensions["dashboard_jobs"], "submit", fake_submit)
    path = "/operations/run"
    assert manager.post(path, data={"csrf": csrf(manager, detail), "operation": "scan"}).status_code == 403
    admin = _admin(app)
    result = admin.post(path, data={"csrf": csrf(admin, detail), "operation": "scan"})
    assert result.status_code == 303 and result.location == "/operations/jobs/42"
    assert submitted == [("scan", "admin")]


def test_corrupt_inventory_blocks_cli_export_and_dashboard_download(deployment, tmp_path, monkeypatch, capsys):
    from cvebeacon import cli

    config, _, app, browser = deployment
    corrupted = add(browser, "Unreadable client")
    healthy = add(browser, "Healthy client")
    assert submit(browser, corrupted, upload(browser, corrupted)).status_code == 303
    contents = CSV.replace(b"private-asset", b"healthy")
    assert submit(browser, healthy, upload(browser, healthy, contents)).status_code == 303
    path = config.inventory_directory / f"{client_key('Unreadable client')}.json"
    path.write_text("PRIVATE-INVENTORY-CONTENTS", encoding="utf-8")
    monkeypatch.setattr(cli, "_run_query", lambda *a, **kw: pytest.fail("queried with incomplete inventory"))

    admin = _admin(app)
    findings = admin.get("/findings")
    assert findings.status_code == 200
    assert "Unreadable client" in findings.text
    assert "No scan results recorded" in findings.text
    reports = admin.get("/reports")
    assert "Unreadable client" in reports.text and "Generate and download" not in reports.text
    assert "Missing results do not establish a clean inventory." in reports.text
    assert 'name="format"' not in reports.text
    result = admin.post("/reports", data={"csrf": csrf(admin, healthy), "format": "json"})
    assert result.status_code == 409 and "Content-Disposition" not in result.headers
    assert "Unreadable client" in result.text
    assert path.stem not in result.text and "PRIVATE-INVENTORY-CONTENTS" not in result.text
    command = ["--config", str(config.config_path)]
    output = tmp_path / "report.json"
    assert cli.main([*command, "export", "--format", "json", "--output", str(output)]) == 4
    assert not output.exists()
    assert cli.main([*command, "asset", "healthy"]) == 4
    error = capsys.readouterr().err
    assert "an inventory is unreadable" in error
    assert "Review or restore it from the Inventory page" in error


def test_combined_schedule_can_be_installed_before_the_first_upload(deployment, monkeypatch):
    from types import SimpleNamespace
    from cvebeacon import dashboard_ops, scheduling

    config, _, app, _ = deployment
    installed = []
    monkeypatch.setattr(dashboard_ops, "_running_as_root", lambda: False)
    monkeypatch.setattr(scheduling.platform, "system", lambda: "Linux")

    def fake_scheduler(argv, **kwargs):
        if argv == ["crontab", "-"]:
            installed.append(kwargs["input"].decode())
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    app.extensions["dashboard_schedule_runner"] = fake_scheduler
    admin = _admin(app)
    path = "/operations/schedule"
    assert config.effective_inventory is None
    assert '<option value="both"' in admin.get(path).text
    response = admin.post(path + "/install", data={
        "csrf": csrf(admin, path), "mode": "interval", "every": "4", "command": "both",
    })
    assert response.status_code == 303
    block, = installed
    rendered = scheduling._describe_cron_block(block)
    assert scheduling.installed_scan_state(rendered, config.config_path) == "scan"
    assert "watch run" not in block


def test_reports_explain_collisions_and_cache_unchanged_inventory_checks(deployment, monkeypatch):
    from cvebeacon import dashboard
    from cvebeacon.managed_inventory import encode_records
    from cvebeacon.models import Asset
    from cvebeacon.web_assets import replace_bytes

    config, _, app, browser = deployment
    detail = add(browser, "First client")
    assert submit(browser, detail, upload(browser, detail)).status_code == 303
    add(browser, "Second client")
    other = config.inventory_directory / f"{client_key('Second client')}.json"
    admin = _admin(app)
    load = dashboard.load_inventory
    checks = []

    def count(*args, **kwargs):
        checks.append(True)
        return load(*args, **kwargs)

    monkeypatch.setattr(dashboard, "load_inventory", count)
    path = "/reports"
    assert "Generate and download" in admin.get(path).text
    assert "Generate and download" in admin.get(path).text
    assert len(checks) == 1
    replace_bytes(other, encode_records([Asset("private-asset", "Example", "Widget", "1", client="Second client")]))
    page = admin.get(path)
    assert len(checks) == 2
    assert "First client" in page.text and "Second client" in page.text
    assert "Generate and download" not in page.text and "private-asset" not in page.text
    assert admin.post(path, data={"csrf": csrf(admin, detail), "format": "json"}).status_code == 409
    assert len(checks) == 3


def test_removing_final_inventory_explains_why_scans_are_unavailable(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    assert submit(browser, detail, upload(browser, detail)).status_code == 303
    removed = change(browser, detail, "remove", confirm="remove")
    page = browser.get(removed.location)
    assert "upload or restore an inventory to run scans" in page.text


def test_dashboard_creates_private_inventory_directory_and_journal(deployment, monkeypatch):
    config, _, _, manager = deployment
    directory = config.inventory_directory
    assert not directory.exists()
    staged = []
    stage_change = dashboard_inventory.stage_change

    def check_staged(directory, db, users, actor, event, key, detail, changes):
        stage_change(directory, db, users, actor, event, key, detail, changes)
        assert directory.is_dir()
        private_directory(directory, owner_only=True)
        names = [inventory_journal.PARTS[kind] for kind in changes]
        for name in [inventory_journal.MARKER, *names]:
            os.close(private_file(directory / name, readonly=True))
        staged.append(set(changes))

    monkeypatch.setattr(dashboard_inventory, "stage_change", check_staged)
    # Uploads publish through the shared managed inventory transaction.
    monkeypatch.setattr(managed_inventory, "stage_change", check_staged)
    detail = add(manager)
    assert submit(manager, detail, upload(manager, detail)).status_code == 303
    newer = CSV.replace(b"private-asset", b"newer-asset")
    assert submit(manager, detail, upload(manager, detail, newer)).status_code == 303
    assert staged == [{"profile"}, {"current"}, {"archive", "current"}]
    assert not list(directory.glob(".inventory-pending*"))
    assert current(manager, detail)[0]["asset_id"] == "newer-asset"


def test_restore_with_stale_revision_reports_the_change_before_checking_the_version(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    assert submit(browser, detail, upload(browser, detail)).status_code == 303
    response = browser.post(detail.split("?")[0] + "/inventory", data={
        "csrf": csrf(browser, detail), "revision": "0" * 64, "action": "restore",
        "confirm": "", "version": "not-a-version",
    })
    assert response.status_code == 409
    assert "This inventory changed." in response.text


def general_upload(browser, data=CSV, filename="example.csv", *, client="", new_client="", pasted=""):
    return browser.post("/inventory/upload", data={
        "csrf": csrf(browser, "/inventory/add"), "client": client, "new_client": new_client,
        "inventory": (io.BytesIO(data), filename), "pasted_rows": pasted, "paste_format": "csv",
    })


def general_paste(browser, text, format="csv", *, client="", new_client=""):
    return browser.post("/inventory/upload", data={
        "csrf": csrf(browser, "/inventory/add"), "client": client, "new_client": new_client,
        "inventory": (io.BytesIO(b""), ""), "pasted_rows": text, "paste_format": format,
    }, content_type="multipart/form-data")


def general_submit(browser, preview, *, action="save", mode="add", product="2", **options):
    fields = {
        "csrf": re.search(r'name="csrf" value="([^"]+)"', preview.text)[1],
        "token": re.search(r'name="token" value="([^"]+)"', preview.text)[1],
        "asset_id": "0", "vendor": "1", "product": product, "version": "3",
        "action": action, "mode": mode, "page": "1",
    }
    fields.update(options)
    return browser.post("/inventory/review", data=fields)


def test_inventory_navigation_empty_state_and_no_client_upload(deployment):
    config, _, _, browser = deployment
    sidebar = browser.get("/watch").text.split('id="sidebar"', 1)[1].split("</nav>", 1)[0]
    assert '<a href="/inventory"' in sidebar and "Inventory" in sidebar

    page = browser.get("/inventory")
    assert page.status_code == 200
    assert "No inventory yet." in page.text
    assert "Add a list of the assets you want CVEBeacon to check." in page.text
    assert 'href="/inventory/add"' in page.text

    form = browser.get("/inventory/add")
    assert form.status_code == 200
    assert '<option value="" selected>No client</option>' in form.text
    assert 'label for="f-new_client">Or a new client name' in form.text
    assert "Download a CSV template" in form.text
    assert "Choose a file or paste rows" in form.text

    preview = general_upload(browser)
    assert preview.status_code == 200
    assert "Preview inventory for No client" in preview.text
    assert re.search(r'name="mode" value="add" checked', preview.text)
    assert "Replace this inventory. Assets not in this file are removed." in preview.text
    saved = general_submit(browser, preview)
    assert saved.status_code == 303
    detail = browser.get(saved.location)
    assert detail.status_code == 200 and "No client" in detail.text
    row, = current(browser, "/inventory/unassigned")
    assert row["client"] == ""
    page = browser.get("/inventory").text
    assert "/inventory/unassigned" in page and ">1</td>" in page and "Last saved" in page


def test_inventory_lists_client_only_and_mixed_sources(deployment):
    _, _, _, browser = deployment
    client_detail = add(browser, "Example client")
    assert submit(browser, client_detail, upload(browser, client_detail)).status_code == 303
    page = browser.get("/inventory").text
    assert "Example client" in page and "/watch/clients/" in page
    assert "No client" not in page

    assert general_submit(browser, general_upload(
        browser, CSV.replace(b"private-asset", b"unassigned-asset"),
    )).status_code == 303
    page = browser.get("/inventory").text
    assert "No client" in page and "Example client" in page
    assert "/inventory/unassigned" in page
    assert browser.get(client_detail).status_code == 200
    assert 'href="/inventory"' in browser.get(client_detail).text


def test_inventory_add_selects_clients_and_resolves_case_variants_atomically(deployment):
    config, users, _, browser = deployment
    add(browser, "Example client")
    form = browser.get("/inventory/add").text
    assert '<option value="Example client">Example client</option>' in form

    preview = general_upload(browser, CSV.replace(b"private-asset", b"managed-asset"), client="Example client")
    assert preview.status_code == 200 and "Preview inventory for Example client" in preview.text
    assert general_submit(browser, preview).status_code == 303
    path = config.inventory_directory / f"{client_key('Example client')}.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    assert rows[0]["client"] == "Example client" and rows[0]["asset_id"] == "managed-asset"

    variant = general_paste(
        browser,
        "asset_id,vendor,product,version\ncase-variant,Example,Widget,1.0\n",
        new_client="eXAMPLE CLIENT",
    )
    assert variant.status_code == 200 and "Preview inventory for Example client" in variant.text
    assert general_submit(browser, variant).status_code == 303
    rows = json.loads(path.read_text(encoding="utf-8"))
    assert [row["asset_id"] for row in rows] == ["managed-asset", "case-variant"]
    assert all(row["client"] == "Example client" for row in rows)

    new_preview = general_upload(browser, new_client="Brand new client")
    assert new_preview.status_code == 200 and "Preview inventory for Brand new client" in new_preview.text
    assert general_submit(browser, new_preview).status_code == 303
    key = client_key("Brand new client")
    profile_path = config.inventory_directory / f"{key}.client"
    inventory_path = config.inventory_directory / f"{key}.json"
    assert json.loads(profile_path.read_text(encoding="utf-8"))["name"] == "Brand new client"
    assert json.loads(inventory_path.read_text(encoding="utf-8"))[0]["client"] == "Brand new client"
    audits = [entry.action for entry in users.audit_entries() if entry.action.startswith("inventory_saved:")]
    assert all("private-asset" not in action and "case-variant" not in action for action in audits)


def test_inventory_add_uses_the_same_client_options_as_web_assets(deployment, monkeypatch):
    from cvebeacon import dashboard_web

    _, _, _, browser = deployment
    names = ("Managed client", "Client from a scan")
    monkeypatch.setattr(dashboard_web, "_inventory_clients", lambda config: list(names))
    add_page = browser.get("/inventory/add").text
    web_page = browser.get("/web-assets").text
    for name in names:
        assert f'<option value="{name}">{name}</option>' in add_page
        assert f'<option value="{name}">' in web_page


def test_inventory_new_client_publish_failure_leaves_no_half_created_profile(deployment, monkeypatch):
    config, _, _, browser = deployment
    preview = general_upload(browser, new_client="Atomic client")
    assert preview.status_code == 200
    original = managed_inventory.stage_change

    def fail_after_staging(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("injected transaction failure")

    monkeypatch.setattr(managed_inventory, "stage_change", fail_after_staging)
    result = general_submit(browser, preview)
    assert result.status_code == 503
    key = client_key("Atomic client")
    assert not (config.inventory_directory / f"{key}.client").exists()
    assert not (config.inventory_directory / f"{key}.json").exists()
    assert not list(config.inventory_directory.glob(".inventory-pending*"))


def test_inventory_replace_confirmation_and_paste_path(deployment):
    _, _, _, browser = deployment
    first = general_paste(
        browser, "asset_id,vendor,product,version\npasted-one,Example,Widget,1.0\n",
    )
    assert first.status_code == 200 and general_submit(browser, first).status_code == 303
    next_preview = general_upload(browser, CSV.replace(b"private-asset", b"replacement"))
    assert next_preview.status_code == 200
    assert re.search(r'name="mode" value="add" checked', next_preview.text)
    assert "Assets not in this file are removed." in next_preview.text
    assert general_submit(browser, next_preview, mode="replace").status_code == 303
    assert [row["asset_id"] for row in current(browser, "/inventory/unassigned")] == ["replacement"]


def test_inventory_preview_errors_and_new_client_name_validation(deployment):
    config, _, _, browser = deployment
    invalid_name = general_upload(browser, new_client="bad\u200fname")
    assert invalid_name.status_code == 400
    assert "control or format characters" in invalid_name.text
    preview = general_upload(browser)
    rejected = general_submit(browser, preview, product="")
    assert rejected.status_code == 400
    assert "Fix the errors" in rejected.text and 'name="action" value="save" disabled' in rejected.text
    assert not (config.inventory_directory / "unassigned.json").exists()


def test_no_client_detail_download_restore_remove_and_stale_revision(deployment):
    _, _, _, browser = deployment
    assert general_submit(browser, general_upload(browser)).status_code == 303
    history = general_upload(browser, CSV.replace(b"private-asset", b"newer-asset"))
    assert general_submit(browser, history, mode="replace").status_code == 303
    detail = "/inventory/unassigned"
    page = browser.get(detail)
    assert page.status_code == 200 and "Asset ID" in page.text and "newer-asset" in page.text
    assert current(browser, detail)[0]["asset_id"] == "newer-asset"
    revision = re.search(r'name="revision" value="([^"]+)"', page.text)[1]
    version, = re.findall(r'name="version" value="([0-9TZ]+)"', page.text)
    stale = browser.post(detail + "/inventory", data={
        "csrf": csrf(browser, detail), "revision": "0" * 64, "action": "restore", "version": version,
    })
    assert stale.status_code == 409 and "This inventory changed." in stale.text
    restore = browser.post(detail + "/inventory", data={
        "csrf": csrf(browser, detail), "revision": revision, "action": "restore", "version": version,
    })
    assert restore.status_code == 303
    assert current(browser, detail)[0]["asset_id"] == "private-asset"
    stale_remove = browser.post(detail + "/inventory", data={
        "csrf": csrf(browser, detail), "revision": "0" * 64, "action": "remove", "confirm": "remove",
    })
    assert stale_remove.status_code == 409 and "This inventory changed." in stale_remove.text
    assert change(browser, detail, "remove").status_code == 409
    assert change(browser, detail, "remove", confirm="remove").status_code == 303
    assert browser.get(detail + "/download").status_code == 404


def test_inventory_read_only_permissions_csrf_and_upload_request_limit(deployment, monkeypatch):
    config, users, app, manager = deployment
    assert general_submit(manager, general_upload(manager)).status_code == 303
    reader = app.test_client()
    login(reader, "reader")
    list_page = reader.get("/inventory")
    assert list_page.status_code == 200 and "private-asset" not in list_page.text
    assert "Add inventory" not in list_page.text
    assert reader.get("/inventory/unassigned").status_code == 200
    assert "Upload inventory" not in reader.get("/inventory/unassigned").text
    assert reader.get("/inventory/add").status_code == 403
    assert reader.post("/inventory/upload", data={"csrf": "0" * 64}).status_code == 403

    no_view = users.authenticate("admin", PASSWORD)
    users.save_role("inventory-no-view", {"manage_inventory"}, authorization=no_view)
    users.add("inventory-no-view", password=PASSWORD, role="inventory-no-view")
    denied = app.test_client()
    login(denied, "inventory-no-view")
    assert denied.get("/inventory").status_code == 403
    assert denied.post("/inventory/upload", data={"csrf": "0" * 64}).status_code == 403

    no_csrf = manager.post("/inventory/upload", data={
        "inventory": (io.BytesIO(CSV), "example.csv"), "client": "", "new_client": "",
    })
    assert no_csrf.status_code == 400
    preview = general_upload(manager, CSV.replace(b"private-asset", b"csrf-review"))
    token = re.search(r'name="token" value="([^"]+)"', preview.text)[1]
    no_review_csrf = manager.post("/inventory/review", data={
        "token": token, "asset_id": "0", "vendor": "1", "product": "2", "version": "3",
        "action": "save", "mode": "add", "page": "1",
    })
    assert no_review_csrf.status_code == 400

    monkeypatch.setattr(dashboard_inventory, "MAX_BYTES", 32 * 1024 * 1024)
    oversized = manager.post("/inventory/upload", data={
        "csrf": csrf(manager, "/inventory/add"), "client": "", "new_client": "",
        "inventory": (io.BytesIO(b"x" * dashboard_inventory.UPLOAD_REQUEST_BYTES), "large.csv"),
        "pasted_rows": "", "paste_format": "csv",
    }, content_type="multipart/form-data")
    assert oversized.status_code == 413


def test_inventory_add_is_unavailable_without_accounts(tmp_path):
    config = write_config(tmp_path, inventory=False, enabled=False, extra="[inventory]\nmanaged=true\n")
    browser = create_app(config).test_client()
    assert browser.get("/inventory").status_code == 200
    assert browser.get("/inventory/unassigned").status_code == 200
    assert browser.get("/watch/clients/add").status_code == 403
    assert browser.get("/watch/clients/inventory-template").status_code == 200
    assert browser.get("/inventory/add").status_code == 403
    with browser.session_transaction() as session:
        session["csrf"] = "a" * 64
    token = "a" * 64
    result = browser.post("/inventory/upload", data={
        "csrf": token, "inventory": (io.BytesIO(CSV), "example.csv"),
        "client": "", "new_client": "", "pasted_rows": "", "paste_format": "csv",
    })
    assert result.status_code == 403


def test_inventory_page_lists_configured_and_web_asset_rows(tmp_path):
    import hashlib
    import os
    from datetime import datetime, timezone

    from cvebeacon.managed_inventory import encode_records
    from cvebeacon.models import Asset

    config = write_config(
        tmp_path, inventory=False, extra='[inventory]\npath = "configured.csv"\nweb_snapshots = true\nmanaged = false\n',
    )
    config.inventory.path.write_text(
        "asset_id,vendor,product,version\nconfigured-row,Example,Configured Product,1.0\n",
        encoding="utf-8", newline="\n",
    )
    data = encode_records([Asset("web-row", "Example", "Web Product", "1.0", client="Web client")])
    snapshots = config.database_path.parent / "web-inventory"
    snapshots.mkdir()
    snapshot = snapshots / "web-example.json"
    now = datetime.now(timezone.utc).isoformat()
    manifest = {
        "contract": "cvebeacon.inventory.v1", "collector": "web-detect", "collector_version": "0.1.0",
        "source_id": "web-example", "generated_at": now,
        "observed_at": now, "sha256": hashlib.sha256(data).hexdigest(),
        "record_count": 1, "status": "success", "omissions": [],
    }
    snapshot.write_bytes(data)
    snapshot.with_name(snapshot.name + ".manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8", newline="\n",
    )
    if os.name == "posix":
        snapshot.chmod(0o600)
        snapshot.with_name(snapshot.name + ".manifest.json").chmod(0o600)

    page = create_app(config).test_client().get("/inventory")
    assert page.status_code == 200
    assert "Set in the configuration file" in page.text and "configured-row" not in page.text
    assert "Web asset results" in page.text and 'href="/web-assets">Web assets</a>' in page.text
    assert ">1</td>" in page.text


def test_no_client_page_adds_through_the_inventory_page_not_a_client_route(deployment):
    _, _, _, browser = deployment
    empty = browser.get("/inventory/unassigned")
    assert empty.status_code == 200
    assert "No inventory has been saved without a client." in empty.text
    assert "for this client" not in empty.text
    assert general_submit(browser, general_upload(browser)).status_code == 303
    page = browser.get("/inventory/unassigned")
    assert 'href="/inventory/add"' in page.text
    assert "/watch/clients/unassigned/upload" not in page.text
    assert "Inventory rows" in page.text


def test_client_inventory_page_keeps_its_previous_sections(deployment):
    _, _, _, browser = deployment
    detail = add(browser)
    assert submit(browser, detail, upload(browser, detail)).status_code == 303
    page = browser.get(detail)
    assert page.status_code == 200
    assert "Inventory rows" not in page.text
    assert "All inventory" in page.text
