"""The account dashboard guides and protects client inventory management."""

import io
import json
import os
import re

from openpyxl import Workbook
import pytest

from cvebeacon import dashboard_inventory
from cvebeacon.dashboard import create_app
from cvebeacon.inventory import load_inventory
from cvebeacon.inventory_preview import preview_upload
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
    })


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
    assert "Add client" in manager.get("/watch/clients").text
    assert manager.post(ADD, data={"name": "Example client"}).status_code == 400
    invalid = manager.post(ADD, data={"name": "bad\u200fname", "csrf": csrf(manager, ADD)})
    assert invalid.status_code == 400
    assert "control or format characters" in invalid.text

    detail = add(manager)
    path = config.inventory_directory / f"{client_key('Example client')}.json"
    assert not path.exists()
    assert "Example client" in manager.get("/watch/clients").text
    assert "private-notes-marker" in manager.get(detail).text
    preview = upload(manager, detail)
    assert preview.status_code == 200
    assert "wrong_title" in preview.text and "Product is missing" in preview.text
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
    assert upload(browser, second, oversized).status_code == 413
    if os.name == "posix":
        target = tmp_path / "untouched.json"
        target.write_text("untouched")
        path = config.inventory_directory / f"{client_key('../Client B')}.json"
        path.symlink_to(target)
        assert upload(browser, second).status_code == 503
        assert target.read_text() == "untouched"
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
    archived.write_text("private-corrupt-version")
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
    path.write_text("PRIVATE-INVENTORY-CONTENTS")
    monkeypatch.setattr(cli, "_run_query", lambda *a, **kw: pytest.fail("queried with incomplete inventory"))

    admin = _admin(app)
    reports = admin.get("/reports")
    assert "Unreadable client" in reports.text and "Generate and download" not in reports.text
    result = admin.post("/reports", data={"csrf": csrf(admin, healthy), "format": "json"})
    assert result.status_code == 409 and "Content-Disposition" not in result.headers
    assert "Unreadable client" in result.text
    assert path.stem not in result.text and "PRIVATE-INVENTORY-CONTENTS" not in result.text
    command = ["--config", str(config.config_path)]
    output = tmp_path / "report.json"
    assert cli.main([*command, "export", "--format", "json", "--output", str(output)]) == 4
    assert not output.exists()
    assert cli.main([*command, "asset", "healthy"]) == 4
    assert "unreadable client inventories" in capsys.readouterr().err


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
