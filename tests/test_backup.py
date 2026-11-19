"""Offline backup creation, verification, retention, restore and dashboard rules."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

import pytest

from cvebeacon import backup, cli, dashboard
from cvebeacon.config import BackupConfig
from cvebeacon.dashboard_jobs import JobStore
from cvebeacon.locking import LOCK_NAME, RunLock
from cvebeacon.state import StateStore
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from watch_support import write_config

PASSWORD = "Synthetic backup password 123"


def seed(config):
    StateStore(config.database_path).initialize()
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.database_path) as db:
        db.execute("CREATE TABLE backup_sentinel(value TEXT)")
        db.execute("INSERT INTO backup_sentinel VALUES ('state original')")
        db.commit()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("CREATE TABLE backup_sentinel(value TEXT)")
        db.execute("INSERT INTO backup_sentinel VALUES ('watch original')")
        db.commit()


def values(path):
    with sqlite3.connect(path) as db:
        return [row[0] for row in db.execute("SELECT value FROM backup_sentinel")]


def manifest(created):
    return json.loads((created.path / "manifest.json").read_text(encoding="utf-8"))


def delay(created, days):
    value = manifest(created)
    value["created_at"] = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    (created.path / "manifest.json").write_text(json.dumps(value), encoding="utf-8")


def test_create_list_and_verify(tmp_path):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    created = backup.create(config, created_by="tester")
    assert created.valid and created.databases == 4
    assert (tmp_path / "backups" / created.id / "manifest.json").is_file()
    listed = backup.list_backups(config)
    assert [item.id for item in listed] == [created.id]
    assert listed[0].created_by == "tester"
    data = manifest(created)
    assert data["version"] == 1
    assert data["created_by"] == "tester"
    assert data["schema_versions"]["state"] == 3
    assert data["schema_versions"]["watch"] == 7
    assert data["include_secrets"] is False
    assert all(len(item["sha256"]) == 64 for item in data["files"])
    assert all(item["size"] == (created.path / item["name"]).stat().st_size for item in data["files"])
    assert backup.verify(config, created.id).id == created.id


def test_create_through_the_cli_and_refuse_a_cancelled_restore(tmp_path, capsys, monkeypatch):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    assert cli.main(["--config", str(config.config_path), "backup", "create"]) == 0
    created = re.search(r"created (\S+):", capsys.readouterr().out)[1]
    assert cli.main(["--config", str(config.config_path), "backup", "list"]) == 0
    assert created in capsys.readouterr().out
    assert cli.main(["--config", str(config.config_path), "backup", "verify", created]) == 0
    assert "verified" in capsys.readouterr().out
    with sqlite3.connect(config.database_path) as db:
        db.execute("DELETE FROM backup_sentinel")
        db.commit()
    monkeypatch.setattr("builtins.input", lambda *args: "no")
    assert cli.main(["--config", str(config.config_path), "backup", "restore", created]) == 1
    assert values(config.database_path) == []
    assert cli.main(["--config", str(config.config_path), "backup", "restore", created, "--yes"]) == 0
    assert values(config.database_path) == ["state original"]
    assert cli.main(["--config", str(config.config_path), "backup", "prune"]) == 0


def test_tampered_file_is_detected(tmp_path):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    created = backup.create(config)
    row = next(item for item in manifest(created)["databases"] if item["role"] == "state")
    path = created.path / row["backup"]
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 0xFF
    path.write_bytes(raw)
    with pytest.raises(backup.BackupError, match="checksum"):
        backup.verify(config, created.id)


def test_retention_keeps_the_minimum(tmp_path):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    created = [backup.create(config) for _ in range(3)]
    ids = [item.id for item in created]
    for item in created:
        delay(item, 30)
    policy = replace(config, backup=BackupConfig(retention_days=1, keep_min=2))
    result = backup.prune(policy)
    assert result["removed"] == [ids[0]]
    assert {item.id for item in backup.list_backups(config)} == set(ids[1:])
    for item in backup.list_backups(config):
        delay(item, 30)
    result = backup.prune(replace(config, backup=BackupConfig(retention_days=1, keep_min=3)))
    assert result["removed"] == []
    assert len(backup.list_backups(config)) == 2
    recent = backup.create(config)
    result = backup.prune(replace(config, backup=BackupConfig(retention_days=7, keep_min=0)))
    assert set(result["removed"]) == set(ids[1:])
    assert [item.id for item in backup.list_backups(config)] == [recent.id]


def test_restore_round_trip_and_safety_backup(tmp_path):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    original_config = config.config_path.read_bytes()
    created = backup.create(config)
    with sqlite3.connect(config.database_path) as db:
        db.execute("DELETE FROM backup_sentinel")
        db.execute("INSERT INTO backup_sentinel VALUES ('state changed')")
        db.commit()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("DELETE FROM backup_sentinel")
        db.execute("INSERT INTO backup_sentinel VALUES ('watch changed')")
        db.commit()
    config.config_path.write_text(original_config.decode("utf-8") + "\n# local change\n", encoding="utf-8")
    result = backup.restore(config, created.id)
    assert values(config.database_path) == ["state original"]
    assert values(config.watch.database) == ["watch original"]
    assert config.config_path.read_bytes() == original_config
    assert result["databases"] == 4
    safety = next(item for item in backup.list_backups(config) if item.id == result["safety"])
    assert safety.created_by == "pre-restore"
    assert safety.id != created.id


def test_restore_is_refused_while_the_run_lock_is_held(tmp_path):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    created = backup.create(config)
    lock = RunLock(Path(config.database_path).parent / LOCK_NAME, command="scan")
    assert lock.acquire()
    try:
        with pytest.raises(backup.BackupError, match="another run is in progress"):
            backup.restore(config, created.id)
    finally:
        lock.release()
    assert backup.restore(config, created.id)["restored"] == created.id


def test_restore_is_refused_for_a_newer_schema(tmp_path, monkeypatch):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    created = backup.create(config)
    monkeypatch.setattr("cvebeacon.state.SCHEMA_VERSION", 2)
    with pytest.raises(backup.BackupError, match="newer state schema"):
        backup.restore(config, created.id)
    assert [item.id for item in backup.list_backups(config)] == [created.id]


def test_restore_is_refused_while_dashboard_jobs_are_active(tmp_path):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    created = backup.create(config)
    store = JobStore(tmp_path / "dashboard-jobs")
    store.create("scan", "tester", ["cvebeacon", "scan"])
    with pytest.raises(backup.BackupError, match="dashboard jobs are active"):
        backup.restore(config, created.id)


def test_secret_files_are_excluded_by_default(tmp_path):
    secret = tmp_path / "smtp-secret.txt"
    secret.write_text("synthetic secret", encoding="utf-8")
    secret.chmod(0o600)
    channels = """
[watch.channels.mail]
type = "smtp"
host = "smtp.example.com"
from = "alerts@example.com"
to = ["security@example.com"]
password_file = "smtp-secret.txt"
"""
    config = write_config(tmp_path, inventory=False, channels=channels)
    assert config.watch.channels[0].secret("password").file == secret
    plain = backup.create(config)
    assert plain.include_secrets is False
    assert manifest(plain)["secrets"] == []
    assert not (plain.path / "secrets").exists()
    included = backup.create(config, include_secrets=True)
    data = manifest(included)
    assert included.include_secrets is True
    assert data["secrets"][0]["reference"] == "watch.channels.mail.password"
    copied = included.path / data["secrets"][0]["file"]
    assert copied.read_text(encoding="utf-8") == "synthetic secret"
    if os.name == "posix":
        assert stat.S_IMODE(copied.stat().st_mode) & 0o077 == 0


def test_backup_permissions_are_private(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX modes are not available")
    config = write_config(tmp_path, inventory=False)
    seed(config)
    created = backup.create(config, include_secrets=False)
    assert stat.S_IMODE((tmp_path / "backups").stat().st_mode) == 0o700
    assert stat.S_IMODE(created.path.stat().st_mode) == 0o700
    for path in created.path.rglob("*"):
        if path.is_file():
            assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_old_config_without_backup_section_keeps_working(tmp_path):
    config = write_config(tmp_path, inventory=False)
    assert config.backup.directory is None
    assert (config.backup.retention_days, config.backup.keep_min, config.backup.compress) == (7, 3, True)
    assert backup.backup_root(config) == tmp_path / "backups"
    seed(config)
    assert backup.create(config).valid


def test_backup_settings_use_existing_config_editor_metadata():
    from cvebeacon import dashboard_config as dc

    assert dc.SECTIONS["backup"] == "edit_system"
    assert dc.FIELD_METADATA["backup.directory"].help
    assert "administrator" in dc.FIELD_METADATA["backup.directory"].help.casefold()
    assert dc.FIELD_METADATA["backup.retention_days"].default == 7
    assert dc.FIELD_METADATA["backup.keep_min"].default == 3
    assert dc.FIELD_METADATA["backup.compress"].default is True


def test_config_editor_saves_backup_settings(tmp_path):
    from cvebeacon.config import load_config
    from test_dashboard_config import confirm, preview

    config = write_config(tmp_path, inventory=False, extra='[backup]\ndirectory = "custom-backups"\n')
    config.config_path.chmod(0o600)
    _accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    _login(client, "admin")
    page = client.get("/config/backup")
    assert page.status_code == 200
    assert "retention_days" in page.text and "keep_min" in page.text
    response = preview(client, "backup", g0_retention_days="14", g0_keep_min="5")
    assert response.status_code == 200
    assert confirm(client, response, "backup").status_code == 303
    saved = load_config(config.config_path)
    assert saved.backup.directory == tmp_path / "custom-backups"
    assert saved.backup.retention_days == 14
    assert saved.backup.keep_min == 5


def _submit(client, path, **values):
    page = client.get("/account")
    assert page.status_code == 200
    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    return client.post(path, data={"csrf": token, **values})


def _login(client, username):
    page = client.get("/login")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    response = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert response.status_code == 303


def _accounts(config):
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    users.add("viewer", password=PASSWORD)
    proof = users.authenticate("admin", PASSWORD)
    users.save_role("viewer-only", {"view"}, authorization=proof)
    users.edit_user("viewer", role="viewer-only", disabled=False, authorization=proof)
    return users


def _wait(app, job_id):
    job = app.extensions["dashboard_jobs"].wait(job_id, timeout=60)
    assert job is not None and job.status == "succeeded", job.message if job else "missing job"
    return job


def _job_id(response):
    return int(response.headers["Location"].rstrip("/").rsplit("/", 1)[1])


def test_dashboard_permission_boundary_csrf_audit_and_restore(tmp_path):
    config = write_config(tmp_path, inventory=False)
    seed(config)
    users = _accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    _login(client, "admin")
    viewer = app.test_client()
    _login(viewer, "viewer")

    page = viewer.get("/backups/")
    assert page.status_code == 200
    assert "Create a backup" not in page.text
    assert viewer.post("/backups/create", data={"csrf": re.search(
        r'name="csrf" value="([^"]+)"', viewer.get("/account").text)[1]}).status_code == 403

    assert client.post("/backups/create").status_code == 400
    response = _submit(client, "/backups/create", include_secrets="yes")
    assert response.status_code == 303
    assert _wait(app, _job_id(response)).operation == "backup-create"
    created = backup.list_backups(config)[0]
    assert created.include_secrets is True
    assert created.created_by == "admin"

    response = _submit(client, "/backups/verify", backup_id=created.id)
    assert response.status_code == 303
    _wait(app, _job_id(response))

    download = _submit(client, "/backups/download", backup_id=created.id)
    assert download.status_code == 200
    assert download.data[:2] == b"\x1f\x8b"

    with sqlite3.connect(config.database_path) as db:
        db.execute("DELETE FROM backup_sentinel")
        db.execute("INSERT INTO backup_sentinel VALUES ('dashboard changed')")
        db.commit()
    response = _submit(client, "/backups/restore", backup_id=created.id, confirm=created.id)
    assert response.status_code == 303
    _wait(app, _job_id(response))
    assert values(config.database_path) == ["state original"]

    response = _submit(client, "/backups/prune")
    assert response.status_code == 303

    actions = [entry.action for entry in users.audit_entries()]
    for expected in ("backup_create_requested", "backup_verify_requested",
                     "backup_download", "backup_restore_requested", "backup_prune"):
        assert any(action.startswith(expected) for action in actions), expected
    assert any(action.startswith("job_succeeded") for action in actions)
