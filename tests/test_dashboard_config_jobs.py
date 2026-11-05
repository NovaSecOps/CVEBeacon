"""Configuration reloads must reuse the process-wide dashboard job manager."""

from __future__ import annotations

from dataclasses import replace

import waitress

from cvebeacon import dashboard
from cvebeacon.dashboard_jobs import JobStore
from test_dashboard_config_fixes import confirm, preview
from test_dashboard_operations import (
    fake_job,
    job_id,
    login,
    make_config,
    new_accounts,
    submit,
    wait_for,
)


def test_config_save_reuses_job_manager_while_jobs_are_active(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    config.config_path.chmod(0o644)
    users = new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    manager = app.extensions["dashboard_jobs"]
    manager.command_builder = lambda *args, **kwargs: fake_job(
        "import time; time.sleep(3)"
    )
    login(client, "admin")
    first_response = submit(client, "/operations/run", operation="watch-notify")
    assert first_response.status_code == 303
    first = job_id(first_response)
    wait_for(lambda: manager.store.get(first).status == "running")
    second_response = submit(client, "/operations/run", operation="watch-notify")
    assert second_response.status_code == 303
    second = job_id(second_response)
    assert manager.store.get(second).status == "queued"
    worker = manager._thread
    assert worker is not None and worker.is_alive()

    response = preview(client, "http", g0_retries="2")
    assert response.status_code == 200, response.text
    assert confirm(client, response, "http").status_code == 303

    editor = app.extensions["dashboard_config"]
    active = editor.active_app
    assert active is not app
    assert active.extensions["dashboard_jobs"] is manager
    assert app.extensions["dashboard_jobs"] is manager
    assert manager.config.http.retries == 2
    assert manager._thread is worker

    login(client, "admin")
    third_response = submit(client, "/operations/run", operation="watch-notify")
    assert third_response.status_code == 303
    third = job_id(third_response)

    for identifier in (first, second, third):
        job = manager.wait(identifier, timeout=10)
        assert job is not None and job.status == "succeeded"
    assert users.verify_audit() is None

    # serve uses the manager attached to the application it runs. Because the
    # reload keeps that object, the finally block shuts down the active manager.
    class Server:
        def run(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(waitress, "create_server", lambda app, **kwargs: Server())
    monkeypatch.setattr(dashboard, "create_app", lambda *args, **kwargs: active)
    dashboard.serve(config, host="127.0.0.1", port=8787,
                    allow_unauthenticated_remote=True)
    assert manager._stopping


def test_create_app_can_reuse_an_existing_job_manager(tmp_path):
    config = make_config(tmp_path)
    new_accounts(config)
    first = dashboard.create_app(config)
    manager = first.extensions["dashboard_jobs"]
    second = dashboard.create_app(config, jobs=manager)
    assert second.extensions["dashboard_jobs"] is manager
    manager.shutdown()


def test_refused_job_storage_move_leaves_no_save_audit_or_backup(tmp_path):
    config = make_config(tmp_path)
    config.config_path.chmod(0o644)
    users = new_accounts(config)
    app = dashboard.create_app(config)
    client = app.test_client()
    manager = app.extensions["dashboard_jobs"]
    manager.command_builder = lambda *args, **kwargs: fake_job(
        "import time; time.sleep(8)"
    )
    login(client, "admin")
    response = submit(client, "/operations/run", operation="watch-notify")
    assert response.status_code == 303
    identifier = job_id(response)
    wait_for(lambda: manager.store.get(identifier).status == "running")
    editor = app.extensions["dashboard_config"]
    before = config.config_path.read_bytes()
    backups = editor.backups()
    audit_count = users.audit_count()

    response = preview(client, "system", g0_database=str(tmp_path / "moved" / "state.db"))
    assert response.status_code == 200, response.text
    saved = confirm(client, response, "system")
    assert saved.status_code == 400
    assert "Cannot change dashboard job storage" in saved.text
    assert config.config_path.read_bytes() == before
    assert editor.backups() == backups
    assert users.audit_count() == audit_count
    assert manager.store.get(identifier).status == "running"
    manager.wait(identifier, timeout=10)
    manager.shutdown()


def test_reconfigure_recovers_a_destination_job_store(tmp_path):
    config = make_config(tmp_path)
    config.config_path.chmod(0o644)
    new_accounts(config)
    app = dashboard.create_app(config)
    manager = app.extensions["dashboard_jobs"]
    users = app.extensions["dashboard_users"]
    destination = tmp_path / "moved" / "dashboard-jobs"
    store = JobStore(destination)
    queued = store.create("watch-evaluate", "admin", ["cvebeacon", "watch"])
    moved = replace(config, database_path=destination.parent / "state.db")

    transition = manager.reserve_reconfigure(moved, users)
    transition.publish()
    assert manager.store.path == store.path
    recovered = manager.store.get(queued.id)
    assert recovered is not None and recovered.status == "failed"
    manager.shutdown()
