"""Configuration reloads must reuse the process-wide dashboard job manager."""

from __future__ import annotations

import waitress

from cvebeacon import dashboard
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

    for identifier in (first, second):
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
