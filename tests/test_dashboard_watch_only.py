"""Watch-only dashboard behaviour when no inventory is configured."""

from __future__ import annotations

import re

import pytest

from cvebeacon import dashboard
from cvebeacon.dashboard_jobs import build_command
from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from watch_support import write_config

PASSWORD = "Synthetic watch-only dashboard password"

INVENTORY_PAGES = (
    "/",
    "/findings",
    "/assets",
    "/asset?asset_id=a",
    "/history",
    "/query",
    "/reports",
)
WORKING_PAGES = (
    ("/watch", "Watch overview"),
    ("/watch/events", "Watch events"),
    ("/watch/clients", "Client allocation requires an inventory scan"),
    ("/operations/", "Run a job"),
    ("/operations/jobs", "Job history"),
    ("/operations/schedule", "Native schedule"),
    ("/users", "Users"),
    ("/users/admin", "admin"),
    ("/roles", "Roles and permissions"),
    ("/account", "My account"),
    ("/audit", "Account audit"),
    ("/sources", "Source status"),
)


def csrf(client, path="/login"):
    page = client.get(path)
    assert page.status_code == 200
    return re.search(r'name="csrf" value="([^"]+)"', page.text)[1]


def login(client):
    response = client.post(
        "/login",
        data={
            "csrf": csrf(client),
            "username": "admin",
            "password": PASSWORD,
        },
    )
    assert response.status_code == 303


@pytest.fixture
def watch_only(tmp_path):
    return write_config(tmp_path, inventory=False)


@pytest.fixture
def watch_only_client(watch_only):
    users = UserStore(watch_only.watch.users_database)
    users.add(
        "admin",
        password=PASSWORD,
        is_admin=True,
        authorization=BOOTSTRAP,
    )
    app = dashboard.create_app(watch_only)
    client = app.test_client()
    login(client)
    return watch_only, app, client


def test_create_app_accepts_watch_only_config(watch_only):
    app = dashboard.create_app(watch_only)
    response = app.test_client().get("/")
    assert response.status_code == 200
    assert "No inventory is configured." in response.text


def test_serve_accepts_watch_only_config(watch_only, monkeypatch):
    import waitress

    calls = []

    class Server:
        def run(self):
            calls.append("run")

        def close(self):
            calls.append("close")

    def create(app, **kwargs):
        assert not app.debug
        calls.append(kwargs)
        return Server()

    monkeypatch.setattr(waitress, "create_server", create)
    dashboard.serve(watch_only, host="127.0.0.1", port=8787)
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8787
    assert calls[-1] == "close"


@pytest.mark.parametrize("path", INVENTORY_PAGES)
def test_inventory_pages_explain_the_missing_configuration(watch_only_client, path):
    _, _, client = watch_only_client
    response = client.get(path)
    assert response.status_code == 200
    text = response.text
    assert "No inventory is configured." in text
    assert "[inventory]" in text
    assert 'path = "inventory.csv"' in text
    assert "docs/USER_GUIDE.md" in text
    assert "Traceback" not in text


@pytest.mark.parametrize("path,heading", WORKING_PAGES)
def test_watch_only_pages_render(watch_only_client, path, heading):
    _, _, client = watch_only_client
    response = client.get(path)
    assert response.status_code == 200
    assert heading in response.text
    assert "Traceback" not in response.text


def test_operations_offers_watch_jobs_and_disables_inventory_jobs(watch_only_client):
    _, _, client = watch_only_client
    text = client.get("/operations/").text
    assert "Synchronise watch data" in text
    assert "Watch run" in text
    assert "Scan inventory" in text
    assert "Run scan and watch together" in text
    assert text.count("Unavailable: no inventory is configured.") == 2


@pytest.mark.parametrize("operation", ["scan", "run"])
def test_inventory_operations_are_refused(watch_only_client, operation):
    _, _, client = watch_only_client
    response = client.post(
        "/operations/run",
        data={"csrf": csrf(client, "/operations/"), "operation": operation},
    )
    assert response.status_code == 400
    assert "no inventory" in response.text
    assert "Unavailable: no inventory is configured." in response.text


@pytest.mark.parametrize("path,values", [
    ("/query", {"mode": "product", "vendor": "Acme", "product": "Widget", "version": "1"}),
    ("/reports", {"format": "json"}),
])
def test_inventory_source_operations_are_refused(watch_only_client, path, values):
    _, _, client = watch_only_client
    response = client.post(
        path,
        data={"csrf": csrf(client, "/operations/"), **values},
    )
    assert response.status_code == 400
    assert "No inventory is configured." in response.text
    assert "Traceback" not in response.text


@pytest.mark.parametrize("operation", ["scan", "run"])
def test_inventory_commands_cannot_be_built(watch_only, operation):
    with pytest.raises(ConfigurationError, match="inventory"):
        build_command(watch_only, operation)


def test_inventory_configuration_keeps_inventory_pages(tmp_path):
    config = write_config(tmp_path)
    (tmp_path / "missing-inventory.csv").write_text(
        "asset_id,vendor,product,version\na,Acme,Widget,1\n",
        encoding="utf-8",
    )
    users = UserStore(config.watch.users_database)
    users.add(
        "admin",
        password=PASSWORD,
        is_admin=True,
        authorization=BOOTSTRAP,
    )
    client = dashboard.create_app(config).test_client()
    login(client)
    findings = client.get("/findings").text
    assert "Latest known findings" in findings
    assert "No inventory is configured." not in findings
    operations = client.get("/operations/").text
    assert "Scan inventory" in operations
    assert "Unavailable: no inventory is configured." not in operations
