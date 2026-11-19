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


def test_overview_explains_watch_alerting_without_inventory(watch_only_client):
    _, _, client = watch_only_client
    text = client.get("/").text
    assert (
        "KEV, critical-severity and custom rule alerting still work without an "
        "inventory" in text
    )
    assert "<code>[inventory]</code> is optional for watch mode" in text


def test_shell_groups_main_and_account_navigation(watch_only_client):
    _, _, client = watch_only_client
    text = client.get("/watch").text
    header, remainder = text.split("</header>", 1)
    sidebar = remainder.split("</nav>", 1)[0]
    assert 'class="topbar"' in header
    assert 'class="skip-link" href="#content"' in text
    assert 'role="search"' in header and 'placeholder="Search CVE' in header
    # Global search goes to the CVE explorer and uses its query parameter.
    assert 'action="/watch/cves"' in header and 'name="q"' in header
    assert "My account" in header
    assert ">Log out<" in header
    assert 'name="csrf"' in header
    assert 'class="theme-toggle"' in header
    assert '<nav class="sidebar" id="sidebar" aria-label="Main navigation">' in sidebar
    for heading in ("Monitoring", "Clients", "Scans", "Activity", "Settings"):
        assert f">{heading}<" in sidebar
    for label in (
        "Home", "Alerts", "Watch overview", "Reported to clients", "Clients",
        "Web assets", "Findings", "Assets", "History", "Reports", "Manual query",
        "Operations", "Schedule", "Sources", "Updates", "Users", "Roles", "Audit",
        "Configuration", "My account",
    ):
        assert f"<span>{label}</span>" in sidebar, label
    # Registered optional features appear; unregistered ones produce no dead links.
    assert "<span>CVE explorer</span>" in sidebar
    assert "<span>Backups</span>" in sidebar
    assert 'aria-current="page"' in sidebar
    assert '<main id="content"' in remainder
    # The shell is the only navigation; page bodies add none.
    main = remainder.split('<main id="content"', 1)[1]
    assert "<nav" not in main
    assert text.count("<nav") == 1


def test_navigation_respects_permissions(watch_only_client):
    config, _, _ = watch_only_client
    users = UserStore(config.watch.users_database)
    users.add("viewer", password=PASSWORD, role="viewer")
    client = dashboard.create_app(config).test_client()
    response = client.post(
        "/login",
        data={"csrf": csrf(client), "username": "viewer", "password": PASSWORD},
    )
    assert response.status_code == 303
    sidebar = client.get("/watch").text.split('id="sidebar"', 1)[1].split("</nav>", 1)[0]
    assert "<span>Alerts</span>" in sidebar
    for label in ("Roles", "Users", "Audit", "Schedule"):
        assert f"<span>{label}</span>" not in sidebar, label


def test_shell_helper_reports_registered_endpoints(watch_only_client):
    _, app, _ = watch_only_client
    helper = app.jinja_env.globals["has_endpoint"]
    assert helper("watch.events") is True
    assert helper("watch.explorer") is True
    assert helper("no.such.endpoint") is False


def test_navigation_contrast_and_narrow_layout(watch_only_client):
    _, _, client = watch_only_client
    css = client.get("/static/dashboard.css").text
    for token in ("--nav-bg", "--nav-text", "--nav-active-bg", "--nav-active-text", "--focus"):
        assert css.count(f"{token}:") >= 3  # light, system dark, manual dark
    assert ':root[data-theme="dark"]' in css and ':root[data-theme="light"]' in css
    assert "prefers-color-scheme: dark" in css
    assert "@media (max-width: 900px)" in css and ".js .sidebar { display: none; }" in css
    assert ".table-wrap {\n  overflow-x: auto" in css
    assert ":focus-visible" in css
    blocks = {
        "light": css.split(":root {", 1)[1].split("}", 1)[0],
        "dark": css.split(':root[data-theme="dark"] {', 1)[1].split("}", 1)[0],
    }
    system_dark = css.split(':root:not([data-theme="light"]) {', 1)[1].split("}", 1)[0]
    assert system_dark.split() == blocks["dark"].split()  # the two dark blocks must not drift
    for name, block in blocks.items():
        tokens = dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-f]{6})", block))
        pairs = [
            ("nav-text", "nav-bg"), ("nav-active-text", "nav-active-bg"),
            ("nav-heading", "nav-bg"), ("text", "bg"), ("text", "surface"),
            ("text-muted", "surface"), ("link", "surface"), ("accent-text", "accent"),
            ("critical-text", "critical-bg"), ("high-text", "high-bg"),
            ("medium-text", "medium-bg"), ("low-text", "low-bg"),
            ("kev-text", "kev-bg"), ("exploited-text", "exploited-bg"),
            ("info-text", "info-bg"), ("success-text", "success-bg"),
            ("warning-text", "warning-bg"), ("danger-text", "danger-bg"),
        ]
        for foreground, background in pairs:
            ratio = _contrast(tokens[foreground], tokens[background])
            assert ratio >= 4.5, (name, foreground, background, ratio)


def _contrast(first: str, second: str) -> float:
    def luminance(colour: str) -> float:
        channels = [int(colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def test_stylesheet_has_no_external_urls():
    from pathlib import Path

    static = Path(dashboard.__file__).parent / "static"
    css = (static / "dashboard.css").read_text()
    assert not re.search(r"(?i)(https?:)?//|@import|url\(", css)
    assert not re.search(r"(?i)https?://|\bimport\b|\beval\(", (static / "ui.js").read_text())


def test_templates_use_no_inline_styles_or_scripts():
    from pathlib import Path

    templates = Path(dashboard.__file__).parent / "templates"
    for path in sorted(templates.glob("*.html")):
        text = path.read_text()
        assert not re.search(r"(?i)\sstyle\s*=", text), path.name
        assert not re.search(r"(?i)\son[a-z]+\s*=", text), path.name
        assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)[^>]*>", text), path.name
        assert not re.search(r"(?is)<style\b", text), path.name


def test_rendered_pages_load_ui_script_without_inline_code(watch_only_client):
    _, _, client = watch_only_client
    for path in ("/", "/watch", "/watch/clients", "/account"):
        text = client.get(path).text
        assert 'src="/static/ui.js"' in text, path
        assert not re.search(r"(?i)\sstyle\s*=", text), path
        assert not re.search(r"(?is)<script\b(?![^>]*\bsrc=)", text), path
    assert client.get("/static/ui.js").status_code == 200


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
