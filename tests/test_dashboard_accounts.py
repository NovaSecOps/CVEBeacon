"""Account, session and authorization boundaries for the dashboard."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import re
import threading
from tempfile import TemporaryDirectory

import pytest

from cvebeacon import dashboard
from cvebeacon.config import AppConfig, DashboardConfig, WatchConfig, load_config
from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.permissions import PERMISSIONS
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from test_dashboard import setup

PASSWORD = "Synthetic account password 123"


def submit(client, path, **values):
    page = client.get(path)
    assert page.status_code == 200
    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    return client.post(path, data={"csrf": token, **values})


@pytest.fixture
def accounts(setup):
    config = setup[0]
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    users.add("reader", password=PASSWORD)
    app = dashboard.create_app(config)
    return config, users, app, app.test_client()


def test_accounts_replace_shared_login(accounts):
    _, users, app, client = accounts
    response = submit(client, "/login", username="reader", password=PASSWORD)
    assert response.status_code == 303
    assert client.get("/").status_code == 200
    assert client.get("/users").status_code == 403
    assert users.audit_entries()[-1].action == "login"
    assert app.extensions["account_sessions"]


def test_local_bootstrap_is_one_time(setup):
    client = setup[2]
    assert client.get("/bootstrap", environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code == 403
    assert submit(client, "/bootstrap", username="admin", password=PASSWORD).status_code == 303
    assert client.get("/bootstrap").status_code in {303, 403}


def login(client, username="reader"):
    assert submit(client, "/login", username=username, password=PASSWORD).status_code == 303


def csrf(client, path="/account"):
    page = client.get(path)
    return re.search(r'name="csrf" value="([^"]+)"', page.text)[1]


def route_cases():
    # Read the real route table at collection, including future routes.
    with TemporaryDirectory() as directory:
        path = Path(directory)
        config = AppConfig(path / "config", object(), path / "state", path / "reports",
                           dashboard=DashboardConfig(password_hash_env="UNUSED_DASHBOARD_TEST_HASH"),
                           watch=WatchConfig(database=path / "watch.db"))
        app = dashboard.create_app(config)
        return [(rule.rule, rule.endpoint, method) for rule in app.url_map.iter_rules()
                if rule.endpoint != "static" for method in sorted(rule.methods - {"HEAD", "OPTIONS"})]


@pytest.mark.parametrize("path,endpoint,method", route_cases())
def test_every_route_declares_and_enforces_its_permission(accounts, path, endpoint, method):
    _, users, app, client = accounts
    policy = getattr(app.view_functions[endpoint], "dashboard_permissions", {})
    permission = policy.get(method)
    needed = {permission} if isinstance(permission, str) else set(permission or ())
    assert needed and needed <= PERMISSIONS | {"public", "self", "admin"}, "every route must declare its policy"
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("empty", set(), authorization=admin)
    users.edit_user("reader", role="empty", disabled=False, authorization=admin)
    login(client)
    path = path.replace("<username>", "reader").replace("<int:event_id>", "1")
    if needed & (PERMISSIONS | {"admin"}):
        response = client.open(path, method=method, data={"csrf": csrf(client)})
        assert response.status_code == 403
        if method == "GET":
            assert client.head(path).status_code == 403
    elif endpoint == "account":
        assert client.get(path).status_code == 200


@pytest.mark.parametrize("path,endpoint,method", route_cases())
def test_all_protected_routes_require_login(accounts, path, endpoint, method):
    _, _, app, client = accounts
    permission = app.view_functions[endpoint].dashboard_permissions[method]
    if permission == "public":
        return
    path = path.replace("<username>", "reader").replace("<int:event_id>", "1")
    response = client.open(path, method=method)
    assert response.status_code == 303 and response.headers["Location"] == "/login"


@pytest.mark.parametrize("path,endpoint,method", [case for case in route_cases() if case[2] == "POST"])
def test_every_post_rejects_missing_and_foreign_csrf(accounts, path, endpoint, method):
    _, _, app, client = accounts
    login(client, "admin")
    stranger = app.test_client()
    foreign = csrf(stranger, "/login")
    path = path.replace("<username>", "reader")
    assert client.post(path).status_code == 400
    assert client.post(path, data={"csrf": foreign}).status_code == 400


def test_bootstrap_cannot_claim_existing_non_admin_store(setup):
    config, _, client = setup
    users = UserStore(config.watch.users_database)
    users.add("reader", password=PASSWORD)
    assert client.get("/bootstrap").status_code == 403
    with pytest.raises(ConfigurationError, match="empty account store"):
        users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP, empty_store_only=True)


def test_concurrent_empty_store_bootstrap(setup):
    config = setup[0]
    barrier = threading.Barrier(2)

    def bootstrap(name):
        users = UserStore(config.watch.users_database)
        barrier.wait(timeout=10)
        try:
            users.add(name, password=PASSWORD, is_admin=True, authorization=BOOTSTRAP, empty_store_only=True)
            return True
        except ConfigurationError as exc:
            assert "empty account store" in str(exc)
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(bootstrap, ["first", "second"])) == [False, True]
    assert len(UserStore(config.watch.users_database).users()) == 1


def test_missing_policy_fails_closed(accounts):
    _, _, app, client = accounts
    app.add_url_rule("/undeclared", "undeclared", lambda: "secret")
    login(client, "admin")
    assert client.get("/undeclared").status_code == 403


def test_generic_failure_lockout_and_unlock(accounts, caplog):
    _, users, app, client = accounts
    now = [100.0]
    app.extensions["account_login_throttle"].clock = lambda: now[0]
    missing = submit(client, "/login", username="missing", password="Wrong password value")
    now[0] += 61  # Admit each attempt through the new origin backoff.
    wrong = submit(client, "/login", username="reader", password="Wrong password value")
    assert missing.status_code == wrong.status_code == 401
    assert missing.text == wrong.text
    for _ in range(4):
        now[0] += 61
        assert submit(client, "/login", username="reader", password="Wrong password value").status_code == 401
    assert users.find("reader").failed_logins == 5
    now[0] += 61
    assert submit(client, "/login", username="reader", password=PASSWORD).status_code == 401
    proof = users.authenticate("admin", PASSWORD)
    users.unlock("reader", authorization=proof)
    now[0] += 61
    login(client)
    assert "Wrong password value" not in caplog.text and PASSWORD not in caplog.text


def test_missing_and_disabled_accounts_use_dummy_hash(accounts, monkeypatch):
    from cvebeacon.watch import users as module
    from cvebeacon.passwords import DUMMY_HASH
    _, users, app, client = accounts
    now = [100.0]
    app.extensions["account_login_throttle"].clock = lambda: now[0]
    users.disable("reader")
    calls = []
    original = module.verify_password
    monkeypatch.setattr(module, "verify_password", lambda encoded, password: calls.append(encoded) or original(encoded, password))
    first = submit(client, "/login", username="missing", password=PASSWORD)
    now[0] += 61
    second = submit(client, "/login", username="reader", password=PASSWORD)
    assert first.status_code == second.status_code == 401 and first.text == second.text
    assert calls == [DUMMY_HASH, DUMMY_HASH]


def test_session_fixation_csrf_and_logout_replay(accounts):
    _, users, app, client = accounts
    assert client.post("/login", data={"username": "reader", "password": PASSWORD}).status_code == 400
    old_token = csrf(client, "/login")
    old_cookie = client.get_cookie(dashboard.ACCOUNT_COOKIE).value
    login(client)
    cookie = client.get_cookie(dashboard.ACCOUNT_COOKIE).value
    assert cookie != old_cookie and re.fullmatch(r"[0-9a-f]{64}", cookie)
    assert csrf(client) != old_token
    assert client.get_cookie("cvebeacon_session") is None
    attacker = app.test_client()
    attacker.set_cookie(dashboard.ACCOUNT_COOKIE, old_cookie)
    assert attacker.get("/").status_code == 303
    assert client.post("/account", data={"csrf": old_token, "action": "logout_all"}).status_code == 400
    assert client.post("/logout").status_code == 400
    assert client.get("/logout").status_code == 405
    token = csrf(client)
    assert client.post("/logout", data={"csrf": token}).status_code == 303
    attacker.set_cookie(dashboard.ACCOUNT_COOKIE, cookie)
    assert attacker.get("/").status_code == 303
    assert users.audit_entries()[-1].action == "logout"
    assert users.verify_audit() is None


@pytest.mark.parametrize("expiry", ["idle", "absolute"])
def test_session_deadlines(accounts, expiry):
    _, _, app, client = accounts
    sessions = app.extensions["account_sessions"]
    now = [100.0]
    sessions.clock = lambda: now[0]
    sessions.lifetime, sessions.idle = 120, 60
    login(client)
    now[0] = 159
    assert client.get("/").status_code == 200
    now[0] = 218
    assert client.get("/").status_code == 200
    now[0] = 220 if expiry == "absolute" else 278
    assert client.get("/").status_code == 303


@pytest.mark.parametrize("mutation", ["password", "disable", "version", "role", "enable"])
def test_account_changes_revoke_sessions(accounts, mutation):
    _, users, app, client = accounts
    login(client)
    admin = users.authenticate("admin", PASSWORD)
    if mutation == "password":
        users.set_password("reader", PASSWORD + " changed", authorization=admin)
    elif mutation == "disable":
        users.disable("reader", authorization=admin)
    elif mutation == "enable":
        users.enable("reader", authorization=admin)
    elif mutation == "role":
        users.edit_user("reader", role="operator", disabled=False, authorization=admin)
    else:
        with users.transaction() as db:
            db.execute("UPDATE cb_user SET credential_version=credential_version+1 WHERE username='reader'")
    assert client.get("/").status_code == 303


def test_own_password_requires_current_and_revokes_other_logins(accounts):
    _, users, app, client = accounts
    login(client)
    other = app.test_client()
    login(other)
    assert len(app.extensions["account_sessions"].own(users.authenticate("reader", PASSWORD))) == 2
    assert submit(client, "/account", action="password", current_password="wrong password value", password=PASSWORD + " changed").status_code == 400
    assert other.get("/").status_code == 200
    assert submit(client, "/account", action="password", current_password=PASSWORD, password=PASSWORD + " changed").status_code == 303
    assert other.get("/").status_code == 303 and client.get("/").status_code == 303
    assert users.authenticate("reader", PASSWORD) is None
    assert users.authenticate("reader", PASSWORD + " changed")


def test_logout_all_invalidates_other_process_and_only_own_sessions(accounts):
    config, users, app, client = accounts
    login(client)
    other_app = dashboard.create_app(config)
    other = other_app.test_client()
    login(other)
    admin = app.test_client()
    login(admin, "admin")
    sessions = app.extensions["account_sessions"]
    assert len(sessions.own(users.authenticate("reader", PASSWORD))) == 1
    assert len(sessions.own(users.authenticate("admin", PASSWORD))) == 1
    own_page = client.get("/account").text
    for entry in app.extensions["account_sessions"].sessions:
        assert entry not in own_page
    assert submit(client, "/account", action="logout_all").status_code == 303
    assert other.get("/").status_code == 303
    assert admin.get("/users").status_code == 200
    assert users.audit_entries()[-1].action == "logout_all"


def test_role_crud_permissions_are_immediate_and_audited(accounts):
    _, users, app, client = accounts
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("custom", {"view", "run"}, authorization=admin)
    users.edit_user("reader", role="custom", disabled=False, authorization=admin)
    login(client)
    assert client.get("/").status_code == 200
    users.save_role("custom", set(), authorization=admin)
    assert client.get("/").status_code == 403
    assert client.get("/account").status_code == 200
    with pytest.raises(ConfigurationError, match="reassign"):
        users.delete_role("custom", authorization=admin)
    users.edit_user("reader", role="viewer", disabled=False, authorization=admin)
    users.delete_role("custom", authorization=admin)
    assert "custom" not in users.roles()
    with pytest.raises(ConfigurationError):
        users.save_role("admin", set(), authorization=admin)
    with pytest.raises(ConfigurationError):
        users.delete_role("admin", authorization=admin)
    with pytest.raises(ConfigurationError):
        users.save_role("custom", {"unknown"}, authorization=admin)
    assert users.verify_audit() is None
    assert any(e.action.startswith("role_save:custom:") and e.actor == "admin" for e in users.audit_entries())


@pytest.mark.parametrize("peer", ["192.0.2.1", "::ffff:192.0.2.1", "unknown", ""])
def test_bootstrap_ignores_forwarded_loopback(setup, peer):
    response = setup[2].get("/bootstrap", environ_overrides={"REMOTE_ADDR": peer},
                            headers={"X-Forwarded-For": "127.0.0.1"})
    assert response.status_code == 403


def test_bootstrap_requires_empty_store_and_transaction_guard(accounts):
    _, users, _, client = accounts
    login(client, "admin")
    assert client.get("/bootstrap").status_code == 403
    with pytest.raises(ConfigurationError, match="empty account store"):
        users.add("extra", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP, empty_store_only=True)


def test_bootstrap_csrf_and_ipv6(setup):
    client = setup[2]
    assert client.post("/bootstrap", data={"username": "admin", "password": PASSWORD}).status_code == 400
    assert client.get("/bootstrap", environ_overrides={"REMOTE_ADDR": "::1"}).status_code == 200


def test_shared_mode_transitions_to_accounts_without_restart(setup, monkeypatch):
    from cvebeacon.passwords import hash_password_value
    config = setup[0]
    monkeypatch.setenv(config.dashboard.password_hash_env, hash_password_value(PASSWORD))
    app = dashboard.create_app(config)
    client = app.test_client()
    assert submit(client, "/login", password=PASSWORD).status_code == 303
    assert client.get("/").status_code == 200
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True)
    assert client.get("/").status_code == 303
    now = [100.0]
    app.extensions["account_login_throttle"].clock = lambda: now[0]
    assert submit(client, "/login", password=PASSWORD).status_code == 401
    now[0] += 61
    login(client, "admin")
    monkeypatch.setenv(config.dashboard.password_hash_env, "invalid ignored hash")
    assert dashboard.create_app(config).test_client().get("/login").status_code == 200


def test_account_mode_cannot_fall_back_after_store_disappears(accounts):
    _, users, _, client = accounts
    login(client)
    users.path.rename(users.path.with_suffix(".saved"))
    assert client.get("/").status_code == 503
    assert client.get("/login").status_code == 503


def test_secure_cookie_host_and_security_headers(accounts):
    config = replace(accounts[0], dashboard=replace(accounts[0].dashboard, secure_cookie=True))
    app = dashboard.create_app(config)
    response = app.test_client().get("/login", base_url="https://localhost")
    cookie = response.headers["Set-Cookie"]
    assert all(value in cookie for value in ["HttpOnly", "Secure", "SameSite=Strict"])
    assert "Expires=" not in cookie and "Max-Age=" not in cookie
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
    assert app.test_client().get("/login", headers={"Host": "attacker.example"}).status_code == 400


def test_admin_pages_and_delegated_user_management(accounts):
    _, users, _, client = accounts
    login(client, "admin")
    assert submit(client, "/users", username="new", password=PASSWORD, role="viewer",
                  display_name="<b>Example</b>", email="new@example.test").status_code == 303
    assert "&lt;b&gt;Example&lt;/b&gt;" in client.get("/users").text
    assert submit(client, "/users/new", action="save", role="operator", disabled="yes",
                  display_name="Changed", email="changed@example.test").status_code == 303
    assert users.find("new").disabled and users.find("new").display_name == "Changed"
    assert submit(client, "/users/new", action="save", role="viewer").status_code == 303
    assert submit(client, "/users/new", action="password", password=PASSWORD + " reset").status_code == 303
    assert submit(client, "/users/new", action="unlock").status_code == 303
    assert submit(client, "/roles", action="save", name="manager", permission=["manage_users", "view_audit"]).status_code == 303
    assert submit(client, "/users/reader", action="save", role="manager").status_code == 303
    assert client.get("/audit").status_code == 200
    manager = client.application.test_client()
    login(manager)
    assert manager.get("/users").status_code == 200
    assert manager.get("/roles").status_code == 403
    assert manager.get("/audit").status_code == 200
    assert manager.get("/").status_code == 403
    assert users.verify_audit() is None


def test_audit_tamper_is_visible(accounts):
    _, users, _, client = accounts
    login(client, "admin")
    assert "Chain verified" in client.get("/audit").text
    with users.transaction() as db:
        db.execute("UPDATE cb_user_audit SET action='altered' WHERE id=1")
    assert "Chain verification failed at row 1" in client.get("/audit").text


@pytest.mark.parametrize("value", ["0", "true", "86401", "'900'", "59"])
def test_idle_config_validation(setup, value):
    path = setup[0].config_path
    path.write_text(path.read_text() + "\n[dashboard]\nsession_idle_seconds=" + value)
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_account_session_table_is_bounded_and_restart_revokes(accounts):
    config, _, app, client = accounts
    sessions = app.extensions["account_sessions"]
    sessions.max_sessions = 2
    login(client)
    identifier = client.get_cookie(dashboard.ACCOUNT_COOKIE).value
    for _ in range(5):
        sessions.issue()
    assert len(sessions.sessions) <= 2
    assert client.get("/").status_code == 200
    fresh = dashboard.create_app(config).test_client()
    fresh.set_cookie(dashboard.ACCOUNT_COOKIE, identifier)
    assert fresh.get("/").status_code == 303


def test_authenticated_session_flood_preserves_other_accounts(accounts):
    _, users, app, client = accounts
    sessions = app.extensions["account_sessions"]
    sessions.max_sessions = 3
    login(client, "admin")
    proof = users.authenticate("reader", PASSWORD)
    for _ in range(8):
        try:
            sessions.issue(proof)
        except ConfigurationError:
            pass
    assert len(sessions.sessions) <= 3
    assert client.get("/").status_code == 200


def test_account_login_spam_is_reserved_before_hashing(accounts, monkeypatch):
    _, users, app, client = accounts
    calls = []
    monkeypatch.setattr(app.extensions["dashboard_users"], "authenticate", lambda *args: calls.append(args))
    first = submit(client, "/login", username="missing", password=PASSWORD)
    for _ in range(5):
        response = submit(client, "/login", username="missing", password=PASSWORD)
        assert response.status_code == first.status_code == 401
    assert len(calls) == 1


def test_login_spam_keeps_worker_capacity_for_authenticated_requests(accounts, monkeypatch):
    _, _, app, client = accounts
    login(client, "admin")
    entered = threading.Barrier(3)
    release = threading.Event()

    def verify(*args):
        entered.wait(timeout=5)
        assert release.wait(5)

    monkeypatch.setattr(app.extensions["dashboard_users"], "authenticate", verify)

    def attempt(origin):
        visitor = app.test_client()
        token = csrf(visitor, "/login")
        return visitor.post("/login", data={"csrf": token, "username": "missing", "password": PASSWORD},
                            environ_overrides={"REMOTE_ADDR": origin})

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(attempt, "192.0.2.1")
        second = pool.submit(attempt, "192.0.2.2")
        entered.wait(timeout=5)
        try:
            assert attempt("192.0.2.3").status_code == 401
            assert client.get("/").status_code == 200
        finally:
            release.set()
        assert first.result().status_code == second.result().status_code == 401


@pytest.mark.parametrize("permissions,path,method,data,status", [
    ({"run"}, "/query", "GET", {}, 200),
    ({"run"}, "/reports", "GET", {}, 200),
    ({"view"}, "/query", "GET", {}, 403),
    ({"view"}, "/reports", "GET", {}, 403),
    ({"run"}, "/query", "POST", {"vendor": "acme", "product": "widget", "version": "1"}, 403),
    ({"run"}, "/reports", "POST", {"format": "json"}, 403),
    ({"manage_users"}, "/roles", "GET", {}, 403),
    ({"manage_users"}, "/roles", "POST", {"action": "save", "name": "newrole"}, 403),
])
def test_capabilities_grant_only_their_required_pages(accounts, permissions, path, method, data, status):
    _, users, _, client = accounts
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("limited", permissions, authorization=admin)
    users.edit_user("reader", role="limited", disabled=False, authorization=admin)
    login(client)
    response = client.open(path, method=method, data={"csrf": csrf(client), **data})
    assert response.status_code == status


def test_shared_password_protects_bootstrap(setup, monkeypatch):
    from cvebeacon.passwords import hash_password_value
    config = setup[0]
    monkeypatch.setenv(config.dashboard.password_hash_env, hash_password_value(PASSWORD))
    client = dashboard.create_app(config).test_client()
    response = client.get("/bootstrap")
    assert response.status_code == 303 and response.headers["Location"] == "/login"
    assert submit(client, "/login", password=PASSWORD).status_code == 303
    assert submit(client, "/bootstrap", username="admin", password=PASSWORD).status_code == 303


@pytest.mark.parametrize("shared", [False, True])
def test_missing_store_at_restart_cannot_downgrade_authentication(accounts, monkeypatch, shared):
    from cvebeacon.passwords import hash_password_value
    from cvebeacon.errors import StateError
    config, users, _, _ = accounts
    if shared:
        monkeypatch.setenv(config.dashboard.password_hash_env, hash_password_value(PASSWORD))
    users.path.unlink()
    with pytest.raises(StateError):
        dashboard.create_app(config)


def test_inaccessible_store_cannot_look_like_fresh_install(accounts, monkeypatch):
    import os
    from cvebeacon.errors import StateError
    config, users, _, _ = accounts
    original_exists, original_lstat = Path.exists, os.lstat
    monkeypatch.setattr(Path, "exists", lambda path: False if path == users.path else original_exists(path))

    def lstat(path, *args, **kwargs):
        if Path(path) == users.path:
            raise PermissionError("unreadable account store")
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(StateError):
        dashboard.create_app(config)


def test_remote_override_cannot_bypass_missing_account_store(accounts, monkeypatch):
    from cvebeacon.errors import StateError
    config, users, _, _ = accounts
    users.path.unlink()
    with pytest.raises(StateError):
        dashboard.serve(config, host="0.0.0.0", allow_unauthenticated_remote=True)


def test_zero_enabled_admin_store_is_detected(accounts, caplog):
    config, users, _, _ = accounts
    with users.transaction() as db:
        db.execute("UPDATE cb_user SET disabled=1 WHERE is_admin=1")
    dashboard.create_app(config)
    assert "no enabled administrator" in caplog.text
    assert "users add NAME --admin" in caplog.text


def test_security_recovery_and_permission_boundaries_are_documented():
    guide = (Path(__file__).resolve().parents[1] / "docs" / "DASHBOARD.md").read_text()
    watch = (Path(__file__).resolve().parents[1] / "docs" / "WATCH.md").read_text()
    assert "full administrative trust" not in guide
    assert "256 anonymous" in guide and "16 per account" in guide
    assert "no enabled administrator" in guide
    assert "creation-lock file" in guide and "shared-password login" in guide
    assert "10,000" in guide and "login_failures_suppressed" in guide
    for document in (guide, watch):
        assert "cb_role" in document and "cb_user_role" in document


def test_existing_account_store_is_migrated_without_creating_a_missing_one(accounts):
    config, users, _, _ = accounts
    with users.transaction() as db:
        db.execute("DROP TABLE cb_role")
        db.execute("DROP TABLE cb_user_role")
        db.execute("DELETE FROM cb_user_meta WHERE key='roles_initialized'")
    app = dashboard.create_app(config)
    login(app.test_client())
    assert app.extensions["dashboard_users"].roles()["viewer"] == {"view"}
