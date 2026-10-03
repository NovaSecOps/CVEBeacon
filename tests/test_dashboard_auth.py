from dataclasses import replace
import re
import warnings

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from cvebeacon import cli, dashboard, dashboard_auth
from cvebeacon.config import load_config
from cvebeacon.errors import CVEBeaconError
from test_dashboard import setup, post, dump, result

PASSWORD = "Synthetic dashboard password"


@pytest.fixture(scope="module")
def encoded():
    return generate_password_hash(PASSWORD)


@pytest.fixture
def authenticated(setup, monkeypatch, encoded):
    config, store, _ = setup
    monkeypatch.setenv(config.dashboard.password_hash_env, encoded)
    app = dashboard.create_app(config)
    return config, store, app.test_client()


@pytest.mark.parametrize("path", ["/", "/assets", "/asset?asset_id=a", "/findings", "/history", "/event/1", "/sources", "/reports", "/query", "/missing"])
def test_protected_views_and_no_redirect_parameters(authenticated, path):
    client = authenticated[2]
    response = client.get(path)
    assert response.status_code == 303 and response.headers["Location"] == "/login"
    assert "Widget" not in response.text


def test_login_static_only_and_host_checks(authenticated):
    client = authenticated[2]
    assert client.get("/login").status_code == 200
    assert client.get("/static/dashboard.css").status_code == 200
    assert client.get("/login", headers={"Host": "attacker.example"}).status_code == 400
    assert client.get("/login", headers={"X-Forwarded-Host": "attacker.example"}).status_code == 200
    assert client.post("/query").status_code == 303
    assert client.post("/reports").status_code == 303


def test_login_csrf_session_rotation_logout_replay_and_expiry(authenticated):
    client = authenticated[2]
    auth = client.application.extensions["dashboard_auth"]
    clock = [100.0]
    auth.clock = lambda: clock[0]
    assert client.post("/login", data={"password": PASSWORD}).status_code == 400
    client.get("/login")
    with client.session_transaction() as session:
        old_csrf = session["csrf"]
        session["untrusted"] = "prelogin"
    old_cookie = client.get_cookie("cvebeacon_session").value
    assert post(client, "/login", password=PASSWORD).status_code == 303
    with client.session_transaction() as session:
        assert "untrusted" not in session and session["csrf"] != old_csrf
        assert set(session) == {"auth_id", "csrf"}
    logged_cookie = client.get_cookie("cvebeacon_session").value
    assert logged_cookie != old_cookie
    attacker = client.application.test_client()
    attacker.set_cookie("cvebeacon_session", old_cookie)
    assert attacker.get("/").status_code == 303
    assert client.get("/").status_code == 200
    assert client.post("/logout").status_code == 400
    assert client.get("/logout").status_code == 405
    assert client.post("/query", data={"csrf": old_csrf}).status_code == 400
    with client.session_transaction() as session:
        token = session["csrf"]
    assert client.post("/logout", data={"csrf": token}).status_code == 303
    assert client.get("/").status_code == 303
    attacker.set_cookie("cvebeacon_session", logged_cookie)
    assert attacker.get("/").status_code == 303
    assert post(client, "/login", password=PASSWORD).status_code == 303
    clock[0] += auth.lifetime - 1
    assert client.get("/").status_code == 200
    clock[0] += 1
    assert client.get("/").status_code == 303  # activity did not extend absolute expiry


def test_failures_throttle_origins_not_forwarded_headers(authenticated, monkeypatch, caplog, encoded):
    client = authenticated[2]
    auth = client.application.extensions["dashboard_auth"]
    clock = [100.0]
    auth.clock = lambda: clock[0]
    calls = []
    original = dashboard_auth.check_password_hash
    monkeypatch.setattr(dashboard_auth, "check_password_hash", lambda h, p: calls.append(True) or original(h, p))
    response = post(client, "/login", password="wrong private attempted password")
    assert response.status_code == 401
    token = re.search(r'name="csrf" value="([^"]+)"', response.text)[1]
    second = client.post("/login", data={"csrf": token, "password": PASSWORD}, headers={"X-Forwarded-For": "192.0.2.1"})
    assert second.status_code == 401 and second.text == response.text and len(calls) == 1
    another = client.application.test_client()
    another.get("/login")
    with another.session_transaction() as session:
        token2 = session["csrf"]
    assert another.post("/login", data={"csrf": token2, "password": PASSWORD}, environ_overrides={"REMOTE_ADDR": "192.0.2.2"}).status_code == 303
    clock[0] += 1
    assert post(client, "/login", password=PASSWORD).status_code == 303
    for path in ("/", "/login", "/sources", "/query"):
        text = client.get(path).text
        assert encoded not in text and PASSWORD not in text
    assert PASSWORD not in caplog.text and "wrong private attempted password" not in caplog.text


def test_bounds_and_no_permanent_lockout(encoded):
    clock = [1.0]
    auth = dashboard_auth.DashboardAuth(encoded, 60, clock=lambda: clock[0])
    auth.max_origins = 2
    for origin in ("a", "b", "c"):
        assert auth.login(origin, "wrong") is None
    assert len(auth.attempts) == 2
    clock[0] += 901
    assert auth.login("c", PASSWORD)
    auth.max_sessions = 2
    first = auth.login("a", PASSWORD)
    auth.login("b", PASSWORD)
    auth.login("c", PASSWORD)
    assert len(auth.sessions) == 2 and not auth.valid(first)


@pytest.mark.parametrize("value", ["", "plaintext", "pbkdf2:sha256:1000$salt$hash", "scrypt:999999:8:1$salt$hash"])
def test_invalid_config_fails_closed(setup, monkeypatch, value):
    monkeypatch.setenv(setup[0].dashboard.password_hash_env, value)
    with pytest.raises(CVEBeaconError, match="invalid dashboard password hash"):
        dashboard.create_app(setup[0])


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.1", "dashboard.example"])
def test_remote_requires_override(setup, host):
    with pytest.raises(CVEBeaconError, match="allow-unauthenticated-remote"):
        dashboard.serve(setup[0], host=host)


def test_authenticated_remote_and_secure_cookies(authenticated, monkeypatch, caplog):
    import waitress
    config = authenticated[0]
    calls = []
    class Server:
        def run(self): pass
        def close(self): pass
    def create(app, **kwargs):
        calls.append(app)
        return Server()
    monkeypatch.setattr(waitress, "create_server", create)
    config = replace(config, dashboard=replace(config.dashboard, secure_cookie=True))
    dashboard.serve(config, host="0.0.0.0")
    response = calls[0].test_client().get("/login", base_url="https://localhost")
    cookie = response.headers["Set-Cookie"]
    assert all(item in cookie for item in ("Secure", "HttpOnly", "SameSite=Strict"))
    assert "Expires=" not in cookie and "Max-Age=" not in cookie
    assert "HTTPS" in caplog.text
    assert calls[0].test_client().get("/login", headers={"Host": "attacker.example"}).status_code == 400


def test_authenticated_manual_query_isolation(authenticated, monkeypatch):
    _, store, client = authenticated
    store.record_scan([result()], channels=("teams", "email"))
    before = dump(store)
    monkeypatch.setattr(cli, "_run_query", lambda *args: [result()])
    post(client, "/login", password=PASSWORD)
    assert post(client, "/query", vendor="Acme", product="Widget", version="1").status_code == 200
    assert post(client, "/reports", format="json").status_code == 200
    assert dump(store) == before


def test_hash_helper_without_config(monkeypatch, capsys):
    values = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr(dashboard_auth.getpass, "getpass", lambda _: next(values))
    assert cli.main(["--config", "absent.toml", "dashboard", "hash-password"]) == 0
    value = capsys.readouterr().out.strip()
    assert PASSWORD not in value and check_password_hash(value, PASSWORD)


@pytest.mark.parametrize("values", [("short", "short"), (PASSWORD, "different"), (" " * 12, " " * 12)])
def test_hash_helper_rejects_bad_inputs(monkeypatch, capsys, values):
    values = iter(values)
    monkeypatch.setattr(dashboard_auth.getpass, "getpass", lambda _: next(values))
    assert cli.main(["dashboard", "hash-password"]) == 2
    assert not capsys.readouterr().out


def test_hash_helper_refuses_echoing_fallback(monkeypatch):
    def prompt(_):
        warnings.warn("no terminal", dashboard_auth.getpass.GetPassWarning)
    monkeypatch.setattr(dashboard_auth.getpass, "getpass", prompt)
    with pytest.raises(CVEBeaconError, match="hidden"):
        dashboard_auth.hash_password()


@pytest.mark.parametrize("setting", ["session_lifetime_seconds=0", "session_lifetime_seconds=true", "session_lifetime_seconds=86401", "secure_cookie='yes'", "password='secret'", "password_hash='hash'", "password_hash_env='' "])
def test_dashboard_config_validation(setup, setting):
    path = setup[0].config_path
    path.write_text(path.read_text() + "\n[dashboard]\n" + setting, encoding="utf-8")
    with pytest.raises(CVEBeaconError):
        load_config(path)
