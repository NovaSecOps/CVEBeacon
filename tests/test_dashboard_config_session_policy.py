"""Reviewed session classifications and access-changing save regressions."""

import pytest

from cvebeacon import dashboard_config as dc
from test_dashboard import setup
from test_dashboard_config import accounts, account_fixture, preview, confirm
from test_dashboard_accounts import login


@pytest.mark.parametrize("before,after", [
    ({"notifications": {"email": {"enabled": False}}}, {"notifications": {"email": {"enabled": False, "future_access": True}}}),
    ({"watch": {"channels": {"email": {"type": "smtp"}}}}, {"watch": {"channels": {"email": {"type": "smtp", "future_access": True}}}}),
    ({"watch": {"rules": [{"name": "example"}]}}, {"watch": {"rules": [{"name": "example", "future_access": True}]}}),
    ({"future": True}, {"future": 1}), ({"future": 1}, {"future": 1.0}),
    ({"future": {"nested": [True]}}, {"future": {"nested": [1]}}),
    ({"notifications": {"email": {"future_access": True}}}, {"notifications": {"email": {"future_access": 1}}}),
])
def test_unknown_nested_and_type_changes_end_sessions(before, after):
    assert dc.session_settings_changed(before, after)



def test_discovered_schema_keys_are_not_automatically_session_safe(monkeypatch):
    monkeypatch.setitem(dc.WATCH_FIELDS, "future_access", False)
    monkeypatch.setitem(dc.SCHEMAS, "future", [("future", {"enabled": False})])
    assert dc.session_settings_changed({}, {"watch": {"future_access": True}})
    assert dc.session_settings_changed({}, {"future": {"enabled": True}})



def test_recovered_reference_does_not_cancel_preview_lockout(accounts, tmp_path, monkeypatch):
    _, _, app, client = accounts
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    reference = tmp_path / "reference.txt"
    reference.write_text("Synthetic reference contents")
    reference.chmod(0o600)
    login(client, "admin")
    assert confirm(client, preview(client, "sources", g0_nvd_api_key_file=str(reference)), "sources").status_code == 303
    other = app.test_client()
    login(other, "admin")
    reference.unlink()
    response = preview(client, "backups")
    assert 'name="lockout"' in response.text
    reference.write_text("Synthetic reference contents")
    reference.chmod(0o600)
    assert confirm(client, response, "backups", lockout="yes").status_code == 303
    assert client.get("/").status_code == 303
    assert other.get("/").status_code == 303



@pytest.mark.parametrize("document", [
    {"watch": {"rules": [{"condition": {"future_access": True}}]}},
    {"watch": {"rules": [{"condition": {"any": [{"future_access": True}]}}]}},
    {"watch": {"enabled": {"future_access": True}}},
])
def test_unclassified_shapes_inside_known_fields_end_sessions(document):
    assert dc.session_settings_changed({}, document)



def test_new_fields_in_existing_presentation_schema_are_unclassified(monkeypatch):
    schema = {**dc.SCHEMAS["http"][0][1], "future_access": False}
    monkeypatch.setitem(dc.SCHEMAS, "http", [("http", schema)])
    assert dc.session_settings_changed({}, {"http": {"future_access": True}})



@pytest.mark.parametrize("section,field", [("watch", "g0_database"), ("system", "g0_database")])
def test_explicit_and_indirect_account_store_moves_end_both_sessions(accounts, tmp_path, section, field):
    from test_dashboard_accounts import PASSWORD
    from cvebeacon.watch.users import BOOTSTRAP, UserStore
    _, _, app, client = accounts
    destination = tmp_path / "destination"
    store = UserStore(destination / "cvebeacon-users.db")
    store.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    login(client, "admin")
    other = app.test_client()
    login(other, "admin")
    response = preview(client, section, **{field: str(destination / "store.db")})
    assert 'name="lockout"' in response.text
    assert confirm(client, response, section, lockout="yes").status_code == 303
    assert client.get("/").status_code == 303
    assert other.get("/").status_code == 303



def test_dashboard_rollback_ends_both_sessions(accounts):
    _, _, app, client = accounts
    login(client, "admin")
    response = preview(client, "dashboard", g0_session_idle_seconds="120")
    assert confirm(client, response, "dashboard", lockout="yes").status_code == 303
    login(client, "admin")
    other = app.test_client()
    login(other, "admin")
    response = preview(client, "backups")
    assert 'name="lockout"' in response.text
    assert confirm(client, response, "backups", lockout="yes").status_code == 303
    assert client.get("/").status_code == 303
    assert other.get("/").status_code == 303
