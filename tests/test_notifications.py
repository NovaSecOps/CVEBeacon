from __future__ import annotations

import httpx
import pytest

from cvebeacon.config import AppConfig, EmailConfig, HttpConfig, InventoryConfig, TeamsConfig
from cvebeacon.errors import NotificationError
from cvebeacon.http import HttpClient
from cvebeacon.models import Applicability, Asset, Finding, QueryResult, Vulnerability
from cvebeacon.notifications import AlertItem, GraphMailNotifier, TeamsNotifier, configured_channels, render_text
from cvebeacon.state import StateStore
from cvebeacon import cli


ITEM = AlertItem(1, "asset-1", "CVE-2026-0001", "new", "affected", 9.8, True, False)


def test_teams_accepts_non_json_success_and_does_not_retry_post():
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, text="1")
    http = HttpClient(HttpConfig(retries=3), client=httpx.Client(transport=httpx.MockTransport(handler)))
    TeamsNotifier(http, "https://workflow.example.test/secret").send([ITEM])
    assert len(requests) == 1
    assert "CISA KEV" in requests[0].content.decode()


def test_teams_failure_is_not_automatically_retried():
    requests = []
    def handler(request):
        requests.append(request); return httpx.Response(503)
    http = HttpClient(HttpConfig(retries=3), client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(NotificationError): TeamsNotifier(http, "https://workflow.example.test/secret").send([ITEM])
    assert len(requests) == 1


def test_graph_token_then_mail_202():
    requests = []
    def handler(request):
        requests.append(request)
        if "oauth2" in str(request.url): return httpx.Response(200, json={"access_token": "token"})
        return httpx.Response(202)
    http = HttpClient(HttpConfig(retries=1), client=httpx.Client(transport=httpx.MockTransport(handler)))
    GraphMailNotifier(http, tenant_id="tenant", client_id="client", client_secret="secret", sender="sender@example.invalid", recipients=("recipient@example.invalid",)).send([ITEM])
    assert len(requests) == 2
    assert requests[1].headers["Authorization"] == "Bearer token"


def test_render_is_consolidated():
    text = render_text([ITEM, ITEM])
    assert "2 material" in text and text.count("CVE-2026-0001") == 2


def test_transport_errors_do_not_expose_webhook_secret():
    def handler(request): raise httpx.ConnectError("connection refused", request=request)
    http = HttpClient(HttpConfig(retries=0), client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(NotificationError) as error:
        TeamsNotifier(http, "https://workflow.example.test/very-secret-token").send([ITEM])
    assert "very-secret-token" not in str(error.value)


@pytest.mark.parametrize("teams,email,expected", [(False, False, ()), (True, False, ("teams",)), (False, True, ("email",)), (True, True, ("teams", "email"))])
def test_notification_channel_matrix(tmp_path, teams, email, expected):
    config = AppConfig(tmp_path / "c.toml", InventoryConfig(tmp_path / "i.csv"), tmp_path / "s.db", tmp_path, teams=TeamsConfig(enabled=teams), email=EmailConfig(enabled=email))
    assert configured_channels(config) == expected


def test_delivery_is_accepted_only_after_remote_acceptance(tmp_path, monkeypatch):
    config = AppConfig(tmp_path / "c.toml", InventoryConfig(tmp_path / "i.csv"), tmp_path / "state.db", tmp_path, teams=TeamsConfig(enabled=True))
    asset = Asset("a", "Any", "Product", "1")
    finding = Finding(asset, Vulnerability("CVE-2026-0001"), Applicability.AFFECTED, "high", "exact")
    store = StateStore(config.database_path)
    _, event_ids = store.record_scan([QueryResult(asset, (finding,), ())], channels=("teams",))
    monkeypatch.setenv(config.teams.webhook_env, "https://workflow.example.test/secret")
    monkeypatch.setattr(TeamsNotifier, "send", lambda self, items: (_ for _ in ()).throw(NotificationError("offline")))
    with pytest.raises(NotificationError): cli._notify_pending(config, store, object(), "teams")
    assert [row["event_id"] for row in store.pending_events("teams")] == event_ids
    monkeypatch.setattr(TeamsNotifier, "send", lambda self, items: None)
    assert cli._notify_pending(config, store, object(), "teams") == 1
    assert store.pending_events("teams") == []
