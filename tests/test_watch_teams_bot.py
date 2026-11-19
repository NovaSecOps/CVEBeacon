"""Offline coverage for the optional Bot Connector channel."""

from dataclasses import replace
from datetime import timedelta
import json
import os
import sqlite3
from urllib.parse import parse_qs

import httpx
import pytest

from cvebeacon.errors import ConfigurationError, StateError
from cvebeacon.watch.channels import parse_channels
from cvebeacon.watch.delivery import deliver_pending, send_test
from cvebeacon.watch.messages import OutgoingMessage, build_messages
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.teams_bot import BOT_SCOPE, GRAPH_SCOPE, _Session, adaptive_card, send_bot
from test_watch_delivery import seed, rows
from watch_support import NOW, mock_client, write_config

TENANT = "11111111-1111-4111-8111-111111111111"
APP = "22222222-2222-4222-8222-222222222222"
USER = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"
SECRET = "synthetic-private-secret"
TOKEN = "synthetic-private-token"
SERVICE = "https://smba.trafficmanager.net/teams/"
MESSAGE = OutgoingMessage((1,), "Test alert", "CVEBeacon alert", "CVEBeacon alert")


@pytest.fixture
def raw(tmp_path):
    secret = tmp_path / "bot-secret"
    secret.write_text(SECRET, encoding="utf-8")
    secret.chmod(0o600)
    return {"type": "teams_bot", "tenant_id": TENANT, "app_id": APP,
            "client_secret_file": secret.name, "recipients": [USER]}


def channel(raw, tmp_path):
    return parse_channels({"bot": raw}, base=tmp_path)[0]


def config(raw, tmp_path):
    base = write_config(tmp_path, channels='''
[watch.channels.bot]
type = "webhook"
url = "https://example.com/hook"
''', extra='''
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["bot"]
''')
    return replace(base, watch=replace(base.watch, channels=(channel(raw, tmp_path),)))


class Connector:
    def __init__(self):
        self.requests = []
        self.activity_status = {}
        self.token_status = 200
        self.create_status = 201

    def __call__(self, request):
        self.requests.append(request)
        if request.url.path.endswith("/token"):
            assert request.url.host == "login.microsoftonline.com"
            assert request.url.path == f"/{TENANT}/oauth2/v2.0/token"
            data = parse_qs(request.content.decode())
            assert data["client_id"] == [APP]
            assert data["client_secret"] == [SECRET]
            assert data["grant_type"] == ["client_credentials"]
            return httpx.Response(self.token_status, json={
                "access_token": TOKEN, "expires_in": 100,
                "error": SECRET + TOKEN,
            })
        if request.url.host == "graph.microsoft.com":
            assert request.method == "GET"
            assert request.url.params["$select"] == "id"
            assert request.headers["Authorization"] == "Bearer " + TOKEN
            return httpx.Response(200, json={"id": USER})
        assert request.url.host == "smba.trafficmanager.net"
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        if request.url.path.endswith("/conversations"):
            data = json.loads(request.content)
            assert "activity" not in data
            assert data["bot"] == {"id": "28:" + APP}
            assert data["channelData"] == {"tenant": {"id": TENANT}}
            assert data["isGroup"] is False
            recipient = data["members"][0]["id"]
            return httpx.Response(self.create_status, json={"id": "dm-" + recipient})
        assert request.url.path.endswith("/activities")
        recipient = request.url.path.split("/")[-2].removeprefix("dm-")
        status = self.activity_status.get(recipient, 200)
        if isinstance(status, Exception):
            raise status
        return httpx.Response(status, json={"id": "activity", "error": TOKEN + SECRET})

    def matching(self, suffix):
        return [request for request in self.requests if request.url.path.endswith(suffix)]


def test_config_defaults_and_canonical_recipients(raw, tmp_path):
    raw["recipients"] += [USER.upper(), "ALERTS@example.com", "alerts@example.com"]
    result = channel(raw, tmp_path)
    assert result.format == "adaptive_card"
    assert result.options["service_url"] == SERVICE
    assert result.options["recipients"] == (USER, "alerts@example.com")
    assert result.secret("client_secret").resolve() == SECRET
    assert SECRET not in repr(result)


@pytest.mark.parametrize("changes", [
    {"tenant_id": "common"}, {"app_id": "bad"}, {"client_secret": SECRET},
    {"client_secret_env": "BOT_SECRET"}, {"client_secret_file": ""},
    {"recipients": []}, {"recipients": "alerts@example.com"},
    {"recipients": ["not-a-user"]}, {"recipients": ["user@example.com\nsecret"]},
    {"recipients": ["user@example.com/path"]},
    {"format": "html"}, {"format": "text"}, {"format": ""},
    {"service_url": "http://example.com/teams"},
    {"service_url": "https://user:secret@example.com"},
    {"service_url": "https://example.com/?secret=value"},
    {"service_url": "https://example.com/../token"},
    {"service_url": "https://example.com/%2e%2e/token"},
    {"service_url": "https://example.com:bad/teams"},
    {"conversation_references": ["bad"]},
    {"conversation_references": [{"conversation_id": ""}]},
    {"conversation_references": [{"conversation_id": "id", "extra": "bad"}]},
])
def test_invalid_config_fails_closed(raw, tmp_path, changes):
    with pytest.raises(ConfigurationError):
        channel({**raw, **changes}, tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_secret_file_must_be_private(raw, tmp_path):
    (tmp_path / raw["client_secret_file"]).chmod(0o644)
    with pytest.raises(ConfigurationError, match="group or other"):
        channel(raw, tmp_path)


def test_card_golden():
    assert adaptive_card(MESSAGE) == {
        "type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.4",
                "body": [{"type": "TextBlock", "wrap": True, "text": "CVEBeacon alert"}],
            },
        }],
    }


def test_token_caching_expiry_scope_and_rotation(raw, tmp_path):
    connector = Connector()
    http = mock_client(connector)
    now = [0.0]
    session = _Session(channel(raw, tmp_path), http, 30, 1000, lambda: now[0], lambda _: None)
    assert session.token(BOT_SCOPE) == TOKEN
    now[0] = 89
    assert session.token(BOT_SCOPE) == TOKEN
    assert len(connector.matching("/token")) == 1
    now[0] = 90
    assert session.token(BOT_SCOPE) == TOKEN
    assert len(connector.matching("/token")) == 2
    session.token(GRAPH_SCOPE)
    assert len(connector.matching("/token")) == 3
    (tmp_path / raw["client_secret_file"]).write_text(SECRET + "-rotated")
    def rotated(request):
        connector.requests.append(request)
        assert parse_qs(request.content.decode())["client_secret"] == [SECRET + "-rotated"]
        return httpx.Response(200, json={"access_token": TOKEN, "expires_in": 100})
    http._client = httpx.Client(transport=httpx.MockTransport(rotated))
    session.token(BOT_SCOPE)
    assert len(connector.matching("/token")) == 4


@pytest.mark.parametrize("body", [
    {}, {"access_token": TOKEN}, {"access_token": TOKEN, "expires_in": True},
    {"access_token": TOKEN, "expires_in": -1},
    {"access_token": TOKEN, "expires_in": float("inf")},
    {"access_token": TOKEN + "\n", "expires_in": 100},
])
def test_invalid_token_response_is_redacted(raw, tmp_path, body):
    def handler(request):
        return httpx.Response(200, content=json.dumps(body))
    outcome = send_test(config(raw, tmp_path), mock_client(handler), "bot")
    assert not outcome.ok
    assert SECRET not in outcome.error and TOKEN not in outcome.error


def test_create_dm_reuse_after_reopen_and_skip_sent(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    http = mock_client(connector)
    report = deliver_pending(cfg, store, http, clock=lambda: NOW)
    assert not report.failed
    assert [result.status for result in report.channels[0].recipients] == ["sent"]
    assert rows(store) == [("bot", "sent", 0, None)]
    reopened = WatchStore(store.path)
    # A new event uses the persisted reference, without another create request.
    message = replace(MESSAGE, event_ids=(2,))
    assert send_bot(cfg.watch.channels[0], message, http, 30, reopened)[0].status == "sent"
    assert send_bot(cfg.watch.channels[0], message, http, 30, reopened)[0].status == "sent"
    assert len(connector.matching("/conversations")) == 1
    assert len(connector.matching("/activities")) == 2
    assert len(connector.matching("/token")) == 1


def test_upn_resolution_uses_separate_graph_token_once(raw, tmp_path):
    raw["recipients"] = ["alerts@example.com"]
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    http = mock_client(connector)
    assert not deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    assert send_bot(cfg.watch.channels[0], replace(MESSAGE, event_ids=(2,)), http, 30, store)[0].status == "sent"
    scopes = [parse_qs(request.content.decode())["scope"][0] for request in connector.matching("/token")]
    assert scopes == [GRAPH_SCOPE, BOT_SCOPE]
    assert sum(request.url.host == "graph.microsoft.com" for request in connector.requests) == 1


def test_conversation_reference_posts_without_lookup_or_create(raw, tmp_path):
    raw["recipients"] = []
    raw["conversation_references"] = [{"conversation_id": "channel;message=123"}]
    cfg = config(raw, tmp_path)
    connector = Connector()
    outcome = send_test(cfg, mock_client(connector), "bot")
    assert outcome.ok and len(outcome.recipients) == 1
    assert not connector.matching("/conversations")
    request = connector.matching("/activities")[0]
    assert request.url.raw_path.endswith(b"/channel%3Bmessage%3D123/activities")


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_recipient_errors_and_redaction(raw, tmp_path, status, caplog):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    connector.activity_status[USER] = status
    report = deliver_pending(cfg, store, mock_client(connector), clock=lambda: NOW, sleep=lambda _: None)
    assert report.failed
    result = report.channels[0].recipients[0]
    assert result.status == "failed" and str(status) in result.error
    assert rows(store)[0][1] == "failed"
    if status in (401, 403):
        assert result.attempts_limit == 3
    for text in (repr(report), repr(rows(store)), caplog.text):
        assert TOKEN not in text and SECRET not in text


def test_retry_after_waits_and_reuses_token(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    calls = []
    def handler(request):
        if request.url.path.endswith("/activities"):
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(429, headers={"Retry-After": "4"})
        return connector(request)
    now, sleeps = [0.0], []
    def sleep(delay):
        sleeps.append(delay)
        now[0] += delay
    report = deliver_pending(cfg, store, mock_client(handler), clock=lambda: NOW,
                             monotonic=lambda: now[0], sleep=sleep)
    assert not report.failed and sleeps == [4]
    assert len(calls) == 2 and len(connector.matching("/token")) == 1


def test_long_retry_after_is_persisted_without_busy_wait(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    def handler(request):
        if request.url.path.endswith("/activities"):
            return httpx.Response(429, headers={"Retry-After": "3600"})
        return connector(request)
    sleeps = []
    results = send_bot(cfg.watch.channels[0], MESSAGE, mock_client(handler), 30, store,
                       sleep=sleeps.append, wall_time=lambda: 100)
    assert results[0].status == "failed" and sleeps == []
    results = send_bot(cfg.watch.channels[0], MESSAGE, mock_client(lambda _: pytest.fail("early retry")),
                       30, store, wall_time=lambda: 200)
    assert results[0].status == "deferred" and "Retry-After" in results[0].error
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT not_before FROM watch_teams_bot_delivery").fetchone()[0] == 3700


@pytest.mark.parametrize("stage", ["token", "conversations", "activities"])
def test_timeout_is_ambiguous_only_when_card_may_have_been_sent(raw, tmp_path, stage):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    def handler(request):
        if request.url.path.endswith("/" + stage):
            raise httpx.ReadTimeout(TOKEN + SECRET)
        return connector(request)
    report = deliver_pending(cfg, store, mock_client(handler), clock=lambda: NOW)
    expected = "ambiguous" if stage == "activities" else "failed"
    assert rows(store)[0][1] == expected
    assert report.channels[0].recipients[0].status == expected
    assert TOKEN not in repr(report) and SECRET not in repr(report)


def test_mixed_recipients_retry_only_failed_and_preserve_ambiguous(raw, tmp_path):
    raw["recipients"] = [USER, OTHER]
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    connector.activity_status[OTHER] = 503
    http = mock_client(connector)
    assert deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    assert rows(store)[0][1] == "failed"
    assert len(connector.matching("/activities")) == 2
    connector.activity_status.clear()
    report = deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=1))
    assert not report.failed
    assert len(connector.matching("/activities")) == 3
    assert connector.matching("/activities")[-1].url.path.endswith(OTHER + "/activities")


def test_ambiguous_recipient_needs_explicit_retry(raw, tmp_path):
    raw["recipients"] = [USER, OTHER]
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    connector.activity_status[OTHER] = httpx.ReadTimeout(TOKEN)
    http = mock_client(connector)
    assert deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    assert rows(store)[0][1] == "ambiguous"
    connector.activity_status.clear()
    deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=1))
    assert len(connector.matching("/activities")) == 2
    report = deliver_pending(cfg, store, http, retry_ambiguous=True, clock=lambda: NOW + timedelta(hours=1))
    assert not report.failed and len(connector.matching("/activities")) == 3


def test_each_channel_test_sends_one_labelled_card_per_recipient(raw, tmp_path):
    raw["recipients"] = [USER, OTHER]
    cfg = config(raw, tmp_path)
    connector = Connector()
    http = mock_client(connector)
    for _ in range(2):
        outcome = send_test(cfg, http, "bot", clock=lambda: NOW)
        assert outcome.ok and len(outcome.recipients) == 2
    assert len(connector.matching("/activities")) == 4
    assert len(connector.matching("/conversations")) == 2
    for request in connector.matching("/activities"):
        assert "test" in json.loads(request.content)["attachments"][0]["content"]["body"][0]["text"].casefold()


def test_migrate_version_seven_preserves_existing_state(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    before = rows(store)
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TABLE watch_teams_bot_delivery")
        db.execute("DROP TABLE watch_teams_bot_conversation")
        db.execute("UPDATE watch_meta SET value='7' WHERE key='schema_version'")
        original_events = db.execute("SELECT * FROM watch_event").fetchall()
    reopened = WatchStore(store.path)
    reopened.initialize()
    reopened.initialize()
    assert reopened.metadata()["schema_version"] == "8"
    assert rows(reopened) == before
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT * FROM watch_event").fetchall() == original_events
        assert db.execute("SELECT count(*) FROM watch_teams_bot_delivery").fetchone() == (0,)
    reopened.teams_bot_conversation(TENANT, APP, USER, SERVICE, "dm-id")
    assert reopened.teams_bot_conversation(TENANT, APP, USER, SERVICE) == "dm-id"
    assert reopened.teams_bot_conversation(TENANT, OTHER, USER, SERVICE) is None
    assert reopened.teams_bot_conversation(OTHER, APP, USER, SERVICE) is None


def test_crash_recovery_keeps_recipient_ambiguous(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    key = ("bot", TENANT, APP, USER, "message")
    assert store.claim_teams_bot_recipient(key, retry_ambiguous=False, now=0) == "sending"
    future = WatchStore(store.path, clock=lambda: NOW + timedelta(hours=1))
    future.recover_sending()
    assert future.claim_teams_bot_recipient(key, retry_ambiguous=False, now=0) == "ambiguous"
    assert future.claim_teams_bot_recipient(key, retry_ambiguous=True, now=0) == "retrying_ambiguous"


def test_future_schema_is_rejected_transactionally(raw, tmp_path):
    store = seed(config(raw, tmp_path))
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TABLE watch_teams_bot_delivery")
        db.execute("UPDATE watch_meta SET value='99' WHERE key='schema_version'")
    with pytest.raises(StateError, match="unsupported"):
        store.initialize()
    with sqlite3.connect(store.path) as db:
        assert not db.execute("SELECT name FROM sqlite_master WHERE name='watch_teams_bot_delivery'").fetchall()


def test_new_pending_events_do_not_replay_successful_recipients(raw, tmp_path):
    raw["recipients"] = [USER, OTHER]
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    connector.activity_status[OTHER] = 503
    http = mock_client(connector)
    assert deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    seed(cfg, identifiers=("CVE-2026-0002",))
    connector.activity_status.clear()
    assert not deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=1)).failed
    user_requests = [request for request in connector.matching("/activities") if USER in request.url.path]
    # The first recipient gets the original event once and then the new event.
    assert len(user_requests) == 2
    assert "CVE-2026-0001" not in user_requests[-1].content.decode()


def test_bot_messages_use_the_workflow_utf8_limit(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg, identifiers=tuple(f"CVE-2026-{index:04d}" for index in range(1, 101)),
                 description="界" * 160)
    events = store.delivery_events("bot", catalogs=cfg.watch.sources, now=NOW)
    # Large batches of Unicode descriptions must be bounded in wire bytes too.
    for kind in ("teams", "teams_bot"):
        messages = build_messages(events, channel_type=kind, grouping="run", max_items=100,
                                  names={"critical": "界" * 7000})
        assert all(len(message.text.encode()) <= 24000 for message in messages)
    assert build_messages(events, channel_type="teams", grouping="run", max_items=100,
                          names={"critical": "界" * 7000}) == build_messages(
        events, channel_type="teams_bot", grouping="run", max_items=100,
        names={"critical": "界" * 7000})


def test_storage_failure_after_accepted_card_stays_ambiguous(raw, tmp_path, monkeypatch):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    def fail(*args, **kwargs):
        raise StateError("synthetic storage failure")
    monkeypatch.setattr(store, "finish_teams_bot_recipient", fail)
    report = deliver_pending(cfg, store, mock_client(Connector()), clock=lambda: NOW)
    assert report.failed
    assert rows(store)[0][1] == "ambiguous"


def test_migration_failure_rolls_back_new_tables(raw, tmp_path, monkeypatch):
    import cvebeacon.watch.store as storage
    store = seed(config(raw, tmp_path))
    with sqlite3.connect(store.path) as db:
        for table in ("delivery", "conversation", "batch"):
            db.execute("DROP TABLE watch_teams_bot_" + table)
        db.execute("UPDATE watch_meta SET value='7' WHERE key='schema_version'")
    monkeypatch.setattr(storage, "_SCHEMA", (*storage._SCHEMA, "INVALID MIGRATION STATEMENT"))
    with pytest.raises(StateError, match="transaction failed"):
        store.initialize()
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT value FROM watch_meta WHERE key='schema_version'").fetchone() == ("7",)
        assert not db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'watch_teams_bot_%'").fetchall()


def test_401_invalidates_token_without_replaying_the_activity(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    http = mock_client(connector)
    connector.activity_status[USER] = 401
    assert deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    assert len(connector.matching("/token")) == 1
    assert len(connector.matching("/activities")) == 1
    connector.activity_status.clear()
    assert not deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=1)).failed
    assert len(connector.matching("/token")) == 2
    assert len(connector.matching("/activities")) == 2


def test_multipart_retry_skips_confirmed_parts(raw, tmp_path, monkeypatch):
    from cvebeacon.watch import delivery
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    def parts(events, **kwargs):
        if not events:
            return ()
        identifiers = tuple(event.event_id for event in events)
        return tuple(replace(MESSAGE, event_ids=identifiers, text=f"part {index}",
                             part_index=index, part_count=2) for index in range(2))
    monkeypatch.setattr(delivery, "build_messages", parts)
    connector = Connector()
    activity_calls = []
    def handler(request):
        if request.url.path.endswith("/activities"):
            activity_calls.append(json.loads(request.content))
            if len(activity_calls) == 2:
                return httpx.Response(503)
        return connector(request)
    http = mock_client(handler)
    assert deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    assert rows(store)[0][1] == "ambiguous"
    assert not deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=1),
                               retry_ambiguous=True).failed
    assert [body["attachments"][0]["content"]["body"][0]["text"] for body in activity_calls] == [
        "part 0", "part 1", "part 1",
    ]


def test_redirect_is_not_followed_and_response_urls_are_ignored(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    def handler(request):
        if request.url.path.endswith("/conversations"):
            return httpx.Response(201, json={"id": "dm-" + USER,
                                            "serviceUrl": "https://example.com/steal"})
        if request.url.path.endswith("/activities"):
            connector.requests.append(request)
            return httpx.Response(302, headers={"Location": "https://example.com/" + TOKEN})
        return connector(request)
    report = deliver_pending(cfg, store, mock_client(handler), clock=lambda: NOW)
    assert report.failed and "302" in report.channels[0].error
    assert all(request.url.host != "example.com" for request in connector.requests)
    assert TOKEN not in repr(report)


@pytest.mark.parametrize("stage", ["token", "conversations"])
@pytest.mark.parametrize("status", [401, 403, 500])
def test_presend_http_errors_never_send_cards(raw, tmp_path, stage, status):
    cfg = config(raw, tmp_path)
    connector = Connector()
    connector.token_status = status if stage == "token" else 200
    connector.create_status = status if stage == "conversations" else 201
    outcome = send_test(cfg, mock_client(connector), "bot")
    assert not outcome.ok and str(status) in outcome.error
    assert not connector.matching("/activities")
    assert outcome.recipients[0].status == "failed"
    assert TOKEN not in repr(outcome) and SECRET not in repr(outcome)


def test_conversation_creation_timeout_can_retry_without_sending_duplicate_cards(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    create_calls = []
    def handler(request):
        if request.url.path.endswith("/conversations"):
            create_calls.append(request)
            if len(create_calls) == 1:
                raise httpx.ReadTimeout(SECRET)
        return connector(request)
    http = mock_client(handler)
    assert deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    assert not connector.matching("/activities")
    assert not deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=1)).failed
    assert len(create_calls) == 2 and len(connector.matching("/activities")) == 1


def test_delivery_budget_is_shared_by_all_recipient_requests(raw, tmp_path):
    raw["recipients"] = [USER, OTHER]
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    now = [0.0]
    def handler(request):
        now[0] += 1
        return connector(request)
    report = deliver_pending(cfg, store, mock_client(handler), clock=lambda: NOW,
                             monotonic=lambda: now[0], budget_seconds=3)
    assert report.failed
    assert len(connector.requests) == 3
    assert not any(OTHER in request.content.decode() for request in connector.requests)
    assert [result.status for result in report.channels[0].recipients] == ["sent", "failed"]


def test_expired_budget_keeps_parent_delivery_pending(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    now = iter([0, 2, 2, 2])
    report = deliver_pending(cfg, store, mock_client(lambda _: pytest.fail("expired budget sent")),
                             clock=lambda: NOW, monotonic=lambda: next(now), budget_seconds=1)
    assert not report.failed and rows(store)[0][1] == "pending"


def test_migration_creates_all_bot_tables(raw, tmp_path):
    store = seed(config(raw, tmp_path))
    with sqlite3.connect(store.path) as db:
        for name in ("conversation", "delivery", "batch"):
            db.execute("DROP TABLE watch_teams_bot_" + name)
        db.execute("UPDATE watch_meta SET value='7' WHERE key='schema_version'")
    store.initialize()
    with sqlite3.connect(store.path) as db:
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'watch_teams_bot_%'")}
    assert names == {"watch_teams_bot_conversation", "watch_teams_bot_delivery", "watch_teams_bot_batch"}


def test_invalid_shared_credentials_are_requested_once_per_batch(raw, tmp_path):
    raw["recipients"] = [USER, OTHER]
    cfg = config(raw, tmp_path)
    connector = Connector()
    connector.token_status = 401
    outcome = send_test(cfg, mock_client(connector), "bot")
    assert not outcome.ok and len(outcome.recipients) == 2
    assert all(result.status == "failed" for result in outcome.recipients)
    assert len(connector.matching("/token")) == 1


def test_failed_explicit_retry_preserves_recipient_ambiguity(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    connector.activity_status[USER] = httpx.ReadTimeout(TOKEN)
    http = mock_client(connector)
    assert deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    connector.activity_status[USER] = 403
    report = deliver_pending(cfg, store, http, retry_ambiguous=True,
                             clock=lambda: NOW + timedelta(hours=1))
    assert rows(store)[0][1] == "ambiguous"
    assert report.channels[0].recipients[0].status == "ambiguous"
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT status FROM watch_teams_bot_delivery").fetchone() == ("ambiguous",)


@pytest.mark.parametrize("url", [
    "https://example.com/", "https://smba.trafficmanager.net.example.com/",
    "https://smba.trafficmanager.net:444/", "https://smba.trafficmanager.net./",
    "http://smba.trafficmanager.net/", "http://127.0.0.1:1234/",
])
@pytest.mark.parametrize("reference", [False, True])
def test_service_url_allowlist_rejects_foreign_origins(raw, tmp_path, url, reference):
    raw["allow_insecure"] = True
    if reference:
        raw["conversation_references"] = [{"conversation_id": "id", "service_url": url}]
    else:
        raw["service_url"] = url
    with pytest.raises(ConfigurationError):
        channel(raw, tmp_path)



@pytest.mark.parametrize("reference", [False, True])
def test_runtime_service_url_validation_precedes_token_requests(raw, tmp_path, reference):
    cfg = config(raw, tmp_path)
    options = dict(cfg.watch.channels[0].options)
    if reference:
        options["conversation_references"] = (("id", "https://example.com/steal/"),)
    else:
        options["service_url"] = "https://example.com/steal/"
    unsafe = replace(cfg.watch.channels[0], options=options)
    with pytest.raises(ConfigurationError, match="Microsoft"):
        send_bot(unsafe, MESSAGE, mock_client(lambda _: pytest.fail("untrusted request")),
                 30, seed(cfg))


@pytest.mark.parametrize("stage", ["activities", "conversations", "graph"])
def test_shared_401_latches_scope_for_remaining_recipients(raw, tmp_path, stage):
    raw["recipients"] = ["one@example.com", "two@example.com"] if stage == "graph" else [USER, OTHER]
    cfg = config(raw, tmp_path)
    connector = Connector()
    rejected = []
    def handler(request):
        if request.url.path.endswith("/" + stage) or (stage == "graph" and request.url.host == "graph.microsoft.com"):
            rejected.append(request)
            return httpx.Response(401)
        return connector(request)
    outcome = send_test(cfg, mock_client(handler), "bot")
    assert not outcome.ok and len(outcome.recipients) == 2
    assert len(rejected) == 1
    assert len(connector.matching("/token")) == 1
    if stage == "graph":
        assert "Graph user lookup" in outcome.error


@pytest.mark.parametrize("initial", [False, True])
@pytest.mark.parametrize("stage", ["teams_bot_conversation", "save_teams_bot_messages"])
def test_presend_storage_failure_is_retryable(raw, tmp_path, monkeypatch, stage, initial):
    cfg = config(raw, tmp_path)
    store = seed(cfg, initial=initial)
    connector = Connector()
    def fail(*args, **kwargs):
        raise StateError("synthetic storage failure")
    monkeypatch.setattr(store, stage, fail)
    report = deliver_pending(cfg, store, mock_client(connector), clock=lambda: NOW)
    assert report.failed and rows(store)[0][1] == "failed"
    assert not connector.matching("/activities")


@pytest.mark.parametrize("initial", [False, True])
def test_retry_after_wait_does_not_spend_parent_failure_budget(raw, tmp_path, initial):
    raw["recipients"] = [USER, OTHER]
    cfg = config(raw, tmp_path)
    store = seed(cfg, initial=initial)
    connector = Connector()
    requests = []
    throttled = [True]
    def handler(request):
        if request.url.path.endswith(OTHER + "/activities"):
            requests.append(request)
            if throttled[0]:
                return httpx.Response(429, headers={"Retry-After": "604800"})
        return connector(request)
    http = mock_client(handler)
    for index in range(12):
        deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=7*index))
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT attempts FROM watch_delivery").fetchone()[0] <= 1
    assert len(requests) == 1
    throttled[0] = False
    assert not deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(days=8)).failed
    assert len(requests) == 2 and rows(store)[0][1] == "sent"
    assert len([r for r in connector.matching("/activities") if USER in r.url.path]) == 1


@pytest.mark.parametrize("change", ["ranking", "new_event"])
def test_initial_retry_freezes_membership_and_sample(raw, tmp_path, change):
    raw["recipients"] = [USER, OTHER]
    raw["max_items"] = 1
    cfg = config(raw, tmp_path)
    ids = ("CVE-2026-0001", "CVE-2026-0002") if change == "ranking" else ("CVE-2026-0001",)
    store = seed(cfg, identifiers=ids, initial=True)
    connector = Connector()
    connector.activity_status[OTHER] = 503
    http = mock_client(connector)
    assert deliver_pending(cfg, store, http, clock=lambda: NOW).failed
    original = connector.matching("/activities")[0].content
    if change == "ranking":
        with sqlite3.connect(store.path) as db:
            db.execute("UPDATE watch_cve SET cvss_json=? WHERE cve_id=?",
                       (json.dumps([{"provider": "nvd", "source": "security@example.com", "version": "3.1", "score": 10}]), ids[-1]))
    else:
        seed(cfg, identifiers=("CVE-2026-0002",), initial=True)
    connector.activity_status.clear()
    assert not deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=1)).failed
    calls = connector.matching("/activities")
    assert len(calls) == 3 and calls[-1].content == original
    if change == "new_event":
        assert rows(store)[-1][1] == "pending"
        assert not deliver_pending(cfg, store, http, clock=lambda: NOW + timedelta(hours=2)).failed
        assert "CVE-2026-0002" in connector.matching("/activities")[-1].content.decode()


def test_resolved_batches_are_pruned_and_indexes_exist(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    assert not deliver_pending(cfg, store, mock_client(Connector()), clock=lambda: NOW).failed
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM watch_teams_bot_batch").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM watch_teams_bot_delivery").fetchone() == (0,)
        indexes = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"watch_teams_bot_delivery_status", "watch_teams_bot_batch_scope"} <= indexes


def test_reference_only_channel_test_does_not_open_database(raw, tmp_path, monkeypatch):
    raw["recipients"] = []
    raw["conversation_references"] = [{"conversation_id": "existing"}]
    cfg = config(raw, tmp_path)
    monkeypatch.setattr(WatchStore, "initialize", lambda *_: pytest.fail("unneeded database write"))
    assert send_test(cfg, mock_client(Connector()), "bot").ok


def test_conversation_lookup_uses_readonly_connection(raw, tmp_path, monkeypatch):
    store = seed(config(raw, tmp_path))
    store.teams_bot_conversation(TENANT, APP, USER, SERVICE, "id")
    monkeypatch.setattr(store, "transaction", lambda **_: pytest.fail("read acquired write lock"))
    assert store.teams_bot_conversation(TENANT, APP, USER, SERVICE) == "id"


def test_long_lived_token_is_refreshed_at_bounded_cache_expiry(raw, tmp_path):
    connector = Connector()
    def handler(request):
        if request.url.path.endswith("/token"):
            connector.requests.append(request)
            return httpx.Response(200, json={"access_token": TOKEN, "expires_in": 172800})
        return connector(request)
    now = [0.0]
    session = _Session(channel(raw, tmp_path), mock_client(handler), 30, 200000,
                       lambda: now[0], lambda _: None)
    assert session.token(BOT_SCOPE) == TOKEN
    now[0] = 86400
    assert session.token(BOT_SCOPE) == TOKEN
    assert len(connector.matching("/token")) == 2


def test_recipient_summary_is_bounded_and_identifies_parts():
    from cvebeacon.watch.delivery import ChannelSummary, format_channel_line
    from cvebeacon.watch.teams_bot import RecipientResult
    results = tuple(RecipientResult("conversation:private-id", "failed", part_index=i)
                    for i in range(30))
    line = format_channel_line(ChannelSummary("bot", "teams_bot", recipients=results))
    assert "30 failed" in line and "part 1" in line
    assert "private-id" not in line and len(line) < 1500


@pytest.mark.parametrize("ok", [False, True])
def test_cli_channel_test_prints_recipient_outcomes(raw, tmp_path, monkeypatch, capsys, ok):
    from cvebeacon import cli
    from cvebeacon.watch.delivery import TestOutcome
    from cvebeacon.watch.teams_bot import RecipientResult
    import cvebeacon.watch.delivery as delivery

    cfg = config(raw, tmp_path)
    monkeypatch.setattr(cli, "load_config", lambda *_: cfg)
    monkeypatch.setattr(delivery, "send_test", lambda *_: TestOutcome(
        "bot", "teams_bot", ok, recipients=(RecipientResult("conversation:private-id", "sent" if ok else "failed"),)))
    assert cli.main(["--config", str(cfg.config_path), "watch", "notify", "test", "bot"]) == (0 if ok else 3)
    output = capsys.readouterr().out
    assert "recipients:" in output and "destination 1 part 1" in output
    assert "private-id" not in output


def test_shared_workflow_and_bot_card_builder_preserves_wire_bytes():
    from cvebeacon.watch.messages import teams_adaptive_card
    from cvebeacon.watch.teams_bot import adaptive_card
    assert adaptive_card is teams_adaptive_card
    expected = b'{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.4","body":[{"type":"TextBlock","wrap":true,"text":"CVEBeacon alert"}]}}]}'
    assert json.dumps(teams_adaptive_card(MESSAGE), separators=(",", ":")).encode() == expected


def test_connector_request_rechecks_host_before_attaching_token(raw, tmp_path):
    session = _Session(channel(raw, tmp_path), mock_client(lambda _: pytest.fail("foreign request")),
                       30, 1000, lambda: 0, lambda _: None)
    with pytest.raises(ConfigurationError, match="Microsoft"):
        session.request("POST", "https://example.com/steal", scope=BOT_SCOPE,
                        headers={"Authorization": "Bearer " + TOKEN})


def test_multipart_results_keep_destination_and_part_identity(raw, tmp_path):
    raw["recipients"] = [USER, OTHER]
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    http = mock_client(connector)
    first = send_bot(cfg.watch.channels[0], replace(MESSAGE, part_index=0), http, 30, store)
    second = send_bot(cfg.watch.channels[0], replace(MESSAGE, part_index=1), http, 30, store)
    assert [(r.destination_index, r.part_index) for r in (*first, *second)] == [(0,0),(1,0),(0,1),(1,1)]


def test_pruning_preserves_an_ambiguous_destination(raw, tmp_path):
    cfg = config(raw, tmp_path)
    store = seed(cfg)
    connector = Connector()
    connector.activity_status[USER] = httpx.ReadTimeout("synthetic interruption")
    assert deliver_pending(cfg, store, mock_client(connector), clock=lambda: NOW).failed
    # A completed parent alone cannot erase unconfirmed destination evidence.
    store.mark_delivery((1,), "bot", "sent")
    store.prune_teams_bot_batches("bot", TENANT, APP)
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM watch_teams_bot_batch").fetchone() == (1,)
        assert db.execute("SELECT status FROM watch_teams_bot_delivery").fetchone() == ("ambiguous",)

