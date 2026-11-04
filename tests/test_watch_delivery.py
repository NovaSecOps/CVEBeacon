from __future__ import annotations

import json
import socket
import socketserver
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from watch_support import NOW, mock_client, nvd_cve, nvd_page, write_config

from cvebeacon import cli
from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.delivery import deliver_pending, send_test
from cvebeacon.watch.records import CVSSEntry, WatchRecord
from cvebeacon.watch.store import WatchStore

REAL_CONNECT = socket.socket.__mro__[1].connect


def loopback_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host not in {"127.0.0.1", "localhost"}:
        raise OSError("test only resolves loopback")
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("127.0.0.1", port),
        )
    ]

WEBHOOK = """
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
"""

RULE = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["hook"]
"""


def make_config(tmp_path, *, channels: str = WEBHOOK, rules: str = RULE, sources=("nvd",)):
    return write_config(tmp_path, sources=sources, channels=channels, extra=rules)


def seed(config, *, identifiers: tuple[str, ...] = ("CVE-2026-0001",), initial: bool = False, **overrides):
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    records = []
    for identifier in identifiers:
        values: dict[str, Any] = {
            "cve_id": identifier,
            "status": "published",
            "description": "Acme Widget allows remote code execution.",
            "source_identifier": "security@acme.example",
            "cvss": (CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),),
        }
        values.update(overrides)
        records.append(WatchRecord(**values))
    store.upsert_nvd(records, catalogs=config.watch.sources)
    store.evaluate_touched(
        config.watch.rules,
        catalogs=config.watch.sources,
        initial=initial,
    )
    return store


def rows(store: WatchStore) -> list[tuple]:
    with sqlite3.connect(store.path) as db:
        return db.execute(
            "SELECT channel,status,attempts,last_error FROM watch_delivery ORDER BY channel"
        ).fetchall()


def deliver(config, store, handler, **kwargs):
    http = mock_client(handler)
    kwargs.setdefault("clock", lambda: NOW)
    kwargs.setdefault("monotonic", lambda: 0.0)
    return deliver_pending(config, store, http, **kwargs)


def test_success_marks_the_delivery_sent(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    report = deliver(config, store, handler)
    assert report.failed is False
    summary = report.channels[0]
    assert (summary.channel, summary.messages, summary.events) == ("hook", 1, 1)
    assert rows(store) == [("hook", "sent", 0, None)]
    payload = json.loads(requests[0].content)
    assert payload["version"] == 1
    assert payload["events"][0]["cve_id"] == "CVE-2026-0001"


def test_sending_is_committed_before_the_request(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    observed = []

    def handler(request):
        with sqlite3.connect(store.path) as db:
            observed.append(db.execute("SELECT status FROM watch_delivery").fetchone()[0])
        return httpx.Response(200, json={})

    deliver(config, store, handler)
    assert observed == ["sending"]


def test_definite_failure_is_retryable(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)

    def handler(request):
        raise httpx.ConnectError("refused")

    report = deliver(config, store, handler)
    summary = report.channels[0]
    assert (summary.failed, summary.ambiguous) == (1, 0)
    assert summary.error == "connection failed"
    assert rows(store) == [("hook", "failed", 1, "connection failed")]


def test_timeout_after_sending_is_ambiguous(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)

    def handler(request):
        raise httpx.ReadTimeout("timeout")

    report = deliver(config, store, handler)
    summary = report.channels[0]
    assert (summary.failed, summary.ambiguous) == (0, 1)
    assert rows(store) == [("hook", "ambiguous", 1, "connection interrupted")]


def test_failed_delivery_waits_for_backoff_then_retries(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)

    def failing(request):
        raise httpx.ConnectError("refused")

    first = deliver(config, store, failing)
    assert first.failed is True
    assert store.delivery_events("hook", catalogs=config.watch.sources, now=NOW) == ()
    assert store.delivery_events(
        "hook", catalogs=config.watch.sources, now=NOW + timedelta(minutes=4)
    ) == ()
    due = store.delivery_events(
        "hook", catalogs=config.watch.sources, now=NOW + timedelta(minutes=5)
    )
    assert len(due) == 1

    def succeeding(request):
        return httpx.Response(200, json={})

    http = mock_client(succeeding)
    report = deliver_pending(
        config,
        store,
        http,
        clock=lambda: NOW + timedelta(minutes=5),
        monotonic=lambda: 0.0,
    )
    assert report.channels[0].events == 1
    assert rows(store) == [("hook", "sent", 1, None)]


def test_retry_delay_doubles_and_caps(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    assert store.delivery_retry_delay(1) == timedelta(minutes=5)
    assert store.delivery_retry_delay(2) == timedelta(minutes=10)
    assert store.delivery_retry_delay(10) == timedelta(hours=6)
    assert store.delivery_retry_delay(50) == timedelta(hours=6)


def test_gives_up_after_ten_attempts(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_delivery SET status='failed', attempts=10, "
            "updated_at=?",
            ((NOW - timedelta(days=1)).isoformat(),),
        )
    assert store.delivery_events(
        "hook", catalogs=config.watch.sources, now=NOW + timedelta(days=30)
    ) == ()
    status = store.delivery_status()
    assert status[0].failed == 1


def test_crash_recovery_marks_sending_ambiguous(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_delivery SET status='sending'")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    assert report.recovered == 1
    assert requests == []
    assert rows(store)[0][1] == "ambiguous"

    report = deliver(config, store, handler, retry_ambiguous=True)
    assert report.channels[0].messages == 1
    assert rows(store)[0][1] == "sent"


def test_matrix_retry_reuses_the_transaction_id(tmp_path, monkeypatch):
    monkeypatch.setenv("MATRIX_TOKEN", "matrix-token")
    channels = """
[watch.channels.matrix]
type = "matrix"
homeserver = "https://matrix.example.org"
room_id = "!room:example.org"
access_token_env = "MATRIX_TOKEN"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["matrix"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    puts: list[str] = []
    state = {"sent": False}

    def handler(request):
        if request.method == "GET":
            return httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
        puts.append(str(request.url))
        if not state["sent"]:
            state["sent"] = True
            raise httpx.ReadTimeout("timeout")
        return httpx.Response(200, json={"event_id": "$event"})

    first = deliver(config, store, handler)
    assert first.channels[0].ambiguous == 1
    assert rows(store) == [("matrix", "ambiguous", 1, "connection interrupted")]

    second = deliver(config, store, handler)
    assert second.channels[0].messages == 1
    assert len(puts) == 2
    assert puts[0] == puts[1]
    assert rows(store) == [("matrix", "sent", 1, None)]


def test_matrix_encrypted_room_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("MATRIX_TOKEN", "matrix-token")
    channels = """
[watch.channels.matrix]
type = "matrix"
homeserver = "https://matrix.example.org"
room_id = "!room:example.org"
access_token_env = "MATRIX_TOKEN"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["matrix"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)

    def handler(request):
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    assert report.channels[0].failed == 1
    assert "encrypted" in report.channels[0].error


def test_matrix_preflight_failure_does_not_send(tmp_path, monkeypatch):
    monkeypatch.setenv("MATRIX_TOKEN", "matrix-token")
    channels = """
[watch.channels.matrix]
type = "matrix"
homeserver = "https://matrix.example.org"
room_id = "!room:example.org"
access_token_env = "MATRIX_TOKEN"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["matrix"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    seen = []

    def handler(request):
        seen.append(request.method)
        return httpx.Response(500)

    report = deliver(config, store, handler)
    assert seen == ["GET"]
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0


def test_per_run_message_cap_leaves_the_rest_pending(tmp_path):
    channels = """
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
grouping = "event"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["hook"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    identifiers = tuple(f"CVE-2026-{index:04d}" for index in range(1, 16))
    store = seed(config, identifiers=identifiers)
    count = {"requests": 0}

    def handler(request):
        count["requests"] += 1
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    assert count["requests"] == 10
    assert report.channels[0].messages == 10
    assert report.channels[0].events == 10
    status = store.delivery_status()
    assert status[0].pending == 5


def test_one_channel_failure_does_not_block_another(tmp_path):
    channels = """
[watch.channels.bad]
type = "webhook"
url = "https://example.test/bad"
[watch.channels.good]
type = "webhook"
url = "https://example.test/good"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["bad", "good"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if "bad" in str(request.url):
            return httpx.Response(500, json={})
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    by_name = {summary.channel: summary for summary in report.channels}
    assert by_name["bad"].failed == 1
    assert by_name["good"].ok is True
    assert len(seen) == 2


def test_interval_budget_stops_after_the_first_message(tmp_path):
    channels = """
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
grouping = "event"
min_interval_seconds = 30
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["hook"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config, identifiers=("CVE-2026-0001", "CVE-2026-0002"))
    count = {"requests": 0}

    def handler(request):
        count["requests"] += 1
        return httpx.Response(200, json={})

    report = deliver(config, store, handler, budget_seconds=10)
    assert count["requests"] == 1
    assert store.delivery_status()[0].pending == 1


def test_slack_payload_and_success_status(tmp_path, monkeypatch):
    monkeypatch.setenv("SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop")
    channels = """
[watch.channels.slack]
type = "slack"
webhook_url_env = "SLACK_URL"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["slack"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    report = deliver(config, store, handler)
    assert report.channels[0].ok
    assert "text" in json.loads(seen[0].content)


def test_discord_payload_suppresses_mentions(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DISCORD_URL",
        "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz",
    )
    channels = """
[watch.channels.discord]
type = "discord"
webhook_url_env = "DISCORD_URL"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["discord"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config, description="@everyone *urgent*")
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(204)

    report = deliver(config, store, handler)
    assert report.channels[0].ok
    body = json.loads(seen[0].content)
    assert body["allowed_mentions"] == {"parse": []}
    assert "\\@everyone" in body["content"]
    assert "\\*urgent\\*" in body["content"]


def test_telegram_success_requires_ok_true(tmp_path, monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
    channels = """
[watch.channels.telegram]
type = "telegram"
bot_token_env = "TELEGRAM_TOKEN"
chat_id = -100123
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["telegram"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    report = deliver(config, store, handler)
    assert report.channels[0].ok
    body = json.loads(seen[0].content)
    assert body["chat_id"] == "-100123"
    assert "danger" not in seen[0].url.path


def test_telegram_ok_false_is_a_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
    channels = """
[watch.channels.telegram]
type = "telegram"
bot_token_env = "TELEGRAM_TOKEN"
chat_id = 1
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["telegram"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)

    def handler(request):
        return httpx.Response(200, json={"ok": False, "error_code": 400})

    report = deliver(config, store, handler)
    assert report.channels[0].failed == 1
    assert "Telegram rejected" in report.channels[0].error


def test_ntfy_and_gotify_payloads(tmp_path, monkeypatch):
    monkeypatch.setenv("NTFY_TOKEN", "ntfy-token")
    monkeypatch.setenv("GOTIFY_TOKEN", "gotify-token")
    channels = """
[watch.channels.ntfy]
type = "ntfy"
topic = "cvebeacon"
token_env = "NTFY_TOKEN"
priority = 4
[watch.channels.gotify]
type = "gotify"
server = "https://gotify.example.org"
app_token_env = "GOTIFY_TOKEN"
priority = 7
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["ntfy", "gotify"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    assert all(summary.ok for summary in report.channels)
    ntfy = next(request for request in seen if request.url.host == "ntfy.sh")
    assert ntfy.headers["Title"].startswith("CVEBeacon:")
    assert ntfy.headers["Priority"] == "4"
    assert ntfy.headers["Authorization"].startswith("Bearer ")
    gotify = next(request for request in seen if request.url.host == "gotify.example.org")
    assert gotify.headers["X-Gotify-Key"]
    assert json.loads(gotify.content)["priority"] == 7


def test_teams_success_status(tmp_path, monkeypatch):
    monkeypatch.setenv("TEAMS_URL", "https://example.webhook.office.com/webhookb2/abc")
    channels = """
[watch.channels.teams]
type = "teams"
webhook_url_env = "TEAMS_URL"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["teams"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(202)

    report = deliver(config, store, handler)
    assert report.channels[0].ok
    body = json.loads(seen[0].content)
    assert body["attachments"][0]["contentType"].endswith("adaptive")


def test_graph_sends_a_token_request_then_mail(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAPH_SECRET", "graph-secret")
    channels = """
[watch.channels.graph]
type = "graph"
tenant_id = "tenant"
client_id = "client"
client_secret_env = "GRAPH_SECRET"
sender = "beacon@example.org"
to = ["soc@example.org"]
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["graph"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    seen = []

    def handler(request):
        seen.append(request)
        if "login.microsoftonline.com" in str(request.url):
            return httpx.Response(200, json={"access_token": "graph-token"})
        return httpx.Response(202)

    report = deliver(config, store, handler)
    assert report.channels[0].ok
    assert len(seen) == 2
    assert seen[1].headers["authorization"] == "Bearer graph-token"
    assert json.loads(seen[1].content)["message"]["subject"].startswith("CVEBeacon:")


def test_no_secret_ever_appears_in_errors(tmp_path, capsys):
    canary = "CANARY-SECRET-9f4c"
    channels = f"""
[watch.channels.hook]
type = "webhook"
url = "https://example.test/{canary}"
header_name = "X-Auth"
header_value_env = "HOOK_SECRET"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["hook"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    import os

    os.environ["HOOK_SECRET"] = canary
    try:
        store = seed(config)
        report = deliver(config, store, lambda request: httpx.Response(500))
        assert canary not in repr(report)
        assert canary not in (report.channels[0].error or "")
        assert canary not in (rows(store)[0][3] or "")
        assert canary not in str(store.status())
        assert canary not in capsys.readouterr().out
    finally:
        os.environ.pop("HOOK_SECRET", None)


def test_notify_test_sends_a_labelled_message(tmp_path):
    config = make_config(tmp_path)
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})

    http = mock_client(handler)
    outcome = send_test(config, http, "hook")
    assert outcome.ok
    body = json.loads(seen[0].content)
    assert body["test"] is True
    assert "no action needed" in body["message"]
    assert store.delivery_status() == ()
    with pytest.raises(ConfigurationError, match="unknown watch channel"):
        send_test(config, http, "missing")


def test_cli_output_never_contains_a_secret(tmp_path, monkeypatch, capsys):
    canary = "CANARY-CLI-OUTPUT-4b72"
    monkeypatch.setenv("HOOK_SECRET", canary)
    channels = """
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
header_name = "X-Auth"
header_value_env = "HOOK_SECRET"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["hook"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    seed(config)
    monkeypatch.setattr(
        cli, "HttpClient", lambda http_config: mock_client(lambda request: httpx.Response(500))
    )
    assert cli.main(["--config", str(config.config_path), "watch", "notify"]) == 3
    captured = capsys.readouterr()
    assert canary not in captured.out
    assert canary not in captured.err


class FakeSMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, mode: str = "ok", **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = mode
        self.messages: list[list[str]] = []


class FakeSMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        server = self.server
        server.messages.append([])
        self.wfile.write(b"220 fake ESMTP\r\n")
        in_data = False
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if in_data:
                if line.strip() == b".":
                    if server.mode == "data-error":
                        self.wfile.write(b"451 4.3.0 rejected\r\n")
                    elif server.mode == "drop":
                        return
                    else:
                        self.wfile.write(b"250 2.0.0 queued\r\n")
                    in_data = False
                else:
                    server.messages[-1].append(line.decode("utf-8", "replace"))
                continue
            command = line.strip().upper()
            if command.startswith(b"EHLO") or command.startswith(b"HELO"):
                self.wfile.write(b"250-fake\r\n250-8BITMIME\r\n250 OK\r\n")
            elif command.startswith(b"MAIL FROM") or command.startswith(b"RCPT TO"):
                self.wfile.write(b"250 OK\r\n")
            elif command == b"DATA":
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data = True
            elif command == b"QUIT":
                self.wfile.write(b"221 Bye\r\n")
                return
            else:
                self.wfile.write(b"250 OK\r\n")


def smtp_channel(port: int) -> str:
    return f"""
[watch.channels.mail]
type = "smtp"
host = "127.0.0.1"
port = {port}
security = "none"
allow_insecure = true
from = "beacon@example.org"
to = ["soc@example.org"]
"""


def smtp_rule() -> str:
    return """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["mail"]
"""


def run_smtp_test(tmp_path, monkeypatch, mode: str):
    monkeypatch.setattr(socket.socket, "connect", REAL_CONNECT)
    monkeypatch.setattr(socket, "getaddrinfo", loopback_getaddrinfo)
    server = FakeSMTPServer(("127.0.0.1", 0), FakeSMTPHandler, mode=mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = make_config(
            tmp_path, channels=smtp_channel(server.server_address[1]), rules=smtp_rule()
        )
        store = seed(config)
        report = deliver(config, store, lambda request: httpx.Response(500))
        return report, store, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_smtp_delivers_through_a_real_conversation(tmp_path, monkeypatch):
    report, store, server = run_smtp_test(tmp_path, monkeypatch, "ok")
    assert report.channels[0].ok
    assert report.channels[0].messages == 1
    message = "\n".join(server.messages[0])
    assert "Subject: CVEBeacon:" in message
    assert "CVE-2026-0001" in message
    assert rows(store)[0][1] == "sent"


def test_smtp_data_rejection_is_a_definite_failure(tmp_path, monkeypatch):
    report, store, server = run_smtp_test(tmp_path, monkeypatch, "data-error")
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0
    assert "SMTP rejected" in report.channels[0].error
    assert rows(store)[0][1] == "failed"


def test_smtp_drop_after_data_is_ambiguous(tmp_path, monkeypatch):
    report, store, server = run_smtp_test(tmp_path, monkeypatch, "drop")
    assert report.channels[0].ambiguous == 1
    assert rows(store)[0][1] == "ambiguous"


@pytest.mark.parametrize(
    "channel_block,env",
    [
        (
            '[watch.channels.c]\ntype = "webhook"\nurl = "https://example.test/hook"\n',
            {},
        ),
        (
            '[watch.channels.c]\ntype = "teams"\nwebhook_url_env = "TEAMS_URL"\n',
            {"TEAMS_URL": "https://example.webhook.office.com/webhookb2/abc"},
        ),
        (
            '[watch.channels.c]\ntype = "slack"\nwebhook_url_env = "SLACK_URL"\n',
            {"SLACK_URL": "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"},
        ),
        (
            '[watch.channels.c]\ntype = "discord"\nwebhook_url_env = "DISCORD_URL"\n',
            {
                "DISCORD_URL": "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz"
            },
        ),
        (
            '[watch.channels.c]\ntype = "telegram"\nbot_token_env = "TELEGRAM_TOKEN"\nchat_id = 1\n',
            {"TELEGRAM_TOKEN": "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"},
        ),
        (
            '[watch.channels.c]\ntype = "ntfy"\ntopic = "cvebeacon"\n',
            {},
        ),
        (
            '[watch.channels.c]\ntype = "gotify"\nserver = "https://gotify.example.org"\napp_token_env = "GOTIFY_TOKEN"\n',
            {"GOTIFY_TOKEN": "gotify-token"},
        ),
    ],
)
def test_http_error_status_is_a_retryable_failure(tmp_path, monkeypatch, channel_block, env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["c"]
"""
    config = make_config(tmp_path, channels=channel_block, rules=rules)
    store = seed(config)
    report = deliver(config, store, lambda request: httpx.Response(500, json={}))
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0


def test_graph_failure_status_is_retryable(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAPH_SECRET", "graph-secret")
    channels = """
[watch.channels.c]
type = "graph"
tenant_id = "tenant"
client_id = "client"
client_secret_env = "GRAPH_SECRET"
sender = "beacon@example.org"
to = ["soc@example.org"]
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["c"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)

    def handler(request):
        if "login.microsoftonline.com" in str(request.url):
            return httpx.Response(200, json={"access_token": "graph-token"})
        return httpx.Response(500)

    report = deliver(config, store, handler)
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0


def test_no_secret_in_logs(tmp_path, monkeypatch, caplog):
    import logging

    canary = "CANARY-LOG-ONLY-8a1f"
    monkeypatch.setenv("HOOK_SECRET", canary)
    channels = """
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
header_name = "X-Auth"
header_value_env = "HOOK_SECRET"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["hook"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    with caplog.at_level(logging.DEBUG):
        deliver(config, store, lambda request: httpx.Response(500))
    assert canary not in caplog.text


def test_watch_status_shows_delivery_counts(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    deliver(config, store, lambda request: httpx.Response(200, json={}))
    from cvebeacon.watch.sync import watch_status

    output = watch_status(config.watch)
    assert "channel hook: pending 0, failed 0, ambiguous 0, last success " in output


def test_cli_notify_test_and_exit_codes(tmp_path, monkeypatch, capsys):
    config = make_config(tmp_path)
    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(lambda request: httpx.Response(200, json={})))
    assert cli.main(["--config", str(config.config_path), "watch", "notify", "test", "hook"]) == 0
    assert "test message sent" in capsys.readouterr().out


def test_cli_notify_returns_three_on_delivery_failure(tmp_path, monkeypatch, capsys):
    config = make_config(tmp_path)
    seed(config)
    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(lambda request: httpx.Response(500)))
    assert cli.main(["--config", str(config.config_path), "watch", "notify"]) == 3
    output = capsys.readouterr().out
    assert "hook (webhook): 0 messages, 0 events sent; 1 failed" in output


def test_cli_notify_channel_filter(tmp_path, monkeypatch):
    channels = """
[watch.channels.bad]
type = "webhook"
url = "https://example.test/bad"
[watch.channels.good]
type = "webhook"
url = "https://example.test/good"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["bad", "good"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    seed(config)
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if "bad" in str(request.url):
            return httpx.Response(500)
        return httpx.Response(200, json={})

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "notify", "--channel", "good"]) == 0
    assert seen == ["https://example.test/good"]


def test_cli_notify_retry_ambiguous(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    store = seed(config)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_delivery SET status='ambiguous'")
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "notify"]) == 0
    assert seen == []
    assert cli.main(
        [
            "--config",
            str(config.config_path),
            "watch",
            "notify",
            "--retry-ambiguous",
        ]
    ) == 0
    assert len(seen) == 1


def test_cli_watch_run_exits_three_on_delivery_failure(tmp_path, monkeypatch, capsys):
    config = write_config(
        tmp_path,
        initial="backfill",
        channels=WEBHOOK,
        extra=RULE,
    )

    def handler(request):
        if "example.test" in str(request.url):
            return httpx.Response(500)
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 3
    output = capsys.readouterr().out
    assert "events:" in output
    assert "hook (webhook):" in output


def test_cli_watch_run_exits_three_on_an_ambiguous_delivery(tmp_path, monkeypatch, capsys):
    config = write_config(
        tmp_path,
        initial="backfill",
        channels=WEBHOOK,
        extra=RULE,
    )

    def handler(request):
        if "example.test" in str(request.url):
            raise httpx.ReadTimeout("timeout")
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 3
    output = capsys.readouterr().out
    assert "1 ambiguous" in output


def test_cli_watch_run_sends_initial_digest(tmp_path, monkeypatch, capsys):
    config = write_config(
        tmp_path,
        initial="backfill",
        channels=WEBHOOK,
        extra=RULE,
    )
    seen = []

    def handler(request):
        if "example.test" in str(request.url):
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={})
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 0
    assert len(seen) == 1
    assert seen[0]["events"][0]["initial"] is True
