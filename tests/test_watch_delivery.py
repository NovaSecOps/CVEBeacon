from __future__ import annotations

import base64
import email
import email.policy
import gzip
import json
import shutil
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import threading
import time
import tracemalloc
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from watch_support import NOW, mock_client, nvd_cve, nvd_page, write_config

from cvebeacon import cli
from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.channels import channel_map
from cvebeacon.watch.delivery import (
    DeliveryFailure,
    _http_call,
    _send_smtp,
    deliver_pending,
    format_channel_line,
    send_test,
)
from cvebeacon.watch.messages import OutgoingMessage
from cvebeacon.watch.records import CVSSEntry, KEVFields, WatchRecord
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
        db.execute(
            "UPDATE watch_delivery SET status='sending', updated_at=?",
            ((NOW - timedelta(minutes=11)).isoformat(),),
        )
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


def test_fresh_sending_rows_belong_to_a_live_run(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_delivery SET status='sending'")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    assert report.recovered == 0
    assert requests == []
    assert rows(store)[0][1] == "sending"


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

    second = deliver(config, store, handler, retry_ambiguous=True)
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
    assert body["flags"] == 4
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
    implicit_tls = False

    def __init__(
        self,
        *args,
        mode: str = "ok",
        certificate: tuple[str, str] | None = None,
        auth: tuple[str, str] | None = None,
        eightbitmime: bool = False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.mode = mode
        self.auth = auth
        self.eightbitmime = eightbitmime
        self.certificate = certificate
        self.messages: list[dict[str, Any]] = []
        self.auth_attempts: list[tuple[str, str]] = []
        self.context = None
        if certificate is not None:
            certfile, keyfile = certificate
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(certfile, keyfile)

    def handle_error(self, request, client_address):
        pass


class FakeSMTPSSLServer(FakeSMTPServer):
    implicit_tls = True

    def get_request(self):
        sock, address = super().get_request()
        return self.context.wrap_socket(sock, server_side=True), address


class FakeSMTPHandler(socketserver.StreamRequestHandler):
    def _reset(self) -> None:
        self.envelope = {"from": None, "rcpt": []}
        self.data_lines: list[bytes] = []

    def setup(self) -> None:
        super().setup()
        self._tls = bool(self.server.implicit_tls)
        self._reset()

    def _record(self) -> None:
        self.server.messages.append(
            {
                "from": self.envelope["from"],
                "rcpt": list(self.envelope["rcpt"]),
                "data": b"".join(self.data_lines),
                "tls": self._tls,
            }
        )
        self._reset()

    def _auth(self, command: bytes) -> None:
        server = self.server
        parts = command.split(None, 2)
        if len(parts) < 3:
            self.wfile.write(b"334 \r\n")
            response = self.rfile.readline().strip()
        else:
            response = parts[2]
        try:
            _, user, password = base64.b64decode(response).split(b"\x00")
        except Exception:
            user = password = b""
        attempt = (user.decode("utf-8", "replace"), password.decode("utf-8", "replace"))
        server.auth_attempts.append(attempt)
        if server.auth is not None and attempt == server.auth:
            self.wfile.write(b"235 2.7.0 accepted\r\n")
        else:
            self.wfile.write(b"535 5.7.8 authentication failed\r\n")

    def _login(self, command: bytes) -> None:
        server = self.server
        parts = command.split(None, 2)
        if len(parts) == 3:
            user = base64.b64decode(parts[2]).decode("utf-8", "replace")
        else:
            self.wfile.write(b"334 VXNlcm5hbWU6\r\n")
            user = base64.b64decode(self.rfile.readline().strip()).decode(
                "utf-8", "replace"
            )
        self.wfile.write(b"334 UGFzc3dvcmQ6\r\n")
        password = base64.b64decode(self.rfile.readline().strip()).decode(
            "utf-8", "replace"
        )
        server.auth_attempts.append((user, password))
        if server.auth is not None and (user, password) == server.auth:
            self.wfile.write(b"235 2.7.0 accepted\r\n")
        else:
            self.wfile.write(b"535 5.7.8 authentication failed\r\n")

    def handle(self):
        server = self.server
        self.wfile.write(b"220 fake ESMTP\r\n")
        in_data = False
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if in_data:
                if line == b".\r\n":
                    mode = server.mode
                    if mode == "data-error":
                        self.wfile.write(b"451 4.3.0 rejected\r\n")
                    elif mode == "drop":
                        return
                    else:
                        self._record()
                        self.wfile.write(b"250 2.0.0 queued\r\n")
                    in_data = False
                else:
                    # RFC 5321 dot-unstuffing: the first dot of ".." is not
                    # part of the message.
                    if line.startswith(b".."):
                        line = line[1:]
                    self.data_lines.append(line)
                continue
            command = line.strip()
            upper = command.upper()
            if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
                capabilities = [b"250-fake"]
                if (
                    server.certificate is not None
                    and not server.implicit_tls
                    and not self._tls
                ):
                    capabilities.append(b"250-STARTTLS")
                if server.auth is not None:
                    capabilities.append(b"250-AUTH PLAIN LOGIN")
                if server.eightbitmime:
                    capabilities.append(b"250-8BITMIME")
                capabilities.append(b"250 HELP")
                self.wfile.write(b"\r\n".join(capabilities) + b"\r\n")
            elif upper == b"STARTTLS":
                self.wfile.write(b"220 Ready to start TLS\r\n")
                self.wfile.flush()
                self.rfile.close()
                self.wfile.close()
                self.connection = server.context.wrap_socket(
                    self.connection, server_side=True
                )
                self.rfile = self.connection.makefile("rb")
                self.wfile = self.connection.makefile("wb", 0)
                self._tls = True
            elif upper.startswith(b"AUTH PLAIN"):
                self._auth(command)
            elif upper.startswith(b"AUTH LOGIN"):
                self._login(command)
            elif upper.startswith(b"MAIL FROM"):
                self.envelope["from"] = command.decode("utf-8", "replace")
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith(b"RCPT TO"):
                if server.mode == "drop-rcpt":
                    return
                if server.mode == "rcpt-refused" and self.envelope["rcpt"]:
                    self.wfile.write(b"550 5.1.1 no such user\r\n")
                else:
                    self.envelope["rcpt"].append(command.decode("utf-8", "replace"))
                    self.wfile.write(b"250 OK\r\n")
            elif upper == b"DATA":
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data = True
            elif upper == b"QUIT":
                self.wfile.write(b"221 Bye\r\n")
                return
            else:
                self.wfile.write(b"250 OK\r\n")


def smtp_channel(
    port: int,
    *,
    security: str = "none",
    extra: str = "",
    to: tuple[str, ...] = ("soc@example.org",),
) -> str:
    allow_insecure = "allow_insecure = true" if security == "none" else ""
    recipients = ", ".join(f'"{address}"' for address in to)
    return f"""
[watch.channels.mail]
type = "smtp"
host = "127.0.0.1"
port = {port}
security = "{security}"
{allow_insecure}
from = "beacon@example.org"
to = [{recipients}]
{extra}
"""


def smtp_rule() -> str:
    return """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["mail"]
"""


@pytest.fixture(scope="module")
def smtp_certificate(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is not available")
    directory = tmp_path_factory.mktemp("smtp-certificate")
    certfile = directory / "cert.pem"
    keyfile = directory / "key.pem"
    completed = subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(keyfile),
            "-out",
            str(certfile),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip("openssl could not create a test certificate")
    return str(certfile), str(keyfile)


def run_smtp_test(
    tmp_path,
    monkeypatch,
    mode: str = "ok",
    *,
    extra: str = "",
    security: str = "none",
    certificate: tuple[str, str] | None = None,
    auth: tuple[str, str] | None = None,
    eightbitmime: bool = False,
    trusted: bool = False,
    to: tuple[str, ...] = ("soc@example.org",),
):
    monkeypatch.setattr(socket.socket, "connect", REAL_CONNECT)
    monkeypatch.setattr(socket, "getaddrinfo", loopback_getaddrinfo)
    server_class = FakeSMTPSSLServer if security == "tls" else FakeSMTPServer
    server = server_class(
        ("127.0.0.1", 0),
        FakeSMTPHandler,
        mode=mode,
        certificate=certificate,
        auth=auth,
        eightbitmime=eightbitmime,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if trusted and certificate is not None:
            context = ssl.create_default_context(cafile=certificate[0])
            monkeypatch.setattr(
                "cvebeacon.watch.delivery.ssl.create_default_context",
                lambda: context,
            )
        config = make_config(
            tmp_path,
            channels=smtp_channel(
                server.server_address[1],
                security=security,
                extra=extra,
                to=to,
            ),
            rules=smtp_rule(),
        )
        store = seed(config)
        report = deliver(config, store, lambda request: httpx.Response(500))
        return report, store, server, config
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def parsed_message(server: FakeSMTPServer) -> email.message.Message:
    return email.message_from_bytes(
        server.messages[0]["data"], policy=email.policy.default
    )


def smtp_recipients(server: FakeSMTPServer) -> list[str]:
    return [
        recipient.split("<", 1)[1].rstrip(">")
        for recipient in server.messages[0]["rcpt"]
    ]


def test_smtp_delivers_through_a_real_conversation(tmp_path, monkeypatch):
    report, store, server, _ = run_smtp_test(tmp_path, monkeypatch)
    assert report.channels[0].ok
    assert report.channels[0].messages == 1
    message = parsed_message(server)
    assert message["Subject"].startswith("CVEBeacon:")
    assert message["Auto-Submitted"] == "auto-generated"
    date_header = next(
        line
        for line in server.messages[0]["data"].split(b"\r\n")
        if line.lower().startswith(b"date:")
    )
    assert date_header.endswith(b"+0000")
    assert message["Content-Transfer-Encoding"] == "quoted-printable"
    body = message.get_content()
    assert "CVE-2026-0001" in body
    assert "https://www.cve.org" in body
    assert smtp_recipients(server) == ["soc@example.org"]
    assert rows(store)[0][1] == "sent"


def test_smtp_bcc_is_in_the_envelope_without_a_header(tmp_path, monkeypatch):
    extra = 'cc = ["cc@example.org"]\nbcc = ["archive@example.org"]'
    report, store, server, _ = run_smtp_test(tmp_path, monkeypatch, extra=extra)
    assert report.channels[0].ok
    assert smtp_recipients(server) == [
        "soc@example.org",
        "cc@example.org",
        "archive@example.org",
    ]
    message = parsed_message(server)
    assert message["Bcc"] is None
    assert message["Cc"] == "cc@example.org"


def test_smtp_test_message_is_quoted_printable(tmp_path, monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", REAL_CONNECT)
    monkeypatch.setattr(socket, "getaddrinfo", loopback_getaddrinfo)
    server = FakeSMTPServer(("127.0.0.1", 0), FakeSMTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = make_config(
            tmp_path,
            channels=smtp_channel(server.server_address[1]),
            rules=smtp_rule(),
        )
        outcome = send_test(config, mock_client(lambda request: httpx.Response(500)), "mail")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert outcome.ok
    assert b"=E2=80=94" in server.messages[0]["data"]
    message = parsed_message(server)
    assert "test message — no action needed" in message.get_content()


def test_smtp_starttls_and_auth(tmp_path, monkeypatch, smtp_certificate):
    monkeypatch.setenv("TEST_SMTP_PASSWORD", "smtp-password")
    report, store, server, _ = run_smtp_test(
        tmp_path,
        monkeypatch,
        certificate=smtp_certificate,
        auth=("beacon", "smtp-password"),
        security="starttls",
        extra='username = "beacon"\npassword_env = "TEST_SMTP_PASSWORD"',
        trusted=True,
    )
    assert report.channels[0].ok, report.channels[0].error
    assert server.messages[0]["tls"] is True
    assert server.auth_attempts == [("beacon", "smtp-password")]
    assert rows(store)[0][1] == "sent"


def test_smtp_implicit_tls(tmp_path, monkeypatch, smtp_certificate):
    report, store, server, _ = run_smtp_test(
        tmp_path,
        monkeypatch,
        certificate=smtp_certificate,
        security="tls",
        trusted=True,
    )
    assert report.channels[0].ok, report.channels[0].error
    assert server.messages[0]["tls"] is True
    assert rows(store)[0][1] == "sent"


def test_smtp_rejects_an_untrusted_certificate(tmp_path, monkeypatch, smtp_certificate):
    report, store, server, _ = run_smtp_test(
        tmp_path,
        monkeypatch,
        certificate=smtp_certificate,
        security="starttls",
    )
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0
    assert "certificate verification failed" in report.channels[0].error
    assert server.messages == []
    assert rows(store)[0][1] == "failed"


def test_smtp_authentication_gives_up_after_three_attempts(tmp_path, monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", REAL_CONNECT)
    monkeypatch.setattr(socket, "getaddrinfo", loopback_getaddrinfo)
    monkeypatch.setenv("TEST_SMTP_PASSWORD", "wrong-password")
    server = FakeSMTPServer(
        ("127.0.0.1", 0), FakeSMTPHandler, auth=("beacon", "right-password")
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = make_config(
            tmp_path,
            channels=smtp_channel(
                server.server_address[1],
                extra='username = "beacon"\npassword_env = "TEST_SMTP_PASSWORD"',
            ),
            rules=smtp_rule(),
        )
        store = seed(config)
        times = [NOW, NOW + timedelta(minutes=5), NOW + timedelta(minutes=15)]
        reports = [
            deliver_pending(
                config,
                store,
                mock_client(lambda request: httpx.Response(500)),
                clock=lambda value=value: value,
                monotonic=lambda: 0.0,
            )
            for value in times
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert all(report.channels[0].failed == 1 for report in reports)
    assert set(server.auth_attempts) == {("beacon", "wrong-password")}
    assert len(server.auth_attempts) >= 3
    assert store.delivery_status()[0].given_up == 1
    assert (
        store.delivery_events(
            "mail",
            catalogs=config.watch.sources,
            now=NOW + timedelta(days=30),
        )
        == ()
    )


def test_smtp_data_rejection_after_data_is_ambiguous(tmp_path, monkeypatch):
    report, store, server, _ = run_smtp_test(tmp_path, monkeypatch, "data-error")
    assert report.channels[0].failed == 0
    assert report.channels[0].ambiguous == 1
    assert "SMTP outcome unknown" in report.channels[0].error
    assert rows(store)[0][1] == "ambiguous"


def test_smtp_drop_after_data_is_ambiguous(tmp_path, monkeypatch):
    report, store, server, _ = run_smtp_test(tmp_path, monkeypatch, "drop")
    assert report.channels[0].ambiguous == 1
    assert rows(store)[0][1] == "ambiguous"


def test_smtp_drop_before_data_is_a_definite_failure(tmp_path, monkeypatch):
    report, store, server, _ = run_smtp_test(tmp_path, monkeypatch, "drop-rcpt")
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0
    assert rows(store)[0][1] == "failed"


def test_smtp_without_starttls_is_refused(tmp_path, monkeypatch):
    report, store, server, _ = run_smtp_test(
        tmp_path, monkeypatch, security="starttls"
    )
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0
    assert report.channels[0].error == "server does not offer STARTTLS"
    assert server.messages == []
    assert rows(store)[0][1] == "failed"


def test_smtp_deadline_stops_between_phases(tmp_path, monkeypatch):
    config = make_config(
        tmp_path, channels=smtp_channel(2525), rules=smtp_rule()
    )
    channel = channel_map(config.watch.channels)["mail"]
    state = {"now": 0.0}

    class FakeSocket:
        def settimeout(self, value):
            pass

    class FakeClient:
        data_sent = False

        def __init__(self):
            self.sock = FakeSocket()
            self.send_called = False
            self.closed = False

        def ehlo(self):
            state["now"] = 2.0

        def send_message(self, *args, **kwargs):
            self.send_called = True
            return {}

        def quit(self):
            pass

        def close(self):
            self.closed = True

    client = FakeClient()
    monkeypatch.setattr(
        "cvebeacon.watch.delivery._smtp_client",
        lambda channel, timeout: client,
    )
    message = OutgoingMessage((), "subject", "text", "body")
    with pytest.raises(DeliveryFailure) as error:
        _send_smtp(
            channel,
            message,
            5.0,
            deadline=1.0,
            monotonic=lambda: state["now"],
        )
    assert error.value.category == "delivery budget exhausted"
    assert error.value.ambiguous is False
    assert client.send_called is False


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
    assert (
        "channel hook: pending 0, failed 0 (0 given up), ambiguous 0, "
        "sending 0, last success "
    ) in output


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


def test_telegram_success_status_without_a_body_is_ambiguous(tmp_path, monkeypatch):
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
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"")

    report = deliver(config, store, handler)
    assert report.channels[0].failed == 0
    assert report.channels[0].ambiguous == 1
    assert rows(store) == [("telegram", "ambiguous", 1, "Telegram confirmation was unreadable")]

    deliver(config, store, handler, clock=lambda: NOW + timedelta(minutes=30))
    assert len(seen) == 1


def test_telegram_success_status_with_an_unreadable_body_is_ambiguous(tmp_path, monkeypatch):
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

    for content in (b"{}", b"not json"):
        with sqlite3.connect(store.path) as db:
            db.execute(
                "UPDATE watch_delivery SET status='pending', attempts=0, "
                "first_attempt_at=NULL, last_error=NULL"
            )
        report = deliver(config, store, lambda request, body=content: httpx.Response(200, content=body))
        assert report.channels[0].ambiguous == 1
        assert rows(store)[0][1] == "ambiguous"


def test_matrix_success_without_an_event_id_is_ambiguous(tmp_path, monkeypatch):
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
        if request.method == "GET":
            return httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    assert report.channels[0].ambiguous == 1
    assert rows(store) == [("matrix", "ambiguous", 1, "Matrix confirmation was unreadable")]


def test_an_ambiguous_retry_that_fails_definitely_stays_ambiguous(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_delivery SET status='ambiguous', attempts=1")
    seen = []

    def failing(request):
        seen.append(request)
        raise httpx.ConnectError("refused")

    report = deliver(config, store, failing, retry_ambiguous=True)
    assert report.channels[0].failed == 0
    assert report.channels[0].ambiguous == 1
    assert rows(store) == [("hook", "ambiguous", 2, "connection failed")]

    deliver(config, store, failing, clock=lambda: NOW + timedelta(days=1))
    assert len(seen) == 1


def test_mark_delivery_never_leaves_sent_or_ambiguous(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    event_id = store.events()[0].id
    assert store.mark_delivery([event_id], "hook", "sent") == 1
    assert store.mark_delivery([event_id], "hook", "failed", error="late") == 0
    assert store.mark_delivery([event_id], "hook", "ambiguous", error="late") == 0
    assert store.mark_delivery([event_id], "hook", "sending") == 0
    assert rows(store) == [("hook", "sent", 0, None)]

    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_delivery SET status='ambiguous'")
    assert store.mark_delivery([event_id], "hook", "failed", error="late") == 0
    assert store.mark_delivery([event_id], "hook", "ambiguous", error="again") == 1
    assert store.mark_delivery([event_id], "hook", "sent") == 1
    assert rows(store) == [("hook", "sent", 1, None)]


def test_matrix_ambiguous_rows_are_not_retried_automatically(tmp_path, monkeypatch):
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
    puts = []

    def handler(request):
        if request.method == "GET":
            return httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
        puts.append(str(request.url))
        return httpx.Response(200, json={"event_id": "$event"})

    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_delivery SET status='ambiguous', attempts=1, "
            "first_attempt_at=?",
            ((NOW - timedelta(minutes=1)).isoformat(),),
        )
    report = deliver(config, store, handler, clock=lambda: NOW)
    assert report.channels[0].messages == 0
    assert puts == []
    assert rows(store)[0][1] == "ambiguous"

    report = deliver(
        config, store, handler, clock=lambda: NOW, retry_ambiguous=True
    )
    assert report.channels[0].messages == 1
    assert len(puts) == 1
    assert rows(store)[0][1] == "sent"


def test_two_runs_claim_each_delivery_once(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    store = seed(config)
    requests = []
    barrier = threading.Barrier(2, timeout=10)
    original = store.delivery_events

    def synchronized(*args, **kwargs):
        events = original(*args, **kwargs)
        barrier.wait()
        return events

    monkeypatch.setattr(store, "delivery_events", synchronized)

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    reports = []
    errors = []

    def run():
        try:
            reports.append(
                deliver_pending(
                    config,
                    store,
                    mock_client(handler),
                    clock=lambda: NOW,
                    monotonic=lambda: 0.0,
                )
            )
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    assert errors == []
    assert len(requests) == 1
    assert rows(store) == [("hook", "sent", 0, None)]
    assert sum(report.channels[0].messages for report in reports) == 1


def test_matrix_parts_get_distinct_transaction_ids(tmp_path, monkeypatch):
    from cvebeacon.watch import messages as messages_module

    monkeypatch.setitem(messages_module.CHANNEL_LIMITS, "matrix", 700)
    monkeypatch.setenv("MATRIX_TOKEN", "matrix-token")
    channels = """
[watch.channels.matrix]
type = "matrix"
homeserver = "https://matrix.example.org"
room_id = "!room:example.org"
access_token_env = "MATRIX_TOKEN"
max_items = 100
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["matrix"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    identifiers = tuple(f"CVE-2026-{index:04d}" for index in range(1, 9))
    store = seed(
        config,
        identifiers=identifiers,
        description="A long description that forces the message to split. " * 4,
    )
    transactions: dict[str, str] = {}

    def handler(request):
        if request.method == "GET":
            return httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
        transaction = str(request.url).rsplit("/", 1)[-1]
        transactions.setdefault(transaction, f"$event-{len(transactions)}")
        return httpx.Response(200, json={"event_id": transactions[transaction]})

    report = deliver(config, store, handler)
    summary = report.channels[0]
    assert summary.ok
    assert summary.messages > 1
    assert len(transactions) == summary.messages
    with sqlite3.connect(store.path) as db:
        sent = db.execute(
            "SELECT COUNT(*) FROM watch_delivery WHERE status='sent'"
        ).fetchone()[0]
    assert sent == len(identifiers)


def test_graph_sends_bcc_recipients(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAPH_SECRET", "graph-secret")
    channels = """
[watch.channels.graph]
type = "graph"
tenant_id = "tenant"
client_id = "client"
client_secret_env = "GRAPH_SECRET"
sender = "beacon@example.org"
to = ["soc@example.org"]
cc = ["cc@example.org"]
bcc = ["archive@example.org"]
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
    body = json.loads(seen[1].content)["message"]
    assert body["bccRecipients"] == [
        {"emailAddress": {"address": "archive@example.org"}}
    ]


def test_graph_auth_failure_gives_up_after_three_attempts(tmp_path, monkeypatch):
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
    tokens = []

    def handler(request):
        tokens.append(request)
        return httpx.Response(401)

    for offset in (0, 5, 15):
        report = deliver(
            config,
            store,
            handler,
            clock=lambda value=offset: NOW + timedelta(minutes=value),
        )
        assert report.channels[0].failed == 1
    assert len(tokens) == 3
    assert store.delivery_status()[0].given_up == 1
    assert (
        store.delivery_events(
            "graph", catalogs=config.watch.sources, now=NOW + timedelta(days=30)
        )
        == ()
    )
    final = deliver(
        config,
        store,
        handler,
        clock=lambda: NOW + timedelta(days=30),
    )
    assert final.channels[0].given_up == 1
    assert (
        "; 1 given up (run cvebeacon watch notify --retry-failed)"
        in format_channel_line(final.channels[0])
    )


def test_retry_failed_resets_attempts_and_backoff(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    store = seed(config)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_delivery SET status='failed', attempts=10, updated_at=?",
            ((NOW - timedelta(days=1)).isoformat(),),
        )
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "notify"]) == 0
    assert seen == []

    assert (
        cli.main(
            [
                "--config",
                str(config.config_path),
                "watch",
                "notify",
                "--retry-failed",
            ]
        )
        == 0
    )
    assert len(seen) == 1
    assert rows(store) == [("hook", "sent", 0, None)]


def test_status_counts_are_per_channel(tmp_path):
    channels = """
[watch.channels.alpha]
type = "webhook"
url = "https://example.test/alpha"
[watch.channels.beta]
type = "webhook"
url = "https://example.test/beta"
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["alpha", "beta"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_delivery SET status='ambiguous' WHERE channel='alpha'")
        db.execute("UPDATE watch_delivery SET status='sent' WHERE channel='beta'")
    report = deliver(config, store, lambda request: httpx.Response(200, json={}))
    by_name = {summary.channel: summary for summary in report.channels}
    assert by_name["alpha"].ambiguous_total == 1
    assert by_name["beta"].ambiguous_total == 0
    from cvebeacon.watch.delivery import format_channel_line

    assert "ambiguous" not in format_channel_line(by_name["beta"])


def test_pacing_sleeps_once_between_messages(tmp_path):
    channels = """
[watch.channels.hook]
type = "webhook"
url = "https://example.test/hook"
grouping = "event"
min_interval_seconds = 5
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["hook"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = seed(config, identifiers=("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"))
    sleeps = []
    report = deliver(
        config,
        store,
        lambda request: httpx.Response(200, json={}),
        sleep=sleeps.append,
        budget_seconds=300,
    )
    assert report.channels[0].messages == 3
    assert sleeps == [5, 5]


def test_budget_exhaustion_before_a_message_keeps_rows_pending(tmp_path):
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
    store = seed(
        config,
        identifiers=("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"),
    )
    state = {"now": 0.0}
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        state["now"] += seconds

    report = deliver(
        config,
        store,
        lambda request: httpx.Response(200, json={}),
        monotonic=lambda: state["now"],
        sleep=fake_sleep,
        budget_seconds=60,
    )
    assert report.channels[0].messages == 2
    assert report.channels[0].failed == 0
    assert report.channels[0].ambiguous == 0
    assert store.delivery_status()[0].pending == 1


def test_budget_expiry_after_a_claim_keeps_non_initial_rows_pending(
    tmp_path, monkeypatch
):
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
    store = seed(config)
    state = {"now": 0.0}
    original = store.claim_delivery

    def claim_then_expire(*args, **kwargs):
        result = original(*args, **kwargs)
        state["now"] = 100.0
        return result

    monkeypatch.setattr(store, "claim_delivery", claim_then_expire)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})

    report = deliver(
        config,
        store,
        handler,
        monotonic=lambda: state["now"],
        budget_seconds=60,
    )
    assert report.channels[0].messages == 0
    assert report.channels[0].failed == 0
    assert report.channels[0].ambiguous == 0
    assert seen == []
    assert rows(store) == [("hook", "pending", 0, None)]


def test_budget_expiry_after_an_initial_claim_keeps_rows_pending(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(
        "SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    )
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
    store = seed(config, initial=True)
    state = {"now": 0.0}
    original = store.claim_initial_digest

    def claim_then_expire(*args, **kwargs):
        result = original(*args, **kwargs)
        state["now"] = 100.0
        return result

    monkeypatch.setattr(store, "claim_initial_digest", claim_then_expire)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    report = deliver(
        config,
        store,
        handler,
        monotonic=lambda: state["now"],
        budget_seconds=60,
    )
    assert report.channels[0].messages == 0
    assert report.channels[0].failed == 0
    assert report.channels[0].ambiguous == 0
    assert seen == []
    assert rows(store) == [("slack", "pending", 0, None)]


class SlowDripServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class SlowDripHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(65536)
        except OSError:
            return
        try:
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            for _ in range(100):
                self.request.sendall(b"x")
                time.sleep(0.1)
        except OSError:
            return


def test_request_once_stops_a_slow_drip_body(tmp_path, monkeypatch):
    from cvebeacon.config import HttpConfig
    from cvebeacon.http import HttpClient

    monkeypatch.setattr(socket.socket, "connect", REAL_CONNECT)
    monkeypatch.setattr(socket, "getaddrinfo", loopback_getaddrinfo)
    server = SlowDripServer(("127.0.0.1", 0), SlowDripHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = HttpClient(HttpConfig(retries=0))
        started = time.monotonic()
        result = client.request_once(
            "POST",
            f"http://127.0.0.1:{server.server_address[1]}/drip",
            json={"test": True},
            timeout=1.0,
        )
        elapsed = time.monotonic() - started
        client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert result.status_code == 200
    assert elapsed < 4


def test_request_once_counts_wire_bytes_and_requests_identity(tmp_path):
    from cvebeacon.config import HttpConfig
    from cvebeacon.http import HttpClient

    class GzipStream(httpx.SyncByteStream):
        def __iter__(self):
            yield compressed

    compressed = gzip.compress(b"x" * (2 * 1024 * 1024))
    seen = {}

    def handler(request):
        seen["encoding"] = request.headers.get("accept-encoding")
        return httpx.Response(
            200,
            stream=GzipStream(),
            headers={"Content-Encoding": "gzip"},
        )

    client = HttpClient(
        HttpConfig(retries=0),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = client.request_once(
        "GET",
        "https://example.test/compressed",
        timeout=5,
        body_limit=1024 * 1024,
    )
    client.close()
    assert seen["encoding"] == "identity"
    assert result.body == compressed


def test_invalid_url_is_a_definite_failure():
    http = mock_client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(DeliveryFailure) as error:
        _http_call(http, "GET", "https://example.test/\x7f", timeout=1)
    assert error.value.category == "invalid request"
    assert error.value.ambiguous is False


def test_local_protocol_error_is_a_definite_failure(tmp_path):
    config = make_config(tmp_path)
    store = seed(config)
    seen = []

    def handler(request):
        seen.append(request)
        raise httpx.LocalProtocolError("illegal header value")

    report = deliver(config, store, handler)
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0
    assert report.channels[0].error == "invalid request"
    assert len(seen) == 1
    assert rows(store) == [("hook", "failed", 1, "invalid request")]


def test_ntfy_and_gotify_do_not_repeat_the_title_in_the_body(tmp_path, monkeypatch):
    monkeypatch.setenv("NTFY_TOKEN", "ntfy-token")
    monkeypatch.setenv("GOTIFY_TOKEN", "gotify-token")
    channels = """
[watch.channels.ntfy]
type = "ntfy"
topic = "cvebeacon"
token_env = "NTFY_TOKEN"
[watch.channels.gotify]
type = "gotify"
server = "https://gotify.example.org"
app_token_env = "GOTIFY_TOKEN"
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
    ntfy_body = ntfy.content.decode("utf-8")
    assert "[NEW] CVE-2026-0001" in ntfy_body
    assert "CVEBeacon:" not in ntfy_body
    gotify = next(request for request in seen if request.url.host == "gotify.example.org")
    gotify_body = json.loads(gotify.content)
    assert "CVEBeacon:" not in gotify_body["message"]
    assert "[NEW] CVE-2026-0001" in gotify_body["message"]
    assert gotify_body["title"].startswith("CVEBeacon:")


def test_slack_url_is_revalidated_at_send_time(tmp_path, monkeypatch):
    monkeypatch.delenv("SLACK_URL", raising=False)
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
    monkeypatch.setenv(
        "SLACK_URL", "https://evil.test/services/T000/B000/abcdefghijklmnop"
    )

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    report = deliver(config, store, handler)
    assert report.channels[0].failed == 1
    assert "hooks.slack.com" in report.channels[0].error
    assert seen == []
    assert rows(store) == [("slack", "failed", 1, report.channels[0].error)]


def test_cli_watch_run_delivers_pending_alerts_when_the_source_fails(
    tmp_path, monkeypatch, capsys
):
    config = write_config(
        tmp_path,
        initial="backfill",
        channels=WEBHOOK,
        extra=RULE,
    )
    store = seed(config)
    seen = []

    def handler(request):
        if "example.test" in str(request.url):
            seen.append(request)
            return httpx.Response(200, json={})
        return httpx.Response(500)

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 2
    assert len(seen) == 1
    assert rows(store) == [("hook", "sent", 0, None)]
    assert "hook (webhook): 1 message, 1 event sent" in capsys.readouterr().out


def test_initial_digest_covers_more_than_one_thousand_events(tmp_path, monkeypatch):
    monkeypatch.setenv("SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop")
    channels = """
[watch.channels.slack]
type = "slack"
webhook_url_env = "SLACK_URL"
max_items = 5
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["slack"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    records = [
        WatchRecord(
            cve_id=f"CVE-2026-{index:04d}",
            status="published",
            description="Example vulnerability.",
            cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),),
        )
        for index in range(1, 1501)
    ]
    store.upsert_nvd(records, catalogs=config.watch.sources)
    store.evaluate_touched(
        config.watch.rules, catalogs=config.watch.sources, initial=True
    )
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    report = deliver(config, store, handler)
    assert len(seen) == 1
    text = json.loads(seen[0].content)["text"]
    assert "1500 CVEs across 1 rule" in text
    assert "critical: 1500 matches" in text
    assert "and 1495 more" in text
    assert report.channels[0].messages == 1
    assert report.channels[0].events == 1500
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM watch_delivery WHERE status='sent'"
            ).fetchone()[0]
            == 1500
        )


def test_initial_digest_does_not_build_a_view_for_the_backlog(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    )
    channels = """
[watch.channels.slack]
type = "slack"
webhook_url_env = "SLACK_URL"
max_items = 20
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["slack"]
"""
    config = make_config(tmp_path, channels=channels, rules=rules)
    identifiers = tuple(f"CVE-2026-{index:04d}" for index in range(1, 5001))
    store = seed(config, identifiers=identifiers, initial=True)
    views = {"count": 0}
    original = store._view

    def counting(*args, **kwargs):
        views["count"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "_view", counting)
    seen: list[str] = []

    def handler(request):
        seen.append(json.loads(request.content)["text"])
        return httpx.Response(200, content=b"ok")

    tracemalloc.start()
    report = deliver(config, store, handler)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert views["count"] <= 22
    assert sum(text.count("CVEBeacon initial summary") for text in seen) == 1
    assert "CVEBeacon initial summary: 5000 CVEs across 1 rule" in seen[0]
    assert "critical: 5000 matches" in seen[0]
    assert any("and 4980 more" in text for text in seen)
    assert report.channels[0].events == 5000
    assert report.channels[0].messages == len(seen)
    assert peak < 8 * 1024 * 1024
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM watch_delivery WHERE status='sent'"
            ).fetchone()[0]
            == 5000
        )


def test_initial_digest_samples_kev_rows_first(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    )
    channels = """
[watch.channels.slack]
type = "slack"
webhook_url_env = "SLACK_URL"
max_items = 1
"""
    rules = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 0 }
channels = ["slack"]
"""
    config = make_config(
        tmp_path, sources=("nvd", "cisa_kev"), channels=channels, rules=rules
    )
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    records = [
        WatchRecord(
            cve_id=f"CVE-2026-{index:04d}",
            status="published",
            description="A high score without exploitation.",
            cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8),),
        )
        for index in range(1, 21)
    ]
    records.append(
        WatchRecord(
            cve_id="CVE-2026-9999",
            status="published",
            description="A lower score that is in KEV.",
            cvss=(CVSSEntry("nvd", "nvd@nist.gov", "3.1", 1.0),),
        )
    )
    store.upsert_nvd(records, catalogs=config.watch.sources)
    store.replace_kev(
        "cisa", {"CVE-2026-9999": KEVFields("2026-11-01")},
        catalogs=config.watch.sources,
    )
    store.evaluate_touched(
        config.watch.rules, catalogs=config.watch.sources, initial=True
    )
    seen = []

    def handler(request):
        seen.append(json.loads(request.content)["text"])
        return httpx.Response(200, content=b"ok")

    report = deliver(config, store, handler)
    assert report.channels[0].ok
    assert "CVE-2026-9999" in seen[0]
    assert "and 20 more" in seen[0]


def test_initial_digest_combines_pending_and_ambiguous_rows(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(
        "SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    )
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
    store = seed(
        config,
        identifiers=("CVE-2026-0001", "CVE-2026-0002"),
        initial=True,
    )
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_delivery SET status='ambiguous', attempts=1, "
            "first_attempt_at=? WHERE event_id=("
            "SELECT id FROM watch_event WHERE cve_id='CVE-2026-0002')",
            ((NOW - timedelta(minutes=30)).isoformat(),),
        )
    seen = []

    def handler(request):
        seen.append(json.loads(request.content)["text"])
        return httpx.Response(200, content=b"ok")

    report = deliver(config, store, handler, retry_ambiguous=True)
    assert len(seen) == 1
    assert "CVEBeacon initial summary: 2 CVEs across 1 rule" in seen[0]
    assert "critical: 2 matches" in seen[0]
    assert report.channels[0].events == 2
    with sqlite3.connect(store.path) as db:
        assert db.execute(
            "SELECT DISTINCT status FROM watch_delivery"
        ).fetchall() == [("sent",)]


def test_initial_failure_keeps_ambiguous_rows_ambiguous(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    )
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
    store = seed(
        config,
        identifiers=("CVE-2026-0001", "CVE-2026-0002"),
        initial=True,
    )
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_delivery SET status='ambiguous', attempts=1, "
            "first_attempt_at=? WHERE event_id=("
            "SELECT id FROM watch_event WHERE cve_id='CVE-2026-0002')",
            ((NOW - timedelta(minutes=30)).isoformat(),),
        )
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(500)

    report = deliver(config, store, handler, retry_ambiguous=True)
    assert len(seen) == 1
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 1
    with sqlite3.connect(store.path) as db:
        statuses = {
            cve_id: (status, attempts)
            for cve_id, status, attempts in db.execute(
                "SELECT e.cve_id,d.status,d.attempts FROM watch_delivery d "
                "JOIN watch_event e ON e.id=d.event_id"
            ).fetchall()
        }
    assert statuses["CVE-2026-0001"] == ("failed", 1)
    assert statuses["CVE-2026-0002"] == ("ambiguous", 2)


def test_initial_webhook_is_sent_in_chunks_of_one_thousand(tmp_path):
    config = make_config(tmp_path)
    identifiers = tuple(f"CVE-2026-{index:04d}" for index in range(1, 5001))
    store = seed(config, identifiers=identifiers, initial=True)
    payloads = []

    def handler(request):
        payloads.append(json.loads(request.content))
        return httpx.Response(200, json={})

    report = deliver(config, store, handler)
    assert [len(payload["events"]) for payload in payloads] == [1000] * 5
    assert all(
        event["initial"]
        for payload in payloads
        for event in payload["events"]
    )
    assert report.channels[0].messages == 5
    assert report.channels[0].events == 5000
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM watch_delivery WHERE status='sent'"
            ).fetchone()[0]
            == 5000
        )


def test_initial_failed_rows_wait_for_their_backoff(tmp_path):
    config = make_config(tmp_path)
    store = seed(config, initial=True)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_delivery SET status='failed', attempts=1, updated_at=?",
            (NOW.isoformat(),),
        )
    assert (
        store.claim_initial_digest(
            "hook",
            catalogs=config.watch.sources,
            now=NOW + timedelta(minutes=4),
            max_items=20,
        )
        is None
    )
    digest = store.claim_initial_digest(
        "hook",
        catalogs=config.watch.sources,
        now=NOW + timedelta(minutes=5),
        max_items=20,
    )
    assert digest is not None
    assert digest.total == 1


def test_fake_smtp_server_unstuffs_leading_dots(tmp_path, monkeypatch):
    import smtplib

    monkeypatch.setattr(socket.socket, "connect", REAL_CONNECT)
    monkeypatch.setattr(socket, "getaddrinfo", loopback_getaddrinfo)
    server = FakeSMTPServer(("127.0.0.1", 0), FakeSMTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = smtplib.SMTP("127.0.0.1", server.server_address[1], timeout=5)
        client.sendmail(
            "beacon@example.org",
            ["soc@example.org"],
            b"Subject: dotted\r\n\r\n.hidden\r\n..also hidden\r\n",
        )
        client.quit()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    data = server.messages[0]["data"]
    assert b"\r\n.hidden\r\n" in data
    assert b"\r\n..hidden\r\n" not in data


def test_smtp_partial_recipient_refusal_is_ambiguous(tmp_path, monkeypatch):
    report, store, server, _ = run_smtp_test(
        tmp_path,
        monkeypatch,
        "rcpt-refused",
        to=("soc@example.org", "other@example.org"),
    )
    assert report.channels[0].failed == 0
    assert report.channels[0].ambiguous == 1
    assert "refused some recipients" in report.channels[0].error
    assert rows(store)[0][1] == "ambiguous"


def test_graph_token_failure_is_a_definite_failure(tmp_path, monkeypatch):
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
        return httpx.Response(500)

    report = deliver(config, store, handler)
    assert report.channels[0].failed == 1
    assert report.channels[0].ambiguous == 0
    assert "Graph token request failed" in report.channels[0].error
    assert len(seen) == 1
    assert rows(store)[0][1] == "failed"
