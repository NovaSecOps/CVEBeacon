"""Real verified TLS wires for four synthetic providers; no public sends.

Only this acceptance fixture translates reviewed provider origins to a local
HTTPS gateway. Production destination validation and payload rendering run
unchanged. The transport still verifies the local fixture certificate.
"""

from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from urllib.parse import urlsplit

from cvebeacon.models import Applicability, Asset, Evidence, Finding, QueryResult, Vulnerability
from cvebeacon.state import StateStore
from cvebeacon_automation.config import Config
from cvebeacon_automation.http import HTTPS, endpoint
from cvebeacon_automation.notifications.service import dispatch
from support import certificate, local_network_only, tls_fixture


class Gateway:
    def __init__(self, local, cert):
        self.local, self.cert = local, cert

    def factory(self, origin, **bounds):
        selected = endpoint(origin).origin
        providers = {("api.telegram.org", 443): "telegram", ("discord.com", 443): "discord",
                     ("hooks.slack.com", 443): "slack", ("matrix.example.invalid", 443): "matrix"}
        assert selected in providers, "unexpected provider fixture destination"
        transport = HTTPS(self.local, ca_file=self.cert, **bounds)
        local = self.local
        provider = providers[selected]
        class Connection:
            def request(self, method, url, **options):
                assert endpoint(url).origin == selected
                parsed = urlsplit(url)
                destination = local + "/" + provider + (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                return transport.request(method, destination, **options)
        return Connection()


def finding(score=8.1):
    asset = Asset("synthetic-component", product="example", version="1", purl="pkg:pypi/example@1",
                  system_id="PRIVATE_SOURCE_NOT_FOR_ALERTS")
    vulnerability = Vulnerability("CVE-2026-1234", cvss_score=score, cisa_kev=True)
    return Finding(asset, vulnerability, Applicability.AFFECTED, "high", "PRIVATE_PATH_NOT_FOR_ALERTS",
                   (Evidence("osv", "applicability", "synthetic evidence", details={"affected": True}),))


def configuration(root):
    secrets = {"FIXTURE_TELEGRAM": "1234:SYNTHETIC_LOCAL_WIRE_ONLY_000000000",
               "FIXTURE_DISCORD": "https://discord.com/api/webhooks/1234/SYNTHETIC_LOCAL_WIRE_ONLY_000000000",
               "FIXTURE_SLACK": "https://hooks.slack.com/services/TFAKE/BFAKE/SYNTHETICLOCALWIREONLY000000000",
               "FIXTURE_MATRIX": "SYNTHETIC_LOCAL_MATRIX_WIRE_ONLY_000000000"}
    os.environ.update(secrets)
    channels = ({"id": "telegram", "provider": "telegram", "token": {"env": "FIXTURE_TELEGRAM"}, "chat_id": "-1001234"},
                {"id": "discord", "provider": "discord", "webhook": {"env": "FIXTURE_DISCORD"}},
                {"id": "slack", "provider": "slack", "webhook": {"env": "FIXTURE_SLACK"}},
                {"id": "matrix", "provider": "matrix", "token": {"env": "FIXTURE_MATRIX"},
                 "homeserver": "https://matrix.example.invalid", "room_id": "!synthetic:example.invalid"})
    return Config(root / "auto.toml", root / "state", root / "staging", root / "merged.json", root / "core.toml", (),
                  notifications=channels), tuple(secrets.values())


def main():
    with tempfile.TemporaryDirectory(prefix="cvebeacon-provider-tls-") as temporary:
        root = Path(temporary)
        cert, key = certificate(root)
        config, secrets = configuration(root)
        database = root / "core.db"
        store = StateStore(database)
        mode = {}
        def behavior(item):
            provider = item["path"].split("/", 2)[1]
            if item["method"] == "GET":
                assert provider == "matrix" and item["path"].endswith("/state/m.room.encryption")
                return 404, {}, b'{"errcode":"M_NOT_FOUND"}'
            payload = json.loads(item["body"])
            text = payload.get("body", payload.get("text", payload.get("content", "")))
            assert "PRIVATE_SOURCE" not in text and "PRIVATE_PATH" not in text
            if provider == "discord":
                assert "?wait=true" in item["path"] and payload["allowed_mentions"] == {"parse": []}
            if provider == "matrix":
                assert item["headers"]["Authorization"].startswith("Bearer SYNTHETIC_")
                assert payload["m.mentions"] == {}
            status = mode.pop(provider, "success")
            if status == "limited":
                return 429, {"Retry-After": "120"}, b'{"retry_after":120}'
            if status == "lost_ack":
                return None, {}, b""
            responses = {"telegram": b'{"ok":true,"result":{"message_id":1}}', "discord": b'{"id":"1"}',
                         "slack": b"ok", "matrix": b'{"event_id":"$synthetic"}'}
            return 200, {}, responses[provider]
        clock = [time.time()]
        with tls_fixture(cert, key, behavior) as (url, requests), local_network_only():
            gateway = Gateway(url, cert)
            def send():
                before = database.read_bytes()
                result = dispatch(config, database, transport_factory=gateway.factory, clock=lambda: clock[0],
                                  sleeper=lambda seconds: clock.__setitem__(0, clock[0] + seconds), random_value=lambda: 0)
                assert database.read_bytes() == before, "Automation modified Core database"
                return result
            original = finding()
            _, events = store.record_scan([QueryResult(original.asset, (original,), ())], channels=("teams",))
            assert len(events) == 1
            first = send()
            assert first["attempted"] == 4 and not first["unhealthy"]
            _, events = store.record_scan([QueryResult(original.asset, (original,), ())], channels=("teams",))
            assert not events and send()["attempted"] == 0
            clock[0] += 100
            changed = finding(9.1)
            _, events = store.record_scan([QueryResult(changed.asset, (changed,), ())], channels=("teams",))
            assert len(events) == 1 and send()["attempted"] == 4
            clock[0] += 100
            outage = finding(9.5)
            store.record_scan([QueryResult(outage.asset, (outage,), ())], channels=("teams",))
            mode["slack"] = "limited"
            result = send()
            assert result["attempted"] == 4 and result["channels"]["slack"]["states"]["retryable"] == 1
            assert send()["attempted"] == 0
            clock[0] += 121
            assert send()["attempted"] == 1
            clock[0] += 100
            final = finding(9.9)
            store.record_scan([QueryResult(final.asset, (final,), ())], channels=("teams",))
            mode.update(discord="lost_ack", matrix="lost_ack")
            result = send()
            assert result["channels"]["discord"]["states"]["ambiguous"] == 1
            clock[0] += 100
            assert send()["attempted"] == 1  # Matrix only: replay uses the same transaction.
            matrix_paths = [item["path"] for item in requests if item["method"] == "PUT"]
            assert matrix_paths[-1] == matrix_paths[-2]
            assert send()["attempted"] == 0
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
                assert db.execute("SELECT count(*) FROM deliveries WHERE channel='teams'").fetchone()[0] == 4
            ledger = (config.state_dir / "notification-ledger.sqlite3").read_bytes()
            assert all(secret.encode() not in ledger for secret in secrets)
    print("four verified local TLS provider wires, actual Core events, unchanged deduplication, changed alerts, persisted429, ambiguous Discord and idempotent Matrix passed")


if __name__ == "__main__":
    main()
