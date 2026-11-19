"""Exercise bot delivery over real HTTP using disposable loopback endpoints only."""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
from urllib.parse import parse_qs

import httpx

from cvebeacon.config import load_config
from cvebeacon.http import HttpClient
from cvebeacon.watch.delivery import deliver_pending, send_test
from cvebeacon.watch.records import CVSSEntry, WatchRecord
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch import teams_bot

TENANT = "11111111-1111-4111-8111-111111111111"
APP = "22222222-2222-4222-8222-222222222222"
USER = "33333333-3333-4333-8333-333333333333"


def main() -> None:
    counts = Counter()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            assert 0 < int(self.headers["Content-Length"]) < 65536
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if self.path == f"/{TENANT}/oauth2/v2.0/token":
                counts["token"] += 1
                form = parse_qs(body.decode())
                assert form["client_id"] == [APP]
                assert form["client_secret"] == ["synthetic-local-secret"]
                assert form["scope"] == [teams_bot.BOT_SCOPE]
                result = {"access_token": "synthetic-local-token", "expires_in": 3600}
                status = 200
            else:
                assert self.headers["Authorization"] == "Bearer synthetic-local-token"
                payload = json.loads(body)
                if self.path == "/teams/v3/conversations":
                    counts["conversation"] += 1
                    assert payload["members"] == [{"id": USER}]
                    assert "activity" not in payload
                    result, status = {"id": "local-conversation"}, 201
                else:
                    assert self.path == "/teams/v3/conversations/local-conversation/activities"
                    counts["activity"] += 1
                    card = payload["attachments"][0]["content"]
                    assert card["type"] == "AdaptiveCard"
                    assert "CVEBeacon" in card["body"][0]["text"]
                    result, status = {"id": "local-activity"}, 200
            encoded = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    original_authority = teams_bot.AUTHORITY
    teams_bot.AUTHORITY = origin
    try:
        with tempfile.TemporaryDirectory(prefix="cvebeacon-teams-") as directory:
            root = Path(directory)
            secret = root / "bot-secret"
            secret.write_text("synthetic-local-secret", encoding="utf-8")
            secret.chmod(0o600)
            path = root / "config.toml"
            path.write_text(f'''
[state]
database = "state.db"
[watch]
enabled = true
database = "watch.db"
sources = ["nvd"]
[watch.channels.bot]
type = "teams_bot"
tenant_id = "{TENANT}"
app_id = "{APP}"
client_secret_file = "bot-secret"
recipients = ["{USER}"]
service_url = "{origin}/teams/"
allow_insecure = true
[[watch.rules]]
name = "critical"
condition = {{ cvss_min = 9 }}
channels = ["bot"]
''', encoding="utf-8")
            config = load_config(path)
            store = WatchStore(config.watch.database)
            store.upsert_nvd([WatchRecord(
                cve_id="CVE-2026-0001", status="published", description="Local acceptance alert",
                cvss=(CVSSEntry("nvd", "security@example.com", "3.1", 9.8),),
            )], catalogs=config.watch.sources)
            store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources)
            # Disable proxy environment variables and reject every nonlocal URL.
            class LocalTransport(httpx.HTTPTransport):
                def handle_request(self, request):
                    assert request.url.host == "127.0.0.1"
                    assert request.url.port == server.server_port
                    return super().handle_request(request)

            with httpx.Client(transport=LocalTransport(), trust_env=False) as client:
                with HttpClient(config.http, client=client) as http:
                    assert send_test(config, http, "bot").ok
                    assert send_test(config, http, "bot").ok
                    # Reopen the DB to prove the reference survives the sender.
                    assert not deliver_pending(config, WatchStore(store.path), http).failed
                    assert not deliver_pending(config, store, http).failed
            assert counts == {"token": 1, "conversation": 1, "activity": 3}, counts
            print("Teams bot loopback check passed: 1 token, 1 conversation, 3 cards; no external requests.")
    finally:
        teams_bot.AUTHORITY = original_authority
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
