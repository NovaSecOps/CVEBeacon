"""Exact handler and concurrent auth checks, without sockets or real tokens."""

from email.message import Message
import hmac
import io
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from cvebeacon_automation.common import AutomationError
from cvebeacon_automation.ingest import server
from cvebeacon_automation.ingest.server import Handler
from test_ingestion import setup, TOKEN


@pytest.fixture(autouse=True)
def require_current_source():
    assert Path(server.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1] / "src")


def test_concurrent_failed_auth_counts_every_rejection(tmp_path, monkeypatch):
    receiver, _, _, _ = setup(tmp_path, monkeypatch)
    entered = threading.Barrier(4)
    original = hmac.compare_digest
    outcomes = []

    def scheduled_compare(left, right):
        entered.wait(timeout=2)
        return original(left, right)

    def rejected():
        try:
            receiver.authenticate("host-a", "Bearer wrong", "synthetic-peer")
        except AutomationError as exc:
            outcomes.append(exc.category)

    monkeypatch.setattr(server.hmac, "compare_digest", scheduled_compare)
    workers = [threading.Thread(target=rejected) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(3)
    assert all(not worker.is_alive() for worker in workers)
    assert outcomes == ["ingestion_unauthorized"] * 4
    assert receiver.attempts["synthetic-peer"][1] == 4
    monkeypatch.setattr(server.hmac, "compare_digest", original)
    for _ in range(6):
        with pytest.raises(AutomationError, match="ingestion_unauthorized"):
            receiver.authenticate("host-a", "Bearer wrong", "synthetic-peer")
    with pytest.raises(AutomationError, match="ingestion_rate_limited"):
        receiver.authenticate("host-a", "Bearer " + TOKEN, "synthetic-peer")
    assert receiver.authenticate("host-a", "Bearer " + TOKEN, "separate-peer").id == "host-a"


class UnreadBody(io.BytesIO):
    def read(self, *args):
        pytest.fail("rejected framing must be refused before authentication or body reads")


@pytest.mark.parametrize("transfer", [[""], ["chunked"], ["identity"], ["", "chunked"], ["chunked", ""]])
def test_any_transfer_encoding_presence_is_rejected_before_auth_or_body(transfer):
    headers = Message()
    for name, value in (("Authorization", "Bearer " + TOKEN), ("X-CVEBeacon-Source", "host-a"),
                        ("Content-Length", "2"), ("Content-Type", "application/json")):
        headers[name] = value
    for value in transfer:
        headers["Transfer-Encoding"] = value
    handler = Handler.__new__(Handler)
    handler.path, handler.headers = "/v1/snapshots", headers
    handler.rfile = UnreadBody(b"{}")
    handler.client_address = ("127.0.0.1", 12345)
    handler.server = SimpleNamespace(receiver=SimpleNamespace(authenticate=lambda *a: pytest.fail("framing first")))
    replies = []
    handler.reply = lambda code, data: replies.append((code, data))
    handler.do_POST()
    assert len(replies) == 1 and replies[0][0] == 400
    assert replies[0][1]["category"] in {"upload_duplicate_header", "upload_encoding_rejected"}


def test_exact_length_raw_json_still_reaches_authenticated_handler(tmp_path, monkeypatch):
    receiver, _, _, body = setup(tmp_path, monkeypatch)
    headers = Message()
    for name, value in (("Authorization", "Bearer " + TOKEN), ("X-CVEBeacon-Source", "host-a"),
                        ("Content-Length", str(len(body))), ("Content-Type", "application/json")):
        headers[name] = value
    handler = Handler.__new__(Handler)
    handler.path, handler.headers, handler.rfile = "/v1/snapshots", headers, io.BytesIO(body)
    handler.client_address = ("127.0.0.1", 12345)
    handler.server = SimpleNamespace(receiver=receiver)
    replies = []
    handler.reply = lambda code, data: replies.append((code, data))
    handler.do_POST()
    assert len(replies) == 1 and replies[0][0] == 200 and replies[0][1]["status"] == "accepted"
