from collections import deque
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import uuid

import pytest

from cvebeacon_automation.common import AutomationError, Secret, digest
from cvebeacon_automation.config import Config
from cvebeacon_automation.http import Response, TransportError
from cvebeacon_automation.notifications import service
from cvebeacon_automation.notifications.adapters import bind, retry_delay, split_message, validate_channels
from cvebeacon_automation.notifications.ledger import destination, ledger, prepare
from cvebeacon_automation.notifications.reader import core_reader, event_batch, render_event


TOKEN = "1234:SYNTHETIC_NOTIFICATION_CANARY_ONLY_000"
HOOK = "https://discord.com/api/webhooks/1234/SYNTHETIC_NOTIFICATION_CANARY_ONLY_000"
SLACK = "https://hooks.slack.com/services/TFAKE/BFAKE/SYNTHETICCANARYONLY00000000"


class Clock:
    def __init__(self):
        self.value = 2000000000.0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class Wire:
    def __init__(self, responses=()):
        self.calls = []
        self.responses = deque(responses)
        self.bounds = []

    def factory(self, url, **bounds):
        self.bounds.append(bounds)
        return self

    def request(self, method, url, *, headers=None, body=b""):
        self.calls.append((method, url, headers or {}, body))
        if method == "GET":
            return Response(404, {}, b'{"errcode":"M_NOT_FOUND","error":"absent"}')
        if self.responses:
            result = self.responses.popleft()
            if isinstance(result, BaseException):
                raise result
            return result
        if "telegram.org" in url:
            return Response(200, {}, b'{"ok":true,"result":{"message_id":1}}')
        if "discord.com" in url:
            return Response(200, {}, b'{"id":"1234"}')
        if "slack.com" in url:
            return Response(200, {}, b"ok")
        return Response(200, {}, b'{"event_id":"$synthetic"}')


def channel(provider, name=None, **extra):
    item = {"id": name or provider, "provider": provider}
    if provider == "telegram":
        item.update(token={"env": "NOTIFY_TELEGRAM"}, chat_id="-1001234")
    elif provider in {"discord", "slack"}:
        item.update(webhook={"env": "NOTIFY_" + provider.upper()})
    else:
        item.update(token={"env": "NOTIFY_MATRIX"}, homeserver="https://matrix.example.invalid", room_id="!synthetic:example.invalid")
    return {**item, **extra}


@pytest.fixture
def secrets(monkeypatch):
    monkeypatch.setenv("NOTIFY_TELEGRAM", TOKEN)
    monkeypatch.setenv("NOTIFY_DISCORD", HOOK)
    monkeypatch.setenv("NOTIFY_SLACK", SLACK)
    monkeypatch.setenv("NOTIFY_MATRIX", "SYNTHETIC_MATRIX_CANARY_ONLY")


def config(tmp_path, providers=("telegram", "discord", "slack", "matrix")):
    return Config(tmp_path / "auto.toml", tmp_path / "state", tmp_path / "staging", tmp_path / "merged.json",
                  tmp_path / "core.toml", (), notifications=tuple(channel(p) for p in providers))


def core(tmp_path, *, version=3, payload=None, count=1, run=None):
    filename = tmp_path / "core.db"
    db = sqlite3.connect(filename)
    db.executescript("""CREATE TABLE schema_info(version INTEGER NOT NULL);
        CREATE TABLE runs(run_id TEXT PRIMARY KEY);
        CREATE TABLE events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT NOT NULL,
          occurred_at TEXT NOT NULL,asset_id TEXT NOT NULL,cve_id TEXT NOT NULL,event_type TEXT NOT NULL,
          fingerprint TEXT NOT NULL,payload_json TEXT NOT NULL);
        CREATE TABLE deliveries(event_id INTEGER,channel TEXT,state TEXT);""")
    db.execute("INSERT INTO schema_info VALUES (?)", (version,))
    run = run or str(uuid.uuid4())
    db.execute("INSERT INTO runs VALUES (?)", (run,))
    if payload is None:
        payload = {"asset": {"product": "sample", "version": "1.0", "system_id": "PRIVATE-SOURCE-CANARY"},
                   "vulnerability": {"cvss_score": 8.1, "cisa_kev": True, "eu_kev": None,
                                     "references": ["SECRET-METADATA-CANARY"]}, "applicability": "needs_review",
                   "reason": "INTERNAL-PATH-CANARY", "evidence": [{"source": "PRIVATE-SOURCE-CANARY"}]}
    encoded = payload if isinstance(payload, str) else json.dumps(payload)
    for index in range(count):
        db.execute("INSERT INTO events(run_id,occurred_at,asset_id,cve_id,event_type,fingerprint,payload_json) VALUES (?,?,?,?,?,?,?)",
                   (run, "2026-10-04T00:00:00Z", "asset-a", "CVE-2026-1234", "new", str(index), encoded))
    db.execute("INSERT INTO deliveries VALUES (1,'teams','pending')")
    db.commit()
    db.close()
    return filename


def dispatch(cfg, filename, wire, clock):
    return service.dispatch(cfg, filename, transport_factory=wire.factory, clock=clock.now,
                            sleeper=clock.sleep, random_value=lambda: 0)


def test_configuration_is_finite_without_secret_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(Secret, "resolve", lambda self: pytest.fail("validation must not read credentials"))
    parsed = validate_channels(tuple(channel(p) for p in ("telegram", "discord", "slack", "matrix")), tmp_path)
    assert len(parsed) == 4
    assert "NOTIFY_" not in repr(parsed)


@pytest.mark.parametrize("update", [{"provider": "unknown"}, {"arbitrary": "CANARY"}, {"max_attempts": True},
                                  {"timeout_seconds": float("nan")}, {"max_parts": 0}, {"batch_size": 1000},
                                  {"webhook": "https://secret.invalid"}, {"retry_base_seconds": 60, "retry_max_seconds": 30}])
def test_bad_configuration_fails_safely(tmp_path, update):
    with pytest.raises(AutomationError) as caught:
        validate_channels(({**channel("discord"), **update},), tmp_path)
    assert "CANARY" not in str(caught.value)


@pytest.mark.parametrize("value", ["http://discord.com/api/webhooks/1234/" + "x" * 32,
    "https://discord.com.attacker.invalid/api/webhooks/1234/" + "x" * 32,
    HOOK + "?redirect=secret", HOOK + "/extra", HOOK.replace("discord.com", "discord.com:444"),
    HOOK.replace("discord.com", "secret@discord.com"), HOOK.replace("/webhooks/", "/%77ebhooks/")])
def test_resolved_webhook_restricted(tmp_path, monkeypatch, value):
    monkeypatch.setenv("NOTIFY_DISCORD", value)
    with pytest.raises(AutomationError):
        bind(validate_channels((channel("discord"),), tmp_path)[0])


@pytest.mark.parametrize("home", ["http://localhost", "https://secret@matrix.invalid", "https://matrix.invalid/path", "https://matrix.invalid/?secret=yes"])
def test_matrix_origin_is_explicit(tmp_path, home):
    with pytest.raises(AutomationError):
        validate_channels((channel("matrix", homeserver=home),), tmp_path)


def test_all_provider_wire_contracts_and_core_readonly(tmp_path, secrets):
    cfg, filename, wire, clock = config(tmp_path), core(tmp_path), Wire(), Clock()
    before = filename.read_bytes()
    result = dispatch(cfg, filename, wire, clock)
    assert not result["unhealthy"]
    assert result["attempted"] == 4
    assert len(wire.calls) == 5
    assert filename.read_bytes() == before
    original = sqlite3.connect(filename).execute("SELECT state FROM deliveries").fetchone()[0]
    assert original == "pending"
    bodies = [(method, url, headers, json.loads(body)) for method, url, headers, body in wire.calls if body]
    telegram = next(item for item in bodies if "telegram.org" in item[1])
    assert telegram[0] == "POST" and telegram[1].endswith("/sendMessage")
    assert "parse_mode" not in telegram[3] and telegram[3]["chat_id"] == "-1001234"
    discord = next(item for item in bodies if "discord.com" in item[1])
    assert discord[1].endswith("?wait=true") and "/api/v10/" in discord[1]
    assert discord[3]["allowed_mentions"] == {"parse": []}
    slack = next(item for item in bodies if "slack.com" in item[1])
    assert slack[3]["blocks"][0]["text"]["type"] == "plain_text"
    matrix = next(item for item in bodies if item[0] == "PUT")
    assert "/%21synthetic%3Aexample.invalid/send/m.room.message/cveb-" in matrix[1]
    assert matrix[2]["Authorization"] == "Bearer SYNTHETIC_MATRIX_CANARY_ONLY"
    assert matrix[3]["m.mentions"] == {}
    for item in bodies:
        text = json.dumps(item[3])
        assert "needs_review" in text.replace("\\", "")
        assert "INTERNAL-PATH-CANARY" not in text and "PRIVATE-SOURCE-CANARY" not in text and "SECRET-METADATA-CANARY" not in text
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 0
    public = json.dumps(result) + json.dumps(service.delivery_status(cfg))
    assert TOKEN not in public and HOOK not in public and "SYNTHETIC_MATRIX_CANARY_ONLY" not in public
    raw = (cfg.state_dir / "notification-ledger.sqlite3").read_bytes()
    assert TOKEN.encode() not in raw and HOOK.encode() not in raw and SLACK.encode() not in raw


@pytest.mark.parametrize("problem", [TransportError("CANARY", True), Response(200, {}, b'{"ok":"true"}'),
                                   Response(204, {}, b""), Response(500, {}, b"SECRET-CANARY"),
                                   Response(302, {"location": "https://SECRET-CANARY.invalid"}, b"")])
def test_nonidempotent_ambiguity_does_not_replay(tmp_path, secrets, problem):
    cfg, filename, wire, clock = config(tmp_path, ("discord",)), core(tmp_path), Wire((problem,)), Clock()
    result = dispatch(cfg, filename, wire, clock)
    assert result["channels"]["discord"]["states"]["ambiguous"] == 1
    clock.value += 100000
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 0
    assert len(wire.calls) == 1
    assert "CANARY" not in json.dumps(result)


def test_definite_pretransmission_failure_retries(tmp_path, secrets):
    cfg, filename, clock = config(tmp_path, ("telegram",)), core(tmp_path), Clock()
    wire = Wire((TransportError("SECRET", False),))
    first = dispatch(cfg, filename, wire, clock)
    assert first["channels"]["telegram"]["states"]["retryable"] == 1
    clock.value += 31
    assert dispatch(cfg, filename, wire, clock)["channels"]["telegram"]["states"]["accepted"] == 1


@pytest.mark.parametrize("provider,response,delay", [
    ("telegram", Response(429, {}, b'{"ok":false,"parameters":{"retry_after":500000}}'), 500000),
    ("discord", Response(429, {"retry-after": "500000"}, b'{"retry_after":0.25}'), 500000),
    ("slack", Response(429, {"retry-after": "500000"}, b"secret"), 500000),
    ("matrix", Response(429, {}, b'{"errcode":"M_LIMIT_EXCEEDED","retry_after_ms":500000000}'), 500000)])
def test_rate_limit_units_and_no_downward_clamp(tmp_path, secrets, provider, response, delay):
    cfg, filename, clock = config(tmp_path, (provider,)), core(tmp_path), Clock()
    wire = Wire((response,))
    result = dispatch(cfg, filename, wire, clock)
    assert result["channels"][provider]["states"]["retryable"] == 1
    with ledger(cfg, readonly=True) as db:
        due_at = db.execute("SELECT next_retry FROM deliveries").fetchone()[0]
    assert due_at >= clock.value + delay
    clock.value += delay - 4  # The dispatcher may wait up to three seconds for a due part.
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 0
    clock.value += 3
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 1
    assert clock.value >= due_at


def test_matrix_retries_identical_transaction_and_body(tmp_path, secrets):
    cfg, filename, clock = config(tmp_path, ("matrix",)), core(tmp_path), Clock()
    wire = Wire((TransportError("SYNTHETIC_MATRIX_CANARY_ONLY", True),))
    assert dispatch(cfg, filename, wire, clock)["channels"]["matrix"]["states"]["retryable"] == 1
    clock.value += 31
    assert not dispatch(cfg, filename, wire, clock)["unhealthy"]
    puts = [item for item in wire.calls if item[0] == "PUT"]
    assert len(puts) == 2 and puts[0][1:] == puts[1][1:]


@pytest.mark.parametrize("response", [Response(200, {}, b'{"algorithm":"m.megolm.v1.aes-sha2"}'),
    Response(403, {}, b'{"errcode":"M_FORBIDDEN"}'), Response(404, {}, b"bad-json")])
def test_matrix_refuses_encrypted_or_unknown_rooms(tmp_path, secrets, response):
    class Encrypted(Wire):
        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            return response
    cfg, filename, wire, clock = config(tmp_path, ("matrix",)), core(tmp_path), Encrypted(), Clock()
    assert dispatch(cfg, filename, wire, clock)["channels"]["matrix"]["states"]["permanent"] == 1
    assert len(wire.calls) == 1 and wire.calls[0][0] == "GET"


@pytest.mark.parametrize("provider,state", [("discord", "ambiguous"), ("matrix", "accepted")])
def test_inflight_process_death_recovery(tmp_path, secrets, provider, state):
    cfg, filename, clock = config(tmp_path, (provider,)), core(tmp_path), Clock()
    target = bind(validate_channels(cfg.notifications, tmp_path)[0])
    with core_reader(filename) as db:
        row = event_batch(db)[0]
        key, text = render_event(row)
    with ledger(cfg) as db:
        destination(db, target)
        prepare(db, target, key, split_message(text, target.channel), clock.value)
        with db:
            db.execute("UPDATE deliveries SET state='sending',attempts=1")
    wire = Wire()
    result = dispatch(cfg, filename, wire, clock)
    assert result["channels"][provider]["states"][state] == 1
    assert len(wire.calls) == (2 if provider == "matrix" else 0)


def test_run_uuid_prevents_replaced_database_event_id_collision(tmp_path, secrets):
    cfg, filename, wire, clock = config(tmp_path, ("discord",)), core(tmp_path), Wire(), Clock()
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 1
    db = sqlite3.connect(filename)
    run = str(uuid.uuid4())
    db.execute("UPDATE events SET run_id=?", (run,))
    db.commit()
    db.close()
    clock.value += 1
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 1


@pytest.mark.parametrize("version", [1, 4, "3"])
def test_unknown_core_schema_fails_without_send(tmp_path, secrets, version):
    cfg, filename, wire, clock = config(tmp_path, ("slack",)), core(tmp_path, version=version), Wire(), Clock()
    if version == "3":
        # INTEGER affinity coerces ordinary strings; force a genuine wrong SQLite type.
        db = sqlite3.connect(filename)
        db.execute("UPDATE schema_info SET version='future'")
        db.commit()
        db.close()
    result = dispatch(cfg, filename, wire, clock)
    assert result["unhealthy"] and result["errors"] and not wire.calls


def test_oversized_core_payload_is_not_materialized_or_sent(tmp_path, secrets):
    cfg, filename, wire, clock = config(tmp_path, ("discord",)), core(tmp_path, payload="x" * 200000), Wire(), Clock()
    result = dispatch(cfg, filename, wire, clock)
    assert result["unhealthy"] and not wire.calls


def test_readonly_connection_rejects_writes(tmp_path):
    filename = core(tmp_path)
    with core_reader(filename) as db:
        assert db.execute("PRAGMA query_only").fetchone()[0] == 1
        assert db.in_transaction
        with pytest.raises(sqlite3.OperationalError):
            db.execute("UPDATE schema_info SET version=4")


def test_all_alert_channels_share_one_core_read_snapshot(tmp_path, secrets, monkeypatch):
    cfg, filename, clock, wire = config(tmp_path), core(tmp_path), Clock(), Wire()
    reads = []
    def counted_reader(path):
        reads.append(path)
        return core_reader(path)
    monkeypatch.setattr(service, "core_reader", counted_reader)
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 4
    assert reads == [filename]


def test_long_unicode_safe_wire_budget(tmp_path, secrets):
    text = "😀_*[]<&" * 700
    for provider in ("telegram", "discord", "slack", "matrix"):
        item = validate_channels((channel(provider),), tmp_path)[0]
        parts = split_message(text, item)
        assert len(parts) > 1
        wire = Wire()
        bound = bind(item)
        for index, part in enumerate(parts):
            assert bound.send(part, "txn" + str(index), transport_factory=wire.factory).state == "accepted"
        for _, _, _, body in wire.calls:
            if not body:
                continue
            payload = json.loads(body)
            assert len(body) <= 32768
            if provider == "discord":
                assert len(payload["content"].encode("utf-16-le")) // 2 <= 2000
            if provider == "telegram":
                assert len(payload["text"].encode("utf-16-le")) // 2 <= 4096
            if provider == "slack":
                assert len(payload["blocks"][0]["text"]["text"]) <= 3000
                assert "<" not in payload["text"]


def test_explicit_test_only_sends_test_not_real_backlog(tmp_path, secrets):
    cfg, clock, wire = config(tmp_path, ("discord",)), Clock(), Wire()
    target = bind(validate_channels(cfg.notifications, tmp_path)[0])
    with ledger(cfg) as db:
        destination(db, target)
        prepare(db, target, digest(b"real-backlog"), ("REAL VULNERABILITY BACKLOG",), clock.value)
    result = service.test_channel(cfg, "discord", transport_factory=wire.factory, clock=clock.now, sleeper=clock.sleep)
    assert result["attempted"] == 1 and len(wire.calls) == 1
    assert "TEST" in json.loads(wire.calls[0][3])["content"]
    with ledger(cfg, readonly=True) as db:
        assert db.execute("SELECT state FROM deliveries WHERE text='REAL VULNERABILITY BACKLOG'").fetchone()[0] == "pending"


def test_operational_digest_failure_and_recovery_are_not_vulnerability_truth(tmp_path, secrets):
    cfg = replace(config(tmp_path, ("slack",)), operations={"enabled": True, "failures": True, "recovery": True, "interval_seconds": 60})
    clock, wire = Clock(), Wire()
    failed = {"status": "failed", "started_at": "t1", "core_exit": 4, "sources": {"SECRET-SOURCE-CANARY": {"error": "SECRET"}}}
    first = service.operational(cfg, failed, {}, transport_factory=wire.factory, clock=clock.now, sleeper=clock.sleep)
    assert first["attempted"] == 2
    same = service.operational(cfg, failed, {}, transport_factory=wire.factory, clock=clock.now, sleeper=clock.sleep)
    assert same["attempted"] == 0
    healthy = {"status": "operational", "started_at": "t2", "core_exit": 0, "sources": {}}
    service.operational(cfg, healthy, failed, transport_factory=wire.factory, clock=clock.now, sleeper=clock.sleep)
    emitted = " ".join(json.loads(item[3])["text"] for item in wire.calls)
    assert "FAILURE" in emitted and "RECOVERY" in emitted and "does not mean vulnerability-free" in emitted
    assert "SECRET" not in emitted
    clock.value += 61
    assert service.operational(cfg, healthy, healthy, transport_factory=wire.factory, clock=clock.now, sleeper=clock.sleep)["attempted"] == 1


def test_bad_provider_does_not_prevent_other_provider_attempt(tmp_path, secrets, monkeypatch):
    cfg, filename, clock, wire = config(tmp_path), core(tmp_path), Clock(), Wire()
    monkeypatch.setenv("NOTIFY_TELEGRAM", "SECRET-CANARY-BAD-TOKEN")
    result = dispatch(cfg, filename, wire, clock)
    assert result["unhealthy"] and result["attempted"] == 3
    assert result["channels"]["slack"]["states"]["accepted"] == 1
    assert "CANARY" not in json.dumps(result)


def test_unexpected_provider_failure_is_safe_and_isolated(tmp_path, secrets):
    cfg, filename, clock = config(tmp_path), core(tmp_path), Clock()
    wire = Wire((RuntimeError("PROVIDER-SECRET-CANARY"),))
    result = dispatch(cfg, filename, wire, clock)
    assert result["attempted"] == 4 and result["unhealthy"]
    assert result["channels"]["telegram"]["states"]["ambiguous"] == 1
    assert result["channels"]["slack"]["states"]["accepted"] == 1
    assert "CANARY" not in json.dumps(result)


def test_hostile_retry_hints_are_bounded():
    assert retry_delay({}, {"retry_after": 10**1000}, "discord", 1) == 0
    assert retry_delay({"retry-after": "NaN"}, {}, "slack", 1) == 0
    assert retry_delay({"retry-after": "1.25"}, {}, "discord", 1) == 1.25
    assert retry_delay({"retry-after": "Thu, 01 Jan 1970 00:00:05 GMT"}, {}, "matrix", 1) == 4


def test_missing_status_does_not_resolve_secrets(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    monkeypatch.setattr(Secret, "resolve", lambda self: pytest.fail("status must not resolve secrets"))
    result = service.delivery_status(cfg)
    assert not result["unhealthy"] and not cfg.state_dir.exists()


def test_changed_matrix_token_pauses_an_attempted_transaction(tmp_path, secrets, monkeypatch):
    cfg, filename, clock = config(tmp_path, ("matrix",)), core(tmp_path), Clock()
    wire = Wire((TransportError("SYNTHETIC", True),))
    assert dispatch(cfg, filename, wire, clock)["channels"]["matrix"]["states"]["retryable"] == 1
    monkeypatch.setenv("NOTIFY_MATRIX", "DIFFERENT_SYNTHETIC_DEVICE_CONTEXT")
    clock.value += 31
    result = dispatch(cfg, filename, wire, clock)
    assert result["attempted"] == 0 and result["channels"]["matrix"]["states"]["ambiguous"] == 1
    with ledger(cfg, readonly=True) as db:
        assert db.execute("SELECT error FROM deliveries").fetchone()[0] == "matrix_credential_context_changed"
    assert len(wire.calls) == 2


def test_matrix_token_change_before_first_attempt_is_safe(tmp_path, secrets, monkeypatch):
    cfg, filename, clock = config(tmp_path, ("matrix",)), core(tmp_path), Clock()
    target = bind(validate_channels(cfg.notifications, tmp_path)[0])
    with core_reader(filename) as db:
        key, text = render_event(event_batch(db)[0])
    with ledger(cfg) as db:
        destination(db, target)
        prepare(db, target, key, (text,), clock.value)
    monkeypatch.setenv("NOTIFY_MATRIX", "DIFFERENT_SYNTHETIC_DEVICE_CONTEXT")
    wire = Wire()
    assert not dispatch(cfg, filename, wire, clock)["unhealthy"]
    assert len(wire.calls) == 2


def test_persistent_global_cooldown_covers_a_new_destination(tmp_path, secrets, monkeypatch):
    cfg, filename, clock = config(tmp_path, ("slack",)), core(tmp_path), Clock()
    wire = Wire((Response(429, {"retry-after": "500000"}, b""),))
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 1
    monkeypatch.setenv("NOTIFY_SLACK_SECOND", "https://hooks.slack.com/services/T222/B222/" + "X" * 32)
    new = channel("slack", "second", webhook={"env": "NOTIFY_SLACK_SECOND"})
    expanded = replace(cfg, notifications=cfg.notifications + (new, channel("discord")))
    result = dispatch(expanded, filename, wire, clock)
    assert result["attempted"] == 1 and result["channels"]["discord"]["states"]["accepted"] == 1
    assert result["channels"]["second"]["states"]["pending"] == 1
    assert len(wire.calls) == 2


def test_schema_rejection_blocks_prepared_alerts_and_operational_drain(tmp_path, secrets):
    cfg = replace(config(tmp_path, ("slack",)), operations={"enabled": True})
    filename, clock = core(tmp_path), Clock()
    wire = Wire((TransportError("SYNTHETIC", False),))
    assert dispatch(cfg, filename, wire, clock)["channels"]["slack"]["states"]["retryable"] == 1
    with sqlite3.connect(filename) as db:
        db.execute("UPDATE schema_info SET version=4")
    clock.value += 31
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 0
    prior = len(wire.calls)
    state = {"status": "failed", "core_exit": 2, "sources": {}}
    result = service.operational(cfg, state, {}, transport_factory=wire.factory, clock=clock.now, sleeper=clock.sleep)
    assert result["attempted"] == 1
    assert all("vulnerability alert" not in json.loads(item[3])["text"] for item in wire.calls[prior:])
    with ledger(cfg, readonly=True) as db:
        assert db.execute("SELECT state FROM deliveries WHERE purpose='event'").fetchone()[0] == "retryable"


@pytest.mark.parametrize("provider,terminal", [("discord", "permanent"), ("matrix", "ambiguous")])
def test_attempt_cap_prevents_infinite_retries(tmp_path, secrets, provider, terminal):
    cfg = replace(config(tmp_path, (provider,)), notifications=(channel(provider, max_attempts=1),))
    filename, clock = core(tmp_path), Clock()
    wire = Wire((TransportError("SYNTHETIC", False),))
    result = dispatch(cfg, filename, wire, clock)
    assert result["attempted"] == 1 and result["channels"][provider]["states"][terminal] == 1
    clock.value += 100000
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 0


def test_ambiguous_first_part_does_not_send_later_parts(tmp_path, secrets):
    cfg, filename, clock = config(tmp_path, ("discord",)), core(tmp_path, count=0), Clock()
    target = bind(validate_channels(cfg.notifications, tmp_path)[0])
    with ledger(cfg) as db:
        destination(db, target)
        prepare(db, target, digest(b"long-event"), ("[1/2] first", "[2/2] second"), clock.value)
    wire = Wire((Response(500, {}, b"SYNTHETIC"),))
    result = dispatch(cfg, filename, wire, clock)
    assert result["attempted"] == 1
    assert result["channels"]["discord"]["states"]["pending"] == 1
    clock.value += 100000
    assert dispatch(cfg, filename, wire, clock)["attempted"] == 0 and len(wire.calls) == 1


@pytest.mark.parametrize("owned", ["notification-ledger.sqlite3", "notifications.lock"])
def test_core_database_state_path_collision_is_rejected_before_mutation(tmp_path, secrets, owned):
    cfg, filename, clock, wire = replace(config(tmp_path), state_dir=tmp_path), core(tmp_path), Clock(), Wire()
    colliding = tmp_path / owned
    colliding.write_bytes(filename.read_bytes())
    before = colliding.read_bytes()
    with pytest.raises(AutomationError, match="notification_state_path_collision"):
        dispatch(cfg, colliding, wire, clock)
    assert colliding.read_bytes() == before and not wire.calls


def test_pending_body_and_transaction_are_durable_before_transmission(tmp_path, secrets):
    cfg, filename, clock = config(tmp_path, ("matrix",)), core(tmp_path), Clock()
    class InspectingWire(Wire):
        def request(self, method, url, *, headers=None, body=b""):
            with ledger(cfg, readonly=True) as db:
                row = db.execute("SELECT state,text,transaction_id FROM deliveries").fetchone()
                assert row[0] == "sending" and row[1] and row[2].startswith("cveb-")
                if body:
                    assert json.loads(body)["body"] == row[1] and url.endswith(row[2])
            return super().request(method, url, headers=headers, body=body)
    assert dispatch(cfg, filename, InspectingWire(), clock)["attempted"] == 1


def test_large_event_history_has_a_finite_preparation_and_send_batch(tmp_path, secrets):
    cfg = replace(config(tmp_path, ("slack",)), notifications=(channel("slack", batch_size=256),))
    filename, clock, wire = core(tmp_path, count=300), Clock(), Wire()
    result = dispatch(cfg, filename, wire, clock)
    assert result["attempted"] == service.MAX_ATTEMPTS_PER_RUN == 32
    assert result["channels"]["slack"]["states"]["accepted"] == 32
    assert result["channels"]["slack"]["states"]["pending"] == 224
    with ledger(cfg, readonly=True) as db:
        assert db.execute("SELECT cursor_id FROM destinations").fetchone()[0] == 256


def test_corrupt_or_future_ledger_cannot_be_interpreted_as_current(tmp_path):
    cfg = config(tmp_path)
    cfg.state_dir.mkdir()
    with sqlite3.connect(cfg.state_dir / "notification-ledger.sqlite3") as db:
        db.execute("PRAGMA user_version=1")
        db.execute("CREATE TABLE deliveries(channel TEXT, state TEXT)")
    with pytest.raises(AutomationError, match="unsupported_notification_ledger"):
        service.delivery_status(cfg)
