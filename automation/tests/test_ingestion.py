import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os

import pytest

from cvebeacon_extensions.contract import ExtensionError, manifest_path, write_snapshot
from cvebeacon_automation.common import AutomationError, Secret
from cvebeacon_automation.http import Response, TransportError
from cvebeacon_automation.ingest.client import push
from cvebeacon_automation.ingest.protocol import decode_envelope, encode_envelope
from cvebeacon_automation.ingest.server import IngestConfig, Receiver, UploadSource, load_ingest_config
from cvebeacon_automation.staging import current_snapshot


TOKEN = "synthetic-upload-credential-canary-0123456789"


def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_UPLOAD_TOKEN", TOKEN)
    source = UploadSource("host-a", Secret(env="TEST_UPLOAD_TOKEN"))
    config = IngestConfig(tmp_path / "staging", (source,))
    pair = tmp_path / "host.json"
    write_snapshot(pair, [dict(asset_id="a", purl="pkg:pypi/example@1.0")], source_id="host-a", collector="synthetic")
    body = encode_envelope("host-a", pair.read_bytes(), manifest_path(pair).read_bytes())
    return Receiver(config), source, pair, body


def test_authenticated_identity_exact_bytes_and_idempotence(tmp_path, monkeypatch):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    authenticated = receiver.authenticate("host-a", "Bearer " + TOKEN)
    assert receiver.accept(authenticated, body)["status"] == "accepted"
    assert receiver.accept(authenticated, body)["status"] == "idempotent"
    assert current_snapshot(receiver.config.staging_dir, "host-a").read_bytes() == pair.read_bytes()
    assert TOKEN not in repr(receiver.config)


@pytest.mark.parametrize("source_id,auth", [("host-b", "Bearer " + TOKEN), ("../host-a", "Bearer " + TOKEN), ("host-a", "Bearer wrong"), ("host-a", None), ("host-a", "Basic " + TOKEN)])
def test_credential_binds_source(tmp_path, monkeypatch, source_id, auth):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    with pytest.raises(AutomationError, match="ingestion_unauthorized") as error:
        receiver.authenticate(source_id, auth)
    assert TOKEN not in str(error.value)


def test_per_peer_bruteforce_bound(tmp_path, monkeypatch):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    for _ in range(10):
        with pytest.raises(AutomationError, match="unauthorized"):
            receiver.authenticate("host-a", "Bearer wrong")
    with pytest.raises(AutomationError, match="rate_limited"):
        receiver.authenticate("host-a", "Bearer " + TOKEN)


@pytest.mark.parametrize("change", ["source", "base64", "hash", "duplicate", "version", "depth", "oversize"])
def test_upload_abuse_preserves_previous(tmp_path, monkeypatch, change):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    receiver.accept(source, body)
    before = (receiver.config.staging_dir / "host-a" / "current.json").read_bytes()
    data = json.loads(body)
    if change == "source":
        data["source_id"] = "host-b"
    elif change == "base64":
        data["inventory_b64"] = "not-base64!"
    elif change == "hash":
        data["inventory_b64"] = base64.b64encode(b"[]").decode()
    elif change == "version":
        data["version"] = True
    body = json.dumps(data).encode()
    if change == "duplicate":
        body = b'{"version":1,"version":1}'
    elif change == "depth":
        body = b"[" * 1000
    elif change == "oversize":
        body = b" " * (receiver.config.max_body_bytes + 1)
    with pytest.raises((AutomationError, ExtensionError)):
        receiver.accept(source, body)
    assert (receiver.config.staging_dir / "host-a" / "current.json").read_bytes() == before


def test_replay_generated_and_observed_rollbacks(tmp_path, monkeypatch):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    receiver.accept(source, body)
    raw = pair.read_bytes()
    side = json.loads(manifest_path(pair).read_bytes())
    side["generated_at"] = side["observed_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with pytest.raises(AutomationError, match="replay_or_rollback"):
        receiver.accept(source, encode_envelope("host-a", raw, json.dumps(side).encode()))


@pytest.mark.parametrize("host,extra", [("0.0.0.0", ""), ("0.0.0.0", "proxy_https=true\n"), ("::", ""), ("localhost", ""), ("224.0.0.1", "")])
def test_remote_plaintext_binding_forbidden(tmp_path, host, extra):
    filename = tmp_path / "ingest.toml"
    filename.write_text(f'[ingestion]\nversion=1\nhost="{host}"\n{extra}[[sources]]\nid="host-a"\ncredential={{env="TOKEN"}}\n')
    with pytest.raises(AutomationError):
        load_ingest_config(filename)


def test_receiver_config_has_no_core_or_notifier(tmp_path):
    filename = tmp_path / "ingest.toml"
    filename.write_text('[ingestion]\nversion=1\n[[sources]]\nid="host-a"\ncredential={env="TOKEN"}\n')
    config = load_ingest_config(filename)
    assert config.host == "127.0.0.1"
    filename.write_text(filename.read_text() + '[notifications]\ntoken="canary"\n')
    with pytest.raises(AutomationError):
        load_ingest_config(filename)


def test_corrupt_pointer_cannot_reset_replay(tmp_path, monkeypatch):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    receiver.accept(source, body)
    pointer = receiver.config.staging_dir / "host-a" / "current.json"
    for corrupt in (b"null", b"{}", b"[]"):
        pointer.write_bytes(corrupt)
        with pytest.raises(AutomationError, match="pointer_invalid"):
            receiver.accept(source, body)
        assert pointer.read_bytes() == corrupt


def test_pointer_times_cannot_downgrade_immutable_manifest(tmp_path, monkeypatch):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    receiver.accept(source, body)
    pointer = receiver.config.staging_dir / "host-a" / "current.json"
    original = json.loads(pointer.read_bytes())
    for field in ("generated_at", "observed_at", "accepted_at", "generation"):
        state = dict(original)
        state[field] = "0" * 64 if field == "generation" else "2000-01-01T00:00:00+00:00"
        pointer.write_text(json.dumps(state))
        with pytest.raises(AutomationError, match="pointer_invalid"):
            receiver.accept(source, body)


def test_ambiguous_push_retransmits_same_bytes_and_redacts(tmp_path, monkeypatch):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    class Fake:
        def __init__(self):
            self.requests = []
        def request(self, method, url, **kwargs):
            self.requests.append(kwargs["body"])
            result = receiver.accept(source, kwargs["body"])
            if len(self.requests) == 1:
                raise TransportError("lost_ack", transmitted=True)
            return Response(200, {}, json.dumps(result).encode())
    fake = Fake()
    monkeypatch.setattr("cvebeacon_automation.ingest.client.time.sleep", lambda _: None)
    result = push(pair, "https://ingest.invalid/v1/snapshots", source.credential, transport=fake)
    assert result["status"] == "idempotent"
    assert fake.requests[0] == fake.requests[1]
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("url", ["http://127.0.0.1/v1/snapshots", "http://remote.invalid/v1/snapshots", "https://remote.invalid/v1/snapshots?token=secret", "https://remote.invalid/elsewhere"])
def test_push_strict_https_fixed_path(tmp_path, monkeypatch, url):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    with pytest.raises(AutomationError):
        push(pair, url, source.credential)


@pytest.mark.parametrize("group", [True, "1000", -1, 2**31])
def test_reader_group_rejects_unbounded_or_untyped_configuration(tmp_path, monkeypatch, group):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    with pytest.raises(AutomationError, match="staging_reader_group_invalid"):
        Receiver(replace(receiver.config, reader_gid=group))


@pytest.mark.skipif(os.name != "posix", reason="explicit Unix group permissions; Windows uses administrator ACLs")
def test_reader_group_applies_before_pointer_publication_without_changing_bytes(tmp_path, monkeypatch):
    import stat
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    receiver = Receiver(replace(receiver.config, reader_gid=os.getgid()))
    assert receiver.accept(source, body)["status"] == "accepted"
    staged = current_snapshot(receiver.config.staging_dir, source.id)
    for file in (staged, manifest_path(staged), staged.parent.parent / "current.json"):
        assert stat.S_IMODE(file.stat().st_mode) == 0o640 and file.stat().st_gid == os.getgid()
    assert stat.S_IMODE(staged.parent.stat().st_mode) == 0o2750
    assert staged.read_bytes() == pair.read_bytes() and manifest_path(staged).read_bytes() == manifest_path(pair).read_bytes()
    assert receiver.accept(source, body)["status"] == "idempotent"


@pytest.mark.parametrize("group", [True, "1000", -1, 2**31])
def test_reader_group_rejects_unbounded_or_untyped_configuration(tmp_path, monkeypatch, group):
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    with pytest.raises(AutomationError, match="staging_reader_group_invalid"):
        Receiver(replace(receiver.config, reader_gid=group))


@pytest.mark.skipif(os.name != "posix", reason="explicit Unix group permissions; Windows uses administrator ACLs")
def test_reader_group_applies_before_pointer_publication_without_changing_bytes(tmp_path, monkeypatch):
    import stat
    receiver, source, pair, body = setup(tmp_path, monkeypatch)
    receiver = Receiver(replace(receiver.config, reader_gid=os.getgid()))
    assert receiver.accept(source, body)["status"] == "accepted"
    staged = current_snapshot(receiver.config.staging_dir, source.id)
    for file in (staged, manifest_path(staged), staged.parent.parent / "current.json"):
        assert stat.S_IMODE(file.stat().st_mode) == 0o640 and file.stat().st_gid == os.getgid()
    assert stat.S_IMODE(staged.parent.stat().st_mode) == 0o2750
    assert staged.read_bytes() == pair.read_bytes() and manifest_path(staged).read_bytes() == manifest_path(pair).read_bytes()
    assert receiver.accept(source, body)["status"] == "idempotent"
