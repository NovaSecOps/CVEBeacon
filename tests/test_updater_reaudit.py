"""Regression coverage for updater advisory and recovery boundaries."""
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cvebeacon import updater as u
from cvebeacon.config import UpdateConfig, load_config
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import RunLock
from test_updater import signed, transaction
from test_updater_review import _audit
from watch_support import write_config


linux = pytest.mark.skipif(sys.platform != "linux", reason="Native updates use Linux service semantics")


@linux
def test_check_writes_only_in_the_reserved_namespace(tmp_path, signed, monkeypatch):
    config = replace(write_config(tmp_path, inventory=False), update=UpdateConfig(enabled=True))
    monkeypatch.setattr(u, "installed_version", lambda name: "0.1.0")
    writes = []
    monkeypatch.setattr(u, "atomic_json", lambda path, value, **kwargs: writes.append(Path(path)))
    assert u.check(config, http=signed[0].http)["available"] == "0.1.1"
    assert writes == [tmp_path / "update-status" / u.CHECK_STATUS]


def test_configuration_reserves_advisory_storage(tmp_path):
    config = write_config(tmp_path, inventory=False)
    path = config.config_path
    original = path.read_text(encoding="utf-8")
    source = 'database = "state.db"'
    assert source in original
    path.write_text(original.replace(source, 'database = "update-status/local.db"'),
                    encoding="utf-8", newline="\n")
    with pytest.raises(ConfigurationError, match="update status"):
        load_config(path)


@linux
@pytest.mark.parametrize("config", ["/opt/example/data/custom.toml", "custom.toml"])
def test_invalid_policy_never_selects_a_request_or_advisory_path(monkeypatch, caplog, config):
    monkeypatch.setattr(u, "unsupported_reason", lambda: None)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(u.Policy, "read", lambda path: (_ for _ in ()).throw(u.UpdateError("private")))
    monkeypatch.setattr(u.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0))
    selected = []
    monkeypatch.setattr(u, "service_data", lambda path, **kwargs: selected.append(path))
    monkeypatch.setattr(u, "consume_request", lambda path: selected.append(path))
    monkeypatch.setattr(u, "atomic_json", lambda path, *a, **kwargs: selected.append(path))
    args = SimpleNamespace(update_command="apply", from_request=True, config=config, policy="unused")
    assert u.cli(args) == 0
    assert selected == []
    assert "policy-invalid" in caplog.text and "private" not in caplog.text


@linux
def test_root_check_does_not_use_a_runtime_selected_fallback(tmp_path, signed, monkeypatch):
    config = replace(write_config(tmp_path, inventory=False), update=UpdateConfig(enabled=True))
    monkeypatch.setattr(u, "installed_version", lambda name: "0.1.0")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    writes = []
    monkeypatch.setattr(u, "atomic_json", lambda path, *a, **kwargs: writes.append(path))
    assert u.check(config, http=signed[0].http)["available"] == "0.1.1"
    assert writes == []


def test_legacy_escaped_status_keeps_transaction_and_newest_request(tmp_path):
    config = write_config(tmp_path, inventory=False)
    updated = {"version": "0.2.0", "result": "updated", "time": "2026-01-01T00:00:00+00:00"}
    request = {"version": "0.2.1", "result": "busy", "time": "2026-02-01T00:00:00+00:00"}
    notes = "漢" * 24000
    u.atomic_json(tmp_path / u.STATUS, {"available": "0.2.1", "notes": notes,
                                       "last_update": updated, "last_request": request})
    u.atomic_json(tmp_path / u.REQUEST_STATUS, {**request, "result": "refused",
                                              "time": "2026-01-15T00:00:00+00:00"})
    assert (tmp_path / u.STATUS).stat().st_size > u.MAX_STATUS
    status = u.read_status(config)
    assert status["last_update"] == updated
    assert status["last_request"] == request
    assert status["notes"] == notes


@linux
@pytest.mark.parametrize("operation", ["apply", "recover"])
def test_advisory_decoder_failure_cannot_obscure_authoritative_completion(transaction, monkeypatch, operation):
    updater, _, config = transaction
    if operation == "recover":
        updater._begin("0.1.0", "0.1.1", updater.policy.units)
    advisory = {"available": "0.1.1", "notes": "decoder test sentinel"}
    u.atomic_json(config.config_path.parent / u.STATUS, advisory)
    modern = u._advisory_directory(config.config_path.parent) / u.STATUS
    u._publish_status(modern, advisory)
    loads = json.loads

    def decode(raw, **kwargs):
        if "decoder test sentinel" in (raw.decode("utf-8") if isinstance(raw, bytes) else raw):
            raise RecursionError("synthetic decoder resource error")
        return loads(raw, **kwargs)

    monkeypatch.setattr(json, "loads", decode)
    expected = "updated" if operation == "apply" else "rolled-back"
    assert getattr(updater, operation)()["result"] == expected
    prefix = updater.policy.prefix
    assert u.read_record(prefix) is None
    records = list((prefix / "transactions").glob("*.json"))
    assert len(records) == 1 and json.loads(records[0].read_bytes())["result"] == expected
    assert json.loads((prefix / "update-result.json").read_bytes())["result"] == expected
    assert u.read_status(config) == {}


@linux
@pytest.mark.parametrize("persistent", [True, False])
def test_request_activation_suspends_only_for_a_persistent_refusal(transaction, monkeypatch, caplog, persistent):
    updater, _, config = transaction
    args = SimpleNamespace(update_command="apply", from_request=True, version=None,
                           config=str(config.config_path), policy="unused")
    monkeypatch.setattr(u, "unsupported_reason", lambda: None)
    monkeypatch.setattr(u.Policy, "read", lambda path: updater.policy)
    monkeypatch.setattr(u, "Updater", lambda policy: updater)
    request = updater.policy.data / u.REQUEST
    u.atomic_json(request, {"version": "0.1.1", "user": "admin", "time": u.stamp()})
    original = request.stat().st_ino, request.read_bytes()
    if persistent:
        def refuse(path):
            raise u.UpdateError("synthetic refusal", reason_code="request-claim-failed")
        monkeypatch.setattr(u, "consume_request", refuse)
    watcher = {"armed": True}

    def systemctl(argv, **kwargs):
        assert argv == ["systemctl", "stop", "cvebeacon-update.path"]
        assert kwargs["timeout"] <= 10
        watcher["armed"] = False
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(u.subprocess, "run", systemctl)
    lock = RunLock(updater.policy.prefix / "update.lock")
    assert lock.acquire()
    activations = 0
    try:
        for _ in range(3):
            if watcher["armed"] and request.exists():
                activations += 1
                assert u.cli(args) == 0
    finally:
        lock.release()
    assert activations == 1
    assert watcher["armed"] is not persistent
    if persistent:
        assert (request.stat().st_ino, request.read_bytes()) == original
        assert caplog.text.count("waiting for administrator") == 1
    else:
        assert u.read_status(config)["last_request"]["result"] == "busy"


@linux
@pytest.mark.parametrize("publication", ["check", "fallback", "request", "manual", "transaction"])
def test_advisory_publication_preserves_occupied_files(transaction, signed, monkeypatch, publication):
    updater, _, config = transaction
    data = updater.policy.data
    if publication == "fallback":
        watch = data / "watch"
        watch.mkdir()
        config = replace(config, watch=replace(config.watch, database=watch / "watch.db"))
    root = config.watch.database.parent if publication == "fallback" else data
    filename = {"check": u.CHECK_STATUS, "fallback": u.CHECK_STATUS, "request": u.REQUEST_STATUS,
                "manual": u.ATTEMPT_STATUS, "transaction": u.STATUS}[publication]
    directory = u._advisory_directory(root)
    paths = [root / filename, directory / filename]
    for occupied in paths:
        occupied.write_bytes(b"independent application data\n")
    original = [(path.stat().st_ino, path.read_bytes()) for path in paths]

    if publication in {"check", "fallback"}:
        check_config = replace(config, update=UpdateConfig(enabled=True))
        monkeypatch.setattr(u, "installed_version", lambda name: "0.1.0")
        mode = data.stat().st_mode
        if publication == "fallback":
            data.chmod(0o555)
        try:
            assert u.check(check_config, http=signed[0].http)["available"] == "0.1.1"
        finally:
            data.chmod(mode)
    elif publication == "transaction":
        assert updater.apply("0.1.1")["result"] == "updated"
    elif publication == "manual":
        with pytest.raises(u.UpdateError, match="noncanonical"):
            updater.apply("invalid")
    else:
        request = data / u.REQUEST
        request.write_text("malformed request", encoding="utf-8", newline="\n")
        with pytest.raises(u.UpdateError, match="invalid update request"):
            updater.apply(from_request=True)

    assert [(path.stat().st_ino, path.read_bytes()) for path in paths] == original
    assert not list(directory.glob(".update-*"))


@linux
@pytest.mark.parametrize("entry", ["file", "unmarked", "wrong-owner", "wrong-mode", "symlink"])
def test_check_does_not_adopt_unknown_advisory_directories(tmp_path, signed, monkeypatch, entry):
    import stat

    config = replace(write_config(tmp_path, inventory=False), update=UpdateConfig(enabled=True))
    monkeypatch.setattr(u, "installed_version", lambda name: "0.1.0")
    path = tmp_path / u.UPDATE_STATUS_DIR
    if entry == "file":
        path.write_bytes(b"existing data")
    elif entry == "symlink":
        other = tmp_path / "other"
        other.mkdir()
        path.symlink_to(other, target_is_directory=True)
    elif entry == "unmarked":
        path.mkdir(mode=0o750)
        path.chmod(0o750)
    else:
        u._advisory_directory(tmp_path)
        if entry == "wrong-mode":
            path.chmod(0o700)
        else:
            inode = path.stat().st_ino
            fstat = os.fstat

            def different_owner(fd):
                details = fstat(fd)
                if stat.S_ISDIR(details.st_mode) and details.st_ino == inode:
                    return SimpleNamespace(st_uid=details.st_uid + 1, st_mode=details.st_mode)
                return details

            monkeypatch.setattr(os, "fstat", different_owner)
    original = path.lstat().st_ino
    assert u.check(config, http=signed[0].http)["available"] == "0.1.1"
    assert path.lstat().st_ino == original
    assert not (path / u.CHECK_STATUS).is_file()
    if entry == "file":
        assert path.read_bytes() == b"existing data"


@linux
@pytest.mark.parametrize("binding", ["valid", "wrong-owner", "mismatched-config"])
def test_requested_update_uses_only_the_bound_service_identity(transaction, monkeypatch, binding):
    updater, _, config = transaction
    policy = updater.policy
    policy.data.chmod(0o700)
    data_uid = policy.data.stat().st_uid
    account = SimpleNamespace(pw_uid=data_uid + (binding == "wrong-owner"), pw_gid=2468)
    object.__setattr__(policy, "_account", account)
    request = policy.data / u.REQUEST
    u.atomic_json(request, {"version": "0.1.1", "user": "admin", "time": u.stamp()})
    lock = RunLock(policy.prefix / "update.lock")
    assert lock.acquire()
    creds = {"uid": 0, "gid": 0, "groups": [88]}
    for name in creds:
        getter = {"uid": "geteuid", "gid": "getegid", "groups": "getgroups"}[name]
        setter = {"uid": "seteuid", "gid": "setegid", "groups": "setgroups"}[name]
        monkeypatch.setattr(os, getter, lambda name=name: creds[name])
        monkeypatch.setattr(os, setter, lambda value, name=name: creds.__setitem__(name, value))
    calls = []
    consume = u.consume_request
    publish = u._publish_status

    def claim(config_path):
        calls.append(("claim", config_path, dict(creds)))
        return consume(config_path)

    def write(path, payload):
        calls.append(("publish", path, dict(creds)))
        return publish(path, payload)

    def read_policy(path):
        u.service_data(policy.config, uid=account.pw_uid)
        return policy

    monkeypatch.setattr(u, "consume_request", claim)
    monkeypatch.setattr(u, "_publish_status", write)
    monkeypatch.setattr(u, "unsupported_reason", lambda: None)
    monkeypatch.setattr(u.Policy, "read", read_policy)
    monkeypatch.setattr(u, "Updater", lambda policy: updater)
    monkeypatch.setattr(u.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0))
    selected = config.config_path if binding != "mismatched-config" else policy.data / "other.toml"
    args = SimpleNamespace(update_command="apply", from_request=True, version=None,
                           config=str(selected), policy="unused")

    try:
        assert u.cli(args) == 0
        assert creds == {"uid": 0, "gid": 0, "groups": [88]}
    finally:
        creds["uid"] = data_uid
        lock.release()
    if binding == "valid":
        service = {"uid": data_uid, "gid": 2468, "groups": []}
        assert calls == [("claim", config.config_path, service),
                         ("publish", policy.data / u.UPDATE_STATUS_DIR / u.REQUEST_STATUS, service)]
        assert not request.exists()
    else:
        assert calls == []
        assert request.exists()


@pytest.mark.parametrize("legacy_size", [0, 24000])
def test_advisory_ordering_survives_rollback_and_readoption(tmp_path, legacy_size):
    config = write_config(tmp_path, inventory=False)
    legacy = tmp_path / u.STATUS
    directory = u._advisory_directory(tmp_path)
    entry = {"version": "0.2.1", "result": "refused", "time": "2026-01-10T00:00:00+00:00"}
    u._publish_status(directory / u.REQUEST_STATUS, entry)
    old = {"last_update": {**entry, "result": "updated", "version": "0.2.0"},
           "last_check": "2026-02-01T03:00:00+03:00", "available": "0.2.1", "notes": "漢" * legacy_size}
    old["last_request"] = {**entry, "result": "busy", "time": "2026-02-01T01:00:00+01:00"}
    u.atomic_json(legacy, old)  # The 0.2.0 combined writer used ASCII escapes.
    status = u.read_status(config)
    assert status["last_check"] == old["last_check"]
    assert status["last_request"] == old["last_request"]
    assert status["last_update"] == old["last_update"]
    assert status["notes"] == old["notes"]

    reactivated = {**entry, "time": "2026-02-01T00:00:00+00:00"}
    u._publish_status(directory / u.REQUEST_STATUS, reactivated)
    assert u.read_status(config)["last_request"] == reactivated


@linux
def test_json_nesting_is_bounded_before_decoder_and_journal_stays_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / u.JOURNAL
    raw = b'{"ignored":' + b"[" * 40 + b"0" + b"]" * 40 + b"}"
    path.write_bytes(raw)
    calls = []
    loads = json.loads

    def decode(raw, **kwargs):
        calls.append(raw)
        return loads(raw, **kwargs)

    monkeypatch.setattr(json, "loads", decode)
    with pytest.raises(u.UpdateError, match="invalid update JSON"):
        u.read_record(tmp_path)
    with pytest.raises(u.UpdateError, match="invalid update JSON"):
        u.read_request(path)
    assert calls == []
    assert u._json(b'{"notes":"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\\"}"}')["notes"].endswith('"}')
