"""Regression cases for durable recovery and the reviewed update boundaries."""
from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from cvebeacon import updater as u, update_state
from cvebeacon.config import UpdateConfig, load_config
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import RunLock
from test_updater import transaction, signed, value
from watch_support import write_config


@pytest.fixture(autouse=True)
def _feed_versions_assume_running_0_1_0(monkeypatch):
    # The fake release feeds in this module are built around a running 0.1.0.
    import cvebeacon.updater as updater_module

    real = updater_module.installed_version
    monkeypatch.setattr(updater_module, "installed_version",
                        lambda name: "0.1.0" if name == "cvebeacon" else real(name))

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Native apply and durable state recovery are Linux-only")


@pytest.mark.parametrize("watch", [None, "nested/watch.db"])
def test_real_config_variants_share_request_and_status_locations(tmp_path, signed, watch):
    from cvebeacon.watch.users import UserStore, BOOTSTRAP
    config = write_config(tmp_path, inventory=False)
    text = config.config_path.read_text().replace('database = "watch.db"', '' if watch is None else f'database = "{watch}"')
    if watch is None:
        text = text.replace('database = "state.db"', "")
    config.config_path.write_text(text)
    config = replace(load_config(config.config_path), update=UpdateConfig(enabled=True))
    users = UserStore(config.watch.users_database)
    users.add("admin", password="Synthetic update permission 123", is_admin=True, authorization=BOOTSTRAP)
    proof = users.authenticate("admin", "Synthetic update permission 123")
    u.request_update(config, "0.1.1", proof, users)
    assert u.read_request(tmp_path / u.REQUEST) == "0.1.1"
    u.check(config, http=signed[0].http)
    assert json.loads((tmp_path / u.STATUS).read_text())["available"] == "0.1.1"
    assert u.read_status(config)["available"] == "0.1.1"


def test_journal_failure_after_migration_cannot_skip_state_restore(transaction, monkeypatch):
    updater, native, config = transaction
    original = u.atomic_json
    def fail(path, *args, **kwargs):
        if Path(path).name == "update-journal.json" and "migrate" in native.calls:
            raise OSError(errno.ENOSPC, "synthetic full journal volume")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(u, "atomic_json", fail)
    with pytest.raises((CVEBeaconError, OSError)):
        updater.apply("0.1.1")
    assert value(config.watch.database) == "old"
    assert updater.current().name == "0.1.0"
    record = json.loads((updater.policy.prefix / "update-journal.json").read_text())
    assert record["old"] == "0.1.0" and record["snapshot_ready"]


def test_journal_is_durable_before_each_live_state_change(transaction):
    updater, native, _ = transaction
    original = native.command
    def command(release, operation):
        if operation == "migrate":
            record = json.loads((updater.policy.prefix / "update-journal.json").read_text())
            assert record["phase"] == "migrating"
            assert record["old"] == "0.1.0" and record["new"] == "0.1.1"
            assert record["snapshot_ready"]
            assert (updater.policy.prefix / "backups" / record["backup"] / "manifest.json").is_file()
        return original(release, operation)
    native.command = command
    updater.apply("0.1.1")


def test_post_replace_fsync_error_restores_the_actual_link(transaction, monkeypatch):
    updater, native, config = transaction
    switch = u.switch
    fired = []
    def fail_once(prefix, destination):
        switch(prefix, destination)
        if not fired:
            fired.append(True)
            raise OSError(errno.EIO, "synthetic post-replace durability failure")
    monkeypatch.setattr(u, "switch", fail_once)
    with pytest.raises(u.UpdateError):
        updater.apply("0.1.1")
    assert value(config.watch.database) == "old"
    assert updater.current().name == "0.1.0"
    assert json.loads((updater.policy.prefix / "update-result.json").read_text())["result"] == "rolled-back"


def test_advisory_status_failure_does_not_reverse_or_fail_a_healthy_update(transaction):
    updater, native, config = transaction
    (config.config_path.parent / u.STATUS).mkdir()
    assert updater.apply("0.1.1")["result"] == "updated"
    assert updater.current().name == "0.1.1"


def test_replacement_request_is_not_unlinked_by_the_consumer(transaction, monkeypatch):
    updater, native, config = transaction
    path = config.config_path.parent / u.REQUEST
    first = {"version": "0.1.1", "user": "admin", "time": u.stamp()}
    u.atomic_json(path, first)
    reader = u.read_request
    def replace_request(claim):
        result = reader(claim)
        u.atomic_json(path, {**first, "version": "0.1.2"})
        return result
    monkeypatch.setattr(u, "read_request", replace_request)
    updater.apply(from_request=True)
    assert reader(path) == "0.1.2"


def test_requested_update_is_consumed_as_busy_without_touching_active_journal(transaction):
    updater, _, config = transaction
    request = config.config_path.parent / u.REQUEST
    u.atomic_json(request, {"version": "0.1.1", "user": "admin", "time": u.stamp()})
    journal = updater.policy.prefix / "update-journal.json"
    journal.write_text("active transaction sentinel")
    with RunLock(updater.policy.prefix / "update.lock"):
        assert updater.apply(from_request=True)["result"] == "busy"
    assert not request.exists()
    assert journal.read_text() == "active transaction sentinel"


def test_private_environment_and_unrelated_non_sqlite_file_do_not_block_discovery(tmp_path, monkeypatch):
    config = write_config(tmp_path, inventory=False)
    private = tmp_path / "cvebeacon.env"
    private.write_text("UNRELATED_PRIVATE_SETTING=value")
    notes = tmp_path / "notes.db"
    notes.write_text("unrelated text, not a state database")
    original = Path.open
    def unreadable(path, *args, **kwargs):
        if path == private:
            raise PermissionError("synthetic root-private environment")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", unreadable)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    update_state.backup(config, tmp_path, snapshot)
    manifest = json.loads((snapshot / "manifest.json").read_text())
    assert "notes.db" not in {row["path"] for row in manifest["databases"]}


def test_snapshot_config_and_manifest_have_explicit_durability_barriers(tmp_path, monkeypatch):
    config = write_config(tmp_path, inventory=False)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    seen = []
    real = os.fsync
    def sync(fd):
        seen.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
        return real(fd)
    monkeypatch.setattr(os, "fsync", sync)
    update_state.backup(config, tmp_path, snapshot)
    assert snapshot / "config.toml" in seen
    assert snapshot / "manifest.json" in seen or any(p.name.startswith(".manifest-") for p in seen)
    assert snapshot in seen


def test_install_preserves_the_current_non_default_interpreter(tmp_path):
    native = object.__new__(u.Native)
    calls = []
    native.run = lambda args, **kwargs: calls.append(([str(a) for a in args], kwargs))
    python = tmp_path / "current/.venv/bin/python"
    native.install(tmp_path / "new/.venv", tmp_path / "verified", ["cvebeacon"], "0.1.1", python=python)
    assert calls[0][0][0] == str(python)


def test_restoration_is_not_subject_to_the_generic_command_timeout(tmp_path):
    native = object.__new__(u.Native)
    native.policy = u.Policy(tmp_path, tmp_path / "config.toml", tmp_path, "service")
    calls = []
    native.run = lambda args, **kwargs: calls.append(kwargs)
    native.state(tmp_path / "python", "restore", tmp_path / "backup")
    assert calls[0]["timeout"] is None


def test_inventory_runs_with_service_credentials(tmp_path):
    native = object.__new__(u.Native)
    calls = []
    def run(args, **kwargs):
        calls.append(kwargs)
        return b'{"cvebeacon":"0.1.0"}'
    native.run = run
    native.inventory(tmp_path / ".venv")
    assert calls[0]["service"] is True


def test_fork_names_with_dots_are_accepted_by_both_config_and_release_client(tmp_path, signed):
    config = write_config(tmp_path, inventory=False)
    config.config_path.write_text(config.config_path.read_text() + '\n[update]\nrepository="owner/CVEBeacon.test"\n')
    configured = load_config(config.config_path)
    assert u.Releases(configured.update, signed[0].http).settings.repository == "owner/CVEBeacon.test"


def test_audit_failure_does_not_prevent_verified_rollback(transaction, monkeypatch):
    updater, native, config = transaction
    native.failure = "migrate"
    original = u.private_file
    def fail(path, *args, **kwargs):
        if Path(path).name == "update-audit.jsonl":
            raise OSError(errno.ENOSPC, "synthetic audit failure")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(u, "private_file", fail)
    with pytest.raises(u.UpdateError, match="previous release and state restored"):
        updater.apply("0.1.1")
    assert value(config.watch.database) == "old"
    assert not (updater.policy.prefix / "update-journal.json").exists()


def test_pending_migration_recovers_before_any_new_release_check(transaction, monkeypatch):
    updater, native, config = transaction
    old_command = native.command
    class Interruption(BaseException):
        pass
    def interrupt(release, operation):
        old_command(release, operation)
        if operation == "migrate":
            raise Interruption()
    native.command = interrupt
    # Preserve the abrupt-exit state without allowing this process to recover it.
    monkeypatch.setattr(updater, "_recover", lambda record: (_ for _ in ()).throw(Interruption()))
    with pytest.raises(Interruption):
        updater.apply("0.1.1")
    record_path = updater.policy.prefix / "update-journal.json"
    record = json.loads(record_path.read_text())
    assert record["phase"] == "migrating"
    assert value(config.watch.database) == "new"
    assert updater.current().name == "0.1.0"
    from cvebeacon.update_transaction import ensure_ready
    with pytest.raises(CVEBeaconError, match="recovery"):
        ensure_ready("watch", prefix=updater.policy.prefix, running_version="0.1.0")
    native.command = old_command
    remote_calls = []
    class NoReleaseTraffic:
        def check(self, *args):
            remote_calls.append(args)
            pytest.fail("recovery must precede new release traffic")
    fresh = u.Updater(updater.policy, native, NoReleaseTraffic())
    assert fresh.apply("0.1.2")["result"] == "rolled-back"
    assert not remote_calls and not record_path.exists()
    assert value(config.watch.database) == "old"
    archived = json.loads((updater.policy.prefix / "transactions" / (record["id"] + ".json")).read_text())
    assert archived["id"] == record["id"] and archived["phase"] == "complete"


def test_failed_restore_verification_preserves_record_and_blocks_writers(transaction):
    updater, native, config = transaction
    native.failure = "migrate"
    original = native.state
    def fail_verify(python, action, directory, manifest_hash=None):
        if action == "verify_restore":
            raise u.UpdateError("synthetic restored state mismatch")
        return original(python, action, directory, manifest_hash)
    native.state = fail_verify
    with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
        updater.apply("0.1.1")
    record_path = updater.policy.prefix / "update-journal.json"
    saved = json.loads(record_path.read_text())
    assert saved["snapshot_ready"] and "start" not in native.calls
    with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
        u.Updater(updater.policy, native, updater.releases).apply("0.1.2")
    assert json.loads(record_path.read_text())["id"] == saved["id"]
    assert json.loads((updater.policy.prefix / "update-result.json").read_text())["result"] == "rollback-failed"


def test_rollback_health_must_be_checked_before_success(transaction):
    updater, native, _ = transaction
    native.failure = "migrate"
    probes = []
    def failed_old(expected=None):
        probes.append(expected)
        if len(probes) > 1:
            raise u.UpdateError("old dashboard failed its restored-state health check")
    native.probe = failed_old
    with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
        updater.apply("0.1.1")
    assert (updater.policy.prefix / "update-journal.json").exists()
    assert probes == ["0.1.0", "0.1.0"]
    status = json.loads((updater.policy.data / u.STATUS).read_text(encoding="utf-8"))
    assert status["last_update"]["reason"] == "recovery-incomplete"


def test_interrupted_restore_can_be_repeated_from_the_same_snapshot(transaction, monkeypatch):
    updater, native, config = transaction
    native.failure = "migrate"
    original = native.state
    interrupted = []
    def interrupt(python, action, directory, manifest_hash=None):
        if action == "restore" and not interrupted:
            interrupted.append(True)
            # One file restored, other files still contain migrated state.
            update_state.restore_config(config.config_path, config.config_path.parent, directory)
            raise OSError("synthetic interrupted restore")
        return original(python, action, directory, manifest_hash)
    native.state = interrupt
    with pytest.raises(u.UpdateError, match="recovery remains incomplete"):
        updater.apply("0.1.1")
    saved = json.loads((updater.policy.prefix / "update-journal.json").read_text())
    native.state = original
    assert u.Updater(updater.policy, native, updater.releases).recover()["result"] == "rolled-back"
    assert value(config.watch.database) == "old"
    assert (updater.policy.prefix / "transactions" / (saved["id"] + ".json")).is_file()


@pytest.mark.parametrize("payload,listener", [({"status": "ok"}, True), ({"status": "ok", "version": "0.1.0", "pid": 42}, True), ({"status": "ok", "version": "0.1.1", "pid": 9}, True), ({"status": "ok", "version": "0.1.1", "pid": 42}, False)])
def test_health_refuses_stale_or_unrelated_listeners(tmp_path, monkeypatch, payload, listener):
    native = object.__new__(u.Native)
    native.policy = u.Policy(tmp_path, tmp_path / "config", tmp_path, "service")
    native.dashboard_pid = lambda *, timeout: 42
    native.process_start = lambda pid: 1
    native.listener_sockets = lambda pid: {"1"} if listener else set()
    class Transport:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def request_once(self, *args, **kwargs):
            return SimpleNamespace(status_code=200, body=json.dumps(payload).encode())
    monkeypatch.setattr(u, "HttpClient", lambda *args, **kwargs: Transport())
    clock = {"now": 0.0}
    monkeypatch.setattr(u.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(u.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + seconds))
    with pytest.raises(u.UpdateError, match="health probe failed"):
        native.probe("0.1.1")
    assert clock["now"] == 120


def test_custom_dashboard_unit_is_not_treated_as_a_sync_service(tmp_path):
    native = object.__new__(u.Native)
    native.policy = u.Policy(tmp_path, tmp_path / "config", tmp_path, "service", units=("cvebeacon.timer", "cvebeacon-web.service"), dashboard_unit="cvebeacon-web.service")
    native.active = lambda unit: pytest.fail("a persistent dashboard must not be waited on as a sync")
    calls = []
    native.run = lambda args: calls.append(args)
    native.stop(native.policy.units)
    native.freeze(native.policy.units)
    native.start(native.policy.units)
    assert calls[1] == ["systemctl", "stop", "cvebeacon-web.service"]
    assert calls[2] == ["systemctl", "start", "cvebeacon.timer", "cvebeacon-web.service"]


def test_unreadable_service_preflight_happens_before_quiescence_or_journal(transaction):
    updater, native, _ = transaction
    native.preflight = lambda venv: (_ for _ in ()).throw(u.UpdateError("service account cannot read code/config"))
    with pytest.raises(u.UpdateError, match="cannot read"):
        updater.apply("0.1.1")
    assert not native.calls and not (updater.policy.prefix / "update-journal.json").exists()


@pytest.fixture
def cron_native(tmp_path, monkeypatch):
    import pwd

    account = SimpleNamespace(pw_name="service", pw_uid=1234, pw_gid=1234)
    monkeypatch.setattr(pwd, "getpwnam", lambda login: account)
    monkeypatch.setattr(u.shutil, "which", lambda *args, **kwargs: "/usr/bin/crontab")
    return u.Native(u.Policy(tmp_path, tmp_path / "config", tmp_path, "service"))


def test_managed_service_cron_prevents_native_adoption_preflight(cron_native):
    native = cron_native
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"# BEGIN CVEBEACON MANAGED\nold-path job\n# END CVEBEACON MANAGED", stderr=b"")
    native.run = run
    with pytest.raises(u.UpdateError, match="remove.*cron"):
        native.managed_cron()
    assert calls[0][0] == ["crontab", "-l", "-u", "service"]
    assert calls[0][1].get("service", False) is False


def test_service_crontab_absence_is_checked_as_root_for_the_named_account(cron_native):
    native = cron_native
    calls = []
    native.run = lambda args, **kwargs: (calls.append((args, kwargs)) or
                                         SimpleNamespace(returncode=1, stdout=b"", stderr=b"no crontab for service"))

    native.managed_cron()

    assert calls[0][0] == ["crontab", "-l", "-u", "service"]
    assert calls[0][1] == {"accepted": (0, 1), "completed": True, "env": {**u.SAFE_ENV, "LC_ALL": "C"}}


def test_non_dict_release_assets_are_already_rejected(signed):
    remote, _, row, _, _ = signed
    row["assets"][0] = None
    with pytest.raises(u.UpdateError, match="artifact name"):
        remote.check("0.1.0")


def test_slow_restore_outlives_the_short_command_deadline(tmp_path):
    native = object.__new__(u.Native)
    native.policy = u.Policy(tmp_path, tmp_path / "config", tmp_path, "service")
    def slowed(args, **kwargs):
        kwargs.setdefault("timeout", 0.001)
        kwargs["service"] = False
        return u.Native.run(native, [sys.executable, "-I", "-c", "import time; time.sleep(0.04)"], **kwargs)
    native.run = slowed
    native.state(tmp_path / "python", "restore", tmp_path / "snapshot")


def test_restore_replaces_a_corrupt_live_database_from_a_valid_snapshot(tmp_path):
    config = write_config(tmp_path, inventory=False)
    with sqlite3.connect(config.watch.database) as db:
        db.execute("CREATE TABLE sentinel(value)")
        db.execute("INSERT INTO sentinel VALUES ('old')")
    backup = tmp_path.parent / (tmp_path.name + "-snapshot")
    backup.mkdir()
    update_state.backup(config, tmp_path, backup)
    config.watch.database.write_bytes(b"synthetic failed migration damaged the database header")
    update_state.restore(config, tmp_path, backup)
    update_state.verify_restore(config, tmp_path, backup)
    assert value(config.watch.database) == "old"


def test_pending_recovery_can_restore_a_deleted_config(transaction):
    updater, native, config = transaction
    original = native.command
    def remove(release, operation):
        original(release, operation)
        if operation == "migrate":
            config.config_path.unlink()
            raise u.UpdateError("synthetic migration removed config")
    native.command = remove
    with pytest.raises(u.UpdateError, match="previous release and state restored"):
        updater.apply("0.1.1")
    assert config.config_path.exists() and value(config.watch.database) == "old"


def test_from_request_policy_failure_consumes_the_request_without_a_service_failure(tmp_path, monkeypatch):
    request = tmp_path / u.REQUEST
    config = tmp_path / "cvebeacon.toml"
    config.write_text("# runtime config")
    u.atomic_json(request, {"version": "0.1.1", "user": "admin", "time": u.stamp()})
    args = SimpleNamespace(update_command="apply", from_request=True, config=str(config), policy=str(tmp_path / "policy"))
    monkeypatch.setattr(u, "unsupported_reason", lambda: None)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(u.Policy, "read", lambda *args: (_ for _ in ()).throw(u.UpdateError("disabled")))
    assert u.cli(args) == 0
    assert not request.exists()


def test_malformed_request_directory_is_quarantined_without_recursive_deletion(transaction):
    updater, _, config = transaction
    request = config.config_path.parent / u.REQUEST
    request.mkdir()
    (request / "keep").write_text("untrusted content must not be recursively removed")
    with pytest.raises(CVEBeaconError):
        updater.apply(from_request=True)
    assert not request.exists()
    assert any((path / "keep").is_file() for path in request.parent.glob(".claimed-update-*"))


def test_logging_handler_failure_cannot_interrupt_rollback(transaction, monkeypatch):
    updater, native, config = transaction
    native.failure = "migrate"
    def failed_log(*args, **kwargs):
        raise OSError("synthetic logging handler failure")
    monkeypatch.setattr(u.LOG, "info", failed_log)
    monkeypatch.setattr(u.LOG, "warning", failed_log)
    with pytest.raises(u.UpdateError, match="previous release and state restored"):
        updater.apply("0.1.1")
    assert value(config.watch.database) == "old"


def test_failed_timer_restart_retains_committed_state_and_retry_entry(transaction):
    updater, native, config = transaction
    original = native.start
    failed = []
    def start(units):
        if "cvebeacon.timer" in units and not failed:
            failed.append(True)
            raise u.UpdateError("synthetic timer restart failure")
        return original(units)
    native.start = start
    result = updater.apply("0.1.1")
    assert result["result"] == "updated" and "recover" in result["warning"]
    assert updater.current().name == "0.1.1" and value(config.watch.database) == "new"
    pending = updater.policy.prefix / "update-journal.json"
    assert json.loads(pending.read_text())["phase"] == "complete"
    assert u.Updater(updater.policy, native, updater.releases).recover()["result"] == "updated"
    assert not pending.exists() and "restore" not in native.calls


def test_unknown_crontab_read_failure_is_not_treated_as_no_schedule(cron_native):
    native = cron_native
    native.run = lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=b"", stderr=b"permission denied")
    with pytest.raises(u.UpdateError, match="cannot verify") as error:
        native.managed_cron()
    assert error.value.reason_code == "preflight-crontab-unreadable"


def test_policy_permits_missing_runtime_config_only_for_recorded_recovery(transaction, monkeypatch):
    import pwd
    updater, _, config = transaction
    config.config_path.parent.chmod(0o700)
    updater._begin("0.1.0", "0.1.1", updater.policy.units)
    config.config_path.unlink()
    path = updater.policy.prefix.parent / "policy.toml"
    path.write_text('enabled=true\nprefix=' + json.dumps(str(updater.policy.prefix)) + '\nconfig=' + json.dumps(str(config.config_path)) + '\ndata=' + json.dumps(str(config.config_path.parent)) + '\nuser="service"\nsigners=' + json.dumps(str(updater.policy.signers)) + '\n')
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(pwd, "getpwnam", lambda user: SimpleNamespace(pw_uid=config.config_path.parent.stat().st_uid, pw_gid=config.config_path.parent.stat().st_gid))
    assert u.Policy.read(path).config == config.config_path
    (updater.policy.prefix / "update-journal.json").unlink()
    with pytest.raises(FileNotFoundError):
        u.Policy.read(path)


def test_startup_fence_is_readable_under_a_private_administrator_umask(transaction):
    updater, _, _ = transaction
    previous = os.umask(0o077)
    try:
        updater._begin("0.1.0", "0.1.1", updater.policy.units)
    finally:
        os.umask(previous)
    assert (updater.policy.prefix / "update-journal.json").stat().st_mode & 0o777 == 0o644


def test_recovery_fence_resolves_current_and_adopted_interpreter_aliases(transaction):
    from cvebeacon.update_transaction import installation_prefix, ensure_ready
    updater, _, _ = transaction
    prefix = updater.policy.prefix
    updater._begin("0.1.0", "0.1.1", updater.policy.units)
    alias = prefix / "current/.venv"
    assert installation_prefix(alias) == prefix
    with pytest.raises(CVEBeaconError, match="recovery"):
        ensure_ready("watch", prefix=installation_prefix(alias), running_version="0.1.0")
    (prefix / "releases/0.1.0/.venv").rmdir()
    (prefix / ".venv").mkdir()
    (prefix / "releases/0.1.0/.venv").symlink_to(prefix / ".venv", target_is_directory=True)
    assert installation_prefix(alias) == prefix
