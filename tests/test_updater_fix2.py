"""Regression coverage for install durability and completion finalization."""
from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest

from cvebeacon import updater as u, update_state
from cvebeacon.config import UpdateConfig, load_config
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import RunLock
from cvebeacon.update_transaction import ensure_ready
from test_updater import transaction, signed, value
from watch_support import write_config
from test_dashboard_updates import updates
from test_dashboard_operations import login, submit

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Native update durability uses Linux filesystem and service semantics")


def test_release_files_and_parent_are_synced_before_migration(transaction, monkeypatch):
    updater, native, _ = transaction
    original_install = native.install
    original_command = native.command
    synced = []
    real = os.fsync
    def fsync(fd):
        synced.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
        return real(fd)
    monkeypatch.setattr(os, "fsync", fsync)
    def install(venv, *args, **kwargs):
        original_install(venv, *args, **kwargs)
        (venv / "installed.py").write_text("# installed release bytes\n")
    native.install = install
    def command(release, operation):
        if operation == "migrate":
            assert release / ".venv/installed.py" in synced
            assert release / ".venv" in synced and release in synced
            assert release.parent in synced
        return original_command(release, operation)
    native.command = command
    assert updater.apply("0.1.1")["result"] == "updated"


def test_release_barrier_failure_keeps_recovery_before_any_migration(transaction, monkeypatch):
    updater, native, config = transaction
    original = u.sync_directory
    def failing(path):
        if Path(path).name == "releases":
            raise OSError(errno.EIO, "synthetic release-parent durability failure")
        return original(path)
    monkeypatch.setattr(u, "sync_directory", failing)
    with pytest.raises(u.UpdateError):
        updater.apply("0.1.1")
    assert "migrate" not in native.calls
    assert updater.current().name == "0.1.0" and value(config.watch.database) == "old"
    assert any((updater.policy.prefix / "transactions").glob("*.json")) or (updater.policy.prefix / "update-journal.json").exists()


@pytest.mark.parametrize("mask", [0o077, 0o027])
def test_adoption_created_directories_have_explicit_traversal_modes(transaction, mask):
    updater, native, _ = transaction
    prefix = updater.policy.prefix
    (prefix / "current").unlink()
    (prefix / "releases/0.1.0/.venv").rmdir()
    (prefix / "releases/0.1.0").rmdir()
    (prefix / "releases").rmdir()
    (prefix / ".venv").mkdir()
    calls = []
    access = native.service_access
    native.service_access = lambda venv: (calls.append(Path(venv)), access(venv))[-1]
    prior = os.umask(mask)
    try:
        assert updater.adopt()["result"] == "adopted"
    finally:
        os.umask(prior)
    assert (prefix / "releases").stat().st_mode & 0o777 == 0o755
    assert (prefix / "releases/0.1.0").stat().st_mode & 0o777 == 0o755
    assert prefix / "current/.venv" in calls


def test_adoption_syncs_the_original_code_and_new_release_parent(transaction, monkeypatch):
    updater, native, _ = transaction
    prefix = updater.policy.prefix
    (prefix / "current").unlink()
    (prefix / "releases/0.1.0/.venv").rmdir()
    (prefix / "releases/0.1.0").rmdir()
    (prefix / ".venv").mkdir()
    code = prefix / ".venv/installed.py"
    code.write_text("# original verified code\n")
    seen = []
    real = os.fsync
    def sync(fd):
        seen.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
        return real(fd)
    monkeypatch.setattr(os, "fsync", sync)
    updater.adopt()
    assert code in seen and prefix / "releases" in seen


def test_archive_fsync_failure_preserves_committed_result_and_recovery(transaction, monkeypatch):
    updater, native, config = transaction
    real = u.sync_directory
    def fail(path):
        if Path(path).name == "transactions":
            raise OSError(errno.EIO, "synthetic archive sync failure")
        return real(path)
    monkeypatch.setattr(u, "sync_directory", fail)
    result = updater.apply("0.1.1")
    assert result["result"] == "updated"
    pending = updater.policy.prefix / "update-journal.json"
    assert json.loads(pending.read_text())["result"] == "updated"
    assert json.loads((updater.policy.prefix / "update-result.json").read_text())["result"] == "updated"
    assert updater.current().name == "0.1.1" and value(config.watch.database) == "new"
    monkeypatch.setattr(u, "sync_directory", real)
    assert u.Updater(updater.policy, native, updater.releases).recover()["result"] == "updated"
    assert value(config.watch.database) == "new" and "restore" not in native.calls
    assert not pending.exists()


def test_post_unlink_sync_failure_retains_a_completed_recovery_entry(transaction, monkeypatch):
    updater, native, config = transaction
    real = u.sync_directory
    failed = []
    def fail(path):
        if Path(path) == updater.policy.prefix and not (Path(path) / "update-journal.json").exists() and (Path(path) / "transactions").exists() and not failed:
            failed.append(True)
            raise OSError(errno.EIO, "synthetic active-name removal sync failure")
        return real(path)
    monkeypatch.setattr(u, "sync_directory", fail)
    assert updater.apply("0.1.1")["result"] == "updated"
    assert failed
    assert (updater.policy.prefix / "update-journal.json").exists()
    monkeypatch.setattr(u, "sync_directory", real)
    assert u.Updater(updater.policy, native, updater.releases).recover()["result"] == "updated"
    assert value(config.watch.database) == "new" and "restore" not in native.calls


def test_retention_layout_error_cannot_misreport_a_completed_update(transaction, monkeypatch):
    updater, _, config = transaction
    monkeypatch.setattr(updater, "_retain", lambda: (_ for _ in ()).throw(u.UpdateError("synthetic retention refusal")))
    assert updater.apply("0.1.1")["result"] == "updated"
    assert updater.current().name == "0.1.1" and value(config.watch.database) == "new"
    assert json.loads((updater.policy.prefix / "update-result.json").read_text())["result"] == "updated"


def test_readonly_config_check_uses_writable_advisory_state(tmp_path, signed):
    config_dir, state = tmp_path / "config", tmp_path / "state"
    config_dir.mkdir()
    state.mkdir()
    config = write_config(config_dir, inventory=False)
    config.config_path.write_text(config.config_path.read_text().replace('database = "state.db"', 'database = "' + str(state / "state.db") + '"').replace('database = "watch.db"', 'database = "' + str(state / "watch.db") + '"'))
    config = replace(load_config(config.config_path), update=UpdateConfig(enabled=True))
    config_dir.chmod(0o555)
    try:
        assert u.check(config, http=signed[0].http)["available"] == "0.1.1"
        assert u.read_status(config)["available"] == "0.1.1"
        assert (state / u.STATUS).is_file()
    finally:
        config_dir.chmod(0o700)


def test_check_returns_data_even_if_all_status_publication_fails(tmp_path, signed, monkeypatch):
    config = replace(write_config(tmp_path, inventory=False), update=UpdateConfig(enabled=True))
    monkeypatch.setattr(u, "atomic_json", lambda *a, **k: (_ for _ in ()).throw(PermissionError("synthetic readonly storage")))
    assert u.check(config, http=signed[0].http)["available"] == "0.1.1"


def test_check_returns_data_when_status_is_a_directory(tmp_path, signed):
    config = replace(write_config(tmp_path, inventory=False), update=UpdateConfig(enabled=True))
    (config.config_path.parent / u.STATUS).mkdir()
    assert u.check(config, http=signed[0].http)["available"] == "0.1.1"


def test_dashboard_check_handles_storage_oserrors(updates, monkeypatch):
    from cvebeacon import dashboard_update
    _, _, client = updates
    login(client)
    monkeypatch.setattr(dashboard_update, "check", lambda *args: (_ for _ in ()).throw(PermissionError("synthetic storage error")))
    assert submit(client, "/updates/check").status_code == 400


def test_tampered_snapshot_config_never_replaces_the_live_config(tmp_path):
    config = write_config(tmp_path, inventory=False)
    snapshot = tmp_path.parent / (tmp_path.name + "-snapshot")
    snapshot.mkdir()
    update_state.backup(config, tmp_path, snapshot)
    before = config.config_path.read_bytes()
    (snapshot / "config.toml").write_text(before.decode() + "\n# tampered snapshot\n")
    with pytest.raises(update_state.SnapshotError, match="config.*checksum|config.*snapshot"):
        update_state.restore(config, tmp_path, snapshot)
    assert config.config_path.read_bytes() == before


def test_complete_phase_admits_only_the_verified_release_for_writers(transaction):
    updater, _, _ = transaction
    updater._begin("0.1.0", "0.1.1", updater.policy.units)
    updater._checkpoint("complete", result="updated")
    ensure_ready("run", prefix=updater.policy.prefix, running_version="0.1.1")
    ensure_ready("watch", prefix=updater.policy.prefix, running_version="0.1.1")
    with pytest.raises(CVEBeaconError):
        ensure_ready("run", prefix=updater.policy.prefix, running_version="0.1.0")


def test_timer_catch_up_starts_after_run_locks_are_released(transaction):
    updater, native, config = transaction
    original = native.start
    observed = []
    def start(units):
        if "cvebeacon.timer" in units:
            lock = RunLock(config.watch.database.parent / u.LOCK_NAME)
            assert lock.acquire(), "timer catch-up must not lose to updater-held resource locks"
            lock.release()
            ensure_ready("run", prefix=updater.policy.prefix, running_version="0.1.1")
            observed.append(True)
        return original(units)
    native.start = start
    assert updater.apply("0.1.1")["result"] == "updated"
    assert observed


def test_fenced_reference_units_do_not_latch_a_start_limit():
    for name in ("cvebeacon.service", "cvebeacon-dashboard.service"):
        assert "StartLimitIntervalSec=0" in (Path("deploy/systemd") / name).read_text()


def test_storage_preflight_probes_service_writes_and_existing_locks(tmp_path):
    native = object.__new__(u.Native)
    native.policy = u.Policy(tmp_path, tmp_path / "config.toml", tmp_path, "service")
    native.service_access = lambda *args: None
    native.managed_cron = lambda: None
    native.lock_paths = lambda *args: (tmp_path / u.LOCK_NAME,)
    calls = []
    native.run = lambda args, **kwargs: calls.append(([str(arg) for arg in args], kwargs))
    native.preflight(tmp_path / ".venv")
    assert calls and any(".update-preflight-" in " ".join(args) for args, _ in calls)
    assert all(options["service"] for _, options in calls)


@pytest.mark.parametrize("blocked", ["data", "config-lock", "run-lock"])
def test_storage_preflight_refuses_unwritable_data_or_locks(tmp_path, blocked):
    native = object.__new__(u.Native)
    native.policy = u.Policy(tmp_path / "prefix", tmp_path / "config.toml", tmp_path, "service")
    native.service_access = lambda *args: None
    native.managed_cron = lambda: None
    run_lock = tmp_path / u.LOCK_NAME
    native.lock_paths = lambda *args: (run_lock,)
    path = {"data": tmp_path, "config-lock": tmp_path / ".config-config.toml.lock", "run-lock": run_lock}[blocked]
    if blocked != "data":
        path.touch()
    path.chmod(0o500 if blocked == "data" else 0o400)
    try:
        with pytest.raises(u.UpdateError):
            native.preflight(Path(sys.prefix))
    finally:
        path.chmod(0o700 if blocked == "data" else 0o600)


def test_policy_rejects_service_owned_data_without_owner_write(transaction, monkeypatch):
    import pwd
    from types import SimpleNamespace
    updater, _, config = transaction
    data = config.config_path.parent
    path = updater.policy.prefix.parent / "policy.toml"
    path.write_text('enabled=true\nprefix=' + json.dumps(str(updater.policy.prefix)) + '\nconfig=' + json.dumps(str(config.config_path)) + '\ndata=' + json.dumps(str(data)) + '\nuser="service"\nsigners=' + json.dumps(str(updater.policy.signers)) + '\n')
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(pwd, "getpwnam", lambda user: SimpleNamespace(pw_uid=data.stat().st_uid, pw_gid=data.stat().st_gid))
    data.chmod(0o500)
    try:
        with pytest.raises(u.UpdateError, match="writable"):
            u.Policy.read(path)
    finally:
        data.chmod(0o700)


def test_archive_copy_failure_keeps_complete_record_for_retry(transaction, monkeypatch):
    updater, native, config = transaction
    original = u.atomic_json
    def publish(path, *args, **kwargs):
        if Path(path).parent.name == "transactions":
            raise OSError(errno.ENOSPC, "synthetic archive write failure")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(u, "atomic_json", publish)
    assert updater.apply("0.1.1")["result"] == "updated"
    assert json.loads((updater.policy.prefix / "update-journal.json").read_text())["phase"] == "complete"
    monkeypatch.setattr(u, "atomic_json", original)
    assert u.Updater(updater.policy, native, updater.releases).recover()["result"] == "updated"
    assert value(config.watch.database) == "new" and "restore" not in native.calls


def test_completed_recovery_health_failure_preserves_the_committed_result(transaction, monkeypatch):
    updater, native, config = transaction
    original = updater._archive
    monkeypatch.setattr(updater, "_archive", lambda: (_ for _ in ()).throw(OSError(errno.EIO, "synthetic archive error")))
    assert updater.apply("0.1.1")["result"] == "updated"
    monkeypatch.setattr(updater, "_archive", original)
    native.probe = lambda *args: (_ for _ in ()).throw(u.UpdateError("synthetic completed-health failure"))
    with pytest.raises(u.UpdateError, match="verification remains incomplete"):
        updater.recover()
    assert (updater.policy.prefix / "update-journal.json").exists()
    assert json.loads((updater.policy.prefix / "update-result.json").read_text())["result"] == "updated"
    assert value(config.watch.database) == "new" and "restore" not in native.calls


def test_same_port_on_another_loopback_address_cannot_pass_health(tmp_path, monkeypatch):
    from contextlib import ExitStack
    import subprocess
    from types import SimpleNamespace
    server = "import socket,sys; s=socket.socket(); s.bind((sys.argv[1],int(sys.argv[2]))); s.listen(); print(s.getsockname()[1],flush=True); sys.stdin.read()"
    with ExitStack() as stack:
        def child(address, port):
            process = subprocess.Popen([sys.executable, "-I", "-c", server, address, str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stack.callback(lambda: (process.terminate(), process.wait(timeout=5)) if process.poll() is None else None)
            assigned = process.stdout.readline().strip()
            assert assigned, process.stderr.read()
            return process, int(assigned)
        dashboard, port = child("127.0.0.2", 0)
        child("127.0.0.1", port)
        native = object.__new__(u.Native)
        native.policy = u.Policy(tmp_path, tmp_path / "config", tmp_path, "service", probe=f"http://127.0.0.1:{port}/healthz")
        native.dashboard_pid = lambda: dashboard.pid
        payload = {"status": "ok", "version": "99.0", "pid": dashboard.pid}
        class HTTP:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def request_once(self, *args, **kwargs):
                return SimpleNamespace(status_code=200, body=json.dumps(payload).encode())
        monkeypatch.setattr(u, "HttpClient", lambda *args, **kwargs: HTTP())
        ticks = iter([0, 31])
        monkeypatch.setattr(u.time, "monotonic", lambda: next(ticks))
        with pytest.raises(u.UpdateError, match="health probe failed"):
            native.probe("99.0")


@pytest.mark.parametrize("bind,probe,accepted", [
    ("127.0.0.1", "127.0.0.1", True),
    ("0.0.0.0", "127.0.0.1", True),
    ("127.0.0.2", "127.0.0.1", False),
    ("::1", "::1", True),
    ("::", "::1", True),
    ("::", "127.0.0.1", False),
    ("0.0.0.0", "::1", False),
])
def test_listener_matches_exact_address_family_and_same_family_wildcard(tmp_path, bind, probe, accepted):
    import socket
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    with socket.socket(family) as listener:
        listener.bind((bind, 0))
        listener.listen()
        port = listener.getsockname()[1]
        host = f"[{probe}]" if ":" in probe else probe
        native = object.__new__(u.Native)
        native.policy = u.Policy(tmp_path, tmp_path / "config", tmp_path, "service", probe=f"http://{host}:{port}/healthz")
        assert native.owns_listener(os.getpid()) is accepted


def test_tampered_snapshot_config_is_refused_by_the_worker_before_loading_it(tmp_path):
    import subprocess
    config = write_config(tmp_path, inventory=False)
    snapshot = tmp_path.parent / (tmp_path.name + "-snapshot")
    snapshot.mkdir()
    update_state.backup(config, tmp_path, snapshot)
    before = config.config_path.read_bytes()
    (snapshot / "config.toml").write_bytes(before + b"\n# tampered snapshot\n")
    result = subprocess.run([sys.executable, "-m", "cvebeacon.update_state", "restore", str(config.config_path), str(tmp_path), str(snapshot)], capture_output=True)
    assert result.returncode != 0
    assert config.config_path.read_bytes() == before
