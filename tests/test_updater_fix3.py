"""Completion admission barriers and finalization feedback regressions."""
import ast
import errno
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest

from cvebeacon import updater as u
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import RunLock
from cvebeacon.update_transaction import ensure_ready
from test_updater import transaction, signed, value
from test_dashboard_updates import updates
from test_dashboard_operations import login

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Native completion and permissions require Linux")


@pytest.mark.parametrize("restart", [False, True])
def test_failed_completion_barrier_blocks_writers_until_recovery(transaction, monkeypatch, restart):
    updater, native, config = transaction
    prefix = updater.policy.prefix
    journal = prefix / u.JOURNAL
    real = os.fsync
    durable = []
    def sync(fd):
        target = Path(os.readlink(f"/proc/self/fd/{fd}"))
        if target == prefix and journal.exists():
            record = journal.read_bytes()
            if json.loads(record)["phase"] == "complete":
                raise OSError(errno.EIO, "synthetic completion parent sync failure")
            real(fd)
            durable[:] = [record]
            return
        return real(fd)
    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(u.UpdateError):
        updater.apply("0.1.1")
    assert json.loads(durable[0])["phase"] == "health"
    assert json.loads(journal.read_bytes())["phase"] == "complete"
    # Resource locks are released after the failure. The independent mutation
    # guard must still refuse both ordinary CLI and dashboard writes.
    with RunLock(config.watch.database.parent / u.LOCK_NAME):
        for command in ("run", "watch", "dashboard-write"):
            with pytest.raises(CVEBeaconError, match="recovery"):
                ensure_ready(command, prefix=prefix, running_version="0.1.1")
        assert value(config.watch.database) == "new"
    monkeypatch.setattr(os, "fsync", real)
    if restart:
        # A possible crash outcome is the last successfully synced health
        # record. No acknowledged writer was admitted against that old state.
        u.atomic_json(journal, json.loads(durable[0]))
    recovered = u.Updater(updater.policy, native, updater.releases)
    result = recovered.recover()
    assert result["result"] == ("rolled-back" if restart else "updated")
    ensure_ready("dashboard-write", prefix=prefix, running_version=result["version"])
    with sqlite3.connect(config.watch.database) as db:
        db.execute("UPDATE sentinel SET value='acknowledged after recovery'")
    assert recovered.recover()["result"] == "no-recovery-required"
    assert value(config.watch.database) == "acknowledged after recovery"


@pytest.mark.parametrize("barrier_fails", [True, False])
def test_writer_in_completion_rename_window_must_establish_durability(transaction, monkeypatch, barrier_fails):
    updater, native, config = transaction
    prefix, journal = updater.policy.prefix, updater.policy.prefix / u.JOURNAL
    real = os.fsync
    observed, durable = [], []
    checking = False
    def sync(fd):
        nonlocal checking
        if Path(os.readlink(f"/proc/self/fd/{fd}")) == prefix and journal.exists() and json.loads(journal.read_bytes())["phase"] == "complete":
            if checking:
                if barrier_fails:
                    raise OSError(errno.EIO, "synthetic guard completion sync failure")
                real(fd)
                durable.append(journal.read_bytes())
                return
            if not observed:
                checking = True
                try:
                    ensure_ready("dashboard-write", prefix=prefix, running_version="0.1.1")
                except CVEBeaconError:
                    observed.append("blocked")
                else:
                    observed.append("admitted")
                    with sqlite3.connect(config.watch.database) as db:
                        db.execute("UPDATE sentinel SET value='acknowledged in completion window'")
                finally:
                    checking = False
                # Only the guard's successful barrier can have persisted the
                # completed record before this simulated updater failure.
                raise OSError(errno.EIO, "synthetic updater completion sync failure")
        return real(fd)
    monkeypatch.setattr(os, "fsync", sync)
    assert updater.apply("0.1.1")["result"] == "updated"
    assert observed == (["blocked"] if barrier_fails else ["admitted"])
    if not barrier_fails:
        assert durable and json.loads(durable[0])["phase"] == "complete"
        monkeypatch.setattr(os, "fsync", real)
        # Restart with the completion persisted by the guard itself. Recovery
        # must preserve the later acknowledged write rather than old snapshots.
        u.atomic_json(journal, json.loads(durable[0]))
        assert u.Updater(updater.policy, native, updater.releases).recover()["result"] == "updated"
        assert value(config.watch.database) == "acknowledged in completion window"
        assert "restore" not in native.calls


@pytest.mark.parametrize("modified", [False, True])
def test_dashboard_maps_only_the_exact_legacy_committed_update_warning(updates, modified):
    config, _, client = updates
    warning = "update committed; run update recover to finish finalization"
    if modified:
        warning += " <script>unsafe</script>"
    u.atomic_json(u.control_paths(config.config_path)[1], {
        "last_update": {"result": "updated", "version": "0.1.1", "time": u.stamp(), "warning": warning}})
    login(client, "viewer")
    page = client.get("/updates/")
    assert page.status_code == 200 and "Last update: updated" in page.text
    assert ("The update was committed and finalization still needs to finish." in page.text) is not modified
    assert ("Run <code>cvebeacon update recover</code>" in page.text) is not modified
    assert "&lt;script&gt;unsafe&lt;/script&gt;" not in page.text
    assert "<script>unsafe</script>" not in page.text


def test_directory_access_documentation_covers_traversal_only_backups():
    guide = Path("docs/UPGRADING.md").read_text()
    layout = guide.split("Generated `releases`", 1)[1].split("Use the reference units", 1)[0]
    assert "`0711`" in layout and "traversal-only" in layout
    assert "Every generated layout directory" not in layout


def test_adoption_retry_repairs_existing_private_layout_directories(transaction):
    updater, _, _ = transaction
    prefix = updater.policy.prefix
    (prefix / "current").unlink()
    (prefix / "releases/0.1.0/.venv").rmdir()
    (prefix / ".venv").mkdir()
    updater._begin("0.1.0", "0.1.0", (), kind="adopt")
    for path in (prefix / "releases", prefix / "releases/0.1.0"):
        path.chmod(0o700)
    previous = os.umask(0o077)
    try:
        assert updater.recover()["result"] == "adopted"
    finally:
        os.umask(previous)
    for path in (prefix / "releases", prefix / "releases/0.1.0", prefix / "transactions"):
        assert path.stat().st_mode & 0o777 == 0o755
    assert not (prefix / u.JOURNAL).exists()


@pytest.mark.parametrize("mask", [0o077, 0o027])
def test_first_apply_sets_traversal_only_backup_container_before_snapshot(transaction, mask):
    updater, native, _ = transaction
    state, seen = native.state, []
    def snapshot(python, action, backup, *args):
        if action == "backup":
            assert backup.parent.stat().st_mode & 0o777 == 0o711
            assert backup.stat().st_mode & 0o777 == 0o700
            seen.append(True)
        return state(python, action, backup, *args)
    native.state = snapshot
    previous = os.umask(mask)
    try:
        assert updater.apply("0.1.1")["result"] == "updated"
    finally:
        os.umask(previous)
    assert seen


def test_active_journal_unlink_failure_retains_completed_recovery(transaction, monkeypatch):
    updater, native, config = transaction
    unlink = Path.unlink
    def fail(path, *args, **kwargs):
        if path == updater.policy.prefix / u.JOURNAL:
            raise OSError(errno.EACCES, "synthetic active journal unlink failure")
        return unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", fail)
    result = updater.apply("0.1.1")
    assert result["result"] == "updated" and "recover" in result["warning"]
    assert json.loads((updater.policy.prefix / u.JOURNAL).read_text())["phase"] == "complete"
    monkeypatch.setattr(Path, "unlink", unlink)
    assert u.Updater(updater.policy, native, updater.releases).recover()["result"] == "updated"
    assert value(config.watch.database) == "new" and "restore" not in native.calls


def test_credential_acceptance_installs_the_generated_directory_version():
    # Evaluate only the path/version expressions, with no privileged commands.
    module = ast.parse(Path("tools/updater_permissions_smoke.py").read_text())
    function = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "acceptance")
    assignment = next(node for node in ast.walk(function) if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "generated" for target in node.targets))
    path_expression = assignment.value.args[0]
    generated = eval(compile(ast.Expression(path_expression), "<release path>", "eval"), {"prefix": Path("/opt/cvebeacon")})
    install = next(node for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "install" and isinstance(node.args[0], ast.BinOp) and isinstance(node.args[0].left, ast.Name) and node.args[0].left.id == "generated")
    target = eval(compile(ast.Expression(install.args[3]), "<release version>", "eval"), {"generated": generated})
    assert target == generated.name


def test_archive_warning_describes_finalization_without_claiming_timer_failure(transaction, monkeypatch):
    updater, _, _ = transaction
    monkeypatch.setattr(updater, "_archive", lambda: (_ for _ in ()).throw(OSError(errno.EIO, "synthetic archive failure")))
    assert updater.apply("0.1.1")["warning"] == "update committed; run update recover to finish finalization"
