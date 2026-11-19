"""Exercise the reported Windows test failures with mandatory lock rules."""

import errno
import os
from pathlib import Path

import pytest

from cvebeacon import locking
import test_run_visibility_audit as audit_cases
import test_run_visibility_fix3 as rollback_cases


@pytest.fixture
def windows_file_rules(monkeypatch):
    original_os = locking.os
    main_locks, record_leases = {}, {}
    original_lock = locking.RunLock._lock
    original_unlock = locking.RunLock._unlock
    original_owner_lock = locking.RunLock._owner_lock
    original_bytes, original_text = Path.read_bytes, Path.read_text

    def identity(fd):
        details = original_os.fstat(fd)
        return details.st_dev, details.st_ino

    def lock(instance, fd):
        original_lock(instance, fd)
        if not getattr(instance, "_probing", False):
            main_locks[fd] = identity(fd)

    def unlock(instance, fd):
        original_unlock(instance, fd)
        main_locks.pop(fd, None)

    def owner_lock(fd, *, probe=False, unlock=False):
        original_owner_lock(fd, probe=probe, unlock=unlock)
        if unlock:
            record_leases.pop(fd, None)
        elif not probe:
            record_leases[fd] = identity(fd)

    class NativeOS:
        def __getattr__(self, name):
            return getattr(original_os, name)

        def close(self, fd):
            main_locks.pop(fd, None)
            record_leases.pop(fd, None)
            return original_os.close(fd)

    class WindowsTestOS(NativeOS):
        name = "nt"

        def replace(self, source, target):
            details = Path(target).stat()
            if (details.st_dev, details.st_ino) in record_leases.values():
                raise PermissionError(errno.EACCES, "synthetic Windows rename of leased record")
            return original_os.replace(source, target)

    def reject_new_reader(path):
        details = path.stat()
        if (details.st_dev, details.st_ino) in main_locks.values():
            raise PermissionError(errno.EACCES, "synthetic Windows byte-zero lock")

    def read_bytes(path):
        reject_new_reader(path)
        return original_bytes(path)

    def read_text(path, *args, **kwargs):
        reject_new_reader(path)
        return original_text(path, *args, **kwargs)

    monkeypatch.setattr(locking, "os", NativeOS())
    monkeypatch.setattr(locking.RunLock, "_lock", lock)
    monkeypatch.setattr(locking.RunLock, "_unlock", unlock)
    monkeypatch.setattr(locking.RunLock, "_owner_lock", staticmethod(owner_lock))
    monkeypatch.setattr(audit_cases, "os", WindowsTestOS())
    monkeypatch.setattr(rollback_cases, "os", WindowsTestOS())
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(locking, "_account_name", lambda: "cvebeacon")
    monkeypatch.setattr(locking, "_host_name", lambda: "example.com")
    try:
        yield
    finally:
        # Also reap handles from the original failing fixture, before it had
        # reached its normal release. Never close a reused descriptor.
        for fd, expected in (*record_leases.items(), *main_locks.items()):
            try:
                if identity(fd) == expected:
                    original_os.close(fd)
            except OSError:
                pass


@pytest.mark.parametrize("case,error", [
    ("permission", errno.EACCES), ("permission", errno.EPERM), ("permission", errno.EROFS),
    ("old-token", None), ("channel", None), ("replacement", None), ("temporary-replacement", None),
])
def test_reported_locking_cases_obey_windows_rules(tmp_path, monkeypatch, windows_file_rules, case, error):
    if case == "permission":
        audit_cases.test_private_metadata_permission_failure_does_not_block_shared_lock(tmp_path, monkeypatch, error)
    elif case == "old-token":
        audit_cases.test_old_token_cannot_identify_holder_before_new_reference_is_written(tmp_path, monkeypatch)
    elif case == "channel":
        audit_cases.test_real_channel_test_is_lock_free_and_does_not_change_watch_storage(tmp_path, monkeypatch)
    elif case == "replacement":
        audit_cases.test_release_does_not_remove_a_replacement_file(tmp_path)
    else:
        rollback_cases.test_temporary_rollback_preserves_a_replacement_inode(tmp_path, monkeypatch)
