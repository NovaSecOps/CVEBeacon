"""Check adoption permissions with real credentials in a disposable prefix.

Run as root with a prepared local wheelhouse. No users or units are installed.
Include Core wheels for 0.1.0 and 0.1.1, plus their binary dependencies.
Only the scratch prefix's otherwise-world-writable temporary ancestors are
excluded from the production protected-path check.
"""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import pwd
import stat
import tempfile
from unittest.mock import patch

from cvebeacon import updater as u


def acceptance(wheelhouse, mask):
    if os.geteuid() != 0:
        raise SystemExit("run this scratch credential check as root")
    account = pwd.getpwnam("nobody")
    with ExitStack() as stack:
        scratch = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="cvebeacon-permissions-")))
        scratch.chmod(0o755)
        prefix, data = scratch / "prefix", scratch / "data"
        prefix.mkdir(mode=0o750)
        data.mkdir(mode=0o700)
        os.chown(data, account.pw_uid, account.pw_gid)
        config = data / "cvebeacon.toml"
        config.write_text('[state]\ndatabase="state.db"\n[watch]\nenabled=true\ndatabase="nested/watch.db"\nsources=["nvd"]\n')
        os.chown(config, account.pw_uid, account.pw_gid)
        config.chmod(0o600)
        private = data / "cvebeacon.env"
        private.write_text("UNRELATED_PRIVATE_SETTING=value\n")
        private.chmod(0o600)  # Deliberately stays root-private throughout.
        policy = u.Policy(prefix, config, data, account.pw_name)
        native = u.Native(policy)
        native.managed_cron = lambda: None  # Never inspect a real account's schedule.
        native.install(prefix / ".venv", wheelhouse, ["cvebeacon"], "0.1.0")
        original = u.protected
        def protected(path, *, directory=False):
            path = Path(path).absolute()
            if not path.is_relative_to(scratch):
                return original(path, directory=directory)
            for entry in (path, *path.parents):
                if entry == scratch.parent:
                    break
                info = entry.lstat()
                assert info.st_uid == 0 and not info.st_mode & 0o022
                assert stat.S_ISDIR(info.st_mode) if entry != path or directory else stat.S_ISREG(info.st_mode)
            return path
        stack.enter_context(patch.object(u, "protected", protected))
        # Reproduce root:root 0750: it must now fail before creating current.
        try:
            u.Updater(policy, native).adopt()
        except (u.UpdateError, OSError):
            pass
        else:
            raise AssertionError("adoption accepted a service-inaccessible code prefix")
        assert not (prefix / "current").exists()
        # Apply the documented root:service, 0750/0640/0750 layout exactly.
        for parent, directories, files in os.walk(prefix, followlinks=False):
            path = Path(parent)
            os.chown(path, 0, account.pw_gid)
            path.chmod(0o750)
            for name in directories + files:
                path = Path(parent) / name
                os.chown(path, 0, account.pw_gid, follow_symlinks=False)
                if not path.is_symlink() and path.is_file():
                    path.chmod(0o750 if path.stat().st_mode & 0o111 else 0o640)
        previous = os.umask(mask)
        try:
            if mask == 0o077:
                # Recover the layout left by an interrupted private-umask adopt.
                pending = u.Updater(policy, native)
                pending._begin("0.1.0", "0.1.0", (), kind="adopt")
                (prefix / "releases").mkdir(mode=0o700)
                (prefix / "releases/0.1.0").mkdir(mode=0o700)
            assert u.Updater(policy, native).adopt()["result"] == "adopted"
        finally:
            os.umask(previous)
        created = (prefix / "releases", prefix / "releases/0.1.0", prefix / "transactions")
        for path in created:
            assert path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o755
        native.directory_access(prefix / "current/.venv", created)
        native.service_access(prefix / "current/.venv")
        code = "import os,sys; assert os.access(sys.argv[1],os.R_OK|os.X_OK); assert not os.access(sys.argv[1],os.W_OK); assert not os.access(sys.argv[2],os.W_OK); assert os.geteuid()==int(sys.argv[3]); assert os.getgroups()==[]"
        native.run([prefix / "current/.venv/bin/python", "-I", "-c", code, prefix, prefix / "current/.venv/bin/cvebeacon", account.pw_uid], service=True)
        # The unprivileged guard must be able to persist a completed root-owned
        # journal, and refuse a writer when that barrier fails.
        completed = u.Updater(policy, native)
        completed._begin("0.1.0", "0.1.0", (), kind="adopt")
        completed._finish("adopted")
        guard = "from cvebeacon.update_transaction import ensure_ready; import sys; ensure_ready('dashboard-write',prefix=sys.argv[1],running_version='0.1.0')"
        native.run([prefix / "current/.venv/bin/python", "-I", "-c", guard, prefix], service=True)
        denied = """import sys
from cvebeacon import updater as u
from cvebeacon.update_transaction import ensure_ready
from cvebeacon.errors import CVEBeaconError
def failed(path):
    raise OSError('synthetic completion barrier failure')
u.sync_directory = failed
try:
    ensure_ready('dashboard-write', prefix=sys.argv[1], running_version='0.1.0')
except CVEBeaconError:
    pass
else:
    raise AssertionError('writer admitted after failed completion barrier')
"""
        native.run([prefix / "current/.venv/bin/python", "-I", "-c", denied, prefix], service=True)
        assert completed._finalize()["result"] == "adopted"
        # Check a generated release too: the outer mask must not affect access.
        previous = os.umask(mask)
        try:
            generated = u.release_directory(prefix / "releases/0.1.1")
            native.install(generated / ".venv", wheelhouse, ["cvebeacon"], generated.name)
        finally:
            os.umask(previous)
        native.directory_access(generated / ".venv", (generated, generated / ".venv"))
        native.service_access(generated / ".venv")
        assert native.inventory(generated / ".venv")["cvebeacon"] == generated.name
        native.run([generated / ".venv/bin/python", "-I", "-c", code, prefix, generated / ".venv/bin/cvebeacon", account.pw_uid], service=True)
        previous = os.umask(mask)
        try:
            backups = u.release_directory(prefix / "backups", mode=0o711)
        finally:
            os.umask(previous)
        assert backups.stat().st_uid == 0 and stat.S_IMODE(backups.stat().st_mode) == 0o711
        traversal = "import os,sys; p=sys.argv[1]; assert os.access(p,os.X_OK) and not os.access(p,os.R_OK) and not os.access(p,os.W_OK)"
        native.run([generated / ".venv/bin/python", "-I", "-c", traversal, backups], service=True)
        data.chmod(0o500)
        try:
            try:
                native.preflight(prefix / "current/.venv")
            except (u.UpdateError, OSError):
                pass
            else:
                raise AssertionError("preflight accepted service-owned read-only data")
        finally:
            data.chmod(0o700)
        # A private config is rejected before quiescence too; secrets stay private.
        os.chown(config, 0, 0)
        config.chmod(0o600)
        try:
            native.preflight(prefix / "current/.venv")
        except (u.UpdateError, OSError):
            pass
        else:
            raise AssertionError("preflight accepted a service-unreadable config")
        assert private.stat().st_uid == 0 and stat.S_IMODE(private.stat().st_mode) == 0o600
        print(f"Umask {mask:03o}: adoption/retry and matching-version releases allow read/execute, deny code writes, clear groups; completion guards enforce durability; backups allow traversal only; read-only data/private config are refused.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    wheelhouse = parser.parse_args().wheelhouse.resolve(strict=True)
    for mask in (0o077, 0o027):
        acceptance(wheelhouse, mask)
