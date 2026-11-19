"""Offline hostile-release and native update transaction coverage."""
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import zipfile

import httpx
import pytest

from cvebeacon import updater as u, update_state
from cvebeacon.config import HttpConfig, UpdateConfig, load_config
from cvebeacon.errors import CVEBeaconError
from cvebeacon.http import HttpClient
from cvebeacon.locking import RunInProgress, RunLock
from watch_support import write_config

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Native apply is Linux-only; other installations are check-only")


def wheel_bytes(name, version, requires=()):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
        metadata += "".join("Requires-Dist: " + item + "\n" for item in requires)
        archive.writestr(f"{name}-{version}.dist-info/METADATA", metadata)
    return output.getvalue()


@pytest.fixture
def signed(tmp_path):
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    signers = tmp_path / "signers"
    signers.write_text('cvebeacon-release namespaces="cvebeacon-release" ' + key.with_suffix(".pub").read_text())
    files = {"cvebeacon-0.1.1-py3-none-any.whl": wheel_bytes("cvebeacon", "0.1.1"),
             "dependency-1.0-py3-none-any.whl": wheel_bytes("dependency", "1.0")}
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text("".join(hashlib.sha256(raw).hexdigest() + "  " + name + "\n" for name, raw in files.items()))
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "cvebeacon-release", str(manifest)], check=True, capture_output=True)
    files.update(SHA256SUMS=manifest.read_bytes(), **{"SHA256SUMS.sig": manifest.with_suffix(".sig").read_bytes()})
    row = {"tag_name": "v0.1.1", "draft": False, "prerelease": False, "body": "<script>release notes</script>",
           "assets": [{"name": name, "browser_download_url": "https://attacker.invalid/untrusted"} for name in files]}
    calls = []

    def handler(request):
        calls.append(str(request.url))
        assert "Authorization" not in request.headers
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=row if "/tags/" in request.url.path else [row])
        assert str(request.url).startswith("https://github.com/NovaSecOps/CVEBeacon/releases/download/v")
        name = request.url.path.rsplit("/", 1)[1]
        return httpx.Response(200, content=files[name])

    http = HttpClient(HttpConfig(retries=0), client=httpx.Client(transport=httpx.MockTransport(handler)))
    return u.Releases(UpdateConfig(enabled=True), http), files, row, signers, calls


def test_valid_signature_and_every_artifact_are_verified(signed, tmp_path):
    remote, files, _, signers, calls = signed
    release = remote.check("0.1.0")
    destination = tmp_path / "download"
    destination.mkdir()
    assert set(remote.verify(release, destination, signers)) == {name for name in files if name.endswith(".whl")}
    assert len(calls) == 1 + len(files)
    assert calls[0] == "https://api.github.com/repos/NovaSecOps/CVEBeacon/releases?per_page=30"


@pytest.mark.parametrize("mode", ["invalid", "missing", "wrong-key", "checksum"])
def test_unsigned_tampered_or_wrong_key_release_is_refused(signed, tmp_path, mode):
    remote, files, row, signers, _ = signed
    if mode == "missing":
        row["assets"] = [a for a in row["assets"] if a["name"] != "SHA256SUMS.sig"]
        with pytest.raises(u.UpdateError, match="unsigned"):
            remote.check("0.1.0")
        return
    if mode == "invalid":
        files["SHA256SUMS.sig"] = b"invalid SSH signature"
    if mode == "wrong-key":
        other = tmp_path / "other"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)], check=True)
        signers.write_text("cvebeacon-release " + other.with_suffix(".pub").read_text())
    if mode == "checksum":
        files["dependency-1.0-py3-none-any.whl"] = b"modified dependency"
    release = remote.check("0.1.0")
    with pytest.raises(u.UpdateError, match="checksum" if mode == "checksum" else "signature"):
        remote.verify(release, tmp_path, signers)


@pytest.mark.parametrize("change", [{"tag_name": "v0.0.9"}, {"tag_name": "v0.1.0"}, {"tag_name": "v0.2.0rc1"}, {"prerelease": True}, {"draft": True}])
def test_downgrade_equal_prerelease_and_draft_are_refused(signed, change):
    remote, _, row, _, _ = signed
    row.update(change)
    assert remote.check("0.1.0") is None
    with pytest.raises(u.UpdateError, match="newer"):
        remote.check("0.1.0", row["tag_name"][1:])


def test_prerelease_requires_explicit_opt_in(signed):
    remote, _, row, _, _ = signed
    row.update(tag_name="v0.2.0rc1", prerelease=True)
    remote.settings = replace(remote.settings, allow_prereleases=True)
    assert remote.check("0.1.0").version == "0.2.0rc1"


@pytest.mark.parametrize("name", ["../escape.whl", "/escape.whl", "SHA256SUMS", "file\n.whl", "a" * 201])
def test_asset_names_are_bounded_and_cannot_escape(signed, name):
    remote, _, row, _, _ = signed
    row["assets"].append({"name": name})
    with pytest.raises(u.UpdateError):
        remote.check("0.1.0")


def test_missing_ssh_keygen_is_clear_and_does_not_download(signed, tmp_path, monkeypatch):
    remote, _, _, signers, calls = signed
    release = remote.check("0.1.0")
    monkeypatch.setattr(u.shutil, "which", lambda *a, **k: None)
    with pytest.raises(u.UpdateError, match="ssh-keygen is required"):
        remote.verify(release, tmp_path, signers)
    assert len(calls) == 1


def test_signed_manifest_must_match_entire_asset_set(signed, tmp_path):
    remote, _, row, signers, _ = signed
    row["assets"].append({"name": "unlisted.whl"})
    with pytest.raises(u.UpdateError, match="does not match"):
        remote.verify(remote.check("0.1.0"), tmp_path, signers)


@pytest.mark.parametrize("target", ["../../escape", "/tmp/escape", "0.1.1/../../bad", "0.1.1\n", "1" * 97, "01.2", "v0.1.1", "invalid"])
def test_request_target_is_strictly_validated(tmp_path, target):
    request = tmp_path / u.REQUEST
    request.write_text(json.dumps({"version": target, "user": "admin", "time": u.stamp()}))
    with pytest.raises(u.UpdateError):
        u.read_request(request)


@pytest.mark.parametrize("payload", [b"x" * 1025, b'{}', b'{"version":"0.1.1","version":"0.1.2","user":"admin","time":"2026-01-01T00:00:00+00:00"}',
    json.dumps({"version": "0.1.1", "user": "admin", "time": "2026-01-01T00:00:00+00:00", "command": "/bin/false"}).encode(),
    json.dumps({"version": "0.1.1", "user": "admin\n", "time": "2026-01-01T00:00:00+00:00"}).encode(),
    json.dumps({"version": "0.1.1", "user": "admin", "time": "2026-99-99T00:00:00+00:00"}).encode()])
def test_hostile_request_size_fields_duplicates_and_types(tmp_path, payload):
    path = tmp_path / u.REQUEST
    path.write_bytes(payload)
    with pytest.raises(u.UpdateError):
        u.read_request(path)


def test_request_symlink_and_hardlink_are_refused(tmp_path):
    target = tmp_path / "target"
    target.write_text(json.dumps({"version": "0.1.1", "user": "admin", "time": u.stamp()}))
    path = tmp_path / u.REQUEST
    path.symlink_to(target)
    with pytest.raises(CVEBeaconError):
        u.read_request(path)
    path.unlink()
    os.link(target, path)
    with pytest.raises(CVEBeaconError):
        u.read_request(path)


def test_no_network_when_disabled_or_daily_not_opted_in(tmp_path, monkeypatch):
    config = write_config(tmp_path, inventory=False)
    monkeypatch.setattr(u, "HttpClient", lambda *_: pytest.fail("network must not be initialized"))
    assert u.check(config) == {}
    assert u.check(replace(config, update=UpdateConfig(enabled=True)), daily=True) == {}


def test_daily_checks_are_one_request_and_rate_limited(signed, tmp_path):
    remote, _, _, _, calls = signed
    config = replace(write_config(tmp_path, inventory=False), update=UpdateConfig(enabled=True, daily=True))
    state = u.check(config, daily=True, http=remote.http)
    assert state["available"] == "0.1.1"
    assert len(calls) == 1
    assert u.check(config, daily=True, http=remote.http) == state
    assert len(calls) == 1


class FakeNative:
    def __init__(self, config, *, failure=None):
        self.config = config
        self.failure = failure
        self.calls = []
        self.fail_once = True
        self.versions = {"cvebeacon": "0.1.0", "cvebeacon-extensions": "0.1.0", "cvebeacon-automation": "0.1.0"}

    def inventory(self, venv):
        return self.versions

    def preflight(self, venv):
        pass

    def service_access(self, venv):
        pass

    def directory_access(self, venv, directories):
        pass

    def active(self, unit):
        return True

    def stop(self, units):
        self.calls.append("stop")

    def start(self, units):
        self.calls.append("start")

    def freeze(self, units):
        self.calls.append("freeze")

    def lock_paths(self, python, backup=None, manifest_hash=None):
        return (self.config.watch.database.parent / u.LOCK_NAME,)

    def acquire_lock(self, lock):
        return lock.acquire()

    def backup_directory(self, path):
        path.mkdir(mode=0o700)

    def state(self, python, action, directory, manifest_hash=None):
        self.calls.append(action)
        if manifest_hash:
            assert hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest() == manifest_hash
        getattr(update_state, action)(self.config, self.config.config_path.parent, directory)

    def install(self, venv, artifacts, packages, target, *, python=None):
        assert packages == list(u.PACKAGES)
        assert any(artifacts.glob("*.whl"))
        self.calls.append("install")
        venv.mkdir()

    def command(self, release, command):
        self.calls.append(command)
        if command == "migrate":
            with sqlite3.connect(self.config.watch.database) as db:
                db.execute("UPDATE sentinel SET value='new'")
            with sqlite3.connect(self.config.config_path.parent / "new.sqlite3") as db:
                db.execute("CREATE TABLE introduced(id)")
            self.config.config_path.write_text(self.config.config_path.read_text() + "\n# migrated config\n")
        if command == self.failure and self.fail_once:
            self.fail_once = False
            raise u.UpdateError("synthetic migration failure")

    def probe(self, expected_version=None):
        self.calls.append("probe")
        if self.failure == "health" and expected_version != "0.1.0" and self.fail_once:
            self.fail_once = False
            raise u.UpdateError("synthetic probe failure")


@pytest.fixture
def transaction(tmp_path, signed, monkeypatch):
    prefix, data = tmp_path / "prefix", tmp_path / "data"
    prefix.mkdir()
    data.mkdir()
    config = write_config(data, inventory=False)
    for path in (config.watch.database, config.database_path, config.watch.users_database, data / "extra.sqlite3"):
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE sentinel(value)")
            db.execute("INSERT INTO sentinel VALUES ('old')")
    (prefix / "releases/0.1.0/.venv").mkdir(parents=True)
    (prefix / "current").symlink_to("releases/0.1.0", target_is_directory=True)
    policy = u.Policy(prefix, config.config_path, data, "service", signers=signed[3])
    native = FakeNative(config)
    monkeypatch.setattr(u, "protected_tree", lambda path: None)
    monkeypatch.setattr(u, "protected", lambda path, **kwargs: path)
    return u.Updater(policy, native, signed[0]), native, config


def value(path):
    with sqlite3.connect(path) as db:
        return db.execute("SELECT value FROM sentinel").fetchone()[0]


def test_apply_verifies_backs_up_migrates_switches_and_health_checks(transaction):
    updater, native, config = transaction
    assert updater.apply("0.1.1") == {"result": "updated", "version": "0.1.1"}
    assert updater.current().name == "0.1.1"
    assert value(config.watch.database) == "new"
    assert native.calls == ["probe", "stop", "freeze", "backup", "install", "migrate", "start", "doctor", "probe", "start"]
    assert [row["step"] for row in updater.events] == ["check", "verify", "quiesce", "lock", "freeze", "backup", "install", "migrate", "switch", "start", "health"]
    assert json.loads((updater.policy.data / u.STATUS).read_text())["last_update"]["result"] == "updated"
    assert json.loads((updater.policy.data / u.STATUS).read_text())["last_check"]
    assert len((updater.policy.prefix / "update-audit.jsonl").read_text().splitlines()) == len(updater.events)


@pytest.mark.parametrize("failure", ["migrate", "doctor", "health"])
def test_failure_restores_all_databases_config_and_old_link(transaction, failure):
    updater, native, config = transaction
    before = config.config_path.read_bytes()
    native.failure = failure
    with pytest.raises(u.UpdateError, match="previous release and state restored"):
        updater.apply("0.1.1")
    assert updater.current().name == "0.1.0"
    assert config.config_path.read_bytes() == before
    for path in (config.watch.database, config.database_path, config.watch.users_database, config.config_path.parent / "extra.sqlite3"):
        assert value(path) == "old"
    assert not (config.config_path.parent / "new.sqlite3").exists()
    assert native.calls[-5:] == ["verify_restore", "start", "doctor", "probe", "start"]
    assert json.loads((updater.policy.prefix / "update-result.json").read_text())["result"] == "rolled-back"


def test_privileged_request_rechecks_signature_and_ignores_advisory_status(transaction, signed):
    updater, native, config = transaction
    u.atomic_json(config.watch.database.parent / u.STATUS, {"available": "0.1.1", "verified": True})
    u.atomic_json(config.watch.database.parent / u.REQUEST, {"version": "0.1.1", "user": "forged", "time": u.stamp()})
    signed[1]["SHA256SUMS.sig"] = b"bad signature"
    with pytest.raises(u.UpdateError, match="signature"):
        updater.apply(from_request=True)
    assert not (config.watch.database.parent / u.REQUEST).exists()
    assert native.calls == []
    assert updater.current().name == "0.1.0"
    assert json.loads((updater.policy.prefix / "update-result.json").read_text())["result"] == "refused"


def test_invalid_request_is_consumed_once(transaction):
    updater, _, config = transaction
    (config.watch.database.parent / u.REQUEST).write_bytes(b"x" * 1025)
    with pytest.raises(u.UpdateError):
        updater.apply(from_request=True)
    assert not (config.watch.database.parent / u.REQUEST).exists()


def test_update_waits_for_run_lock_without_killing_the_holder(transaction, monkeypatch):
    updater, native, config = transaction
    lock = RunLock(config.watch.database.parent / u.LOCK_NAME)
    assert lock.acquire()
    slept = []
    def release(seconds):
        slept.append(seconds)
        assert "backup" not in native.calls
        lock.release()
    monkeypatch.setattr(u.time, "sleep", release)
    updater.apply("0.1.1")
    assert slept


def test_concurrent_update_is_refused_without_replacing_the_journal(transaction):
    updater, _, _ = transaction
    with RunLock(updater.policy.prefix / "update.lock"):
        with pytest.raises(RunInProgress):
            updater.apply("0.1.1")
    assert not (updater.policy.prefix / "update-journal.json").exists()


def test_switch_replaces_existing_link_atomically(tmp_path, monkeypatch):
    (tmp_path / "releases/0.1.0").mkdir(parents=True)
    (tmp_path / "releases/0.1.1").mkdir(parents=True)
    u.switch(tmp_path, tmp_path / "releases/0.1.0")
    original = os.replace
    def inspect(source, destination):
        assert (tmp_path / "current").resolve().name == "0.1.0"
        assert Path(source).resolve().name == "0.1.1"
        return original(source, destination)
    monkeypatch.setattr(os, "replace", inspect)
    u.switch(tmp_path, tmp_path / "releases/0.1.1")
    assert (tmp_path / "current").resolve().name == "0.1.1"


def test_adopt_preserves_absolute_venv_path(transaction):
    updater, native, _ = transaction
    prefix = updater.policy.prefix
    (prefix / "current").unlink()
    (prefix / "releases/0.1.0/.venv").rmdir()
    (prefix / "releases/0.1.0").rmdir()
    (prefix / ".venv").mkdir()
    assert updater.adopt() == {"result": "adopted", "version": "0.1.0"}
    assert updater.current().joinpath(".venv").resolve() == prefix / ".venv"
    with pytest.raises(u.UpdateError, match="already"):
        updater.adopt()


def test_sqlite_online_backup_includes_committed_wal_and_private_accounts(tmp_path):
    config = write_config(tmp_path, inventory=False)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE sentinel(value)")
        db.execute("INSERT INTO sentinel VALUES ('wal data')")
        db.commit()
        update_state.backup(config, tmp_path, snapshot)
    row = next(r for r in json.loads((snapshot / "manifest.json").read_text())["databases"] if r["path"] == "watch.db")
    assert value(snapshot / row["backup"]) == "wal data"
    assert (snapshot / row["backup"]).stat().st_mode & 0o077 == 0


def test_backup_refuses_external_database_or_symlink(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    config = write_config(data, inventory=False)
    outside = tmp_path / "outside"
    outside.write_bytes(b"sensitive")
    (data / "linked").symlink_to(outside)
    with pytest.raises(update_state.SnapshotError, match="symbolic"):
        update_state.databases(config, data)
    (data / "linked").unlink()
    with pytest.raises(update_state.SnapshotError, match="inside"):
        update_state.databases(replace(config, database_path=outside), data)


def test_native_install_is_offline_binary_only_and_preserves_optional_packages(tmp_path):
    native = object.__new__(u.Native)
    calls = []
    native.run = lambda args, **kwargs: calls.append([str(a) for a in args])
    native.install(tmp_path / ".venv", tmp_path / "verified", list(u.PACKAGES), "0.1.1")
    pip = calls[1]
    assert "--no-index" in pip and "--only-binary=:all:" in pip and "--isolated" in pip
    assert pip[-3:] == [name + "==0.1.1" for name in u.PACKAGES]
    assert all("https://" not in a for row in calls for a in row)


def test_wheel_metadata_cannot_request_unverified_urls(tmp_path):
    path = tmp_path / "cvebeacon-0.1.1-py3-none-any.whl"
    path.write_bytes(wheel_bytes("cvebeacon", "0.1.1", ["dependency @ https://example.com/unverified.whl"]))
    with pytest.raises(u.UpdateError, match="direct URL"):
        u.validate_wheel(path)


def test_wheel_with_vendored_dist_info_uses_its_own_metadata(tmp_path):
    path = tmp_path / "tool-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("tool-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: tool\nVersion: 1.0\n")
        archive.writestr("tool/_vendor/helper-2.0.dist-info/METADATA",
                         "Metadata-Version: 2.1\nName: helper\nVersion: 2.0\n")
    u.validate_wheel(path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("other-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: other\nVersion: 1.0\n")
    with pytest.raises(u.UpdateError):
        u.validate_wheel(path)


def test_policy_refuses_unprivileged_apply_and_unprotected_code(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(u.UpdateError, match="sudo"):
        u.Policy.read(tmp_path / "policy")
    with pytest.raises(u.UpdateError, match="administrator-owned"):
        u.protected(tmp_path, directory=True)


def test_restore_worker_recovers_a_config_corrupted_by_migration(tmp_path):
    import sys
    data = tmp_path / "data"
    data.mkdir()
    config = write_config(data, inventory=False)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    original = config.config_path.read_bytes()
    update_state.backup(config, data, snapshot)
    config.config_path.write_text("invalid = [")
    result = subprocess.run([sys.executable, "-m", "cvebeacon.update_state", "restore", str(config.config_path), str(data), str(snapshot)], capture_output=True)
    assert result.returncode == 0
    assert config.config_path.read_bytes() == original


def test_native_stop_waits_for_running_sync_and_never_stops_it(tmp_path, monkeypatch):
    native = object.__new__(u.Native)
    native.policy = u.Policy(tmp_path, tmp_path / "config", tmp_path, "service")
    checks = iter([True, False])
    native.active = lambda unit: next(checks)
    calls, sleeps = [], []
    native.run = lambda args: calls.append(args)
    monkeypatch.setattr(u.time, "sleep", lambda seconds: sleeps.append(seconds))
    native.stop(native.policy.units)
    assert sleeps == [1]
    assert calls == [["systemctl", "stop", "cvebeacon.timer"]]


def test_backup_retention_keeps_newest_snapshots(transaction):
    updater, _, _ = transaction
    root = updater.policy.prefix / "backups"
    root.mkdir()
    for index in range(10):
        path = root / str(index).zfill(2)
        path.mkdir()
        (path / "private").write_text("snapshot")
    updater._retain()
    assert sorted(p.name for p in root.iterdir()) == [str(index).zfill(2) for index in range(3, 10)]


def test_oversized_api_and_assets_are_refused(signed, tmp_path):
    remote, files, _, signers, _ = signed
    release = remote.check("0.1.0")
    files["SHA256SUMS.sig"] = b"x" * 16385
    with pytest.raises(u.UpdateError, match="size limit"):
        remote.verify(release, tmp_path, signers)


@pytest.mark.parametrize("url", ["http://127.0.0.1/asset", "https://example.com/asset", "https://release-assets.githubusercontent.com:invalid/asset", "https://attacker@objects.githubusercontent.com/asset"])
def test_untrusted_redirects_are_refused(tmp_path, url):
    client = HttpClient(HttpConfig(retries=0), client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(302, headers={"Location": url}))))
    remote = u.Releases(UpdateConfig(enabled=True), client)
    # The HTTP client's own parser can reject a malformed Location first.
    with pytest.raises(u.UpdateError, match="unsafe|release request failed"):
        remote.download(u.Release("0.1.1", "", ()), "artifact.whl", tmp_path / "asset", 1024)
    assert client.requests == 1
    assert not (tmp_path / "asset").exists()


def test_retention_refuses_a_redirected_backup_root(transaction, tmp_path, monkeypatch):
    updater, _, _ = transaction
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "first").mkdir()
    (outside / "second").mkdir()
    (updater.policy.prefix / "backups").symlink_to(outside, target_is_directory=True)
    def guard(path, **kwargs):
        if Path(path).is_symlink():
            raise u.UpdateError("unsafe backup root")
        return path
    monkeypatch.setattr(u, "protected", guard)
    with pytest.raises(u.UpdateError, match="unsafe backup root"):
        updater._retain()
    assert (outside / "first").is_dir() and (outside / "second").is_dir()


def test_dashboard_children_are_not_stopped_before_run_locks(transaction, monkeypatch):
    updater, native, config = transaction
    held = RunLock(config.watch.database.parent / u.LOCK_NAME)
    assert held.acquire()
    def finish_sync(seconds):
        assert "freeze" not in native.calls
        held.release()
    monkeypatch.setattr(u.time, "sleep", finish_sync)
    def freeze(units):
        probe = RunLock(config.watch.database.parent / u.LOCK_NAME)
        assert not probe.acquire()
        native.calls.append("freeze")
    native.freeze = freeze
    updater.apply("0.1.1")
    assert "freeze" in native.calls
