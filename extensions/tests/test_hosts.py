from io import BytesIO
import json
import subprocess
import os
import sys
import time

import pytest

from cvebeacon_extensions import hosts
from cvebeacon_extensions.contract import ExtensionError, read_snapshot
from cvebeacon_extensions.hosts import linux_inventory, windows_inventory, windows_observations

OS_RELEASE = 'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\n'
PACKAGES = "installed\tcurl\t1:8.0-1\tamd64\ninstalled\tlibc6\t2.40-1\tamd64\nconfig-files\tremoved\t1\tall\n"


def linux(raw=PACKAGES, **kwargs):
    return linux_inventory(OS_RELEASE, raw, backend="dpkg", source_id="host-a", **kwargs)


def test_linux_stable_upgrades_removals_source_and_core_roundtrip(tmp_path):
    old, reviews = linux(package_namespace="debian")
    new, _ = linux("installed\tcurl\t1:8.1-1\tamd64\n", package_namespace="debian")
    assert len(old) == 3 and len(new) == 2 and not reviews
    old_curl = next(row for row in old if "curl" in row["purl"])
    new_curl = next(row for row in new if "curl" in row["purl"])
    assert old_curl["asset_id"] == new_curl["asset_id"]
    assert old_curl["version"] == "1:8.0-1"
    assert "arch=amd64" in old_curl["purl"] and "distro=debian-13" in old_curl["purl"]
    again, _ = linux(package_namespace="debian")
    assert again == old
    other, _ = linux_inventory(OS_RELEASE, PACKAGES, backend="dpkg", source_id="host-b", package_namespace="debian")
    assert not {row["asset_id"] for row in old} & {row["asset_id"] for row in other}
    out = tmp_path / "host.json"
    hosts.publish_host(out, old, reviews, source_id="host-a", collector="linux")
    assert read_snapshot(out).records == old


def test_namespace_not_inferred_and_derivative_release_not_universalized():
    rows, reviews = linux()
    assert len(rows) == 1 and len(reviews) == 2
    assert all(review["reason"] == "package-vendor-namespace-unverified" for review in reviews)
    rows, _ = linux_inventory('ID=linuxmint\nID_LIKE="ubuntu debian"\nNAME="Linux Mint"\nVERSION_ID="22"',
                             "installed\tcurl\t1\tamd64\n", backend="dpkg", source_id="mint", package_namespace="example")
    assert "distro=linuxmint-22" in next(row["purl"] for row in rows if row["purl"])
    assert not any("ubuntu-22" in row["purl"] for row in rows)


def test_rpm_epoch_release_arch_and_multiversion_review():
    rows, _ = linux_inventory('ID=fedora\nNAME=Fedora\nVERSION_ID=43', "ExamplePkg\t1.2\t3.fc43\tx86_64\t2\n", backend="rpm", source_id="host", package_namespace="fedora")
    package = next(row for row in rows if row["purl"])
    assert package["version"] == "1.2-3.fc43" and "epoch=2" in package["purl"]
    assert "ExamplePkg" in package["purl"]
    for namespace in (None, "fedora"):
        rows, reviews = linux_inventory('ID=fedora\nVERSION_ID=43', "kernel\t1\t1\tx86_64\t0\nkernel\t2\t1\tx86_64\t0\n", backend="rpm", source_id="host", package_namespace=namespace)
        assert len(rows) == 1 and len(reviews) == 2
        assert {item["reason"] for item in reviews} == {"coinstalled-package-instances"}


@pytest.mark.parametrize("raw", ["", "installed\tcurl\t1\n", "half-installed\tcurl\t1\tamd64\n", "installed\tcurl;touch marker\t1\tamd64\n", "installed\tcurl\t1\tamd64\ninstalled\tcurl\t1\tamd64\n"])
def test_malformed_packages_fail(raw):
    with pytest.raises(ExtensionError):
        linux(raw, package_namespace="debian")


def test_os_release_is_not_executed_and_rejects_duplicate_keys():
    assert hosts.os_release('ID=example\nNAME="$(touch marker)"')["NAME"] == "$(touch marker)"
    with pytest.raises(ExtensionError):
        hosts.os_release("ID=debian\nID=ubuntu")
    with pytest.raises(ExtensionError):
        hosts.os_release('NAME="unterminated')
    rows, reviews = linux_inventory('ID=rolling\nNAME=Rolling', "installed\tpkg\t1\tall\n", backend="dpkg", source_id="host")
    assert not rows and len(reviews) == 2


class FakeProcess:
    def __init__(self, output=b"installed\tpkg\t1\tall\n", code=0, timeout=False):
        self.stdout, self.code, self.timeout, self.killed = BytesIO(output), code, timeout, False
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def wait(self, timeout=None):
        if self.timeout and not self.killed: raise subprocess.TimeoutExpired("fixed", timeout)
        return self.code
    def kill(self): self.killed = True


def test_fixed_subprocess_and_environment_privacy(monkeypatch):
    monkeypatch.setenv("PACKAGE_SECRET_CANARY", "must-not-be-inherited")
    monkeypatch.setenv("DPKG_ROOT", "/untrusted")
    called = []
    def launch(args, **kwargs):
        called.append((args, kwargs))
        assert kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL
        assert set(kwargs["env"]) == {"PATH", "LANG", "LC_ALL", "HOME", "XDG_CONFIG_HOME"}
        assert "must-not-be-inherited" not in json.dumps(kwargs["env"])
        assert kwargs["stderr"] == subprocess.DEVNULL
        return FakeProcess()
    monkeypatch.setattr(hosts.subprocess, "Popen", launch)
    monkeypatch.setattr(hosts, "_terminate", lambda process: process.kill())
    assert "pkg" in hosts.run_packages(hosts.DPKG_ARGS)
    with pytest.raises(ExtensionError): hosts.run_packages(["sh", "-c", "anything"])
    assert len(called) == 1


@pytest.mark.parametrize("kind", ["timeout", "nonzero", "large", "encoding"])
def test_failed_package_commands(kind, monkeypatch):
    monkeypatch.setattr(hosts, "MAX_BYTES", 100)
    process = FakeProcess(output=b"a"*101 if kind == "large" else b"\xff" if kind == "encoding" else b"ok", code=1 if kind=="nonzero" else 0, timeout=kind=="timeout")
    monkeypatch.setattr(hosts.subprocess, "Popen", lambda *a, **kw: process)
    monkeypatch.setattr(hosts, "_terminate", lambda process: process.kill())
    with pytest.raises(ExtensionError): hosts.run_packages(hosts.DPKG_ARGS)


class Key:
    def __init__(self, hive, path, flag): self.hive, self.path, self.flag = hive, path, flag
    def __enter__(self): return self
    def __exit__(self, *args): return False


class Registry:
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER = 1, 2
    KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 0x20019, 0x100, 0x200
    REG_SZ, REG_EXPAND_SZ, REG_DWORD = 1, 2, 4
    def __init__(self):
        self.queries, self.opens = [], []
        self.programs = {"shared": dict(DisplayName="Example Program", DisplayVersion="1", Publisher="Example Vendor")}
    def OpenKey(self, hive, path, reserved, flags):
        self.opens.append(flags)
        if isinstance(hive, Key): return Key(hive.hive, path, flags)
        if hive == self.HKEY_CURRENT_USER: raise FileNotFoundError()
        return Key(hive, path, flags)
    def EnumKey(self, key, index):
        if index >= len(self.programs):
            error = OSError("no more items"); error.winerror = 259; raise error
        return list(self.programs)[index]
    def QueryValueEx(self, key, name):
        self.queries.append(name)
        if key.path == hosts.WINDOWS_VERSION:
            return {"ProductName":("Windows Example",1), "CurrentBuildNumber":("12345",1), "UBR":(7,4)}[name]
        value = self.programs[key.path].get(name)
        if value is None: raise FileNotFoundError()
        return value, self.REG_SZ


def test_registry_fixed_allowlist_preserves_distinct_views_and_no_mutation():
    registry = Registry()
    info, observations = windows_observations(registry)
    assert len(observations) == 2 and info["version"] == "12345.7"
    assert set(registry.queries) == {"DisplayName", "DisplayVersion", "Publisher", "ProductName", "CurrentBuildNumber", "UBR"}
    assert set(registry.opens) <= {registry.KEY_READ|registry.KEY_WOW64_64KEY, registry.KEY_READ|registry.KEY_WOW64_32KEY}
    rows, reviews = windows_inventory(info, observations, source_id="win-a")
    assert len(rows) == 3 and not reviews
    assert all(not row["purl"] and not row["cpe"] for row in rows)
    before = {row["asset_id"] for row in rows}
    observations[0]["version"] = "2"
    after, _ = windows_inventory(info, observations, source_id="win-a")
    assert {row["asset_id"] for row in after} == before


def test_registry_permission_and_enumeration_failures_are_not_success():
    registry = Registry()
    def denied(*args): raise PermissionError("denied")
    registry.EnumKey = denied
    with pytest.raises(PermissionError): windows_observations(registry)


def test_windows_incomplete_types_duplicates_and_no_environment_expansion(monkeypatch):
    registry = Registry()
    monkeypatch.setenv("SECRET_CANARY", "not-observed")
    registry.programs["shared"]["DisplayName"] = "%SECRET_CANARY%"
    info, programs = windows_observations(registry)
    rows, _ = windows_inventory(info, programs, source_id="win")
    assert "not-observed" not in json.dumps(rows)
    assert any(row["product"] == "%SECRET_CANARY%" for row in rows)
    duplicates, review = windows_inventory(info, programs+programs, source_id="win")
    assert len(duplicates) == 1 and len(review) == 4
    assert {item["reason"] for item in review} == {"ambiguous-program-instances"}
    programs[0]["version"] = ""
    rows, reviews = windows_inventory(info, programs, source_id="win")
    assert len(rows) == 2 and len(reviews) == 1
    registry.programs["shared"]["Publisher"] = 7
    with pytest.raises(ExtensionError): windows_observations(registry)


def test_failed_collection_does_not_refresh_prior_snapshot(tmp_path, monkeypatch):
    from cvebeacon_extensions.cli import main
    rows, reviews = linux(package_namespace="debian")
    output = tmp_path / "host.json"
    hosts.publish_host(output, rows, reviews, source_id="host-a", collector="linux")
    before = (output.read_bytes(), (tmp_path / "host.json.manifest.json").read_bytes())
    def failure(**kwargs): raise ExtensionError("synthetic failure")
    monkeypatch.setattr(hosts, "collect_linux", failure)
    assert main(["collect", "linux", "--source-id", "host-a", "--output", str(output)]) == 2
    assert before == (output.read_bytes(), (tmp_path / "host.json.manifest.json").read_bytes())


def test_residual_dpkg_entries_and_review_arch_epoch():
    rows, _ = linux("not-installed\told\t\t\ninstalled\tcurl\t1\tamd64\n", package_namespace="debian")
    assert len(rows) == 2
    _, review = linux_inventory('ID=fedora\nVERSION_ID=43', 'pkg\t1\t2\taarch64\t7\n', backend="rpm", source_id="host")
    assert review[0]["epoch"] == "7" and review[0]["architecture"] == "aarch64" and review[0]["backend"] == "rpm"
    with pytest.raises(ExtensionError, match="epoch"):
        linux_inventory('ID=fedora', 'pkg\t1\t2\taarch64\t'+'9'*5000+'\n', backend="rpm", source_id="host")


def test_missing_windows_build_cannot_become_revision_only():
    registry = Registry()
    original = registry.QueryValueEx
    def query(key, name):
        if name == "CurrentBuildNumber": raise FileNotFoundError()
        return original(key, name)
    registry.QueryValueEx = query
    info, programs = windows_observations(registry)
    assert info["version"] == ""
    rows, reviews = windows_inventory(info, programs, source_id="host")
    assert not any(row["category"] == "operating-system" for row in rows)
    assert reviews[0]["reason"] == "incomplete-os-identity"


@pytest.mark.skipif(os.name != "posix", reason="Linux package-query process groups")
@pytest.mark.parametrize("parent_sleeps", [False, True])
def test_query_timeout_kills_helpers_holding_stdout(monkeypatch, parent_sleeps):
    script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time;time.sleep(8)']);" + ("time.sleep(8)" if parent_sleeps else "")
    args = [sys.executable, "-c", script]
    monkeypatch.setattr(hosts, "DPKG_ARGS", args)
    monkeypatch.setattr(hosts, "READER_GRACE_SECONDS", 0.1)
    start = time.monotonic()
    with pytest.raises(ExtensionError):
        hosts.run_packages(args, timeout=0.1)
    assert time.monotonic() - start < 3


def test_invalid_os_release_encoding_is_controlled(monkeypatch):
    monkeypatch.setattr(hosts.sys, "platform", "linux")
    monkeypatch.setattr(hosts.Path, "exists", lambda self: True)
    monkeypatch.setattr(hosts.Path, "resolve", lambda self: self)
    monkeypatch.setattr(hosts, "read_bytes", lambda *args: b"\xff")
    with pytest.raises(ExtensionError, match="UTF-8"):
        hosts.collect_linux(source_id="host")
