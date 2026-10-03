"""One-shot local host observations with fixed, unprivileged data sources."""

from __future__ import annotations

from dataclasses import asdict
from collections import Counter
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading

from packageurl import PackageURL
from cvebeacon.identity import purl_string
from cvebeacon.inventory import validate_records

from .contract import (ExtensionError, MAX_BYTES, MAX_RECORDS, _atomic, canonical_records,
                       json_bytes, label, read_bytes, write_snapshot)
from .sbom import stable_id, text

DPKG_ARGS = ["/usr/bin/dpkg-query", "--no-pager", "--show",
             "--showformat=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n"]
RPM_ARGS = ["/usr/bin/rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{EPOCHNUM}\n"]
READER_GRACE_SECONDS = 2


def _terminate(process):
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def run_packages(args: list[str], *, timeout: int = 30) -> str:
    """Fixed trusted executable, clean environment, no shell or package arguments."""
    if args not in (DPKG_ARGS, RPM_ARGS):
        raise ExtensionError("unsupported collector command")
    with tempfile.TemporaryDirectory(prefix="cvebeacon-collector-") as home_dir:
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                       "HOME": home_dir, "XDG_CONFIG_HOME": home_dir}
        with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, shell=False, env=environment,
                              start_new_session=True) as process:
            chunks = []
            errors = []
            def read_output():
                try:
                    result = process.stdout.read(MAX_BYTES + 1)
                    chunks.append(result)
                    if len(result) > MAX_BYTES:
                        _terminate(process)
                except OSError as exc:
                    errors.append(exc)
            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            orphaned_output = False
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                _terminate(process)
                process.wait()
                raise ExtensionError("package query timed out") from exc
            finally:
                reader.join(timeout=READER_GRACE_SECONDS)
                if reader.is_alive():
                    orphaned_output = True
                    # Kill the whole isolated query process group, including
                    # helpers holding stdout after the main query exits.
                    _terminate(process)
                    reader.join(timeout=READER_GRACE_SECONDS)
            if orphaned_output or reader.is_alive() or errors or code != 0 or not chunks or len(chunks[0]) > MAX_BYTES:
                raise ExtensionError("package query failed or exceeded output limit")
    try:
        return chunks[0].decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ExtensionError("package query returned invalid UTF-8") from exc


def os_release(raw: str) -> dict[str, str]:
    if len(raw) > 65536:
        raise ExtensionError("os-release exceeds size limit")
    result = {}
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z_][A-Z_0-9]*", key) or key in result:
            raise ExtensionError("malformed os-release")
        try:
            parsed = shlex.split(value, comments=False, posix=True)
        except ValueError as exc:
            raise ExtensionError("malformed os-release value") from exc
        if len(parsed) > 1:
            raise ExtensionError("unquoted os-release value")
        result[key] = text(parsed[0] if parsed else "", "os-release value")
    return {key: result[key] for key in ("ID", "NAME", "VERSION_ID", "ID_LIKE") if key in result}


def _package_rows(raw: str, backend: str) -> list[tuple[str, str, str, str]]:
    if len(raw.encode("utf-8")) > MAX_BYTES:
        raise ExtensionError("package output exceeds size limit")
    lines = raw.splitlines()
    if not lines or len(lines) > MAX_RECORDS:
        raise ExtensionError("package query has invalid record count")
    records = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) != (4 if backend == "dpkg" else 5):
            raise ExtensionError("malformed package query row")
        if backend == "dpkg":
            status, name, version, arch = fields
            if status in {"not-installed", "config-files"}:
                continue
            if status != "installed":
                raise ExtensionError("package database contains an incomplete installation")
            epoch = ""
        else:
            name, version, release, arch, epoch = fields
            if not epoch.isascii() or not epoch.isdigit() or len(epoch) > 10 or int(epoch) > 4294967295:
                raise ExtensionError("invalid RPM epoch")
            epoch = str(int(epoch)) if int(epoch) else ""
            version += "-" + release
        for value in fields:
            text(value, "package field", required=True)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*", name) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", arch):
            raise ExtensionError("invalid package name or architecture")
        records.append((name, version, arch, epoch))
    return records


def linux_inventory(raw_release: str, raw_packages: str, *, backend: str, source_id: str,
                    package_namespace: str | None = None) -> tuple[list[dict], list[dict]]:
    label(source_id)
    if backend not in {"dpkg", "rpm"}:
        raise ExtensionError("supported Linux backends are dpkg and rpm")
    release = os_release(raw_release)
    distro = text(release.get("ID"), "OS ID", required=True)
    if not re.fullmatch(r"[a-z0-9._-]+", distro):
        raise ExtensionError("invalid OS ID")
    if package_namespace is not None and not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", package_namespace):
        raise ExtensionError("package namespace must be a lowercase vendor identifier")
    rows, reviews = [], []
    version = release.get("VERSION_ID", "")
    if version:
        rows.append(dict(asset_id=stable_id(source_id, "os"), vendor=distro,
                         product=release.get("NAME") or distro, version=version,
                         category="operating-system", system_id=source_id))
    else:
        reviews.append(dict(name=release.get("NAME") or distro, version="", reason="no-os-release-version"))
    packages = _package_rows(raw_packages, backend)
    if len(set(packages)) != len(packages):
        raise ExtensionError("duplicate package record")
    counts = Counter((name, arch) for name, version, arch, epoch in packages)
    for name, package_version, arch, epoch in packages:
        slot = f"{backend}:{name}:{arch}"
        if package_namespace is None or counts[(name, arch)] > 1:
            reviews.append(dict(name=name, version=package_version, architecture=arch, epoch=epoch,
                                backend=backend, reason="coinstalled-package-instances" if counts[(name, arch)] > 1 else "package-vendor-namespace-unverified"))
            continue
        qualifiers = {"arch": arch}
        if version:
            qualifiers["distro"] = distro + "-" + version
        if epoch:
            qualifiers["epoch"] = epoch
        purl = PackageURL(type="deb" if backend == "dpkg" else "rpm", namespace=package_namespace,
                          name=name, version=package_version, qualifiers=qualifiers)
        rows.append(dict(asset_id=stable_id(source_id, slot), purl=purl_string(purl),
                         category="os-package", system_id=source_id))
    return (canonical_records(rows) if rows else [], reviews)


def collect_linux(*, source_id: str, backend: str = "auto", package_namespace: str | None = None):
    if not sys.platform.startswith("linux"):
        raise ExtensionError("Linux collector requires Linux")
    release_path = Path("/etc/os-release")
    if not release_path.exists():
        release_path = Path("/usr/lib/os-release")
    try:
        raw = read_bytes(release_path.resolve(), 65536).decode("utf-8")
    except UnicodeError as exc:
        raise ExtensionError("os-release contains invalid UTF-8") from exc
    if backend == "auto":
        release = os_release(raw)
        family = {release.get("ID", ""), *release.get("ID_LIKE", "").split()}
        backend = "dpkg" if family & {"debian", "ubuntu"} else "rpm" if family & {"rhel", "fedora", "centos", "suse", "opensuse", "rocky", "almalinux"} else "unknown"
    if backend not in {"dpkg", "rpm"}:
        raise ExtensionError("cannot select supported package manager; supply --backend")
    return linux_inventory(raw, run_packages(DPKG_ARGS if backend == "dpkg" else RPM_ARGS),
                           backend=backend, source_id=source_id, package_namespace=package_namespace)


UNINSTALL = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
WINDOWS_VERSION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def _registry_value(registry, key, name, *, integer=False):
    try:
        value, kind = registry.QueryValueEx(key, name)
    except FileNotFoundError:
        return ""
    if integer:
        if kind != registry.REG_DWORD or type(value) is not int or value < 0:
            raise ExtensionError("unexpected Windows build metadata type")
        return str(value)
    if kind not in {registry.REG_SZ, registry.REG_EXPAND_SZ}:
        raise ExtensionError("unexpected installed-program metadata type")
    # REG_EXPAND_SZ is read literally, never expanded from environment values.
    return text(value, "registry field")


def windows_observations(registry) -> tuple[dict, list[dict]]:
    programs = []
    for hive, scope in [(registry.HKEY_LOCAL_MACHINE, "machine"), (registry.HKEY_CURRENT_USER, "current-user")]:
        for flag, view in [(registry.KEY_WOW64_64KEY, "64"), (registry.KEY_WOW64_32KEY, "32")]:
            try:
                parent = registry.OpenKey(hive, UNINSTALL, 0, registry.KEY_READ | flag)
            except FileNotFoundError:
                continue
            with parent:
                index = 0
                while True:
                    try:
                        name = registry.EnumKey(parent, index)
                    except OSError as exc:
                        if getattr(exc, "winerror", None) == 259:
                            break
                        raise
                    index += 1
                    if index > MAX_RECORDS or len(programs) >= MAX_RECORDS:
                        raise ExtensionError("installed-program count exceeds limit")
                    with registry.OpenKey(parent, name, 0, registry.KEY_READ | flag) as key:
                        item = dict(name=_registry_value(registry, key, "DisplayName"),
                                    version=_registry_value(registry, key, "DisplayVersion"),
                                    vendor=_registry_value(registry, key, "Publisher"), scope=scope, view=view)
                    # Preserve both logical views: identical display fields do
                    # not prove the physical registration is shared.
                    programs.append(item)
    with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, WINDOWS_VERSION, 0, registry.KEY_READ | registry.KEY_WOW64_64KEY) as key:
        product = _registry_value(registry, key, "ProductName")
        build = _registry_value(registry, key, "CurrentBuildNumber")
        revision = _registry_value(registry, key, "UBR", integer=True)
    return dict(product=product, version=build + ("." + revision if revision and build else "")), programs


def windows_inventory(os_info: dict, programs: list[dict], *, source_id: str):
    label(source_id)
    rows, reviews, candidates = [], [], []
    product, version = text(os_info.get("product"), "Windows product"), text(os_info.get("version"), "Windows build")
    if product and version:
        rows.append(dict(asset_id=stable_id(source_id, "os"), vendor="Microsoft", product=product,
                         version=version, category="operating-system", system_id=source_id))
    else:
        reviews.append(dict(name=product, version=version, reason="incomplete-os-identity"))
    if len(programs) > MAX_RECORDS:
        raise ExtensionError("too many installed programs")
    for item in programs:
        vendor, name, version = (text(item.get(key), key) for key in ("vendor", "name", "version"))
        scope, view = item.get("scope"), item.get("view")
        if scope not in {"machine", "current-user"} or view not in {"32", "64"}:
            raise ExtensionError("invalid Windows registry scope/view")
        if not vendor or not name or not version:
            reviews.append(dict(name=name, version=version, reason="incomplete-program-identity"))
            continue
        # Use core's generic normalization before deriving the stable slot.
        asset = validate_records([dict(asset_id="candidate", vendor=vendor, product=name, version=version)])[0]
        slot = json_bytes([scope, view, asset.vendor.casefold(), asset.product.casefold()]).decode("utf-8")
        row = asdict(asset)
        row.update(asset_id=stable_id(source_id, slot), category="installed-program", system_id=source_id)
        candidates.append((slot, row, scope, view))
    counts = Counter(slot for slot, row, scope, view in candidates)
    for slot, row, scope, view in candidates:
        if counts[slot] > 1:
            reviews.append(dict(name=row["product"], vendor=row["vendor"], version=row["version"],
                                scope=scope, view=view, reason="ambiguous-program-instances"))
        else:
            rows.append(row)
    return (canonical_records(rows) if rows else [], reviews)


def collect_windows(*, source_id: str):
    if sys.platform != "win32":
        raise ExtensionError("Windows collector requires Windows")
    import winreg
    os_info, programs = windows_observations(winreg)
    return windows_inventory(os_info, programs, source_id=source_id)


def publish_host(output: Path, rows: list[dict], reviews: list[dict], *, source_id: str, collector: str):
    data = json_bytes(dict(source_id=source_id, reviews=reviews))
    if len(data) > MAX_BYTES:
        raise ExtensionError("review output exceeds size limit")
    if rows:
        canonical_records(rows)
    _atomic(Path(str(output) + ".review.json"), data)
    if not rows:
        raise ExtensionError("no validated observations; review output written")
    return write_snapshot(output, rows, source_id=source_id, collector=collector,
                          omissions=["review-required"] if reviews else [])
