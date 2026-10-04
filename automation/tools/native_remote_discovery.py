"""Native SSH/Nmap acceptance restricted to disposable Linux GitHub CI.

Only generated keys, an ephemeral loopback daemon, and its selected port are
used. No owner hosts, credentials, home configuration, or canonical promotion.
"""

from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from cvebeacon_extensions.contract import manifest_path, read_snapshot, write_snapshot
from cvebeacon_automation.common import AutomationError
from cvebeacon_automation.config import Config, Source
from cvebeacon_automation.discovery.nmap import run_jobs
from cvebeacon_automation.remote.ssh import collect_ssh
from cvebeacon_automation.staging import current_snapshot

from support import command, local_network_only


def disposable_ci():
    if (not sys.platform.startswith("linux") or os.environ.get("CI") != "true"
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.getuid() == 0):
        raise SystemExit("native remote acceptance requires a disposable Linux GitHub CI runner")
    for path in ("/usr/bin/ssh-keygen", "/usr/sbin/sshd", "/usr/bin/python3", "/usr/bin/dpkg-query"):
        if not Path(path).is_file():
            raise SystemExit("native remote fixture dependency unavailable")
    sudo = shutil.which("sudo", path="/usr/bin:/bin")
    if not sudo:
        raise SystemExit("native remote fixture requires disposable runner sudo")
    return sudo


def keypair(path):
    command(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], timeout=15)
    path.chmod(0o600)
    # Only this freshly generated PUBLIC key is read by the fixture.
    fields = path.with_name(path.name + ".pub").read_text(encoding="ascii").split()
    assert len(fields) >= 2 and fields[0] == "ssh-ed25519"
    return " ".join(fields[:2])


def available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    assert 1024 < port < 65536
    return port


@contextmanager
def ephemeral_sshd(root, sudo, client_public, host_key):
    import pwd

    port = available_port()
    user = pwd.getpwuid(os.getuid()).pw_name
    authorized = root / "authorized_keys"
    authorized.write_text(client_public + "\n", encoding="ascii")
    authorized.chmod(0o600)
    pidfile = root / "sshd.pid"
    settings = root / "sshd.fixture.conf"
    settings.write_text("\n".join((
        "Port " + str(port), "ListenAddress 127.0.0.1", "AddressFamily inet",
        "HostKey " + str(host_key), "PidFile " + str(pidfile),
        "AuthorizedKeysFile " + str(authorized), "AllowUsers " + user,
        "PubkeyAuthentication yes", "AuthenticationMethods publickey",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "HostbasedAuthentication no",
        # Hosted runner passwords can be locked. PAM account checks allow its
        # existing account without changing it; all password authentication is off.
        "PermitRootLogin no", "UsePAM yes", "UseDNS no", "StrictModes no",
        "AllowAgentForwarding no", "AllowTcpForwarding no", "X11Forwarding no",
        "PermitTunnel no", "GatewayPorts no", "PermitUserEnvironment no", "PermitUserRC no",
        "PrintMotd no", "Banner none", "LoginGraceTime 10", "MaxSessions 1", "MaxStartups 2:100:2",
        "LogLevel ERROR", "",
    )), encoding="ascii")
    # The directory belongs only to this disposable runner, not the owner host.
    command([sudo, "-n", "/usr/bin/install", "-d", "-m", "0755", "/run/sshd"], timeout=10)
    command([sudo, "-n", "/usr/sbin/sshd", "-t", "-f", str(settings)], timeout=10)
    daemon = subprocess.Popen([sudo, "-n", "/usr/sbin/sshd", "-D", "-e", "-f", str(settings)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        shell=False, start_new_session=True)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if daemon.poll() is not None:
                raise AssertionError("synthetic loopback sshd failed to start")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("synthetic loopback sshd readiness deadline")
        assert pidfile.is_file()
        yield port, user
    finally:
        if pidfile.is_file():
            raw_pid = pidfile.read_text(encoding="ascii").strip()
            assert raw_pid.isdigit() and 1 < int(raw_pid) < 2 ** 31
            # Exact PID came from this daemon's private, generated configuration.
            command([sudo, "-n", "/usr/bin/kill", "-TERM", raw_pid], timeout=10)
        else:
            daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise AssertionError("synthetic loopback sshd cleanup deadline") from None


def rejected_host_key(config, source, known_hosts, previous):
    bad = replace(source, options={**source.options, "known_hosts": str(known_hosts)})
    try:
        collect_ssh(config, bad)
    except AutomationError as exc:
        assert exc.category == "ssh_collection_failed"
    else:
        raise AssertionError("unenrolled synthetic server key accepted")
    assert (config.staging_dir / source.id / "current.json").read_bytes() == previous


def run_acceptance(root, sudo):
    client_key, host_key = root / "fixture-client-key", root / "fixture-host-key"
    client_public, host_public = keypair(client_key), keypair(host_key)
    wrong_public = keypair(root / "fixture-wrong-host-key")
    with local_network_only(), ephemeral_sshd(root, sudo, client_public, host_key) as (port, user):
        known = root / "fixture known hosts"
        known.write_text(f"[127.0.0.1]:{port} {host_public}\n", encoding="ascii")
        known.chmod(0o600)
        source = Source("native-linux", kind="ssh", options=dict(host="127.0.0.1", port=port, user=user,
            key=str(client_key), known_hosts=str(known), backend="dpkg", timeout=60, package_namespace="ubuntu"))
        config = Config(root / "automation.toml", root / "state", root / "staging", root / "canonical.json",
            root / "unused-core.toml", (source,), discovery=(dict(id="native-loopback", enabled=True,
            targets=["127.0.0.1"], allowlist=["127.0.0.1"], ports=[port], timeout=45),))
        write_snapshot(config.inventory_path, [dict(asset_id="synthetic-canonical", purl="pkg:pypi/example@1.0")],
            source_id="manual", collector="synthetic-ci")
        canonical = config.inventory_path.read_bytes()
        canonical_manifest = manifest_path(config.inventory_path).read_bytes()
        result = collect_ssh(config, source)
        assert result["status"] == "accepted" and result["observations"] > 1
        staged = current_snapshot(config.staging_dir, source.id)
        snapshot = read_snapshot(staged, allow_partial=True)
        assert snapshot.manifest["source_id"] == source.id
        assert any(row.get("purl", "").startswith("pkg:deb/ubuntu/") for row in snapshot.records)
        pointer = (config.staging_dir / source.id / "current.json").read_bytes()
        wrong = root / "wrong known hosts"
        wrong.write_text(f"[127.0.0.1]:{port} {wrong_public}\n", encoding="ascii")
        wrong.chmod(0o600)
        unknown = root / "unknown known hosts"
        unknown.write_text("", encoding="ascii")
        unknown.chmod(0o600)
        rejected_host_key(config, source, wrong, pointer)
        rejected_host_key(config, source, unknown, pointer)
        duplicates = root / "duplicate known hosts"
        duplicates.write_text(f"[127.0.0.1]:{port} {wrong_public}\n[127.0.0.1]:{port} {wrong_public}\n", encoding="ascii")
        duplicates.chmod(0o600)
        rejected_host_key(config, source, duplicates, pointer)
        duplicates.write_text(f"[127.0.0.1]:{port} {wrong_public}\n[127.0.0.1]:{port} {host_public}\n", encoding="ascii")
        # Multiple explicitly enrolled keys are supported; a matching pinned key is required.
        duplicate_source = replace(source, id="native-duplicate-enrollment", options={**source.options, "known_hosts": str(duplicates)})
        assert collect_ssh(config, duplicate_source)["status"] == "accepted"
        review_source = replace(source, id="native-review", options={key: value for key, value in source.options.items()
            if key != "package_namespace"})
        review_result = collect_ssh(config, review_source)
        assert review_result["review_required"] > 0
        partial = read_snapshot(current_snapshot(config.staging_dir, review_source.id), allow_partial=True)
        assert partial.manifest["omissions"] == ["review-required"]
        assert not any(row.get("purl", "").startswith("pkg:deb/") for row in partial.records)
        discovered = run_jobs(config)["native-loopback"]
        assert discovered["status"] == "success" and discovered.get("observations") == 1, discovered
        observation_file = config.state_dir / "discovery" / "native-loopback" / "current.json"
        observation = json.loads(observation_file.read_bytes())
        row = observation["observations"][0]
        assert observation["trust"] == "discovery-observation"
        assert row["address"] == "127.0.0.1" and row["port"] == port and row["protocol"] == "tcp"
        assert row["service"] == "ssh" and row["product"]
        assert not {"asset_id", "purl", "applicability"} & set(row)
        assert config.inventory_path.read_bytes() == canonical
        assert manifest_path(config.inventory_path).read_bytes() == canonical_manifest
    print("native enrolled SSH/host-key rejection/transient collection/review omissions/loopback Nmap/separate inventory passed")


if __name__ == "__main__":
    fixture_sudo = disposable_ci()
    with tempfile.TemporaryDirectory(prefix="cvebeacon-native-remote-") as temporary:
        run_acceptance(Path(temporary), fixture_sudo)
