from dataclasses import replace
import json
import os
from pathlib import Path
import sys

import pytest

from cvebeacon_extensions.contract import manifest_path, read_snapshot
from cvebeacon_automation.common import AutomationError
from cvebeacon_automation.config import Config, Source
from cvebeacon_automation.remote import ssh
from cvebeacon_automation.remote.probe import REMOTE_COMMAND, script
from cvebeacon_automation.staging import current_snapshot


def setup(tmp_path, namespace="ubuntu"):
    key = tmp_path / "synthetic key"
    known = tmp_path / "synthetic known hosts"
    key.write_text("synthetic-key-placeholder\n")
    known.write_text("synthetic-host-key-placeholder\n")
    key.chmod(0o600)
    known.chmod(0o600)
    options = dict(host="collector.example.test", user="collector", key=str(key), known_hosts=str(known), backend="dpkg")
    if namespace is not None:
        options["package_namespace"] = namespace
    source = Source("linux-fixture", kind="ssh", options=options)
    config = Config(tmp_path / "automation.toml", tmp_path / "state", tmp_path / "staging", tmp_path / "merged.json", tmp_path / "core.toml", (source,))
    return config, source


def observation(version="1.2-3"):
    return json.dumps(dict(version=1, backend="dpkg", os_release='ID=ubuntu\nNAME="Ubuntu"\nVERSION_ID="24.04"\n',
        packages="installed\tdemo-package\t" + version + "\tamd64\n")).encode()


@pytest.mark.parametrize("field,value", [
    ("host", "-oProxyCommand=bad"), ("host", "host; touch marker"), ("host", "user@host"),
    ("host", "ssh://host"), ("host", "host\nLocalCommand bad"), ("host", "host..test"),
    ("host", "[::1]"), ("host", "fe80::1%eth0"), ("host", "0.0.0.0"),
    ("user", "-oProxyCommand=bad"), ("user", "x;whoami"), ("user", "x y"),
    ("port", True), ("port", "22 -oProxyCommand=bad"), ("port", 0), ("port", 65536),
    ("backend", ["dpkg"]), ("backend", "dpkg;bad"), ("timeout", 0), ("timeout", 301),
    ("key", "${HOME}/identity"), ("known_hosts", "%h"), ("known_hosts", 'hosts" LocalCommand bad'),
    ("package_namespace", "Ubuntu"), ("package_namespace", "ubuntu;bad"),
])
def test_malicious_ssh_options_rejected_before_io(tmp_path, monkeypatch, field, value):
    config, source = setup(tmp_path)
    options = dict(source.options, **{field: value})
    monkeypatch.setattr(ssh, "run", lambda *a, **k: pytest.fail("invalid options must not run"))
    with pytest.raises(AutomationError):
        ssh.collect_ssh(config, replace(source, options=options))


def test_validation_does_not_read_or_resolve_key_material(tmp_path, monkeypatch):
    options = dict(host="example.test", user="collector", key="missing-key", known_hosts="missing-hosts")
    monkeypatch.setattr(Path, "read_bytes", lambda *a: pytest.fail("key content is not configuration"))
    result = ssh.validate_options(options, tmp_path)
    assert result["key"] == tmp_path / "missing-key"
    assert "package_namespace" in result and result["package_namespace"] is None
    with pytest.raises(AutomationError, match="invalid_ssh_options"):
        ssh.validate_options(dict(options, ssh_options=["-oStrictHostKeyChecking=no"]), tmp_path)


def test_fixed_ssh_transport_and_stdin_only_probe(tmp_path, monkeypatch):
    config, source = setup(tmp_path)
    monkeypatch.setattr(ssh, "executable", lambda name: "/trusted/ssh")
    seen = []
    def fake_run(command, **settings):
        seen.append((command, settings))
        assert len(command) <= 64
        options = {value[2:] for value in command if value.startswith("-o")}
        assert command[-1] == REMOTE_COMMAND
        assert command[-2] == "collector.example.test"
        assert "-F" in command and command[command.index("-F") + 1] == "none"
        assert {"StrictHostKeyChecking=yes", "NoHostAuthenticationForLocalhost=no", "GlobalKnownHostsFile=none",
            "IdentityAgent=none", "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes",
            "PermitLocalCommand=no", "ProxyCommand=none", "KnownHostsCommand=none", "ControlPath=none"} <= options
        assert "-T" in command and "-a" in command and "-x" in command
        assert any(value.startswith('UserKnownHostsFile="') and "synthetic known hosts" in value for value in options)
        assert settings["input"] == script("dpkg") and settings["limit"] == 32 * 1024 * 1024
        assert settings["timeout"] == 60
        assert settings["environment"] == {name: str(settings["cwd"]) for name in ("HOME", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA")}
        assert "ubuntu" not in settings["input"].split(b"\n", 1)[0].decode()
        return 0, observation()
    monkeypatch.setattr(ssh, "run", fake_run)
    result = ssh.collect_ssh(config, source)
    assert result["status"] == "accepted" and result["review_required"] == 0
    path = current_snapshot(config.staging_dir, source.id)
    snapshot = read_snapshot(path)
    assert any(row["purl"].startswith("pkg:deb/ubuntu/demo-package@") for row in snapshot.records)
    assert manifest_path(path).exists()
    assert list((config.state_dir / "remote" / source.id).glob("*.review.json"))
    assert len(seen) == 1


def test_collection_shared_process_boundary_is_offline_and_sanitized(tmp_path, monkeypatch):
    config, source = setup(tmp_path)
    canary_name = "SYNTHETIC_REMOTE_SECRET_CANARY"
    monkeypatch.setenv(canary_name, "never-pass-this-synthetic-value")
    # The actual shared helper launches only this local, isolated emitter.
    emitter = ("import json, os, sys; data=sys.stdin.buffer.read(); "
        "assert b'REQUESTED_BACKEND' in data; "
        "assert '" + canary_name + "' not in os.environ; "
        "assert os.environ['HOME']==os.getcwd(); "
        "sys.stdout.buffer.write(" + repr(observation()) + ")")
    monkeypatch.setattr(ssh, "argv", lambda options: [sys.executable, "-I", "-c", emitter])
    assert ssh.collect_ssh(config, source)["status"] == "accepted"
    assert current_snapshot(config.staging_dir, source.id).exists()


def test_remote_package_text_never_enters_command_or_script(tmp_path, monkeypatch):
    config, source = setup(tmp_path)
    monkeypatch.setattr(ssh, "executable", lambda name: "/trusted/ssh")
    canary = "1.2;$(touch /tmp/synthetic-marker)"
    def fake_run(command, **settings):
        assert not any(canary in value for value in command)
        assert canary.encode() not in settings["input"]
        return 0, observation(canary)
    monkeypatch.setattr(ssh, "run", fake_run)
    ssh.collect_ssh(config, source)
    assert not (tmp_path / "synthetic-marker").exists()


def test_unverified_package_namespace_stays_partial_review(tmp_path, monkeypatch):
    config, source = setup(tmp_path, None)
    monkeypatch.setattr(ssh, "executable", lambda name: "/trusted/ssh")
    monkeypatch.setattr(ssh, "run", lambda *a, **k: (0, observation()))
    result = ssh.collect_ssh(config, source)
    assert result["review_required"] == 1
    path = current_snapshot(config.staging_dir, source.id)
    snapshot = read_snapshot(path, allow_partial=True)
    assert snapshot.manifest["omissions"] == ["review-required"]
    assert len(snapshot.records) == 1 and snapshot.records[0]["category"] == "operating-system"
    review = json.loads(next((config.state_dir / "remote" / source.id).glob("*.review.json")).read_text())
    assert review["reviews"][0]["reason"] == "package-vendor-namespace-unverified"


@pytest.mark.parametrize("output", [
    b'{"version":1,"version":1,"backend":"dpkg","os_release":"x","packages":"x"}',
    b'{"version":true,"backend":"dpkg","os_release":"x","packages":"x"}',
    b'{"version":2,"backend":"dpkg","os_release":"x","packages":"x"}',
    b'{"version":1,"backend":[],"os_release":"x","packages":"x"}',
    b'{"version":1,"backend":"rpm","os_release":"x","packages":"x"}',
    b'{"version":1,"backend":"dpkg","os_release":[],"packages":"x"}',
    b'{"version":1,"backend":"dpkg","os_release":"x","packages":"x","command":"canary"}',
    b'login-banner\n{"version":1}', b'\xff', b'[' * 100 + b']' * 100,
], ids=["duplicate-key", "bool-version", "future-version", "backend-list", "wrong-backend", "wrong-release-type", "unknown-key", "banner", "bad-utf8", "deep-json"])
def test_malicious_probe_output_preserves_previous_generation(tmp_path, monkeypatch, output):
    config, source = setup(tmp_path)
    monkeypatch.setattr(ssh, "executable", lambda name: "/trusted/ssh")
    monkeypatch.setattr(ssh, "run", lambda *a, **k: (0, observation()))
    ssh.collect_ssh(config, source)
    pointer = config.staging_dir / source.id / "current.json"
    before = pointer.read_bytes()
    monkeypatch.setattr(ssh, "run", lambda *a, **k: (0, output))
    with pytest.raises(AutomationError) as error:
        ssh.collect_ssh(config, source)
    assert "canary" not in str(error.value)
    assert pointer.read_bytes() == before


@pytest.mark.parametrize("failure", ["host_key_rejected", "process_timeout", "process_output_limit"])
def test_host_key_process_failures_never_publish(tmp_path, monkeypatch, failure):
    config, source = setup(tmp_path)
    monkeypatch.setattr(ssh, "executable", lambda name: "/trusted/ssh")
    def failed(*a, **k):
        if failure == "host_key_rejected":
            return 255, b"synthetic-private-output"
        raise AutomationError(failure)
    monkeypatch.setattr(ssh, "run", failed)
    with pytest.raises(AutomationError) as error:
        ssh.collect_ssh(config, source)
    assert "synthetic-private-output" not in str(error.value)
    assert not (config.staging_dir / source.id / "current.json").exists()


def test_credential_hardlinks_rejected(tmp_path, monkeypatch):
    config, source = setup(tmp_path)
    try:
        os.link(source.options["key"], tmp_path / "second-key-link")
    except OSError:
        pytest.skip("hardlink creation unavailable")
    monkeypatch.setattr(ssh, "run", lambda *a, **k: pytest.fail("unsafe key must not run"))
    with pytest.raises(AutomationError, match="unsafe_file"):
        ssh.collect_ssh(config, source)


def test_winrm_is_disabled_before_credentials_or_transport():
    with pytest.raises(AutomationError, match="winrm_disabled_no_validated_secure_backend"):
        ssh.collect_winrm(password="synthetic-unused-canary", verify=False)
