from dataclasses import replace
from html import escape
import json
from pathlib import Path

import pytest

from cvebeacon_automation.common import AutomationError
from cvebeacon_automation.config import Config
from cvebeacon_automation.discovery import nmap


@pytest.fixture(autouse=True)
def no_owner_nmap_data_preflight(tmp_path, monkeypatch):
    monkeypatch.setattr(nmap, "_user_data_directories", lambda: (tmp_path / "synthetic-config-fallback",))


def job(**values):
    return dict(id="synthetic-services", enabled=True, targets=["127.0.0.1"], allowlist=["127.0.0.1"], ports=[22], **values)


def xml(address="127.0.0.1", version="1.0", *, total=1, doctype=True, host=True):
    family = "ipv6" if ":" in address else "ipv4"
    host_xml = ('<host><status state="up"/><address addr="' + address + '" addrtype="' + family + '"/>'
        '<hostnames><hostname name="synthetic.example.test" type="user"/></hostnames><ports><port protocol="tcp" portid="22">'
        '<state state="open"/><service name="ssh" product="Synthetic SSH" version="' + escape(version, quote=True) + '" method="probed" conf="10">'
        '<cpe>cpe:/a:synthetic:ssh:' + escape(version) + '</cpe></service></port></ports></host>') if host else ""
    return ('<?xml version="1.0" encoding="UTF-8"?>\n' + ('<!DOCTYPE nmaprun>\n' if doctype else "") +
        '<nmaprun scanner="nmap" version="7.synthetic" xmloutputversion="1.05">' + host_xml +
        '<runstats><finished exit="success"/><hosts up="' + str(total) + '" down="0" total="' + str(total) + '"/></runstats></nmaprun>').encode()


def config(tmp_path, jobs=None):
    return Config(tmp_path / "auto.toml", tmp_path / "state", tmp_path / "staging", tmp_path / "inventory.json", tmp_path / "core.toml", (), discovery=jobs or (job(),))


@pytest.mark.parametrize("target", ["0.0.0.0/0", "::/0", "10.0.0.0/16", "224.0.0.1", "ff02::1", "255.255.255.255", "0.0.0.0", "::",
    "169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254", "fe80::1%eth0",
    "-iL /tmp/targets", "127.0.0.1;bad", "127.0.0-255.1", "https://127.0.0.1", "example.test", "1.1.1.1"])
def test_unauthorized_or_broad_targets_rejected(target):
    candidate = job()
    candidate["targets"] = candidate["allowlist"] = [target]
    with pytest.raises(AutomationError):
        nmap.validate_jobs((candidate,))


def test_explicit_public_opt_in_and_subnet_broadcast_exclusion():
    candidate = job()
    candidate.update(targets=["1.1.1.1"], allowlist=["1.1.1.1"], allow_public=True)
    assert nmap.validate_jobs((candidate,))[0]["targets"] == ("1.1.1.1",)
    candidate.update(targets=["10.0.0.255"], allowlist=["10.0.0.0/24"], allow_public=False)
    with pytest.raises(AutomationError, match="not_allowlisted"):
        nmap.validate_jobs((candidate,))


@pytest.mark.parametrize("field,value", [("ports", [True]), ("ports", [0]), ("ports", [65536]), ("ports", [22] * 129),
    ("timeout", 301), ("enabled", "yes"), ("allow_public", 1), ("allowlist", []), ("targets", ["127.0.0.2"]), ("args", ["--script=all"])])
def test_invalid_discovery_schema_bounds(field, value):
    candidate = job()
    candidate[field] = value
    with pytest.raises(AutomationError):
        nmap.validate_jobs((candidate,))


def test_normal_xml_is_low_trust_projected_without_inventory_identity():
    result = nmap.parse_xml(xml(), targets=["127.0.0.1"], ports=[22])
    assert result["coverage"] == "complete"
    row = result["observations"][0]
    assert row["method"] == "probed" and row["confidence"] == 10
    assert row["cpes"] == ["cpe:/a:synthetic:ssh:1.0"]
    assert not {"asset_id", "purl", "vendor", "applicability"} & set(row)
    missing = nmap.parse_xml(xml(host=False), targets=["127.0.0.1"], ports=[22])
    assert missing["coverage"] == "incomplete"
    no_port = xml().replace(xml().split(b"<ports>")[1].split(b"</ports>")[0], b"")
    assert nmap.parse_xml(no_port, targets=["127.0.0.1"], ports=[22])["coverage"] == "incomplete"


@pytest.mark.parametrize("declaration", [
    '<!DOCTYPE nmaprun SYSTEM "https://outside.example.test/evil.dtd">',
    '<!DOCTYPE nmaprun [<!ENTITY bomb "boom">]>',
    '<!DOCTYPE nmaprun [<!ENTITY secret SYSTEM "file:///synthetic-secret">]>',
    '<!DOCTYPE nmaprun>\n<!DOCTYPE nmaprun>',
    '<!-- <!DOCTYPE nmaprun> -->',
], ids=["external-http", "internal-entity", "external-file", "duplicate-doctype", "comment-doctype"])
def test_xml_dtd_attacks_rejected_before_parser(monkeypatch, declaration):
    data = xml().replace(b"<!DOCTYPE nmaprun>", declaration.encode())
    monkeypatch.setattr(nmap.expat, "ParserCreate", lambda *a, **k: pytest.fail("preflight must reject DTD"))
    with pytest.raises(AutomationError, match="declaration"):
        nmap.parse_xml(data, targets=["127.0.0.1"], ports=[22])


@pytest.mark.parametrize("data", [b"\xff\xfe" + xml().decode().encode("utf-16-le"), b"\x00" + xml(),
    xml().replace(b'<host>', b'<host value="' + b"x" * 40000 + b'">')], ids=["utf16", "nul", "large-token"])
def test_encoding_and_large_tokens_fail_before_parser(monkeypatch, data):
    monkeypatch.setattr(nmap.expat, "ParserCreate", lambda *a, **k: pytest.fail("preflight must bound bytes/tokens"))
    with pytest.raises(AutomationError):
        nmap.parse_xml(data, targets=["127.0.0.1"], ports=[22])


@pytest.mark.parametrize("data", [
    xml().replace(b"<host>", b"<host>" + b"<x>" * 20).replace(b"</host>", b"</x>" * 20 + b"</host>"),
    xml().replace(b"<host>", b"<host " + b" ".join(b'a' + str(i).encode() + b'="v"' for i in range(40)) + b">"),
    xml().replace(b"</cpe>", b"x" * 8200 + b"</cpe>"),
    xml().replace(b"<host>", b'<?xml-stylesheet href="https://outside.example.test/style"?><host>'),
    xml(address="127.0.0.2"), xml().replace(b'portid="22"', b'portid="443"'),
    xml().replace(b'conf="10"', b'conf="99"'), xml().replace(b'protocol="tcp"', b'protocol="udp"'),
    xml().replace(b'<state state="open"/>', b'<state state="open"/><state state="open"/>'),
    xml().replace(b'<finished exit="success"/>', b'<finished exit="error"/>'),
    xml(total=2), xml()[:-20],
    xml().replace(b'<runstats>', b'<untrusted><runstats>').replace(b'</runstats>', b'</runstats></untrusted>'),
    xml().replace(b'addrtype="ipv4"', b'addrtype="ipv6"'),
], ids=["deep", "many-attributes", "large-text", "stylesheet", "wrong-address", "wrong-port", "bad-confidence", "udp", "duplicate-state", "failed-run", "wrong-count", "truncated", "nested-completion", "wrong-address-family"])
def test_xml_structure_scope_and_completion_attacks(data):
    with pytest.raises(AutomationError):
        nmap.parse_xml(data, targets=["127.0.0.1"], ports=[22])


def test_ipv6_fixed_command_and_sanitized_environment(tmp_path, monkeypatch):
    candidate = job()
    candidate.update(targets=["127.0.0.1", "::1"], allowlist=["127.0.0.1", "::1"])
    monkeypatch.setattr(nmap, "executable", lambda name: "/trusted/nmap")
    monkeypatch.setattr(nmap, "_data_directory", lambda binary: Path("/trusted/nmap-data"))
    seen = []
    def fake_run(command, **settings):
        seen.append(command)
        assert {"--unprivileged", "-sT", "-sV", "--version-light", "--open", "-n", "-Pn", "--no-stylesheet", "--noninteractive", "--servicedb", "--versiondb"} <= set(command)
        assert command[command.index("--servicedb") + 1].endswith("nmap-services")
        assert command[command.index("--versiondb") + 1].endswith("nmap-service-probes")
        assert not {"-A", "-O", "-sC", "--script", "--allports", "--webxml"} & set(command)
        assert settings["limit"] == nmap.MAX_XML_BYTES and 1 <= settings["timeout"] <= 120
        assert len(command) <= 64
        assert settings["environment"] == {name: str(tmp_path) for name in ("HOME", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA")}
        address = command[-1]
        assert ("-6" in command) == (address == "::1")
        return 0, xml(address=address)
    monkeypatch.setattr(nmap, "run", fake_run)
    result = nmap.run_discovery(candidate, scratch=tmp_path)
    assert result["coverage"] == "complete" and len(result["observations"]) == 2
    assert len(seen) == 2
    with pytest.raises(AutomationError):
        nmap.run_discovery(dict(candidate, args=["--script=all"]), scratch=tmp_path)


def test_many_targets_fit_fixed_argv_and_share_total_deadline(tmp_path, monkeypatch):
    candidate = job()
    candidate.update(targets=["127.0.0.0/26"], allowlist=["127.0.0.0/26"])
    monkeypatch.setattr(nmap, "executable", lambda name: "/trusted/nmap")
    monkeypatch.setattr(nmap, "_data_directory", lambda binary: Path("/trusted/nmap-data"))
    monkeypatch.setattr(nmap, "parse_xml", lambda output, **bounds: dict(observations=[], observed_targets=list(bounds["targets"]), backend_version="synthetic", coverage="complete"))
    clock = iter((10.0, 11.0, 80.0))
    monkeypatch.setattr(nmap.time, "monotonic", lambda: next(clock))
    calls = []
    def fake_run(command, **settings):
        assert len(command) <= 64
        calls.append(settings["timeout"])
        return 0, b"synthetic"
    monkeypatch.setattr(nmap, "run", fake_run)
    assert nmap.run_discovery(candidate, scratch=tmp_path)["coverage"] == "complete"
    assert calls == [119.0, 50.0]


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_existing_real_user_fallback_fails_without_reading_contents(tmp_path, monkeypatch, kind):
    fallback = tmp_path / "synthetic-config-fallback"
    if kind == "directory":
        fallback.mkdir()
    else:
        fallback.write_text("synthetic data that must never be opened")
    monkeypatch.setattr(Path, "read_bytes", lambda *a: pytest.fail("fallback contents must not be read"))
    monkeypatch.setattr(Path, "iterdir", lambda *a: pytest.fail("fallback contents must not be enumerated"))
    monkeypatch.setattr(nmap, "executable", lambda *a: pytest.fail("existing fallback must fail before backend"))
    with pytest.raises(AutomationError, match="nmap_user_configuration_present"):
        nmap.run_discovery(job(), scratch=tmp_path)


def test_discovery_history_changes_and_failure_preserve_good_state(tmp_path, monkeypatch):
    settings = config(tmp_path)
    settings.inventory_path.write_text("synthetic canonical inventory remains unchanged")
    payload = nmap.parse_xml(xml(), targets=["127.0.0.1"], ports=[22])
    def observed(job, **kwargs):
        return dict(observations=payload["observations"], backend_versions=[payload["backend_version"]], coverage=payload["coverage"])
    monkeypatch.setattr(nmap, "run_discovery", observed)
    first = nmap.run_jobs(settings)["synthetic-services"]
    assert first["status"] == "success" and first["changed"] and first["added"] == 1
    folder = settings.state_dir / "discovery" / "synthetic-services"
    assert not nmap.run_jobs(settings)["synthetic-services"]["changed"]
    assert len(list((folder / "history").glob("*.json"))) == 1
    payload = nmap.parse_xml(xml(version="2.0"), targets=["127.0.0.1"], ports=[22])
    changed = nmap.run_jobs(settings)["synthetic-services"]
    assert changed["changed"] and changed["service_changes"] == 1
    assert len(list((folder / "history").glob("*.json"))) == 2
    before = (folder / "current.json").read_bytes()
    payload["coverage"] = "incomplete"
    failed = nmap.run_jobs(settings)["synthetic-services"]
    assert failed["status"] == "incomplete" and not failed["changed"]
    assert (folder / "current.json").read_bytes() == before
    assert settings.inventory_path.read_text() == "synthetic canonical inventory remains unchanged"


def test_corrupt_history_fails_before_new_process(tmp_path, monkeypatch):
    settings = config(tmp_path)
    parsed = nmap.parse_xml(xml(), targets=["127.0.0.1"], ports=[22])
    monkeypatch.setattr(nmap, "run_discovery", lambda *a, **k: dict(observations=parsed["observations"], backend_versions=["synthetic"], coverage="complete"))
    assert nmap.run_jobs(settings)["synthetic-services"]["status"] == "success"
    folder = settings.state_dir / "discovery" / "synthetic-services"
    next((folder / "history").glob("*.json")).write_text("corrupt synthetic history")
    monkeypatch.setattr(nmap, "run_discovery", lambda *a, **k: pytest.fail("corrupt state cannot be reset"))
    assert nmap.run_jobs(settings)["synthetic-services"]["status"] == "failed"


def test_disabled_job_never_runs_or_creates_state(tmp_path, monkeypatch):
    candidate = job()
    candidate.pop("enabled")
    monkeypatch.setattr(nmap, "run_discovery", lambda *a, **k: pytest.fail("disabled must not scan"))
    result = nmap.run_jobs(config(tmp_path, (candidate,)))[candidate["id"]]
    assert result == {"status": "disabled", "changed": False}
    assert not (tmp_path / "state").exists()
