"""Bounded authorized Nmap observations; no canonical inventory promotion."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from xml.parsers import expat

from cvebeacon_extensions.contract import ExtensionError, json_bytes, timestamp

from ..common import (AutomationError, digest, directory, identifier, lock, now, read_json,
    regular, write_json)
from ..config import boolean, number
from ..process import run
from ..remote.executables import executable

MAX_TARGETS = 256
MAX_PORTS = 128
MAX_XML_BYTES = 16 * 1024 * 1024
MAX_ELEMENTS = 150000
MAX_DEPTH = 16
MAX_TOKEN = 32768
MAX_FIELD = 1024
JOB_KEYS = {"id", "enabled", "targets", "allowlist", "ports", "allow_public", "timeout"}
METADATA = {ipaddress.ip_address(value) for value in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254")}
PRIVATE = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
LOCATIONS = {
    "nmaprun": ("nmaprun",), "host": ("nmaprun", "host"),
    "status": ("nmaprun", "host", "status"), "address": ("nmaprun", "host", "address"),
    "hostnames": ("nmaprun", "host", "hostnames"), "hostname": ("nmaprun", "host", "hostnames", "hostname"),
    "ports": ("nmaprun", "host", "ports"), "port": ("nmaprun", "host", "ports", "port"),
    "state": ("nmaprun", "host", "ports", "port", "state"), "service": ("nmaprun", "host", "ports", "port", "service"),
    "cpe": ("nmaprun", "host", "ports", "port", "service", "cpe"),
    "runstats": ("nmaprun", "runstats"), "finished": ("nmaprun", "runstats", "finished"), "hosts": ("nmaprun", "runstats", "hosts"),
}


def _address(address, allow_public):
    effective = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
    if (effective in METADATA or effective.is_unspecified or effective.is_multicast or effective.is_link_local
        or effective.is_reserved and not effective.is_loopback or effective == ipaddress.ip_address("255.255.255.255")):
        raise AutomationError("discovery_target_forbidden")
    private = effective.is_loopback or any(effective in network for network in PRIVATE if effective.version == network.version)
    if not private and (not allow_public or not effective.is_global):
        raise AutomationError("discovery_public_target_not_authorized")
    return str(address)


def _targets(values, allow_public):
    if not isinstance(values, list) or not 0 < len(values) <= MAX_TARGETS:
        raise AutomationError("invalid_discovery_targets")
    result = set()
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 64 or "%" in value:
            raise AutomationError("invalid_discovery_target")
        try:
            if "/" in value:
                network = ipaddress.ip_network(value, strict=True)
                if network.num_addresses > MAX_TARGETS:
                    raise AutomationError("discovery_target_limit")
                addresses = network.hosts()
            else:
                addresses = (ipaddress.ip_address(value),)
            for address in addresses:
                result.add(_address(address, allow_public))
                if len(result) > MAX_TARGETS:
                    raise AutomationError("discovery_target_limit")
        except ValueError:
            raise AutomationError("invalid_discovery_target") from None
    if not result:
        raise AutomationError("invalid_discovery_targets")
    return tuple(sorted(result, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))))


def validate_jobs(jobs) -> tuple[dict, ...]:
    if not isinstance(jobs, tuple) or len(jobs) > 16:
        raise AutomationError("invalid_discovery_jobs")
    result, names = [], set()
    for job in jobs:
        if not isinstance(job, dict) or set(job) - JOB_KEYS:
            raise AutomationError("invalid_discovery_job")
        name = identifier(job.get("id"), "discovery_id")
        if name.casefold() in names:
            raise AutomationError("duplicate_discovery_id")
        names.add(name.casefold())
        allow_public = boolean(job.get("allow_public", False))
        allowed = _targets(job.get("allowlist"), allow_public)
        targets = _targets(job.get("targets"), allow_public)
        if not set(targets) <= set(allowed):
            raise AutomationError("discovery_target_not_allowlisted")
        ports = job.get("ports", [22, 80, 443])
        if not isinstance(ports, list) or not 0 < len(ports) <= MAX_PORTS:
            raise AutomationError("invalid_discovery_ports")
        ports = tuple(sorted({number(port, 1, 65535) for port in ports}))
        result.append(dict(id=name, enabled=boolean(job.get("enabled", False)), targets=targets,
            allowlist=allowed, ports=ports, allow_public=allow_public, timeout=number(job.get("timeout", 120), 5, 300)))
    return tuple(result)


def _text(value, limit=MAX_FIELD):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise AutomationError("discovery_field_invalid")
    return value


def _preflight(data):
    if not isinstance(data, bytes) or len(data) > MAX_XML_BYTES:
        raise AutomationError("discovery_xml_limit")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        raise AutomationError("discovery_xml_encoding") from None
    if "\x00" in text or "<!ENTITY" in text:
        raise AutomationError("discovery_xml_declaration")
    if "<!DOCTYPE" in text:
        if text.count("<!DOCTYPE") != 1 or "<!DOCTYPE nmaprun>" not in text:
            raise AutomationError("discovery_xml_declaration")
        prefix = text[:text.index("<!DOCTYPE")]
        if re.fullmatch(r"\ufeff?\s*(?:<\?xml\b[^?]{0,256}\?>\s*)?", prefix) is None:
            raise AutomationError("discovery_xml_declaration")
        text = text.replace("<!DOCTYPE nmaprun>", "", 1)
    # Bound unfinished tags/attribute tokens before Expat can buffer them.
    beginning, quote, comment = None, None, False
    for index, char in enumerate(text):
        if beginning is None:
            if char == "<":
                beginning, comment = index, text.startswith("<!--", index)
        elif index - beginning > MAX_TOKEN:
            raise AutomationError("discovery_xml_token_limit")
        elif comment:
            if char == ">" and text[index - 2:index] == "--":
                beginning, comment = None, False
        elif quote:
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == ">":
            beginning = None
    return text


def parse_xml(data: bytes, *, targets, ports) -> dict:
    """Event parser bounds structures before allocating a result tree."""
    text = _preflight(data)
    allowed_targets, allowed_ports = set(targets), set(ports)
    stack, text_lengths = [], []
    rows, hosts, keys = [], set(), set()
    empty_hosts = set()
    current_host, current_port, cpe_parts = None, None, []
    count, finished, totals, backend_version = 0, False, False, ""
    parser = expat.ParserCreate(encoding="UTF-8")

    def reject(*args):
        raise AutomationError("discovery_xml_declaration")

    def declaration(version, encoding, standalone):
        if version != "1.0" or encoding is not None and encoding.upper() not in {"UTF-8", "UTF8"}:
            raise AutomationError("discovery_xml_encoding")

    def start(name, attributes):
        nonlocal count, current_host, current_port, cpe_parts, finished, totals, backend_version
        count += 1
        if count > MAX_ELEMENTS or len(stack) >= MAX_DEPTH or len(attributes) > 32 or len(name) > 64:
            raise AutomationError("discovery_xml_structure_limit")
        if any(len(key) > 64 or len(value) > 16384 for key, value in attributes.items()):
            raise AutomationError("discovery_xml_attribute_limit")
        parent = stack[-1] if stack else None
        stack.append(name)
        text_lengths.append(0)
        if name in LOCATIONS and tuple(stack) != LOCATIONS[name]:
            raise AutomationError("discovery_xml_structure")
        if parent is None:
            if name != "nmaprun" or attributes.get("scanner") != "nmap" or attributes.get("xmloutputversion") != "1.05":
                raise AutomationError("discovery_xml_protocol")
            backend_version = _text(attributes.get("version", ""), 128)
            if not backend_version:
                raise AutomationError("discovery_xml_protocol")
        elif name == "host" and parent == "nmaprun":
            if current_host is not None or len(hosts) >= MAX_TARGETS or attributes.get("timedout") == "true":
                raise AutomationError("discovery_incomplete")
            current_host = dict(addresses=[], hostnames=[], ports=[], status=None)
        elif name == "status" and parent == "host" and current_host is not None:
            if current_host["status"] is not None:
                raise AutomationError("discovery_xml_duplicate")
            current_host["status"] = attributes.get("state", "")
        elif name == "address" and parent == "host" and current_host is not None:
            if attributes.get("addrtype") in {"ipv4", "ipv6"}:
                try:
                    parsed_address = ipaddress.ip_address(attributes.get("addr", ""))
                    address = str(parsed_address)
                except ValueError:
                    raise AutomationError("discovery_xml_address") from None
                if attributes["addrtype"] != "ipv" + str(parsed_address.version) or address not in allowed_targets:
                    raise AutomationError("discovery_result_not_authorized")
                current_host["addresses"].append(address)
        elif name == "hostname" and parent == "hostnames" and current_host is not None:
            current_host["hostnames"].append(_text(attributes.get("name", ""), 253))
            if len(current_host["hostnames"]) > 8:
                raise AutomationError("discovery_xml_structure_limit")
        elif name == "port" and parent == "ports" and current_host is not None:
            if current_port is not None or len(current_host["ports"]) >= MAX_PORTS or attributes.get("protocol") != "tcp":
                raise AutomationError("discovery_xml_port")
            raw_port = attributes.get("portid", "")
            if not raw_port.isascii() or not raw_port.isdigit() or len(raw_port) > 5 or int(raw_port) not in allowed_ports:
                raise AutomationError("discovery_result_not_authorized")
            current_port = dict(protocol="tcp", port=int(raw_port), state=None, service="", product="", version="",
                extrainfo="", tunnel="", method="", confidence=None, cpes=[], _service_seen=False)
        elif name == "state" and parent == "port" and current_port is not None:
            if current_port["state"] is not None:
                raise AutomationError("discovery_xml_duplicate")
            current_port["state"] = _text(attributes.get("state", ""), 32)
        elif name == "service" and parent == "port" and current_port is not None:
            if current_port["_service_seen"]:
                raise AutomationError("discovery_xml_duplicate")
            current_port["_service_seen"] = True
            for field in ("product", "version", "extrainfo", "tunnel", "method"):
                current_port[field] = _text(attributes.get(field, ""))
            current_port["service"] = _text(attributes.get("name", ""))
            confidence = attributes.get("conf")
            if confidence is not None:
                if not confidence.isascii() or not confidence.isdigit() or not 1 <= len(confidence) <= 2 or not 0 <= int(confidence) <= 10:
                    raise AutomationError("discovery_field_invalid")
                current_port["confidence"] = int(confidence)
        elif name == "cpe" and parent == "service" and current_port is not None:
            cpe_parts = []
        elif name == "finished" and parent == "runstats":
            if finished or attributes.get("exit") != "success":
                raise AutomationError("discovery_incomplete")
            finished = True
        elif name == "hosts" and parent == "runstats":
            if totals:
                raise AutomationError("discovery_xml_duplicate")
            numbers = []
            for field in ("up", "down", "total"):
                value = attributes.get(field, "")
                if not value.isascii() or not value.isdigit() or len(value) > 3:
                    raise AutomationError("discovery_incomplete")
                numbers.append(int(value))
            if numbers[0] + numbers[1] != numbers[2] or numbers[2] != len(allowed_targets):
                raise AutomationError("discovery_incomplete")
            totals = True

    def content(value):
        if not stack:
            return
        text_lengths[-1] += len(value)
        if text_lengths[-1] > 8192:
            raise AutomationError("discovery_xml_text_limit")
        if stack[-1] == "cpe" and len(stack) > 1 and stack[-2] == "service" and current_port is not None:
            cpe_parts.append(value)

    def end(name):
        nonlocal current_host, current_port
        parent = stack[-2] if len(stack) > 1 else None
        if name == "cpe" and parent == "service" and current_port is not None:
            current_port["cpes"].append(_text("".join(cpe_parts)))
            if len(current_port["cpes"]) > 8:
                raise AutomationError("discovery_xml_structure_limit")
        elif name == "port" and parent == "ports" and current_port is not None:
            if current_port["state"] != "open":
                raise AutomationError("discovery_xml_port_state")
            current_port["cpes"] = sorted(set(current_port["cpes"]))
            current_port.pop("_service_seen")
            current_host["ports"].append(current_port)
            current_port = None
        elif name == "host" and parent == "nmaprun" and current_host is not None:
            if len(current_host["addresses"]) != 1 or current_host["status"] != "up":
                raise AutomationError("discovery_incomplete")
            address = current_host["addresses"][0]
            if address in hosts:
                raise AutomationError("discovery_xml_duplicate")
            hosts.add(address)
            if not current_host["ports"]:
                empty_hosts.add(address)
            for port in current_host["ports"]:
                key = (address, port["protocol"], port["port"])
                if key in keys:
                    raise AutomationError("discovery_xml_duplicate")
                keys.add(key)
                rows.append(dict(address=address, hostnames=sorted(set(current_host["hostnames"])), **port))
            current_host = None
        stack.pop()
        text_lengths.pop()

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = content
    parser.XmlDeclHandler = declaration
    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.NotationDeclHandler = reject
    parser.ProcessingInstructionHandler = reject
    try:
        for offset in range(0, len(text), 4096):
            parser.Parse(text[offset:offset + 4096], False)
        parser.Parse("", True)
    except expat.ExpatError:
        raise AutomationError("discovery_xml_invalid") from None
    if not finished or not totals:
        raise AutomationError("discovery_incomplete")
    rows.sort(key=lambda row: (ipaddress.ip_address(row["address"]).version, int(ipaddress.ip_address(row["address"])), row["port"]))
    return dict(version=1, observations=rows, observed_targets=sorted(hosts), backend_version=backend_version,
        coverage="complete" if hosts == allowed_targets and not empty_hosts else "incomplete")


def _data_directory(binary: str) -> Path:
    folder = Path(binary).parent
    candidates = [folder] if os.name == "nt" else [Path(os.path.abspath(folder / ".." / "share" / "nmap")), Path("/usr/share/nmap")]
    for candidate in candidates:
        try:
            info = candidate.lstat()
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                continue
            for name in ("scripts", "nselib", "nselib/data"):
                data_info = (candidate / name).lstat()
                if not stat.S_ISDIR(data_info.st_mode) or getattr(data_info, "st_file_attributes", 0) & 0x400:
                    raise AutomationError("nmap_trusted_data_unavailable")
            for file in ("nmap-services", "nmap-service-probes", "nse_main.lua", "scripts/script.db",
                         "nselib/stdnse.lua", "nselib/shortport.lua"):
                regular(candidate / file)
            return candidate
        except (OSError, AutomationError):
            continue
    raise AutomationError("nmap_trusted_data_unavailable")


def _user_data_directories() -> tuple[Path, ...]:
    """Match upstream real-user lookup; HOME overrides do not control it."""
    if os.name == "posix":
        import pwd
        try:
            return tuple(dict.fromkeys(Path(pwd.getpwuid(uid).pw_dir) / ".nmap" for uid in (os.getuid(), os.geteuid())))
        except KeyError:
            raise AutomationError("nmap_user_config_preflight_failed") from None
    if os.name == "nt":
        import ctypes
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        locate = shell.SHGetFolderPathW
        locate.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p)
        locate.restype = ctypes.c_long
        folder = ctypes.create_unicode_buffer(260)
        if locate(None, 0x1A, None, 0, folder) != 0 or not Path(folder.value).is_absolute():
            raise AutomationError("nmap_user_config_preflight_failed")
        return (Path(folder.value) / "nmap",)
    raise AutomationError("nmap_user_config_preflight_failed")


def _reject_user_data():
    for folder in _user_data_directories():
        try:
            folder.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise AutomationError("nmap_user_config_preflight_failed") from None
        raise AutomationError("nmap_user_configuration_present")


def run_discovery(job: dict, *, scratch: Path) -> dict:
    """Validate even direct helper calls; no configurable argv or implicit targets."""
    if not isinstance(job, dict):
        raise AutomationError("invalid_discovery_job")
    candidate = dict(job)
    for name in ("targets", "allowlist", "ports"):
        if isinstance(candidate.get(name), tuple):
            candidate[name] = list(candidate[name])
    job = validate_jobs((candidate,))[0]
    if not job["enabled"]:
        raise AutomationError("discovery_disabled")
    _reject_user_data()
    binary = executable("nmap")
    data_dir = _data_directory(binary)
    observations, versions = [], set()
    observed_targets = set()
    coverage = "complete"
    deadline = time.monotonic() + job["timeout"]
    for family in (4, 6):
        targets = [target for target in job["targets"] if ipaddress.ip_address(target).version == family]
        # Fixed target batches also fit the shared process helper's argv bound.
        for offset in range(0, len(targets), 32):
            batch = targets[offset:offset + 32]
            remaining = deadline - time.monotonic()
            if remaining < 1:
                raise AutomationError("process_timeout")
            command = [binary, "--unprivileged", "-n", "-Pn", "-sT", "-sV", "--version-light", "--open",
                "--no-stylesheet", "--noninteractive", "--datadir", str(data_dir), "-oX", "-",
                "--servicedb", str(data_dir / "nmap-services"), "--versiondb", str(data_dir / "nmap-service-probes"),
                "--host-timeout", str(min(60, job["timeout"])) + "s", "--max-retries", "1", "--max-parallelism", "8",
                "-p", ",".join(str(port) for port in job["ports"])]
            if family == 6:
                command.append("-6")
            command.extend(batch)
            code, output = run(command, timeout=remaining, limit=MAX_XML_BYTES, cwd=scratch,
                environment={name: str(scratch) for name in ("HOME", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA")})
            if code != 0:
                raise AutomationError("discovery_process_failed")
            parsed = parse_xml(output, targets=batch, ports=job["ports"])
            observations.extend(parsed["observations"])
            observed_targets.update(parsed["observed_targets"])
            versions.add(parsed["backend_version"])
            if parsed["coverage"] != "complete":
                coverage = "incomplete"
    return dict(observations=observations, observed_targets=sorted(observed_targets), backend_versions=sorted(versions), coverage=coverage)


def _identity(state):
    if not isinstance(state, dict) or type(state.get("version")) is not int or state["version"] != 1 or not isinstance(state.get("observations"), list) or not isinstance(state.get("scope"), dict):
        raise AutomationError("discovery_state_invalid")
    scope = state["scope"]
    if set(scope) != {"targets", "ports"} or not isinstance(scope["targets"], list) or not isinstance(scope["ports"], list):
        raise AutomationError("discovery_state_invalid")
    allowed_targets = _targets(scope["targets"], True)
    allowed_ports = {number(port, 1, 65535) for port in scope["ports"]}
    if not 0 < len(scope["ports"]) <= MAX_PORTS or len(state["observations"]) > MAX_TARGETS * MAX_PORTS:
        raise AutomationError("discovery_state_invalid")
    fields = {"address", "hostnames", "protocol", "port", "state", "service", "product", "version", "extrainfo", "tunnel", "method", "confidence", "cpes"}
    seen = set()
    for row in state["observations"]:
        if not isinstance(row, dict) or set(row) != fields or row["address"] not in allowed_targets or row["protocol"] != "tcp" or row["state"] != "open" or type(row["port"]) is not int or row["port"] not in allowed_ports:
            raise AutomationError("discovery_state_invalid")
        if row["confidence"] is not None and (type(row["confidence"]) is not int or not 0 <= row["confidence"] <= 10):
            raise AutomationError("discovery_state_invalid")
        for name in ("service", "product", "version", "extrainfo", "tunnel", "method"):
            _text(row[name])
        for name, limit in (("hostnames", 253), ("cpes", MAX_FIELD)):
            if not isinstance(row[name], list) or len(row[name]) > 8:
                raise AutomationError("discovery_state_invalid")
            for value in row[name]:
                _text(value, limit)
        key = row["address"], row["protocol"], row["port"]
        if key in seen:
            raise AutomationError("discovery_state_invalid")
        seen.add(key)
    return dict(scope=scope, observations=state["observations"])


def _previous(folder: Path):
    pointer = folder / "current.json"
    if not pointer.exists() and not pointer.is_symlink():
        return None
    state = read_json(pointer, MAX_XML_BYTES)
    identity = _identity(state)
    fingerprint = digest(json_bytes(identity))
    if fingerprint != state.get("fingerprint"):
        raise AutomationError("discovery_state_invalid")
    timestamp(state.get("observed_at"))
    history = read_json(folder / "history" / (fingerprint + ".json"), MAX_XML_BYTES)
    if _identity(history) != identity or history.get("fingerprint") != fingerprint:
        raise AutomationError("discovery_state_invalid")
    return state


def _changes(previous, observations):
    def index(rows):
        return {(row["address"], row["protocol"], row["port"]): row for row in rows}
    before = index(previous["observations"]) if previous else {}
    after = index(observations)
    return dict(added=len(after.keys() - before.keys()), not_observed=len(before.keys() - after.keys()),
        service_changes=sum(before[key] != after[key] for key in before.keys() & after.keys()))


def run_jobs(config) -> dict:
    jobs = validate_jobs(config.discovery)
    results = {}
    for job in jobs:
        if not job["enabled"]:
            results[job["id"]] = dict(status="disabled", changed=False)
            continue
        previous = None
        try:
            folder = directory(directory(config.state_dir / "discovery") / job["id"])
            with lock(folder / "discovery.lock"):
                previous = _previous(folder)
                observed_at = now()
                with tempfile.TemporaryDirectory(prefix=".nmap-", dir=folder) as temporary:
                    observed = run_discovery(job, scratch=Path(temporary))
                if observed["coverage"] != "complete":
                    raise AutomationError("discovery_incomplete")
                scope = dict(targets=list(job["targets"]), ports=list(job["ports"]))
                identity = dict(scope=scope, observations=observed["observations"])
                fingerprint = digest(json_bytes(identity))
                state = dict(version=1, fingerprint=fingerprint, observed_at=observed_at, **identity,
                    backend_versions=observed["backend_versions"], trust="discovery-observation")
                if len(json_bytes(state)) > MAX_XML_BYTES:
                    raise AutomationError("discovery_state_limit")
                changes = _changes(previous, observed["observations"])
                history = directory(folder / "history") / (fingerprint + ".json")
                if history.exists() or history.is_symlink():
                    if _identity(read_json(history, MAX_XML_BYTES)) != identity:
                        raise AutomationError("discovery_history_conflict")
                else:
                    write_json(history, state)
                write_json(folder / "current.json", state)
                results[job["id"]] = dict(status="success", changed=previous is None or previous["fingerprint"] != fingerprint,
                    scope_changed=previous is not None and previous["scope"] != scope, observations=len(observed["observations"]),
                    last_success=observed_at, **changes)
        except (AutomationError, ExtensionError, OSError, ValueError, KeyError, TypeError) as exc:
            results[job["id"]] = dict(status="incomplete" if isinstance(exc, AutomationError) and exc.category == "discovery_incomplete" else "failed",
                error=exc.category if isinstance(exc, AutomationError) else "discovery_state_or_io_failure", changed=False)
            if previous:
                results[job["id"]]["last_success"] = previous["observed_at"]
    return results
