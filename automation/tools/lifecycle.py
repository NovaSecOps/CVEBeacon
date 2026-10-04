"""Offline synthetic lifecycle using real product APIs and explicit fake transports.

Run from a checkout: python automation/tools/lifecycle.py --output NEW_DIRECTORY
No sockets, SSH commands, Nmap scans or external messages are permitted here.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import sqlite3
import sys
from unittest.mock import patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
for package in ("src", "extensions/src", "automation/src"):
    sys.path.insert(0, str(ROOT / package))

from cvebeacon.config import load_config as load_core
from cvebeacon.engine import QueryEngine
from cvebeacon.inventory import load_inventory
from cvebeacon.models import Applicability
from cvebeacon.sources.nvd import CPE_URL, CVE_URL
from cvebeacon.sources.osv import BASE_URL
from cvebeacon.state import StateStore
from cvebeacon_extensions import contract
from cvebeacon_extensions.contract import json_bytes, manifest_path, read_snapshot, write_snapshot
from cvebeacon_automation import common, pipeline, staging
from cvebeacon_automation.common import AutomationError, Secret, digest
from cvebeacon_automation.config import Config, Source
from cvebeacon_automation.discovery import nmap
from cvebeacon_automation.health import status
from cvebeacon_automation.http import Response
from cvebeacon_automation.ingest.protocol import encode_envelope
from cvebeacon_automation.ingest.server import IngestConfig, Receiver, UploadSource
from cvebeacon_automation.notifications import service
from cvebeacon_automation.process import clean_environment
from cvebeacon_automation.registry import acquire, client
from cvebeacon_automation.remote import ssh
from cvebeacon_automation.remote.probe import REMOTE_COMMAND

PROVIDERS = ("telegram", "discord", "slack", "matrix")
ENVIRONMENT = {
    "LIFECYCLE_UPLOAD_TOKEN": "SYNTHETIC_UPLOAD_CANARY_ONLY_00000000000000000000",
    "LIFECYCLE_REGISTRY_TOKEN": "SYNTHETIC_REGISTRY_CANARY_ONLY_000000000",
    "LIFECYCLE_TELEGRAM_TOKEN": "1234:SYNTHETIC_TELEGRAM_CANARY_ONLY_0000000",
    "LIFECYCLE_DISCORD_HOOK": "https://discord.com/api/webhooks/1234/SYNTHETIC_DISCORD_CANARY_ONLY_0000000",
    "LIFECYCLE_SLACK_HOOK": "https://hooks.slack.com/services/TFAKE/BFAKE/SYNTHETICCANARYONLY000000000",
    "LIFECYCLE_MATRIX_TOKEN": "SYNTHETIC_MATRIX_CANARY_ONLY_000000000",
}
ADVISORY = "LIFECYCLE-SYNTHETIC-2099-1"
CVE = "CVE-2099-0001"


class Clock:
    """No real sleeping; observation/replay/backoff time is fixture-controlled."""

    def __init__(self):
        self.value = datetime(2026, 10, 4, 9, tzinfo=timezone.utc)

    def wall(self):
        return self.value

    def now(self):
        return self.value.timestamp()

    def advance(self, seconds):
        assert seconds >= 0
        self.value += timedelta(seconds=seconds)


class CoreHTTPFixture:
    """Synthetic OSV discovery/advisory and NVD CVE enrichment payloads only."""

    def __init__(self):
        self.score = 7.5
        self.calls = []

    def post_json(self, url, *, source, json):
        assert url == BASE_URL + "/querybatch" and source == "osv"
        self.calls.append(("POST", "osv-querybatch"))
        assert all(not any(secret in str(query) for secret in ENVIRONMENT.values()) for query in json["queries"])
        return {"results": [{"vulns": [{"id": ADVISORY}]} if query["package"]["purl"] == "pkg:pypi/lifecycle-upload-example" else {}
                            for query in json["queries"]]}

    def get_json(self, url, *, source, **options):
        assert not options.get("headers"), "Core fixture must receive no registry/notification/API credentials"
        self.calls.append(("GET", source))
        if source == "osv":
            assert url == BASE_URL + "/vulns/" + ADVISORY
            return dict(id=ADVISORY, schema_version="1.7.3", modified="2026-10-04T09:00:00Z", aliases=[CVE],
                summary="SYNTHETIC lifecycle advisory; no real vulnerability assertion",
                affected=[dict(package=dict(ecosystem="PyPI", name="lifecycle-upload-example"), versions=["1.0.0"])])
        assert source == "nvd"
        if url == CPE_URL:
            # Synthetic Linux OS identity remains unknown; no guessed CPE.
            return dict(startIndex=0, resultsPerPage=0, totalResults=0, products=[])
        assert url == CVE_URL and options["params"]["cveId"] == CVE
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:" + ("N/A:N" if self.score == 7.5 else "H/A:H")
        payload = dict(id=CVE, published="2026-10-04T09:00:00Z", lastModified="2026-10-04T09:00:00Z", vulnStatus="Analyzed",
                       descriptions=[dict(lang="en", value="SYNTHETIC CVSS enrichment fixture")],
                       metrics=dict(cvssMetricV31=[dict(cvssData=dict(version="3.1", baseScore=self.score, vectorString=vector))]))
        return dict(startIndex=0, resultsPerPage=1, totalResults=1, vulnerabilities=[dict(cve=payload)])


class RegistryFixture:
    """Finite exact-digest OCI responses; no actual HTTPS or registry server."""

    url = "https://registry.example.invalid"
    repo = "team/application"

    def __init__(self):
        self.calls = []
        self.missing = False
        self.empty = b"{}"
        sbom = dict(bomFormat="CycloneDX", specVersion="1.6", components=[dict(type="library", name="lifecycle-sbom-example",
            version="1.0.0", purl="pkg:pypi/lifecycle-sbom-example@1.0.0")])
        self.sbom = json_bytes(sbom)
        image_config = json_bytes(dict(architecture="amd64", os="linux"))
        self.target = json_bytes(dict(schemaVersion=2, mediaType=client.IMAGE,
            config=self.descriptor(image_config, "application/vnd.oci.image.config.v1+json"), layers=[]))
        self.subject = self.descriptor(self.target, client.IMAGE)
        self.reference = "registry.example.invalid/" + self.repo + "@" + self.subject["digest"]
        self.artifact = json_bytes(dict(schemaVersion=2, mediaType=client.IMAGE, artifactType="application/vnd.cyclonedx+json",
            config=self.descriptor(self.empty, client.EMPTY), subject=self.subject,
            layers=[self.descriptor(self.sbom, "application/vnd.cyclonedx+json")]))
        self.referrer = self.descriptor(self.artifact, client.IMAGE, artifactType="application/vnd.cyclonedx+json")
        self.routes = {
            f"/v2/{self.repo}/manifests/{self.subject['digest']}": Response(200, {"content-type": client.IMAGE}, self.target),
            f"/v2/{self.repo}/manifests/{self.referrer['digest']}": Response(200, {"content-type": client.IMAGE}, self.artifact),
            f"/v2/{self.repo}/blobs/sha256:{digest(self.empty)}": Response(200, {}, self.empty),
            f"/v2/{self.repo}/blobs/sha256:{digest(self.sbom)}": Response(200, {}, self.sbom),
        }

    @staticmethod
    def descriptor(raw, media, **extra):
        return dict(mediaType=media, digest="sha256:" + digest(raw), size=len(raw), **extra)

    def request(self, method, url, *, headers=None, body=b""):
        parsed = urlsplit(url)
        assert method == "GET" and body == b"" and parsed.netloc == "registry.example.invalid" and parsed.scheme == "https"
        assert headers["Authorization"] == "Bearer " + ENVIRONMENT["LIFECYCLE_REGISTRY_TOKEN"]
        self.calls.append(parsed.path)
        if parsed.path == f"/v2/{self.repo}/referrers/{self.subject['digest']}":
            return Response(200, {"content-type": client.INDEX}, json_bytes(dict(schemaVersion=2, mediaType=client.INDEX,
                manifests=[] if self.missing else [self.referrer])))
        assert parsed.path in self.routes, "fixture refuses arbitrary outbound paths"
        return self.routes[parsed.path]


class NotificationFixture:
    """Real adapter wire methods/payloads, synthetic acceptance/rate-limit replies."""

    def __init__(self):
        self.calls = []
        self.slack_outage = False

    def factory(self, url, **bounds):
        return self

    def request(self, method, url, *, headers=None, body=b""):
        host = urlsplit(url).hostname
        provider = {"api.telegram.org": "telegram", "discord.com": "discord", "hooks.slack.com": "slack",
                    "matrix.example.invalid": "matrix"}[host]
        self.calls.append(dict(provider=provider, method=method, body=body))
        if method == "GET":
            assert provider == "matrix" and url.endswith("/state/m.room.encryption")
            return Response(404, {}, b'{"errcode":"M_NOT_FOUND"}')
        assert method == ("PUT" if provider == "matrix" else "POST")
        payload = json.loads(body)
        content = payload.get("text", payload.get("content", payload.get("body", "")))
        assert content and not any(secret in content for secret in ENVIRONMENT.values())
        if provider == "slack" and self.slack_outage:
            return Response(429, {"retry-after": "120"}, b"rate_limited")
        replies = {"telegram": b'{"ok":true,"result":{"message_id":1}}', "discord": b'{"id":"1234"}',
                   "slack": b"ok", "matrix": b'{"event_id":"$synthetic-lifecycle"}'}
        return Response(200, {}, replies[provider])

    def sends(self):
        return [row for row in self.calls if row["method"] != "GET"]


def notification_channels():
    return (
        dict(id="telegram", provider="telegram", token={"env": "LIFECYCLE_TELEGRAM_TOKEN"}, chat_id="-1001234"),
        dict(id="discord", provider="discord", webhook={"env": "LIFECYCLE_DISCORD_HOOK"}),
        dict(id="slack", provider="slack", webhook={"env": "LIFECYCLE_SLACK_HOOK"}),
        dict(id="matrix", provider="matrix", token={"env": "LIFECYCLE_MATRIX_TOKEN"},
             homeserver="https://matrix.example.invalid", room_id="!synthetic:example.invalid"),
    )


def read_sql(filename, query):
    """Read-only evidence query; all Core writes go through StateStore APIs."""
    connection = sqlite3.connect(filename.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def discovery_xml(version):
    assert version in {"1.0", "2.0"}
    return (f'<nmaprun scanner="nmap" version="synthetic-1" xmloutputversion="1.05"><host><status state="up"/>'
        '<address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/>'
        f'<service name="http" product="Synthetic banner" version="{version}" method="probed" conf="10">'
        f'<cpe>cpe:/a:synthetic:banner:{version}</cpe></service></port></ports></host>'
        '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>').encode("ascii")


def run_demo(output: Path) -> dict:
    """Write only to a new/empty caller-selected tree; return asserted JSON counts."""
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise AutomationError("lifecycle_output_must_be_empty")
    clock, registry_wire, notify_wire, core_wire = Clock(), RegistryFixture(), NotificationFixture(), CoreHTTPFixture()
    offline_attempts, ssh_calls, core_scans = [], [], []
    discovery_version = ["1.0"]
    summary = dict(contract="cvebeacon.automation-lifecycle.v1", authority="offline-synthetic-fixtures", external_network_calls=0,
                   real_credentials=False, operational_messages="asserted-separately", phases={})

    def offline(*args, **kwargs):
        offline_attempts.append("blocked-socket-attempt")
        raise AssertionError("lifecycle demonstration prohibits every socket operation")

    class FixtureDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock.wall() if tz is not None else clock.wall().replace(tzinfo=None)

    with ExitStack() as boundaries:
        socket_type = socket.socket
        for name in ("connect", "connect_ex", "bind", "listen", "send", "sendall", "sendto"):
            boundaries.enter_context(patch.object(socket_type, name, offline))
        for name in ("socket", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
            boundaries.enter_context(patch.object(socket, name, offline))
        boundaries.enter_context(patch.dict("os.environ", ENVIRONMENT))
        boundaries.enter_context(patch.object(contract, "utc_now", clock.wall))
        for module in (common, staging, acquire):
            boundaries.enter_context(patch.object(module, "datetime", FixtureDatetime))

        core_config = output / "core.toml"
        core_config.write_text('[inventory]\npath="merged.json"\nformat="json"\n[state]\ndatabase="core.db"\n'
            '[sources]\nosv_enabled=true\nnvd_enabled=true\ncve_enabled=false\neuvd_enabled=false\n'
            'cisa_kev_enabled=false\neu_kev_enabled=false\nepss_enabled=false\nnvd_api_key_env="LIFECYCLE_UNUSED_NVD_API_KEY"\n', encoding="utf-8")
        key, known_hosts = output / "synthetic-ssh.key", output / "synthetic-known-hosts"
        key.write_text("SYNTHETIC NOT A VALID SSH KEY; NEVER EXECUTED\n", encoding="ascii")
        known_hosts.write_text("SYNTHETIC NOT VALID HOST KEYS; TRANSPORT IS A FIXTURE\n", encoding="ascii")
        key.chmod(0o600)
        known_hosts.chmod(0o600)
        sources = (
            Source("uploaded-host", kind="upload", max_age_seconds=3600),
            Source("ssh-host", kind="ssh", max_age_seconds=3600, options=dict(host="ssh.example.invalid", user="synthetic",
                known_hosts=known_hosts.name, key=key.name, timeout=5, backend="dpkg", package_namespace="debian")),
            Source("cluster-a", kind="kubernetes", max_age_seconds=3600, options=dict(observations="observations.json", registries=["fixture"])),
        )
        config = Config(output / "automation.toml", output / "automation-state", output / "staging", output / "merged.json", core_config,
                        sources, notifications=notification_channels(), registries=(dict(id="fixture", url=registry_wire.url,
                        repositories=[registry_wire.repo], bearer={"env": "LIFECYCLE_REGISTRY_TOKEN"}),))
        # Config path is an inert administrator-owned input in this API harness.
        config.config_path.write_text("# Synthetic lifecycle API configuration; see summary.json\n", encoding="ascii")

        upload = output / "uploaded.json"
        write_snapshot(upload, [dict(asset_id="uploaded-component", purl="pkg:pypi/lifecycle-upload-example@1.0.0")],
                       source_id="uploaded-host", collector="synthetic-local")
        envelope = encode_envelope("uploaded-host", upload.read_bytes(), manifest_path(upload).read_bytes())
        receiver = Receiver(IngestConfig(config.staging_dir, (UploadSource("uploaded-host", Secret(env="LIFECYCLE_UPLOAD_TOKEN"), 3600),)))
        authenticated = receiver.authenticate("uploaded-host", "Bearer " + ENVIRONMENT["LIFECYCLE_UPLOAD_TOKEN"])
        accepted = receiver.accept(authenticated, envelope)
        assert accepted["status"] == "accepted"
        pointer = config.staging_dir / "uploaded-host/current.json"
        before_pointer = pointer.read_bytes()
        assert receiver.accept(authenticated, envelope)["status"] == "idempotent" and pointer.read_bytes() == before_pointer
        older = json.loads(manifest_path(upload).read_bytes())
        older["generated_at"] = older["observed_at"] = (clock.wall() - timedelta(seconds=1)).isoformat()
        try:
            receiver.accept(authenticated, encode_envelope("uploaded-host", upload.read_bytes(), json_bytes(older)))
        except AutomationError as exc:
            assert exc.category == "snapshot_replay_or_rollback"
        else:
            raise AssertionError("older upload was accepted")
        assert pointer.read_bytes() == before_pointer
        summary["phases"]["upload"] = dict(accepted=True, exact_repeat="idempotent", older_replay="rejected", pointer_preserved=True)

        observations = dict(contract="cvebeacon.kubernetes-observations.v1", source_id="cluster-a", generated_at=clock.wall().isoformat(),
            observations=[dict(namespace="synthetic", pod="application", pod_uid="synthetic-pod-1", owner_kind="Deployment", owner="application",
                container="main", container_kind="regular", image="registry.example.invalid/team/application:synthetic-tag",
                image_id="containerd://" + registry_wire.reference, running=True)])
        (output / "observations.json").write_bytes(json_bytes(observations))

        def ssh_fixture(argv, *, timeout, limit, input, cwd, environment):
            assert argv[-1] == REMOTE_COMMAND and "-oStrictHostKeyChecking=yes" in argv and "-F" in argv
            assert timeout == 5 and input and set(environment) == {"HOME", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA"}
            ssh_calls.append("fixed-argv-synthetic-result")
            return 0, json_bytes(dict(version=1, backend="dpkg", os_release='ID=debian\nNAME="Synthetic Debian"\nVERSION_ID="12"\n',
                                     packages="installed\tlifecycle-ssh-example\t1.0-1\tamd64\n"))

        boundaries.enter_context(patch.object(ssh, "executable", lambda name: "synthetic-ssh-never-executed"))
        boundaries.enter_context(patch.object(ssh, "run", ssh_fixture))
        real_client = client.RegistryClient
        boundaries.enter_context(patch.object(acquire, "RegistryClient", lambda registry, **kwargs: real_client(registry, transport=registry_wire, **kwargs)))
        real_dispatch = service.dispatch
        def dispatch(configured, database):
            return real_dispatch(configured, database, transport_factory=notify_wire.factory, clock=clock.now,
                                 sleeper=clock.advance, random_value=lambda: 0)
        boundaries.enter_context(patch.object(service, "dispatch", dispatch))

        def scanner(configured):
            core = load_core(configured.core_config)
            assets = load_inventory(core.inventory)
            with patch.dict("os.environ", clean_environment(), clear=True):
                assert not set(ENVIRONMENT) & __import__("os").environ.keys()
                store = StateStore(core.database_path)
                store.initialize()
                with QueryEngine(core, http=core_wire) as engine:
                    results = engine.scan(assets, known_findings=store.latest_findings())
                _, events = store.record_scan(results)  # No direct SQL event insertion.
            code = 4 if any(result.coverage is not None for result in results) else 0
            core_scans.append(dict(assets=len(assets), events=len(events), event_ids=events, coverage_unknown=sum(
                result.coverage == Applicability.COVERAGE_UNKNOWN for result in results), exit=code))
            return code

        for phase, score in (("initial", 7.5), ("unchanged", 7.5), ("material_cvss_change", 9.8)):
            if phase != "initial":
                clock.advance(60)
            before_sends = len(notify_wire.sends())
            core_wire.score = score
            code = pipeline.run_pipeline(config, scanner=scanner)
            expected_events = 0 if phase == "unchanged" else 1
            assert code == 4 and status(config.state_dir)["status"] == "coverage_warning"
            assert core_scans[-1]["assets"] == 4 and core_scans[-1]["events"] == expected_events
            assert len(notify_wire.sends()) - before_sends == expected_events * 4
            assert not status(config.state_dir)["notifications"]["unhealthy"]
            summary["phases"][phase] = dict(sources=3, assets=4, core_events=expected_events,
                provider_attempts=expected_events * 4, cvss=score, core_exit=code, health="coverage_warning",
                coverage_unknown=core_scans[-1]["coverage_unknown"])
        core_db = output / "core.db"
        assert read_sql(core_db, "SELECT event_type FROM events ORDER BY event_id") == [("new",), ("changed",)]
        assert read_sql(core_db, "SELECT COUNT(*) FROM deliveries") == [(0,)], "Automation must not own Core deliveries"
        finding = StateStore(core_db).latest_findings()[0]
        assert finding["applicability"] == "affected" and finding["vulnerability"]["cvss_score"] == 9.8
        assert service.delivery_status(config)["channels"]["slack"]["states"]["accepted"] == 2

        # Operational outage is independent of the two material event counts.
        clock.advance(60)
        operations = replace(config, operations=dict(enabled=True, interval_seconds=86400))
        operation_state = dict(status="coverage_warning", sources={source.id: {} for source in sources}, core_exit=4)
        notify_wire.slack_outage = True
        before_events = read_sql(core_db, "SELECT COUNT(*) FROM events")
        outage = service.operational(operations, operation_state, operation_state, transport_factory=notify_wire.factory,
            clock=clock.now, sleeper=clock.advance, random_value=lambda: 0)
        assert outage["attempted"] == 4 and outage["unhealthy"] and outage["channels"]["slack"]["states"]["retryable"] == 1
        persisted = service.delivery_status(config)
        assert persisted["channels"]["slack"]["states"]["retryable"] == 1
        ledger_path = config.state_dir / "notification-ledger.sqlite3"
        retry_rows = read_sql(ledger_path, "SELECT attempts,state,next_retry FROM deliveries WHERE state='retryable'")
        assert len(retry_rows) == 1 and retry_rows[0][0] == 1 and retry_rows[0][2] > clock.now()
        notify_wire.slack_outage = False
        clock.advance(121)
        recovered = service.operational(operations, operation_state, operation_state, transport_factory=notify_wire.factory,
            clock=clock.now, sleeper=clock.advance, random_value=lambda: 0)
        assert recovered["attempted"] == 1 and not recovered["unhealthy"] and read_sql(core_db, "SELECT COUNT(*) FROM events") == before_events
        assert read_sql(ledger_path, "SELECT purpose,COUNT(*) FROM deliveries GROUP BY purpose ORDER BY purpose") == [("event", 8), ("operational", 4)]
        summary["phases"]["notification_outage"] = dict(operational_attempts=4, retryable_persisted=1, retry_attempts=1,
            recovered=True, core_events_added=0, event_rows=8, operational_rows=4)

        registry_pointer = config.staging_dir / "cluster-a/current.json"
        registry_before = registry_pointer.read_bytes()
        registry_wire.missing = True
        try:
            acquire.collect_source(config, sources[2])
        except AutomationError as exc:
            assert exc.category == "registry_sbom_missing"
        else:
            raise AssertionError("missing SBOM erased or invented inventory")
        assert registry_pointer.read_bytes() == registry_before
        registry_wire.missing = False
        summary["phases"]["registry_absence"] = dict(category="registry_sbom_missing", previous_pointer_preserved=True)

        merged_before = (config.inventory_path.read_bytes(), manifest_path(config.inventory_path).read_bytes())
        db_before, scan_count = core_db.read_bytes(), len(core_scans)
        clock.advance(7200)
        assert pipeline.run_pipeline(config, scanner=scanner) == 2 and len(core_scans) == scan_count
        assert status(config.state_dir)["sources"]["uploaded-host"]["failure_category"] == "source_stale_or_future"
        assert merged_before == (config.inventory_path.read_bytes(), manifest_path(config.inventory_path).read_bytes()) and core_db.read_bytes() == db_before
        summary["phases"]["stale_required"] = dict(core_exit=2, scanner_called=False, inventory_pair_preserved=True, core_db_preserved=True)
        missing = replace(config, sources=(Source("missing-required", snapshot=output / "nonexistent.json"),))
        assert pipeline.run_pipeline(missing, scanner=scanner) == 2 and len(core_scans) == scan_count
        assert status(config.state_dir)["sources"]["missing-required"]["failure_category"] == "source_missing"
        assert merged_before == (config.inventory_path.read_bytes(), manifest_path(config.inventory_path).read_bytes()) and core_db.read_bytes() == db_before
        summary["phases"]["missing_required"] = dict(core_exit=2, scanner_called=False, inventory_pair_preserved=True, core_db_preserved=True)

        def nmap_fixture(job, *, scratch):
            parsed = nmap.parse_xml(discovery_xml(discovery_version[0]), targets=job["targets"], ports=job["ports"])
            return dict(observations=parsed["observations"], observed_targets=parsed["observed_targets"],
                        backend_versions=[parsed["backend_version"]], coverage=parsed["coverage"])
        boundaries.enter_context(patch.object(nmap, "run_discovery", nmap_fixture))
        discovery = replace(config, discovery=(dict(id="synthetic-loopback", enabled=True, targets=["127.0.0.1"],
            allowlist=["127.0.0.1"], ports=[8080], timeout=5),))
        first = nmap.run_jobs(discovery)["synthetic-loopback"]
        same = nmap.run_jobs(discovery)["synthetic-loopback"]
        discovery_version[0] = "2.0"
        changed = nmap.run_jobs(discovery)["synthetic-loopback"]
        assert first["changed"] and not same["changed"] and changed["changed"] and changed["service_changes"] == 1
        assert merged_before == (config.inventory_path.read_bytes(), manifest_path(config.inventory_path).read_bytes()) and core_db.read_bytes() == db_before
        discovery_state = json.loads((config.state_dir / "discovery/synthetic-loopback/current.json").read_bytes())
        assert discovery_state["trust"] == "discovery-observation" and discovery_state["observations"][0]["cpes"]
        summary["phases"]["discovery"] = dict(initial_change=True, unchanged_change=False, service_changes=1,
            trust="discovery-observation", inventory_promoted=False, core_db_preserved=True)

        assert len(ssh_calls) == 4 and len(core_scans) == 3
        assert len(notify_wire.sends()) == 13
        assert not offline_attempts, "product attempted actual networking despite fixture boundaries"
        summary.update(core_scans=3, core_events=2, core_deliveries=0, event_provider_attempts=8,
            operational_provider_attempts=5, accepted_delivery_rows=12, synthetic_ssh_collections=len(ssh_calls),
            registry_integrity="sha256-and-subject", native_transport_proof=False, assertions="passed")
        # Inspect only this freshly created synthetic tree, never owner files.
        for filename in output.rglob("*"):
            if filename.is_file():
                assert not any(value.encode("ascii") in filename.read_bytes() for value in ENVIRONMENT.values()), "credential canary leaked into artifact"
        (output / "summary.json").write_bytes(json_bytes(summary))
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new or empty synthetic evidence directory; never overwrites prior results")
    args = parser.parse_args(argv)
    summary = run_demo(args.output)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
