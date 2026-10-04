"""Offline guards for the v2 deployment boundary and native fixture fidelity."""

import base64
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import uuid

import pytest
import yaml

from cvebeacon_automation.common import AutomationError, Secret, lock
from cvebeacon_automation.config import load_config
from cvebeacon_automation.http import Response
from cvebeacon_automation.registry.client import RegistryClient, validate_registries
from cvebeacon.models import Applicability, Asset, QueryResult
from cvebeacon.state import StateStore


ROOT = Path(__file__).resolve().parents[2]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@pytest.fixture
def acceptance(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "automation/tools"))
    return module(ROOT / "automation/tools/kubernetes_acceptance.py", "kubernetes_v2_acceptance")


@pytest.fixture
def scanner():
    return module(ROOT / "automation/deploy/kubernetes/scan.py", "kubernetes_v2_scan")


def live_database(tmp_path):
    path = tmp_path / "core.db"
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("CREATE TABLE schema_info(version INTEGER NOT NULL);"
                    "CREATE TABLE runs(run_id TEXT PRIMARY KEY);"
                    "CREATE TABLE events(event_id INTEGER PRIMARY KEY,run_id TEXT,payload_json TEXT);")
    run = str(uuid.uuid4())
    db.execute("INSERT INTO schema_info VALUES (3)")
    db.execute("INSERT INTO runs VALUES (?)", (run,))
    db.execute("INSERT INTO events VALUES (7,?,?)", (run, '{"synthetic":"uncheckpointed"}'))
    db.commit()
    return path, db, run


def test_reference_limits_rbac_credentials_storage_and_runtime(acceptance):
    cron = acceptance.validate_reference()
    assert cron["metadata"]["name"] == "cvebeacon-v2"


@pytest.mark.parametrize("filename", ["acquire.example.toml", "scan.example.toml", "notify.example.toml"])
def test_role_configuration_validates_without_resolving_a_secret(acceptance, monkeypatch, filename):
    monkeypatch.setattr(Secret, "resolve", lambda self: pytest.fail("configuration validation must not read credentials"))
    cfg = load_config(acceptance.REFERENCE / filename)
    if filename.startswith("acquire"):
        assert cfg.sources[0].id == "cluster-v2" and cfg.sources[0].kind == "kubernetes"
        assert len(cfg.registries) == 1 and not cfg.notifications
    elif filename.startswith("scan"):
        assert cfg.sources[0].id == "cluster-v2" and cfg.sources[0].kind == "upload"
        assert not cfg.registries and not cfg.notifications
    else:
        assert not cfg.sources and not cfg.registries and not cfg.notifications


def test_backup_copies_uncheckpointed_rows_without_changing_live_journal(scanner, tmp_path):
    path, writer, run = live_database(tmp_path)
    destination = tmp_path / "notification-core.db"
    before = path.read_bytes()
    try:
        scanner.snapshot(path, destination)
        assert path.read_bytes() == before
        assert writer.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        names = {item.name for item in tmp_path.iterdir()}
        reader = sqlite3.connect(destination.as_uri() + "?mode=ro", uri=True)
        try:
            reader.execute("PRAGMA query_only=ON")
            assert reader.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            assert reader.execute("SELECT run_id FROM runs").fetchone()[0] == run
            assert reader.execute("SELECT event_id,run_id,payload_json FROM events").fetchone() == (7, run, '{"synthetic":"uncheckpointed"}')
            with pytest.raises(sqlite3.OperationalError):
                reader.execute("UPDATE schema_info SET version=4")
        finally:
            reader.close()
        assert names == {item.name for item in tmp_path.iterdir()}
    finally:
        writer.close()


def test_failed_copy_preserves_previous_snapshot(scanner, tmp_path):
    path, writer, _ = live_database(tmp_path)
    destination = tmp_path / "notification-core.db"
    try:
        scanner.snapshot(path, destination)
        before = destination.read_bytes()
        writer.execute("UPDATE schema_info SET version=4")
        writer.commit()
        with pytest.raises(AutomationError, match="unsupported_core_schema"):
            scanner.snapshot(path, destination)
        assert destination.read_bytes() == before
        assert not list(tmp_path.glob(".notification-copy-*"))
    finally:
        writer.close()


def test_backup_respects_cooperating_live_database_lock(scanner, tmp_path):
    path, writer, _ = live_database(tmp_path)
    try:
        with lock(path.with_name(path.name + ".automation.lock")):
            with pytest.raises(AutomationError, match="locked"):
                scanner.snapshot(path, tmp_path / "notification-core.db")
        assert not (tmp_path / "notification-core.db").exists()
    finally:
        writer.close()


def test_backup_keeps_shared_core_lock_through_atomic_publication(scanner, tmp_path, monkeypatch):
    path, writer, _ = live_database(tmp_path)
    replace = scanner.os.replace
    publications = []
    def publication(pending, destination):
        with pytest.raises(AutomationError, match="locked"):
            with lock(path.with_name(path.name + ".automation.lock")):
                pytest.fail("competing publisher acquired the shared lock")
        publications.append(destination)
        replace(pending, destination)
    monkeypatch.setattr(scanner.os, "replace", publication)
    try:
        scanner.snapshot(path, tmp_path / "notification-core.db")
        assert publications == [tmp_path / "notification-core.db"]
    finally:
        writer.close()


def test_backup_schema_lookup_obeys_the_sql_progress_deadline(scanner, tmp_path, monkeypatch):
    path, writer, _ = live_database(tmp_path)
    destination = tmp_path / "notification-core.db"
    try:
        scanner.snapshot(path, destination)
        previous = destination.read_bytes()
        writer.executescript("DROP TABLE schema_info; CREATE VIEW schema_info AS SELECT CASE WHEN sum(n)>0 THEN 3 END AS version "
                             "FROM (WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<5000) SELECT n FROM x);")
        ticks = iter([0.0])
        monkeypatch.setattr(scanner, "time", SimpleNamespace(monotonic=lambda: next(ticks, 31.0)))
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            scanner.snapshot(path, destination)
        assert destination.read_bytes() == previous
        assert not list(tmp_path.glob(".notification-copy-*"))
    finally:
        writer.close()


@pytest.mark.parametrize("same_path", [True, False])
def test_backup_destination_is_separate_and_beside_source(scanner, tmp_path, same_path):
    path, writer, _ = live_database(tmp_path)
    try:
        target = path if same_path else tmp_path / "other" / "copy.db"
        with pytest.raises(AutomationError, match="notification_snapshot_path_invalid"):
            scanner.snapshot(path, target)
    finally:
        writer.close()


def test_backup_budget_failure_preserves_previous_copy(scanner, tmp_path, monkeypatch):
    path, writer, _ = live_database(tmp_path)
    destination = tmp_path / "notification-core.db"
    try:
        scanner.snapshot(path, destination)
        before = destination.read_bytes()
        monkeypatch.setattr(scanner, "MAX_DATABASE", 1)
        with pytest.raises(AutomationError, match="notification_snapshot_capacity"):
            scanner.snapshot(path, destination)
        assert destination.read_bytes() == before
    finally:
        writer.close()


def test_fixture_routes_have_exact_digest_subject_and_no_credentials(acceptance):
    media = "application/vnd.oci.image.manifest.v1+json"
    raw = acceptance.encoded(dict(schemaVersion=2, mediaType=media,
                                 config=acceptance.descriptor(b"{}", "application/vnd.oci.image.config.v1+json"), layers=[]))
    routes = acceptance.registry_routes(raw)
    calls = []
    class Wire:
        timeout = max_response = 1
        def request(self, method, url, *, headers=None, body=b""):
            assert method == "GET" and not body and url.startswith("https://docker.io/")
            route = url.removeprefix("https://docker.io")
            calls.append(route)
            item = routes[route]
            value = base64.b64decode(item["body"])
            assert acceptance.digest(value) == item["digest"]
            response_headers = {"content-type": item["media"]}
            if "/manifests/" in route:
                response_headers["docker-content-digest"] = item["digest"]
            return Response(200, response_headers, value)
    registry = validate_registries([dict(id="fixture", url="https://docker.io", repositories=["library/python"])], ROOT)[0]
    evidence = RegistryClient(registry, transport=Wire()).acquire("docker.io/library/python@" + acceptance.digest(raw), running=True)
    assert evidence.image_bytes == raw and evidence.image_digest == acceptance.digest(raw)
    assert json.loads(evidence.sbom_bytes)["components"][0]["purl"] == "pkg:pypi/example@1"
    assert len(calls) == 5
    assert acceptance.REGISTRY_TOKEN not in json.dumps(routes) and acceptance.MATRIX_TOKEN not in json.dumps(routes)


@pytest.mark.parametrize("unknown", [True, False])
def test_native_inspector_checks_persisted_coverage_without_on_demand_reports(acceptance, scanner, tmp_path, monkeypatch, capsys, unknown):
    # Core's supported scan API persists coverage; Automation does not request
    # an on-demand JSON report. Native API/mount/locking proof remains in CI.
    store = StateStore(tmp_path / "core.db")
    coverage = Applicability.COVERAGE_UNKNOWN if unknown else None
    store.record_scan([QueryResult(Asset("synthetic", purl="pkg:pypi/example@1"), (), (), coverage)])
    scanner.snapshot(tmp_path / "core.db", tmp_path / "notification-core.db")
    (tmp_path / "runner").mkdir()
    (tmp_path / "runner/health.json").write_text(json.dumps(dict(core_exit=4, status="coverage_warning")))
    (tmp_path / "inventory.json").write_text(json.dumps([dict(purl="pkg:pypi/example@1")]))
    (tmp_path / "inventory.json.manifest.json").write_text(json.dumps(dict(status="partial")))
    assert not (tmp_path / "reports").exists()
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *args: None))
    monkeypatch.setattr(acceptance.subprocess, "run", lambda *args, **options: SimpleNamespace(returncode=75))
    monkeypatch.setattr(sys, "argv", ["synthetic-inspector", "1"])
    script = acceptance.INSPECT.replace("root=pathlib.Path('/core-state')", "root=pathlib.Path(" + repr(str(tmp_path)) + ")")
    if unknown:
        exec(compile(script, "synthetic-inspector", "exec"), {})
        assert json.loads(capsys.readouterr().out)["core_exit"] == 4
    else:
        with pytest.raises(AssertionError):
            exec(compile(script, "synthetic-inspector", "exec"), {})


def test_native_helpers_do_not_use_an_owner_kubeconfig(acceptance, monkeypatch):
    captured = []
    def fake(args, **options):
        captured.append((args, options["env"]["KUBECONFIG"]))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")
    monkeypatch.setenv("KUBECONFIG", "OWNER-KUBECONFIG-CANARY")
    monkeypatch.setattr(acceptance.subprocess, "run", fake)
    acceptance.run(["kind", "load", "docker-image", "--name", "test-only", "synthetic:ci"])
    cluster = acceptance.Cluster(Path("synthetic-kubeconfig"), "test-only")
    cluster.kubectl("get", "pods")
    assert captured[0][1] == acceptance.os.devnull
    assert captured[1][1] == "synthetic-kubeconfig"
    assert "--context" in captured[1][0] and "kind-test-only" in captured[1][0]
    assert "OWNER-KUBECONFIG-CANARY" not in str(captured)


def test_runtime_fixture_pod_mounts_are_validated_before_submission(acceptance, monkeypatch):
    submitted = []
    cluster = acceptance.Cluster(Path("synthetic-kubeconfig"), "test-only")
    monkeypatch.setattr(cluster, "kubectl", lambda *args, **options: submitted.append(options["data"]))
    spec = dict(volumes=[dict(name="one", emptyDir={})], containers=[dict(name="test", volumeMounts=[dict(name="missing", mountPath="/missing")])])
    with pytest.raises(AssertionError, match="undeclared"):
        cluster.apply(dict(kind="Pod", spec=spec))
    assert not submitted
    spec["containers"][0]["volumeMounts"] = [dict(name="one", mountPath="/tmp")]
    cluster.apply(dict(kind="Pod", spec=spec))
    assert len(submitted) == 1


def test_complete_native_plan_constructs_positive_negative_and_scheduled_specs(acceptance, tmp_path, monkeypatch):
    # Exercise resource construction/control flow only. Actual API, TLS, mounts
    # and scheduling are deliberately left to the native workflow.
    config = tmp_path / "kubeconfig"
    config.write_text(yaml.safe_dump({"clusters": [{"cluster": {"certificate-authority-data": base64.b64encode(b"PUBLIC TEST CA").decode()}}]}))
    def cert(folder, **options):
        public, private = folder / "tls.crt", folder / "tls.key"
        public.write_text("PUBLIC TEST CA")
        private.write_text("SYNTHETIC PRIVATE KEY")
        return public, private
    monkeypatch.setattr(acceptance, "certificate", cert)
    class Plan(acceptance.Cluster):
        submitted = {}
        created_jobs = []
        unsuspended = False
        def kubectl(self, *args, data=None, timeout=120):
            if args[:3] == ("apply", "-f", "-"):
                doc = json.loads(data)
                self.submitted[doc["metadata"]["name"]] = doc
            if "create" in args:
                offset = args.index("create")
                assert args[offset + 1] == "job"
                self.created_jobs.append(args[offset + 2])
            if "patch" in args:
                self.unsuspended = json.loads(args[-1])["spec"]["suspend"] is False
            return "{}"
        def get(self, kind, name=None):
            if kind == "service":
                return {"spec": {"clusterIP": "10.0.0.10"}}
            if kind == "pod":
                return {"status": {"containerStatuses": [{"imageID": "docker-pullable://" + acceptance.WORKLOAD}]}}
            if kind == "cronjob":
                return {"metadata": {"uid": "synthetic-controller"}}
            assert kind == "jobs" and self.unsuspended
            return {"items": [{"metadata": {"name": "genuine-scheduled", "annotations": {"batch.kubernetes.io/cronjob-scheduled-timestamp": "synthetic"},
                "ownerReferences": [{"uid": "synthetic-controller", "controller": True}]}}]}
        def wait_job(self, name, *, failed=False, seconds=300):
            if name.startswith("inspect-"):
                count = int(self.submitted[name]["spec"]["template"]["spec"]["containers"][0]["command"][-1])
                return json.dumps({"runs": count, "inventory_sha256": "same", "manifest_sha256": "same"})
            if name == "rbac-probe":
                return "seven HTTP 403"
            if name == "missing-sbom":
                assert failed
                return "registry_sbom_missing"
            if name == "missing-registry-credential":
                assert failed
                return "passed: acquire secret_unavailable"
            if name == "matrix-fixture-test":
                return '{"accepted": 1}'
            return "passed: observe passed: acquire passed: scan passed: notify"
        def fixture_exec(self, code):
            return json.dumps({"registry_ok": 17, "matrix_puts": 1}) if "report.json" in code else ""
    plan = Plan(config, "synthetic-only")
    raw = acceptance.encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": []})
    report = acceptance.smoke(plan, tmp_path, raw)
    assert report["scans"] == 3 and report["actual_scheduled_job"] == "genuine-scheduled"
    assert {"rbac-probe", "missing-registry-credential", "matrix-fixture-test"} <= set(plan.submitted)
    assert "missing-sbom" in plan.created_jobs
    cron = plan.submitted["cvebeacon-v2"]
    pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert pod["hostAliases"] == [{"ip": "10.0.0.10", "hostnames": ["docker.io"]}]


def test_ci_pins_match_frozen_native_versions_and_evidence_is_safe(acceptance):
    original = (ROOT / ".github/workflows/kubernetes.yml").read_text()
    new = (ROOT / ".github/workflows/automation-kubernetes.yml").read_text()
    for value in ("v0.33.0", "v1.36.4", "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d",
                  "8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a"):
        assert value in original and value in new
    workflow = yaml.safe_load(new)
    assert workflow["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in new
    assert "persist-credentials: false" in new and "subject-manifest" not in str(workflow["permissions"])
    for script in (acceptance.SERVER, acceptance.RBAC, acceptance.STAGE, acceptance.INSPECT):
        compile(script, "synthetic-in-cluster-script", "exec")
