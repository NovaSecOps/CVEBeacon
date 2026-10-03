"""Create, exercise and remove only a uniquely named synthetic kind cluster.

Requires locally built cvebeacon:ci and cvebeacon-extensions:ci images. Never
uses the caller's kubeconfig or an existing cluster, and never publishes images.
"""

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

import yaml


ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "cvebeacon-demo"
NODE = "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
# A public, immutable linux/amd64 manifest, matching this amd64 CI runner.
WORKLOAD = "docker.io/library/python@sha256:b92e6b9bb1ea9d826e9956fd8d30bf18bc384c130231d74fdf0ba3460c290b0b"
CANARY = "synthetic-kubernetes-env-not-for-inventory-7391"


def run(args, *, data=None, timeout=120):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"command {args[:2]} failed ({result.returncode}): {result.stdout}\n{result.stderr}")
    return result.stdout


def reference_documents():
    return list(yaml.safe_load_all((ROOT / "deploy/kubernetes/reference.yaml").read_text()))


def validate_reference():
    documents = reference_documents()
    role = next(doc for doc in documents if doc["kind"] == "Role")
    assert role["rules"] == [{"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]}]
    cron = next(doc for doc in documents if doc["kind"] == "CronJob")
    assert cron["spec"]["suspend"] and cron["spec"]["concurrencyPolicy"] == "Forbid"
    pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    collector, core = pod["initContainers"][0], pod["containers"][0]
    assert "persistent" not in {mount["name"] for mount in collector["volumeMounts"]}
    assert "api-access" not in {mount["name"] for mount in core["volumeMounts"]}
    for container in (collector, core):
        assert container["securityContext"] == dict(readOnlyRootFilesystem=True, allowPrivilegeEscalation=False,
                                                    capabilities={"drop": ["ALL"]})
    assert pod["securityContext"]["runAsUser"] == 65532
    pvc = next(doc for doc in documents if doc["kind"] == "PersistentVolumeClaim")
    assert pvc["spec"]["accessModes"] == ["ReadWriteOncePod"]
    print("reference structure passed")


RBAC = r'''
from cvebeacon_extensions.kubernetes import in_cluster_client
from cvebeacon_extensions.contract import ExtensionError
get=in_cluster_client()
assert b'PodList' in get('/api/v1/namespaces/cvebeacon-demo/pods?limit=1')
for path in ['/api/v1/namespaces/cvebeacon-demo/secrets',
             '/api/v1/namespaces/cvebeacon-demo/configmaps',
             '/api/v1/nodes', '/api/v1/pods',
             '/api/v1/namespaces/cvebeacon-forbidden/pods',
             '/api/v1/namespaces/cvebeacon-demo/pods/synthetic-workload',
             '/api/v1/namespaces/cvebeacon-demo/pods?watch=true']:
    try: get(path)
    except ExtensionError as error: assert '(HTTP 403)' in str(error), str(error)
    else: raise AssertionError('unexpected RBAC authorization')
print('actual TLS API allowed list and seven forbidden requests passed')
'''

OBSERVE = r'''
from pathlib import Path
from cvebeacon_extensions.kubernetes import collect_kubernetes
path=Path('/tmp/observations.json')
collect_kubernetes(path,source_id='synthetic-observation',selected_namespace='cvebeacon-demo',observations_only=True)
print(path.read_text())
'''

CORE_CHECK = r'''
import hashlib,importlib.util,json,pathlib,runpy,sys
assert not pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount/token').exists()
assert importlib.util.find_spec('cvebeacon_extensions') is None
raw=pathlib.Path('/inventory/inventory.json').read_bytes()
manifest=json.loads(pathlib.Path('/inventory/inventory.json.manifest.json').read_text())
assert manifest['status']=='partial',manifest
rows=json.loads(raw)
assert rows and all(row['purl']=='pkg:pypi/example@1' for row in rows),rows
assert 'synthetic-kubernetes-env-not-for-inventory-7391' not in raw.decode()
print('core inventory enrichment and token isolation passed',flush=True)
sys.argv=['/scripts/scan.py','--accept-degraded']
runpy.run_path('/scripts/scan.py',run_name='__main__')
'''

INSPECT = r'''
import fcntl,json,pathlib,sqlite3,subprocess,sys
expected=int(sys.argv[1])
with sqlite3.connect('/persistent/state.db') as db:
    assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    assert db.execute('SELECT count(*) FROM runs').fetchone()[0]==expected
    assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0]==0
reports=list(pathlib.Path('/persistent/reports').glob('*.json'))
assert reports
for report in reports:
    rows=json.loads(report.read_text())
    assert rows and all(row['coverage']=='coverage_unknown' for row in rows)
assert json.loads(pathlib.Path('/persistent/last-execution.json').read_text())['core_exit_code']==4
with open('/persistent/.cvebeacon.lock','a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    blocked=subprocess.run(['python','/scripts/scan.py'],capture_output=True,text=True,timeout=10)
    assert blocked.returncode==75,(blocked.returncode,blocked.stderr)
print('persistent scans, unknown coverage, no delivery and lock exclusion passed:',expected)
'''


def smoke(kubeconfig: Path, cluster: str):
    def kubectl(*args, data=None, timeout=120):
        return run(["kubectl", "--kubeconfig", str(kubeconfig), "--context", "kind-" + cluster,
                    *args], data=data, timeout=timeout)

    def apply(document):
        return kubectl("apply", "-f", "-", data=json.dumps(document))

    def get(kind, name=None):
        return json.loads(kubectl("-n", NAMESPACE, "get", kind, *([name] if name else []), "-o", "json"))

    def configmap(name, data):
        apply(dict(apiVersion="v1", kind="ConfigMap", metadata=dict(name=name, namespace=NAMESPACE), data=data))

    def logs(job):
        pods = json.loads(kubectl("-n", NAMESPACE, "get", "pods", "-l", "job-name=" + job, "-o", "json"))["items"]
        outputs = []
        for pod in pods:
            for container in pod["spec"].get("initContainers", []) + pod["spec"]["containers"]:
                outputs.append(kubectl("-n", NAMESPACE, "logs", pod["metadata"]["name"], "-c", container["name"]))
        result = "\n".join(outputs)
        assert CANARY not in result
        return result

    def wait_job(name):
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            job = get("job", name)
            if job.get("status", {}).get("succeeded") == 1:
                return logs(name)
            if any(condition["type"] == "Failed" and condition["status"] == "True"
                   for condition in job.get("status", {}).get("conditions", [])):
                raise AssertionError("synthetic job failed: " + name + "\n" + logs(name))
            time.sleep(2)
        raise AssertionError("synthetic job timed out: " + name)

    documents = reference_documents()
    cron = next(doc for doc in documents if doc["kind"] == "CronJob")
    for document in documents:
        if document["kind"] == "CronJob":
            continue
        if document["kind"] == "PersistentVolumeClaim":
            # kind's ephemeral local-path provisioner is not RWOP-capable CSI.
            document["spec"]["accessModes"] = ["ReadWriteOnce"]
            document["spec"]["storageClassName"] = "standard"
        apply(document)
    apply(dict(apiVersion="v1", kind="Namespace", metadata=dict(name="cvebeacon-forbidden")))
    configmap("cvebeacon-scripts", {name: (ROOT / "deploy/kubernetes" / name).read_text()
                                    for name in ("collector.py", "scan.py")})
    config = (ROOT / "deploy/kubernetes/cvebeacon.example.toml").read_text()
    config += "\n[sources]\n" + "\n".join(f"{name}_enabled = false" for name in
                                         ("osv", "nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")) + "\n"
    configmap("cvebeacon-config", {"cvebeacon.toml": config})
    template = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    security = deepcopy(template["securityContext"])
    container_security = deepcopy(template["containers"][0]["securityContext"])
    apply(dict(apiVersion="v1", kind="Pod", metadata=dict(name="synthetic-workload", namespace=NAMESPACE,
               annotations={"synthetic-canary": CANARY}), spec=dict(automountServiceAccountToken=False,
               securityContext=security, containers=[dict(name="workload", image=WORKLOAD, imagePullPolicy="IfNotPresent",
                   command=["python", "-c", "import time; time.sleep(1800)"], securityContext=container_security,
                   env=[dict(name="SYNTHETIC_SECRET", value=CANARY)])])))
    kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/synthetic-workload", "--timeout=180s", timeout=190)
    # Ensure partial provenance without racing publication of our init status.
    apply(dict(apiVersion="v1", kind="Pod", metadata=dict(name="synthetic-unmapped", namespace=NAMESPACE),
               spec=dict(automountServiceAccountToken=False, securityContext=security,
                         containers=[dict(name="unmapped", image="cvebeacon-extensions:ci", imagePullPolicy="Never",
                                          command=["python", "-c", "import time; time.sleep(1800)"],
                                          securityContext=container_security)])))
    kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/synthetic-unmapped", "--timeout=90s")
    reference = get("pod", "synthetic-workload")["status"]["containerStatuses"][0]["imageID"]
    for prefix in ("docker-pullable://", "docker://", "containerd://"):
        if reference.startswith(prefix):
            reference = reference[len(prefix):]
            break
    assert re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", reference), "runtime must supply exact repository digest for positive enrichment"
    sbom = dict(bomFormat="CycloneDX", specVersion="1.6", version=1,
                components=[dict(type="library", name="example", version="1", purl="pkg:pypi/example@1")])
    configmap("cvebeacon-sboms", {"map.json": json.dumps(dict(contract="cvebeacon.image-sboms.v1", images={reference: "workload.json"})),
                                 "workload.json": json.dumps(sbom)})

    def probe(name, script):
        mounts = [dict(name="api-access", mountPath="/var/run/secrets/kubernetes.io/serviceaccount", readOnly=True),
                  dict(name="collector-tmp", mountPath="/tmp")]
        volumes = [deepcopy(volume) for volume in template["volumes"] if volume["name"] in {"api-access", "collector-tmp"}]
        spec = dict(serviceAccountName="cvebeacon-collector", automountServiceAccountToken=False,
                    restartPolicy="Never", securityContext=security, volumes=volumes,
                    containers=[dict(name="probe", image="cvebeacon-extensions:ci", imagePullPolicy="Never",
                                     command=["python", "-c", script], securityContext=container_security, volumeMounts=mounts)])
        apply(dict(apiVersion="batch/v1", kind="Job", metadata=dict(name=name, namespace=NAMESPACE),
                   spec=dict(backoffLimit=0, activeDeadlineSeconds=180, template=dict(spec=spec))))
        return wait_job(name)

    assert "seven forbidden requests passed" in probe("rbac-probe", RBAC)
    observation = json.loads(probe("observation-probe", OBSERVE))
    target = [row for row in observation["observations"] if row["pod"] == "synthetic-workload"]
    assert len(target) == 1 and target[0]["running"] and reference in target[0]["image_id"]
    assert CANARY not in json.dumps(observation)
    template["initContainers"][0]["image"] = "cvebeacon-extensions:ci"
    template["initContainers"][0]["imagePullPolicy"] = "Never"
    template["initContainers"][0]["args"].append("--allow-partial")
    template["containers"][0]["image"] = "cvebeacon:ci"
    template["containers"][0]["imagePullPolicy"] = "Never"
    template["containers"][0]["command"] = ["python", "-c", CORE_CHECK]
    cron["spec"]["schedule"] = "* * * * *"
    apply(cron)
    for number in (1, 2):
        name = "manual-scan-" + str(number)
        kubectl("-n", NAMESPACE, "create", "job", name, "--from=cronjob/cvebeacon")
        assert "core inventory enrichment and token isolation passed" in wait_job(name)

    def inspect(count):
        spec = deepcopy(template)
        spec.pop("initContainers")
        spec["volumes"] = [volume for volume in spec["volumes"] if volume["name"] in {"persistent", "scripts", "core-tmp"}]
        core = spec["containers"][0]
        core["volumeMounts"] = [mount for mount in core["volumeMounts"] if mount["name"] in {"persistent", "scripts", "core-tmp"}]
        core["command"] = ["python", "-c", INSPECT, str(count)]
        name = "inspect-state-" + str(count)
        apply(dict(apiVersion="batch/v1", kind="Job", metadata=dict(name=name, namespace=NAMESPACE),
                   spec=dict(backoffLimit=0, activeDeadlineSeconds=60, template=dict(spec=spec))))
        assert "lock exclusion passed" in wait_job(name)

    inspect(2)
    cron_uid = get("cronjob", "cvebeacon")["metadata"]["uid"]
    kubectl("-n", NAMESPACE, "patch", "cronjob", "cvebeacon", "--type=merge", "-p", '{"spec":{"suspend":false}}')
    scheduled = None
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        # kubectl's manual Jobs also have a CronJob owner; require the actual
        # controller's scheduled timestamp, never infer scheduling from owner.
        jobs = get("jobs")["items"]
        owned = [job for job in jobs if job["metadata"].get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp")
                 and any(owner.get("uid") == cron_uid and owner.get("controller")
                         for owner in job["metadata"].get("ownerReferences", []))]
        if owned:
            assert len(owned) == 1
            scheduled = owned[0]["metadata"]["name"]
            break
        time.sleep(2)
    kubectl("-n", NAMESPACE, "patch", "cronjob", "cvebeacon", "--type=merge", "-p", '{"spec":{"suspend":true}}')
    assert scheduled, "CronJob did not produce a genuine scheduled Job"
    assert "core inventory enrichment and token isolation passed" in wait_job(scheduled)
    inspect(3)
    print("kind acceptance passed: actual TLS/RBAC, projection, digest enrichment, two repeated scans, scheduled scan, persistence and lock")


def main():
    validate_reference()
    cluster = "cvebeacon-ci-" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="cvebeacon-kind-") as temporary:
        kubeconfig = Path(temporary) / "kubeconfig"
        try:
            run(["kind", "create", "cluster", "--name", cluster, "--image", NODE,
                 "--kubeconfig", str(kubeconfig), "--wait", "120s"], timeout=240)
            run(["kind", "load", "docker-image", "--name", cluster, "cvebeacon:ci", "cvebeacon-extensions:ci"], timeout=180)
            smoke(kubeconfig, cluster)
        finally:
            # This exact random name was generated by this process; never use
            # current-context, user's kubeconfig or unqualified cluster deletion.
            run(["kind", "delete", "cluster", "--name", cluster], timeout=120)


if __name__ == "__main__":
    main()
