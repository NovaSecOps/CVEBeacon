"""Actual disposable kind acceptance; no owner kubeconfig, images or credentials.

The in-cluster TLS registry is a protocol simulator. Its subject bytes are the
digest-verified public workload manifest; its SBOM is deliberately synthetic.
"""

from copy import deepcopy
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
import uuid

import yaml

from support import certificate


ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "automation/deploy/kubernetes"
NAMESPACE = "cvebeacon-v2-demo"
NODE = "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
WORKLOAD = "docker.io/library/python@sha256:b92e6b9bb1ea9d826e9956fd8d30bf18bc384c130231d74fdf0ba3460c290b0b"
IMAGE = "cvebeacon-automation:ci"
EXT_IMAGE = "cvebeacon-extensions:ci"
CANARY = "SYNTHETIC-POD-ENV-AND-ANNOTATION-CANARY"
REGISTRY_TOKEN = "SYNTHETIC_REGISTRY_BEARER_ONLY_7391"
MATRIX_TOKEN = "SYNTHETIC_MATRIX_TOKEN_ONLY_8391"
FIXTURE_HOST = "fixture.cvebeacon-v2-demo.svc.cluster.local"


def run(args, *, data=None, timeout=120, expected=0):
    env = dict(os.environ)
    # Every kube invocation below supplies its temporary path/context explicitly.
    env["KUBECONFIG"] = str(args[args.index("--kubeconfig") + 1]) if "--kubeconfig" in args else os.devnull
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout, env=env)
    if result.returncode != expected:
        # Tool error strings can quote request data; never echo them or credentials.
        raise AssertionError(f"synthetic {Path(args[0]).name} failed with code {result.returncode}")
    return result.stdout


def documents():
    return list(yaml.safe_load_all((REFERENCE / "reference.yaml").read_text(encoding="utf-8")))


def validate_reference():
    docs = documents()
    role = next(item for item in docs if item["kind"] == "Role")
    assert role["rules"] == [{"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]}]
    assert not any(item["kind"] in {"ClusterRole", "ClusterRoleBinding", "Secret"} for item in docs)
    sa = next(item for item in docs if item["kind"] == "ServiceAccount")
    assert sa["automountServiceAccountToken"] is False
    claims = [item for item in docs if item["kind"] == "PersistentVolumeClaim"]
    assert len(claims) == 3 and all(item["spec"]["accessModes"] == ["ReadWriteOncePod"] for item in claims)
    cron = next(item for item in docs if item["kind"] == "CronJob")
    assert cron["spec"]["suspend"] and cron["spec"]["concurrencyPolicy"] == "Forbid"
    assert cron["spec"]["startingDeadlineSeconds"] == 120
    job = cron["spec"]["jobTemplate"]["spec"]
    assert job["backoffLimit"] == 0 and job["activeDeadlineSeconds"] == 600
    pod = job["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False and "hostAliases" not in pod
    assert pod["securityContext"] == dict(runAsNonRoot=True, runAsUser=65532, runAsGroup=65532,
                                         fsGroup=65532, seccompProfile={"type": "RuntimeDefault"})
    stages = pod["initContainers"] + pod["containers"]
    assert [item["name"] for item in stages] == ["observe", "acquire", "scan", "notify"]
    expected = {"observe": {"api-access", "observations", "observe-tmp"},
                "acquire": {"observations", "sources", "acquire-config", "registry-ca", "acquire-tmp"},
                "scan": {"sources", "core", "scan-config", "core-scan-config", "scripts", "scan-tmp"},
                "notify": {"core", "notifications", "notify-config", "core-notify-config", "notify-tmp"}}
    for item in stages:
        assert {mount["name"] for mount in item["volumeMounts"]} == expected[item["name"]]
        assert item["securityContext"] == dict(readOnlyRootFilesystem=True, allowPrivilegeEscalation=False,
                                               capabilities={"drop": ["ALL"]})
        assert item["resources"]["limits"]
    assert next(mount for mount in stages[2]["volumeMounts"] if mount["name"] == "sources")["readOnly"]
    assert next(mount for mount in stages[3]["volumeMounts"] if mount["name"] == "core") == {
        "name": "core", "mountPath": "/core-ro/notification-core.db",
        "subPath": "notification-core.db", "readOnly": True}
    assert "--observations-only" in stages[0]["args"] and "--accept-coverage-warning" not in stages[2]["args"]
    assert not stages[0].get("env") and not stages[2].get("env")
    assert [item["name"] for item in stages[1]["env"]] == ["CVEBEACON_REGISTRY_BEARER"]
    assert [item["name"] for item in stages[3]["env"]] == ["CVEBEACON_MATRIX_TOKEN"]
    return cron


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def descriptor(raw, media, **extra):
    return dict(mediaType=media, digest=digest(raw), size=len(raw), **extra)


def public_manifest(reference):
    """Anonymous bounded read from two fixed public Docker endpoints, no redirects."""
    assert reference == WORKLOAD
    def get(host, path, headers=None):
        assert host in {"auth.docker.io", "registry-1.docker.io"}
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        client = http.client.HTTPSConnection(host, timeout=20, context=context)
        try:
            client.request("GET", path, headers=headers or {})
            reply = client.getresponse()
            assert reply.status == 200, "public fixture manifest unavailable"
            raw = reply.read(1024 * 1024 + 1)
            assert len(raw) <= 1024 * 1024
            return raw
        finally:
            client.close()
    authorization = json.loads(get("auth.docker.io", "/token?service=registry.docker.io&scope=repository:library/python:pull"))
    token = authorization.get("token")
    assert isinstance(token, str) and 1 <= len(token) <= 16384
    expected = reference.split("@", 1)[1]
    raw = get("registry-1.docker.io", "/v2/library/python/manifests/" + expected,
              {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"})
    assert digest(raw) == expected, "public manifest raw digest mismatch"
    data = json.loads(raw)
    assert data["mediaType"] in {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
    return raw


def registry_routes(raw):
    """Digest-exact OCI 1.1 subset with an explicitly synthetic CycloneDX artifact."""
    image = "application/vnd.oci.image.manifest.v1+json"
    index = "application/vnd.oci.image.index.v1+json"
    cdx = "application/vnd.cyclonedx+json"
    empty = "application/vnd.oci.empty.v1+json"
    subject = descriptor(raw, json.loads(raw)["mediaType"])
    sbom = encoded(dict(bomFormat="CycloneDX", specVersion="1.6", version=1,
                        components=[dict(type="library", name="example", version="1", purl="pkg:pypi/example@1")]))
    artifact = encoded(dict(schemaVersion=2, mediaType=image, artifactType=cdx, subject=subject,
                            config=descriptor(b"{}", empty), layers=[descriptor(sbom, cdx)]))
    referrer = descriptor(artifact, image, artifactType=cdx)
    routes = {}
    for path, body, media in [("manifests/" + subject["digest"], raw, subject["mediaType"]),
                              ("manifests/" + referrer["digest"], artifact, image),
                              ("blobs/" + digest(b"{}"), b"{}", "application/octet-stream"),
                              ("blobs/" + digest(sbom), sbom, "application/octet-stream"),
                              ("referrers/" + subject["digest"], encoded(dict(schemaVersion=2, mediaType=index, manifests=[referrer])), index)]:
        routes["/v2/library/python/" + path] = dict(body=base64.b64encode(body).decode("ascii"), media=media, digest=digest(body))
    return routes


SERVER = r'''
import base64,hashlib,json,os,pathlib,ssl,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
routes=json.loads(pathlib.Path('/fixture/routes.json').read_text())
stats={'registry_ok':0,'registry_denied':0,'matrix_puts':0,'matrix_body_sha256':[]}
guard=threading.Lock()
def save(): pathlib.Path('/tmp/report.json').write_text(json.dumps(stats,sort_keys=True))
save()
class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def log_message(self,*args): pass
    def handle_message(self):
        length=int(self.headers.get('Content-Length','0'))
        if not 0<=length<=32768: self.send_error(413); return
        body=self.rfile.read(length)
        registry=self.path.startswith('/v2/')
        expected=os.environ['REGISTRY_EXPECTED'] if registry else os.environ['MATRIX_EXPECTED']
        if self.headers.get('Authorization')!='Bearer '+expected:
            with guard:
                if registry: stats['registry_denied']+=1
                save()
            status,media,raw=401,'application/json',b'{}'
        elif registry:
            with guard: stats['registry_ok']+=1; save()
            item=routes.get(self.path)
            if item is None: status,media,raw=404,'application/json',b'{}'
            else:
                status,media,raw=200,item['media'],base64.b64decode(item['body'])
                if '/referrers/' in self.path and pathlib.Path('/tmp/missing-sbom').exists():
                    raw=b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}'
        elif self.command=='GET' and self.path.endswith('/state/m.room.encryption'):
            status,media,raw=404,'application/json',b'{"errcode":"M_NOT_FOUND"}'
        elif self.command=='PUT' and '/send/m.room.message/cveb-' in self.path:
            data=json.loads(body)
            assert data['msgtype']=='m.text' and data['m.mentions']=={} and 'TEST' in data['body']
            with guard:
                stats['matrix_puts']+=1
                stats['matrix_body_sha256'].append(hashlib.sha256(body).hexdigest())
                save()
            status,media,raw=200,'application/json',b'{"event_id":"$synthetic-kind-test"}'
        else: status,media,raw=404,'application/json',b'{}'
        self.send_response(status)
        self.send_header('Content-Type',media)
        self.send_header('Content-Length',str(len(raw)))
        if registry and status==200 and '/manifests/' in self.path:
            self.send_header('Docker-Content-Digest','sha256:'+hashlib.sha256(raw).hexdigest())
        self.end_headers()
        self.wfile.write(raw)
    do_GET=do_PUT=handle_message
server=ThreadingHTTPServer(('0.0.0.0',8443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/fixture-tls/tls.crt','/fixture-tls/tls.key')
server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
'''


RBAC = r'''
from cvebeacon_extensions.kubernetes import in_cluster_client
from cvebeacon_extensions.contract import ExtensionError
get=in_cluster_client()
assert b'PodList' in get('/api/v1/namespaces/cvebeacon-v2-demo/pods?limit=1')
for path in ['/api/v1/namespaces/cvebeacon-v2-demo/secrets',
             '/api/v1/namespaces/cvebeacon-v2-demo/configmaps','/api/v1/nodes','/api/v1/pods',
             '/api/v1/namespaces/cvebeacon-v2-forbidden/pods',
             '/api/v1/namespaces/cvebeacon-v2-demo/pods/synthetic-workload',
             '/api/v1/namespaces/cvebeacon-v2-demo/pods?watch=true']:
    try: get(path)
    except ExtensionError as error: assert '(HTTP 403)' in str(error)
    else: raise AssertionError('unexpected API authorization')
print('verified API TLS: list allowed, seven HTTP 403 denials')
'''


STAGE = r'''
import http.client,json,os,pathlib,runpy,ssl,sys
phase=sys.argv[1]
api=pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount')
registry=os.environ.get('CVEBEACON_REGISTRY_BEARER')
notifier=os.environ.get('CVEBEACON_MATRIX_TOKEN')
if phase=='observe':
    assert (api/'token').exists() and (api/'ca.crt').exists()
    assert not registry and not notifier and not pathlib.Path('/registry-ca/ca.crt').exists()
    assert not pathlib.Path('/core-state/core.db').exists() and not pathlib.Path('/core-ro/core.db').exists()
else:
    assert not (api/'token').exists() and not (api/'ca.crt').exists() and not (api/'namespace').exists()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=pathlib.Path('/tests/api-ca.crt').read_text())
    client=http.client.HTTPSConnection(os.environ['KUBERNETES_SERVICE_HOST'],443,timeout=10,context=context)
    try:
        client.request('GET','/api/v1/namespaces/cvebeacon-v2-demo/pods?limit=1')
        assert client.getresponse().status in (401,403)
    finally: client.close()
    if phase=='acquire':
        assert not notifier and pathlib.Path('/registry-ca/ca.crt').exists()
        assert not pathlib.Path('/config/core.toml').exists() and not pathlib.Path('/core-state/core.db').exists()
        assert not pathlib.Path('/core-ro/core.db').exists()
    elif phase=='scan':
        assert not registry and not notifier and not pathlib.Path('/registry-ca/ca.crt').exists()
        assert not pathlib.Path('/observations/pods.json').exists()
    else:
        assert not registry and notifier and not pathlib.Path('/registry-ca/ca.crt').exists()
        assert not pathlib.Path('/observations/pods.json').exists()
        if phase=='notify':
            database=pathlib.Path('/core-ro/notification-core.db')
            assert database.is_file()
            assert {item.name for item in database.parent.iterdir()}=={'notification-core.db'}
            assert not pathlib.Path('/core-ro/core.db').exists()
            assert not pathlib.Path('/core-ro/inventory.json').exists()
            try:
                with database.open('r+b'): pass
            except OSError: pass
            else: raise AssertionError('notifier Core mount is writable')
print('stage isolation and actual API denial passed: '+phase,flush=True)
if phase=='observe':
    from cvebeacon_extensions.cli import main
else:
    from cvebeacon_automation.cli import main
code=main(sys.argv[2:])
if phase=='scan' and code==0:
    import importlib.util
    spec=importlib.util.spec_from_file_location('deployment_snapshot','/scripts/scan.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.snapshot(pathlib.Path('/core-state/core.db'),pathlib.Path('/core-state/notification-core.db'))
if phase=='observe' and code==0:
    raw=pathlib.Path('/observations/pods.json').read_text()
    assert (api/'token').read_text().strip() not in raw
    assert 'SYNTHETIC-POD-ENV-AND-ANNOTATION-CANARY' not in raw
raise SystemExit(code)
'''


INSPECT = r'''
import fcntl,hashlib,json,pathlib,sqlite3,subprocess,sys
expected=int(sys.argv[1])
root=pathlib.Path('/core-state')
with sqlite3.connect((root/'core.db').as_uri()+'?mode=ro',uri=True) as db:
    db.execute('PRAGMA query_only=ON')
    assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    assert db.execute('SELECT count(*) FROM runs').fetchone()[0]==expected
    assert db.execute('SELECT count(*) FROM events').fetchone()[0]==0
    assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0]==0
    latest,assets,unknown=db.execute('SELECT run_id,asset_count,coverage_unknown_count FROM runs ORDER BY completed_at DESC LIMIT 1').fetchone()
    assert 0<assets<=4096 and unknown==assets
    payloads=db.execute("SELECT CASE WHEN typeof(payload_json)='text' AND length(CAST(payload_json AS BLOB))<=65536 THEN payload_json END FROM scan_assets WHERE run_id=? LIMIT 4097",(latest,)).fetchall()
    assert len(payloads)==assets and all(row[0] is not None and json.loads(row[0])['coverage']=='coverage_unknown' for row in payloads)
with sqlite3.connect((root/'notification-core.db').as_uri()+'?mode=ro',uri=True) as db:
    assert db.execute('PRAGMA journal_mode').fetchone()[0]=='delete'
    assert db.execute('SELECT count(*) FROM runs').fetchone()[0]==expected
health=json.loads((root/'runner/health.json').read_text())
assert health['core_exit']==4 and health['status']=='coverage_warning'
rows=json.loads((root/'inventory.json').read_text())
assert rows and all(row['purl']=='pkg:pypi/example@1' for row in rows)
manifest=json.loads((root/'inventory.json.manifest.json').read_text())
assert manifest['status']=='partial'
with open(root/'runner/automation.lock','a') as handle:
    fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
    result=subprocess.run(['cvebeacon-auto','--config','/config/scan.toml','run','--accept-coverage-warning'],capture_output=True,text=True,timeout=15)
    assert result.returncode==75
summary={'runs':expected,'core_exit':4,'events':0,'core_deliveries':0,
         'inventory_sha256':hashlib.sha256((root/'inventory.json').read_bytes()).hexdigest(),
         'manifest_sha256':hashlib.sha256((root/'inventory.json.manifest.json').read_bytes()).hexdigest()}
print(json.dumps(summary,sort_keys=True))
'''


class Cluster:
    def __init__(self, kubeconfig, name):
        self.kubeconfig, self.name = kubeconfig, name

    def kubectl(self, *args, data=None, timeout=120):
        return run(["kubectl", "--kubeconfig", str(self.kubeconfig), "--context", "kind-" + self.name,
                    *args], data=data, timeout=timeout)

    def apply(self, document):
        kind = document["kind"]
        spec = None
        if kind == "Pod":
            spec = document["spec"]
        elif kind in {"Job", "Deployment"}:
            spec = document["spec"]["template"]["spec"]
        elif kind == "CronJob":
            spec = document["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        if spec is not None:
            declared = [item["name"] for item in spec.get("volumes", [])]
            assert len(declared) == len(set(declared)), "duplicate synthetic Pod volume"
            for container in spec.get("initContainers", []) + spec["containers"]:
                mounts = container.get("volumeMounts", [])
                assert all(item["name"] in declared for item in mounts), "undeclared synthetic Pod volume"
                assert len({item["mountPath"] for item in mounts}) == len(mounts), "duplicate synthetic mount path"
        return self.kubectl("apply", "-f", "-", data=json.dumps(document))

    def get(self, kind, name=None):
        return json.loads(self.kubectl("-n", NAMESPACE, "get", kind, *([name] if name else []), "-o", "json"))

    def configmap(self, name, data):
        self.apply(dict(apiVersion="v1", kind="ConfigMap", metadata=dict(name=name, namespace=NAMESPACE), data=data))

    def secret(self, name, data):
        values = {key: base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode("ascii") for key, value in data.items()}
        self.apply(dict(apiVersion="v1", kind="Secret", metadata=dict(name=name, namespace=NAMESPACE), type="Opaque", data=values))

    def logs(self, job):
        pods = json.loads(self.kubectl("-n", NAMESPACE, "get", "pods", "-l", "job-name=" + job, "-o", "json"))["items"]
        outputs = []
        for pod in pods:
            states = pod.get("status", {}).get("initContainerStatuses", []) + pod.get("status", {}).get("containerStatuses", [])
            active = {item["name"] for item in states if "terminated" in item.get("state", {}) or "running" in item.get("state", {})}
            for container in pod["spec"].get("initContainers", []) + pod["spec"]["containers"]:
                if container["name"] in active:
                    outputs.append(self.kubectl("-n", NAMESPACE, "logs", pod["metadata"]["name"], "-c", container["name"]))
        result = "\n".join(outputs)
        assert all(canary not in result for canary in (CANARY, REGISTRY_TOKEN, MATRIX_TOKEN))
        return result

    def wait_job(self, name, *, failed=False, seconds=300):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            job = self.get("job", name)
            if job.get("status", {}).get("succeeded") == 1:
                assert not failed, "expected failure unexpectedly succeeded"
                return self.logs(name)
            if any(item["type"] == "Failed" and item["status"] == "True" for item in job.get("status", {}).get("conditions", [])):
                if not failed:
                    raise AssertionError("synthetic job failed: " + name + "\n" + self.logs(name))
                return self.logs(name)
            time.sleep(2)
        raise AssertionError("synthetic job deadline: " + name)

    def job(self, name, pod, *, deadline=300):
        self.apply(dict(apiVersion="batch/v1", kind="Job", metadata=dict(name=name, namespace=NAMESPACE),
                        spec=dict(backoffLimit=0, activeDeadlineSeconds=deadline, template=dict(spec=pod))))

    def fixture_exec(self, code):
        pod = self.get("pods")["items"]
        selected = [item["metadata"]["name"] for item in pod if item["metadata"].get("labels", {}).get("app") == "fixture"]
        assert len(selected) == 1
        return self.kubectl("-n", NAMESPACE, "exec", selected[0], "--", "python", "-c", code)


def smoke(cluster, root, manifest):
    cron = validate_reference()
    for item in documents():
        if item["kind"] == "CronJob":
            continue
        if item["kind"] == "PersistentVolumeClaim":
            item["spec"].update(accessModes=["ReadWriteOnce"], storageClassName="standard")
        cluster.apply(item)
    cluster.apply(dict(apiVersion="v1", kind="Namespace", metadata=dict(name="cvebeacon-v2-forbidden")))
    pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    security = deepcopy(pod["securityContext"])
    container_security = deepcopy(pod["containers"][0]["securityContext"])
    cert, key = certificate(root, names="DNS:docker.io,DNS:" + FIXTURE_HOST)
    cluster.secret("fixture-tls", {"tls.crt": cert.read_bytes(), "tls.key": key.read_bytes()})
    cluster.secret("cvebeacon-v2-registry", {"bearer": REGISTRY_TOKEN})
    cluster.secret("cvebeacon-v2-notifier", {"matrix-token": MATRIX_TOKEN})
    cluster.configmap("cvebeacon-v2-registry-ca", {"ca.crt": cert.read_text()})
    cluster.configmap("fixture", {"server.py": SERVER, "routes.json": json.dumps(registry_routes(manifest))})
    server = dict(automountServiceAccountToken=False, securityContext=security,
                  containers=[dict(name="server", image=IMAGE, imagePullPolicy="Never", command=["python", "/fixture/server.py"],
                    securityContext=container_security, ports=[dict(containerPort=8443)],
                    readinessProbe=dict(tcpSocket=dict(port=8443), initialDelaySeconds=1, periodSeconds=2),
                    resources=dict(requests=dict(cpu="100m", memory="64Mi"), limits=dict(cpu="1", memory="256Mi")),
                    env=[dict(name="REGISTRY_EXPECTED", valueFrom=dict(secretKeyRef=dict(name="cvebeacon-v2-registry", key="bearer"))),
                         dict(name="MATRIX_EXPECTED", valueFrom=dict(secretKeyRef=dict(name="cvebeacon-v2-notifier", key="matrix-token")))],
                    volumeMounts=[dict(name="fixture", mountPath="/fixture", readOnly=True),
                                  dict(name="tls", mountPath="/fixture-tls", readOnly=True), dict(name="tmp", mountPath="/tmp")])],
                  volumes=[dict(name="fixture", configMap=dict(name="fixture")), dict(name="tls", secret=dict(secretName="fixture-tls")),
                           dict(name="tmp", emptyDir=dict(medium="Memory", sizeLimit="64Mi"))])
    cluster.apply(dict(apiVersion="apps/v1", kind="Deployment", metadata=dict(name="fixture", namespace=NAMESPACE),
                       spec=dict(replicas=1, selector=dict(matchLabels=dict(app="fixture")),
                                 template=dict(metadata=dict(labels=dict(app="fixture")), spec=server))))
    cluster.apply(dict(apiVersion="v1", kind="Service", metadata=dict(name="fixture", namespace=NAMESPACE),
                       spec=dict(selector=dict(app="fixture"), ports=[dict(port=443, targetPort=8443)])))
    cluster.kubectl("-n", NAMESPACE, "rollout", "status", "deployment/fixture", "--timeout=90s", timeout=100)
    service_ip = cluster.get("service", "fixture")["spec"]["clusterIP"]
    # Test-only mapping: node image pulls retain public DNS. Only these Pods use the simulator.
    pod["hostAliases"] = [dict(ip=service_ip, hostnames=["docker.io"])]
    pod["volumes"].append(dict(name="tests", configMap=dict(name="acceptance-tests")))
    api_ca = yaml.safe_load(cluster.kubeconfig.read_text())["clusters"][0]["cluster"]["certificate-authority-data"]
    cluster.configmap("acceptance-tests", {"stage.py": STAGE, "api-ca.crt": base64.b64decode(api_ca).decode("ascii")})
    cluster.configmap("cvebeacon-v2-scripts", {"scan.py": (REFERENCE / "scan.py").read_text()})
    for item in pod["initContainers"] + pod["containers"]:
        item["image"] = EXT_IMAGE if item["name"] == "observe" else IMAGE
        item["imagePullPolicy"] = "Never"
        item["command"] = ["python", "/tests/stage.py", item["name"]]
        item["volumeMounts"].append(dict(name="tests", mountPath="/tests", readOnly=True))
    pod["initContainers"][2]["args"] = ["--config", "/config/scan.toml", "run", "--accept-coverage-warning"]
    acquire = (REFERENCE / "acquire.example.toml").read_text().replace("https://registry.example.org", "https://docker.io").replace('"team/workload"', '"library/python"').replace("allow_partial = false", "allow_partial = true")
    scan = (REFERENCE / "scan.example.toml").read_text().replace("allow_partial = false", "allow_partial = true")
    core = (REFERENCE / "core-scan.example.toml").read_text()
    core += "\n[sources]\n" + "\n".join(name + "_enabled = false" for name in ("osv", "nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")) + "\n"
    for name, data in [("cvebeacon-v2-acquire", {"acquire.toml": acquire}), ("cvebeacon-v2-scan", {"scan.toml": scan}),
                       ("cvebeacon-v2-core-scan", {"core.toml": core}),
                       ("cvebeacon-v2-core-notify", {"core.toml": (REFERENCE / "core-notify.example.toml").read_text()}),
                       ("cvebeacon-v2-notify", {"notify.toml": (REFERENCE / "notify.example.toml").read_text()})]:
        cluster.configmap(name, data)
    workload = dict(automountServiceAccountToken=False, securityContext=security,
                    containers=[dict(name="workload", image=WORKLOAD, command=["python", "-c", "import time; time.sleep(1800)"],
                                     securityContext=container_security, env=[dict(name="SYNTHETIC_PRIVATE_ENV", value=CANARY)])])
    cluster.apply(dict(apiVersion="v1", kind="Pod", metadata=dict(name="synthetic-workload", namespace=NAMESPACE,
                       annotations=dict(synthetic_canary=CANARY)), spec=workload))
    cluster.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/synthetic-workload", "--timeout=180s", timeout=190)
    runtime = cluster.get("pod", "synthetic-workload")["status"]["containerStatuses"][0]["imageID"]
    normalized = re.sub(r"^(docker-pullable|docker|containerd)://", "", runtime)
    assert normalized == WORKLOAD, "actual runtime must report the pinned platform repository manifest"
    probe = dict(serviceAccountName=pod["serviceAccountName"], automountServiceAccountToken=False,
                 restartPolicy="Never", securityContext=security,
                 containers=[dict(name="probe", image=EXT_IMAGE, imagePullPolicy="Never", command=["python", "-c", RBAC],
                                  securityContext=container_security,
                                  volumeMounts=[dict(name="api-access", mountPath="/var/run/secrets/kubernetes.io/serviceaccount", readOnly=True),
                                                dict(name="observe-tmp", mountPath="/tmp")])],
                 volumes=[deepcopy(item) for item in pod["volumes"] if item["name"] in {"api-access", "observe-tmp"}])
    cluster.job("rbac-probe", probe, deadline=120)
    assert "seven HTTP 403" in cluster.wait_job("rbac-probe", seconds=130)
    cron["spec"]["schedule"] = "* * * * *"
    cluster.apply(cron)
    for number in (1, 2):
        name = "manual-v2-" + str(number)
        cluster.kubectl("-n", NAMESPACE, "create", "job", name, "--from=cronjob/cvebeacon-v2")
        output = cluster.wait_job(name)
        assert all("passed: " + stage in output for stage in ("observe", "acquire", "scan", "notify"))

    def inspect(count, name):
        inspection = deepcopy(pod)
        inspection.pop("initContainers")
        inspection.pop("hostAliases")
        inspection["volumes"] = [item for item in inspection["volumes"] if item["name"] in {"core", "sources", "scan-config", "core-scan-config", "scan-tmp"}]
        inspection["containers"] = [deepcopy(pod["initContainers"][2])]
        inspector = inspection["containers"][0]
        inspector["volumeMounts"] = [item for item in inspector["volumeMounts"] if item["name"] not in {"tests", "scripts"}]
        inspector["command"], inspector["args"] = ["python", "-c", INSPECT, str(count)], []
        cluster.job(name, inspection, deadline=60)
        return json.loads(cluster.wait_job(name, seconds=70).strip())
    prior = inspect(2, "inspect-before-failure")
    cluster.fixture_exec("from pathlib import Path; Path('/tmp/missing-sbom').touch()")
    cluster.kubectl("-n", NAMESPACE, "create", "job", "missing-sbom", "--from=cronjob/cvebeacon-v2")
    failed_output = cluster.wait_job("missing-sbom", failed=True)
    assert "registry_sbom_missing" in failed_output and "passed: scan" not in failed_output
    after = inspect(2, "inspect-after-missing-sbom")
    assert after == prior, "failed required acquisition changed scan history or inventory"
    cluster.fixture_exec("from pathlib import Path; Path('/tmp/missing-sbom').unlink()")
    bad = deepcopy(pod)
    bad["initContainers"][1].pop("env")
    cluster.job("missing-registry-credential", bad)
    failed_output = cluster.wait_job("missing-registry-credential", failed=True)
    assert "passed: acquire" in failed_output and "secret_unavailable" in failed_output and "passed: scan" not in failed_output
    assert inspect(2, "inspect-after-missing-credential") == prior
    cron_uid = cluster.get("cronjob", "cvebeacon-v2")["metadata"]["uid"]
    cluster.kubectl("-n", NAMESPACE, "patch", "cronjob", "cvebeacon-v2", "--type=merge", "-p", '{"spec":{"suspend":false}}')
    scheduled, deadline = None, time.monotonic() + 100
    while time.monotonic() < deadline:
        selected = [item for item in cluster.get("jobs")["items"]
                    if item["metadata"].get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp")
                    and any(owner.get("uid") == cron_uid and owner.get("controller") for owner in item["metadata"].get("ownerReferences", []))]
        if selected:
            assert len(selected) == 1
            scheduled = selected[0]["metadata"]["name"]
            break
        time.sleep(2)
    cluster.kubectl("-n", NAMESPACE, "patch", "cronjob", "cvebeacon-v2", "--type=merge", "-p", '{"spec":{"suspend":true}}')
    assert scheduled, "genuine scheduled Job missing"
    cluster.wait_job(scheduled)
    final = inspect(3, "inspect-scheduled-state")
    matrix_config = (REFERENCE / "notify.example.toml").read_text().split("# Additional channels", 1)[0]
    matrix_config += '\n[[notifications]]\nid="matrix-fixture"\nprovider="matrix"\nhomeserver="https://' + FIXTURE_HOST + '"\nroom_id="!synthetic:example.invalid"\ntoken={env="CVEBEACON_MATRIX_TOKEN"}\n'
    cluster.configmap("matrix-test-config", {"notify.toml": matrix_config, "ca.crt": cert.read_text()})
    matrix = deepcopy(pod)
    matrix.pop("initContainers")
    matrix.pop("hostAliases")
    matrix["volumes"] = [item for item in matrix["volumes"] if item["name"] in {"notifications", "notify-tmp", "tests"}]
    matrix["volumes"].append(dict(name="matrix-config", configMap=dict(name="matrix-test-config")))
    container = matrix["containers"][0]
    container["command"] = ["python", "/tests/stage.py", "matrix-test"]
    container["args"] = ["--config", "/config/notify.toml", "notify", "test", "matrix-fixture"]
    container["volumeMounts"] = [item for item in container["volumeMounts"] if item["name"] in {"notifications", "notify-tmp", "tests"}]
    container["volumeMounts"].extend([dict(name="matrix-config", mountPath="/config/notify.toml", subPath="notify.toml", readOnly=True),
                                    dict(name="matrix-config", mountPath="/fixture-ca/ca.crt", subPath="ca.crt", readOnly=True)])
    container["env"].append(dict(name="SSL_CERT_FILE", value="/fixture-ca/ca.crt"))
    cluster.job("matrix-fixture-test", matrix, deadline=90)
    assert '"accepted": 1' in cluster.wait_job("matrix-fixture-test", seconds=100)
    stats = json.loads(cluster.fixture_exec("from pathlib import Path; print(Path('/tmp/report.json').read_text())"))
    assert stats["registry_ok"] >= 15 and stats["matrix_puts"] == 1
    return dict(version=1, outcome="passed", cluster=cluster.name, namespace=NAMESPACE, runtime_image_id=runtime,
                subject_sha256=digest(manifest), synthetic_sbom=True, vendor_attestation_verified=False,
                api_http_403_count=7, actual_scheduled_job=scheduled, scans=final["runs"], core_exit=4,
                core_deliveries=0, missing_sbom_preserved_inventory=True, missing_credential_preserved_inventory=True,
                credential_isolation=True, anonymous_api_denials=True, automation_lock_exclusion=True,
                matrix_local_tls_test_accepted=1, fixture=stats, storage="kind-local-path-RWO-not-production-RWOP")


def main():
    validate_reference()
    assert os.name == "posix", "native kind acceptance requires a disposable Linux runner"
    name = "cvebeacon-v2-ci-" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="cvebeacon-v2-kind-") as temporary:
        root = Path(temporary)
        kubeconfig = root / "kubeconfig"
        manifest = public_manifest(WORKLOAD)
        (root / "subject-manifest.json").write_bytes(manifest)
        try:
            run(["kind", "create", "cluster", "--name", name, "--image", NODE, "--kubeconfig", str(kubeconfig), "--wait", "120s"], timeout=240)
            kubeconfig.chmod(0o600)
            run(["kind", "load", "docker-image", "--name", name, IMAGE, EXT_IMAGE], timeout=180)
            report = smoke(Cluster(kubeconfig, name), root, manifest)
            # Preserve only safe result/public bytes in the workflow's explicit evidence path.
            evidence = os.environ.get("CVEBEACON_KUBERNETES_EVIDENCE")
            if evidence:
                folder = Path(evidence)
                folder.mkdir(parents=True, exist_ok=False)
                (folder / "subject-manifest.json").write_bytes(manifest)
                (folder / "acceptance.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, sort_keys=True))
        finally:
            # Delete only this process's exact uniquely named disposable cluster.
            run(["kind", "delete", "cluster", "--name", name, "--kubeconfig", str(kubeconfig)], timeout=120)


if __name__ == "__main__":
    main()
