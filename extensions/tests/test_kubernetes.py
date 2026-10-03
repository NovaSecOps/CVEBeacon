import copy
import json
from pathlib import Path

import pytest

from cvebeacon.config import InventoryConfig
from cvebeacon.inventory import load_inventory
from cvebeacon_extensions import kubernetes as kube
from cvebeacon_extensions.contract import ExtensionError, read_snapshot

IMAGE = "registry.example.invalid/app@sha256:" + "a"*64


def pod(*, image=IMAGE, image_id="docker-pullable://"+IMAGE, running=True):
    return dict(metadata=dict(name="example", namespace="demo", uid="pod-uid", annotations={"secret":"annotation-canary"},
                              ownerReferences=[dict(kind="ReplicaSet", name="example-replica", controller=True)]),
                spec=dict(containers=[dict(name="app", image=image, env=[dict(name="SECRET",value="environment-canary")])],
                          imagePullSecrets=[dict(name="never-collected")]),
                status=dict(containerStatuses=[dict(name="app", imageID=image_id, state={"running":{}} if running else {"waiting":{}})]))


def page(items=None, continuation="", version="1"):
    return json.dumps(dict(apiVersion="v1", kind="PodList", metadata=dict(resourceVersion=version, **{"continue":continuation}),
                           items=items if items is not None else [pod()])).encode()


def mapping(tmp_path):
    sbom = tmp_path / "app.json"
    sbom.write_text(json.dumps(dict(bomFormat="CycloneDX", specVersion="1.7", components=[dict(name="example",purl="pkg:pypi/example@1")])) )
    result = tmp_path / "map.json"
    result.write_text(json.dumps(dict(contract="cvebeacon.image-sboms.v1", images={IMAGE:"app.json"})))
    return result


def test_api_projection_and_digest_sbom_inventory(tmp_path):
    calls = []
    def get(path): calls.append(path); return page()
    output = tmp_path / "inventory.json"
    manifest = kube.collect_kubernetes(output, source_id="cluster-a", selected_namespace="demo", sbom_map=mapping(tmp_path), get=get)
    assert calls == ["/api/v1/namespaces/demo/pods?limit=500"]
    assert manifest["status"] == "success"
    assert len(read_snapshot(output).records) == 1
    assert load_inventory(InventoryConfig(output))[0].purl == "pkg:pypi/example@1"
    observation_bytes = (tmp_path / "inventory.json.observations.json").read_bytes()
    assert all(canary not in observation_bytes for canary in [b"environment-canary", b"annotation-canary", b"never-collected"])
    observation = json.loads(observation_bytes)["observations"][0]
    assert observation["image_id"] == "docker-pullable://"+IMAGE and observation["owner_kind"] == "ReplicaSet"
    first = output.read_bytes()
    kube.collect_kubernetes(output, source_id="cluster-a", selected_namespace="demo", sbom_map=tmp_path/"map.json", get=get)
    assert output.read_bytes() == first


def test_no_package_identity_from_tags_or_bare_runtime_digests(tmp_path):
    map_path = mapping(tmp_path)
    for image_id in ["containerd://sha256:"+"a"*64, "app:1.2.3", ""]:
        output = tmp_path / "out.json"
        with pytest.raises(ExtensionError, match="no running"):
            kube.collect_kubernetes(output, source_id="cluster", selected_namespace="demo", sbom_map=map_path,
                                    get=lambda _:page([pod(image="app:1.2.3", image_id=image_id)]))
        assert not output.exists()


def test_observations_only_is_explicit_noninventory_document(tmp_path):
    out = tmp_path/"observations.json"
    result = kube.collect_kubernetes(out, source_id="cluster", selected_namespace=None, observations_only=True, get=lambda _:page())
    assert result["status"] == "observations-only"
    assert json.loads(out.read_bytes())["contract"] == "cvebeacon.kubernetes-observations.v1"
    assert not Path(str(out)+".manifest.json").exists()


def test_namespace_pagination_and_duplicate_guards():
    second = pod(); second["metadata"].update(name="second", uid="second-uid")
    calls = []
    pages = [page(continuation="token/+"), page([second])]
    def get(path): calls.append(path); return pages.pop(0)
    assert len(kube.list_pods(get, selected_namespace="demo")) == 2
    assert calls[1].endswith("continue=token%2F%2B")
    pages = [page(continuation="again"), page(version="2")]
    with pytest.raises(ExtensionError, match="resource version"):
        kube.list_pods(lambda _:pages.pop(0), selected_namespace="demo")
    with pytest.raises(ExtensionError, match="repeated"):
        kube.list_pods(lambda _:page([],continuation="again"), selected_namespace="demo")
    with pytest.raises(ExtensionError, match="duplicate"):
        kube.list_pods(lambda _:page([pod(),pod()]), selected_namespace="demo")
    with pytest.raises(ExtensionError, match="outside"):
        kube.list_pods(lambda _:page(), selected_namespace="other")
    with pytest.raises(ExtensionError, match="namespace"):
        kube.list_pods(lambda _:page(), selected_namespace="../secrets")


@pytest.mark.parametrize("value", ["../app.json", "/etc/passwd", "https://example.invalid/app.json", "a/b.json", "C:app.json"])
def test_mapping_paths_cannot_escape_directory(tmp_path, value):
    path = mapping(tmp_path)
    path.write_text(json.dumps(dict(contract="cvebeacon.image-sboms.v1", images={IMAGE:value})))
    with pytest.raises(ExtensionError, match="filenames"):
        kube.load_sbom_map(path)


def test_digest_conflict_not_running_and_input_preservation(tmp_path):
    mapped = mapping(tmp_path)
    output = tmp_path/"inventory.json"
    with pytest.raises(ExtensionError, match="no running"):
        kube.collect_kubernetes(output, source_id="cluster", selected_namespace="demo", sbom_map=mapped,
                                get=lambda _:page([pod(image_id=IMAGE.replace("a"*64,"b"*64))]))
    with pytest.raises(ExtensionError, match="no running"):
        kube.collect_kubernetes(output, source_id="cluster", selected_namespace="demo", sbom_map=mapped,get=lambda _:page([pod(running=False)]))
    with pytest.raises(ExtensionError, match="overwrite"):
        kube.collect_kubernetes(tmp_path/"app.json", source_id="cluster", selected_namespace="demo", sbom_map=mapped,get=lambda _:page())


def test_malformed_pod_status_and_size_limits(tmp_path, monkeypatch):
    value = pod(); value["status"]["containerStatuses"][0]["state"] = {"running":{},"waiting":{}}
    with pytest.raises(ExtensionError, match="ambiguous"):
        kube.list_pods(lambda _:page([value]), selected_namespace="demo")
    value = pod(); value["status"]["containerStatuses"] *= 2
    with pytest.raises(ExtensionError, match="duplicate"):
        kube.list_pods(lambda _:page([value]), selected_namespace="demo")
    monkeypatch.setattr(kube,"MAX_BYTES",10)
    with pytest.raises(ExtensionError, match="size"):
        kube.list_pods(lambda _:page(), selected_namespace="demo")


def test_transport_no_redirects_and_no_env_proxies(tmp_path, monkeypatch):
    token = tmp_path/"token"; token.write_text("synthetic.token.value")
    (tmp_path/"ca.crt").write_text("synthetic CA file")
    monkeypatch.setattr(kube,"SERVICE_ACCOUNT",tmp_path)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST","10.96.0.1")
    monkeypatch.setenv("HTTPS_PROXY","https://proxy.invalid")
    class Context:
        def load_verify_locations(self, **kw): assert kw["cafile"] == str(tmp_path/"ca.crt")
    monkeypatch.setattr(kube.ssl,"SSLContext",lambda protocol: Context())
    requests=[]
    class Response:
        status=200
        def read(self,size):return page()
    class Connection:
        sock = None
        def __init__(self,host,port,timeout,context):
            assert host=="10.96.0.1" and port==443
            assert timeout==15
        def connect(self): pass
        def request(self,method,path,headers): requests.append((method,path,headers))
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(kube.http.client,"HTTPSConnection",Connection)
    get=kube.in_cluster_client()
    get("/api/v1/namespaces/demo/pods?limit=500")
    assert requests==[("GET","/api/v1/namespaces/demo/pods?limit=500",
                       {"Authorization":"Bearer synthetic.token.value","Accept":"application/json"})]
    Response.status=302
    with pytest.raises(ExtensionError,match="HTTP 302"):
        get("/api/v1/pods")


def test_reported_platform_digest_selects_sbom_not_declared_index(tmp_path):
    output=tmp_path/"out.json"
    mapped=mapping(tmp_path)
    result=kube.collect_kubernetes(output,source_id="cluster",selected_namespace="demo",sbom_map=mapped,
        get=lambda _:page([pod(image=IMAGE.replace("a"*64,"b"*64))]))
    assert result["status"]=="success"
    assert read_snapshot(output).records[0]["purl"]=="pkg:pypi/example@1"


def test_tls_does_not_honor_environment_keylog(tmp_path,monkeypatch):
    import certifi
    monkeypatch.setenv("SSLKEYLOGFILE",str(tmp_path/"tls-secret.log"))
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST","10.96.0.1")
    (tmp_path/"token").write_text("synthetic.token")
    (tmp_path/"ca.crt").write_bytes(Path(certifi.where()).read_bytes())
    monkeypatch.setattr(kube,"SERVICE_ACCOUNT",tmp_path)
    get=kube.in_cluster_client()  # No request; only construct verified TLS client.
    assert callable(get) and not (tmp_path/"tls-secret.log").exists()


def test_deadline_after_final_response(monkeypatch):
    clock=[0]
    monkeypatch.setattr(kube.time,"monotonic",lambda:clock[0])
    def get(_): clock[0]=61; return page()
    with pytest.raises(ExtensionError,match="deadline"):
        kube.list_pods(get,selected_namespace="demo")


def test_duplicate_pod_identity_and_malformed_running():
    second=pod(); second["metadata"]["name"]="contradiction"
    second["spec"]["containers"][0]["name"]="different"
    with pytest.raises(ExtensionError,match="duplicate Pod"):
        kube.list_pods(lambda _:page([pod(),second]),selected_namespace="demo")
    broken=pod(); broken["status"]["containerStatuses"][0]["state"]={"running":[]}
    with pytest.raises(ExtensionError,match="ambiguous"):
        kube.list_pods(lambda _:page([broken]),selected_namespace="demo")


def test_sbom_extraction_cached_across_instances(tmp_path,monkeypatch):
    mapped=kube.load_sbom_map(mapping(tmp_path))
    calls=[]
    original=kube.extract_sbom
    def extract(*args,**kwargs): calls.append(1); return original(*args,**kwargs)
    monkeypatch.setattr(kube,"extract_sbom",extract)
    pods=[]
    for number in range(20):
        value=pod(); value["metadata"].update(uid=str(number),name="pod-"+str(number)); pods.append(value)
    rows,reviews=kube.enrich(kube.project_pods(pods,selected_namespace="demo"),mapped,source_id="cluster")
    assert len(calls)==1 and len(rows)==20 and not reviews
    assert len({row["asset_id"] for row in rows})==20


def test_transport_hard_timer_interrupts_slow_body(tmp_path,monkeypatch):
    import http.client
    (tmp_path/"token").write_text("synthetic.token")
    monkeypatch.setattr(kube,"SERVICE_ACCOUNT",tmp_path)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST","10.96.0.1")
    class Context:
        def load_verify_locations(self,**kwargs): pass
    monkeypatch.setattr(kube.ssl,"SSLContext",lambda _:Context())
    closed=[]; interrupted=[]; callbacks=[]
    class Transport:
        def shutdown(self,how): interrupted.append(how)
    class Response:
        status=200
        def read(self,size):
            callbacks[0]()
            raise http.client.IncompleteRead(b"")
    class Connection:
        sock=Transport()
        def __init__(self,*args,**kwargs): pass
        def connect(self): pass
        def request(self,*args,**kwargs): pass
        def getresponse(self): return Response()
        def close(self): closed.append(True)
    class Timer:
        def __init__(self,seconds,callback): assert seconds==15; callbacks.append(callback)
        def start(self): pass
        def cancel(self): closed.append("timer")
    monkeypatch.setattr(kube.http.client,"HTTPSConnection",Connection)
    monkeypatch.setattr(kube.threading,"Timer",Timer)
    with pytest.raises(ExtensionError,match="connection failed"):
        kube.in_cluster_client()("/api/v1/pods")
    assert interrupted==[kube.socket.SHUT_RDWR] and closed==["timer",True]
