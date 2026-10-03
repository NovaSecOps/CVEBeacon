"""Native Linux Docker acceptance; synthetic data, no publishing or source traffic."""

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import time
import uuid

from werkzeug.security import generate_password_hash

IMAGE = "cvebeacon:ci"


def docker(*args, expected=0, env=None, capture_stderr=False):
    result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=120, env=env)
    assert result.returncode == expected, (args[:3], result.returncode, result.stdout, result.stderr)
    return (result.stdout + (result.stderr if capture_stderr else "")).strip()


def inspect_image(image=IMAGE, *, companion=False):
    metadata = json.loads(docker("image", "inspect", image))[0]
    assert metadata["Config"]["User"] == "65532:65532"
    assert metadata["Config"]["StopSignal"] == "SIGTERM"
    versions = docker("run", "--rm", "--network", "none", "--read-only", "--entrypoint", "python", image,
                      "-c", "import sys,json,importlib.metadata as m; assert sys.version_info[:2]==(3,13); print(json.dumps({'python':sys.version,'packages':sorted((d.metadata['Name'],d.version) for d in m.distributions())}))")
    print("Runtime versions:", versions)
    docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
           "--entrypoint", "python", image, "-c", f"import os,importlib.util; assert os.geteuid()==65532; assert (importlib.util.find_spec('cvebeacon_extensions') is not None)=={companion!r}; assert importlib.util.find_spec('kubernetes') is None; print('non-root dependency isolation passed')")
    docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
           "--entrypoint", "python", image, "-c",
           "import os,pathlib\nassert os.getegid()==65532\nstatus=pathlib.Path('/proc/self/status').read_text()\nassert 'CapEff:\\t0000000000000000' in status and 'NoNewPrivs:\\t1' in status\ntry:\n os.seteuid(0)\nexcept PermissionError: pass\nelse: raise AssertionError('root escalation allowed')\nprint('effective capabilities and root escalation checks passed')")
    # The image-owned directory is writable to this UID without --read-only.
    # An EACCES failure at / alone would not prove a read-only mount.
    docker("run", "--rm", "--network", "none", "--read-only", "--entrypoint", "python", image, "-c",
           "import errno\ntry:\n open('/reports/root-probe','w').close()\nexcept OSError as e: assert e.errno==errno.EROFS,e\nelse: raise AssertionError('writable root filesystem')")
    forbidden_parts = {".git", ".private", ".aws", ".env", "state.db"}
    if not companion:
        forbidden_parts.add("cvebeacon_extensions")
    container = docker("create", image)
    try:
        process = subprocess.Popen(["docker", "export", container], stdout=subprocess.PIPE)
        forbidden = []
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for entry in archive:
                parts = entry.name.split("/")
                if forbidden_parts & set(parts):
                    forbidden.append(entry.name)
                if entry.name.startswith(("build/", "root/.cache/", "opt/venv/lib/python3.13/site-packages/cvebeacon/tests")):
                    forbidden.append(entry.name)
        assert process.wait(timeout=30) == 0
        assert not forbidden, forbidden
    finally:
        docker("rm", container)
    # Removed files can remain in earlier image layers; inspect each layer.
    with tempfile.TemporaryDirectory(prefix="cvebeacon-image-layers-") as temporary:
        saved = Path(temporary) / "image.tar"
        docker("image", "save", "--output", str(saved), image)
        with tarfile.open(saved) as image_tar:
            manifests = json.load(image_tar.extractfile("manifest.json"))
            for layer in {name for manifest in manifests for name in manifest["Layers"]}:
                with tarfile.open(fileobj=image_tar.extractfile(layer), mode="r|*") as archive:
                    for entry in archive:
                        assert not forbidden_parts & set(entry.name.split("/")), entry.name


CLIENT = r'''
import re,sys,time
from http.cookiejar import CookieJar
from urllib.request import build_opener, ProxyHandler, HTTPCookieProcessor, Request
from urllib.parse import urlencode
from urllib.error import URLError
auth = sys.argv[1] == "auth"
client = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
base = "http://127.0.0.1:8787"
def get(path):
    with client.open(base+path, timeout=5) as reply:
        assert reply.status == 200
        return reply.read().decode()
deadline=time.monotonic()+30
while True:
    try:
        body=get('/')
        break
    except URLError:
        if time.monotonic()>deadline: raise
        time.sleep(.1)
assert ('Dashboard login' if auth else 'Monitoring overview') in body
if auth:
    assert 'Dashboard login' in get('/findings')
    token=re.search(r'name="csrf" value="([^"]+)"', get('/login'))[1]
    with client.open(Request(base+'/login', data=urlencode(dict(csrf=token,password='Synthetic container smoke passphrase')).encode()), timeout=10) as reply:
        assert 'Monitoring overview' in reply.read().decode()
for path in ['/findings','/history','/assets','/sources','/query','/reports','/static/dashboard.css']:
    get(path)
print('dashboard loopback smoke passed; auth='+str(auth))
'''


def smoke(directory: Path):
    assert os.getuid() != 0, "run smoke as the normal hosted CI user"
    for name in ("config", "inventory", "state", "reports"):
        (directory / name).mkdir()
    root = Path(__file__).resolve().parents[1]
    config = (root / "deploy/container/cvebeacon.example.toml").read_text()
    config += "\n[sources]\n" + "\n".join(f"{name}_enabled = false" for name in ("osv", "nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")) + "\n"
    (directory / "config/cvebeacon.toml").write_text(config)
    (directory / "inventory/inventory.json").write_text(json.dumps([dict(asset_id="synthetic", purl="pkg:pypi/example@1")]))
    common = ["--read-only", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
              "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
              "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,mode=1777"]
    for name in ("config", "inventory", "state", "reports"):
        common += ["--mount", f"type=bind,src={directory/name},dst=/{name}" + (",readonly" if name in {"config", "inventory"} else "")]
    prefix = ["--config", "/config/cvebeacon.toml"]
    error_output = docker("run", "--rm", *common, "--env", "CVEBEACON_AUDIT_CANARY=synthetic-error-env-canary",
                          IMAGE, "--config", "/config/nonexistent.toml", "scan", expected=2, capture_stderr=True)
    assert "synthetic-error-env-canary" not in error_output
    docker("run", "--rm", *common, IMAGE, "--help")
    docker("run", "--rm", *common, IMAGE, *prefix, "inventory", "validate")
    for _ in range(2):
        docker("run", "--rm", *common, IMAGE, *prefix, "scan", "--report", "json", expected=4)
    with closing(sqlite3.connect(directory / "state/state.db")) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM deliveries").fetchone()[0] == 0
        before = list(db.iterdump())
    reports = list((directory / "reports").glob("*.json"))
    assert reports and all(json.loads(path.read_text())[0]["coverage"] == "coverage_unknown" for path in reports)
    for auth in (False, True):
        name = "cvebeacon-smoke-" + uuid.uuid4().hex[:12]
        env = dict(os.environ)
        env.pop("CVEBEACON_DASHBOARD_PASSWORD_HASH", None)
        options = []
        if auth:
            env["CVEBEACON_DASHBOARD_PASSWORD_HASH"] = generate_password_hash("Synthetic container smoke passphrase", method="scrypt:32768:8:1")
            options = ["--env", "CVEBEACON_DASHBOARD_PASSWORD_HASH"]
        docker("run", "--detach", "--name", name, *common, *options, IMAGE, *prefix, "serve", env=env)
        try:
            host_config = json.loads(docker("inspect", name))[0]["HostConfig"]
            assert host_config["ReadonlyRootfs"] and not host_config["Privileged"]
            assert host_config["CapDrop"] == ["ALL"]
            docker("exec", name, "python", "-c", CLIENT, "auth" if auth else "no-auth")
            docker("stop", "--time", "10", name)
            state = json.loads(docker("inspect", name))[0]["State"]
            assert state["ExitCode"] == 143 and not state["OOMKilled"], state
        finally:
            docker("rm", "--force", name)
    with closing(sqlite3.connect(directory / "state/state.db")) as db:
        assert list(db.iterdump()) == before
    print("container acceptance passed: isolation, persistence, reports, auth, signals, image hygiene")


if __name__ == "__main__":
    inspect_image()
    inspect_image("cvebeacon-extensions:ci", companion=True)
    docker("run", "--rm", "--network", "none", "--read-only", "cvebeacon-extensions:ci", "--help")
    with tempfile.TemporaryDirectory(prefix="cvebeacon-container-") as temporary:
        smoke(Path(temporary))
