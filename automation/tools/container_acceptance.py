"""Separate image native checks; actual persisted offline pipeline and layers."""

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import uuid

from cvebeacon_extensions.contract import write_snapshot
from cvebeacon_automation.common import AutomationError, Secret
from cvebeacon_automation.ingest.client import push
from cvebeacon_automation.staging import current_snapshot
from support import certificate, command, local_network_only

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "cvebeacon-automation:ci"


def docker(*args, expected=0):
    return command(["docker", *args], expected=expected)


def main():
    # Reuse verified inspection only; no changes to the v1 checker or images.
    spec = importlib.util.spec_from_file_location("existing_container_inspection", ROOT / "tools" / "container_smoke.py")
    inspection = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inspection)
    inspection.inspect_image(IMAGE, companion=True)
    docker("run", "--rm", "--network", "none", "--read-only", IMAGE, "--help")
    with tempfile.TemporaryDirectory(prefix="cvebeacon-automation-container-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        for name in ("config", "state", "inventory", "core", "reports", "staging"):
            (root / name).mkdir(mode=0o777)
            (root / name).chmod(0o777)
        config = root / "config"
        write_snapshot(config / "host.json", [dict(asset_id="synthetic-host", purl="pkg:pypi/example@1")], source_id="host-a", collector="synthetic")
        for file in config.iterdir():
            file.chmod(0o644)
        (config / "core.toml").write_text('[inventory]\npath="/inventory/merged.json"\nformat="json"\n[state]\ndatabase="/core-state/core.db"\n[output]\ndirectory="/reports"\n[sources]\nosv_enabled=false\nnvd_enabled=false\ncve_enabled=false\neuvd_enabled=false\ncisa_kev_enabled=false\neu_kev_enabled=false\nepss_enabled=false\n')
        (config / "automation.toml").write_text('[automation]\nversion=1\nstate_dir="/automation-state"\nstaging_dir="/staging"\ninventory_path="/inventory/merged.json"\ncore_config="/config/core.toml"\n[[sources]]\nid="host-a"\nsnapshot="/config/host.json"\n')
        common = ["--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"]
        for name, destination in (("config", "/config"), ("state", "/automation-state"), ("inventory", "/inventory"), ("core", "/core-state"), ("reports", "/reports"), ("staging", "/staging")):
            common.extend(["--mount", f"type=bind,source={root / name},target={destination}" + (",readonly" if name == "config" else "")])
        for _ in range(2):
            docker("run", "--rm", *common, IMAGE, "--config", "/config/automation.toml", "run", expected=4)
        # Files intentionally belong to image UID65532/mode600; inspect as that
        # UID instead of weakening production state permissions for the host test.
        docker("run", "--rm", *common, "--entrypoint", "python", IMAGE, "-c",
               "import json,sqlite3\nh=json.load(open('/automation-state/health.json'))\nassert h['core_exit']==4 and h['status']=='coverage_warning'\nwith sqlite3.connect('file:/core-state/core.db?mode=ro',uri=True) as db:\n assert db.execute('SELECT count(*) FROM runs').fetchone()[0]==2\n assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0]==0\n assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'")
        assert not (root / "staging" / "core.db").exists()
        receiver_config = root / "receiver-config"
        receiver_secrets = root / "receiver-secrets"
        receiver_staging = root / "receiver-staging"
        for path in (receiver_config, receiver_secrets, receiver_staging):
            path.mkdir(mode=0o755)
        cert, key = certificate(receiver_secrets)
        (receiver_config / "ingest.toml").write_text('[ingestion]\nversion=1\nstaging_dir="/staging"\nhost="0.0.0.0"\nport=8765\ncertificate="/run/secrets/tls.crt"\nkey="/run/secrets/tls.key"\nreader_gid=' + str(os.getgid()) + '\n[[sources]]\nid="host-a"\ncredential={env="INGEST_SYNTHETIC_TOKEN"}\n')
        token = "SYNTHETIC_CONTAINER_UPLOAD_ONLY_01234567890123456789"
        os.environ["INGEST_SYNTHETIC_TOKEN"] = token
        name = "cvebeacon-intake-" + uuid.uuid4().hex[:16]
        receiver = docker("run", "--detach", "--name", name, "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges:true", "--user", f"{os.getuid()}:{os.getgid()}",
                          "--publish", "127.0.0.1::8765", "--env", "INGEST_SYNTHETIC_TOKEN=" + token,
                          "--mount", f"type=bind,source={receiver_config},target=/config,readonly",
                          "--mount", f"type=bind,source={receiver_secrets},target=/run/secrets,readonly",
                          "--mount", f"type=bind,source={receiver_staging},target=/staging",
                          IMAGE, "--config", "/config/ingest.toml", "ingest", "serve")
        assert len(receiver) == 64 and all(c in "0123456789abcdef" for c in receiver)
        try:
            port = docker("port", receiver, "8765/tcp")
            assert port.startswith("127.0.0.1:") and port.count(":") == 1
            endpoint = "https://" + port + "/v1/snapshots"
            deadline = time.monotonic() + 20
            with local_network_only():
                while True:
                    try:
                        result = push(config / "host.json", endpoint, Secret(env="INGEST_SYNTHETIC_TOKEN"), ca_file=cert, timeout=2)
                        break
                    except AutomationError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
            assert result["status"] == "accepted"
            assert current_snapshot(receiver_staging, "host-a").read_bytes() == (config / "host.json").read_bytes()
            # A different UID can read the explicitly shared staging group,
            # without receiving the receiver's config, TLS key or upload token.
            docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges:true", "--user", f"65532:{os.getgid()}",
                   "--mount", f"type=bind,source={receiver_staging},target=/staging,readonly",
                   "--entrypoint", "python", IMAGE, "-c",
                   "from pathlib import Path\nfrom cvebeacon_automation.staging import current_snapshot\nfrom cvebeacon_extensions.contract import read_snapshot\np=current_snapshot(Path('/staging'),'host-a')\nassert read_snapshot(p).records\nassert not Path('/run/secrets/tls.key').exists()\nassert not Path('/config/ingest.toml').exists()\nassert not Path('/core-state/core.db').exists()")
            metadata = json.loads(docker("inspect", receiver))[0]
            assert {item["Destination"] for item in metadata["Mounts"]} == {"/config", "/run/secrets", "/staging"}
            docker("stop", "--time", "5", receiver)
            assert docker("inspect", "--format", "{{.State.ExitCode}}", receiver) == "143"
        finally:
            docker("rm", "--force", receiver)
    print("automation OCI/layers/nonroot/read-only/no-capabilities/two persisted coverage-warning scans and isolated TLS receiver/SIGTERM passed")


if __name__ == "__main__":
    main()
