"""One-shot native collector smoke on disposable CI hosts; no network or upload."""

import socket
import sys
import tempfile
from pathlib import Path


def blocked(*args, **kwargs):
    raise AssertionError("collector must not use network")


socket.socket.connect = blocked
socket.socket.connect_ex = blocked
socket.getaddrinfo = blocked

from cvebeacon_extensions.cli import main
from cvebeacon_extensions.contract import read_snapshot
from cvebeacon.config import InventoryConfig
from cvebeacon.inventory import load_inventory

with tempfile.TemporaryDirectory(prefix="cvebeacon-native-host-") as temporary:
    output = Path(temporary) / "host.json"
    host = "windows" if sys.platform == "win32" else "linux"
    assert main(["collect", host, "--source-id", "ci-host", "--output", str(output)]) == 0
    first = read_snapshot(output, allow_partial=True)
    assert load_inventory(InventoryConfig(output))
    assert main(["collect", host, "--source-id", "ci-host", "--output", str(output)]) == 0
    assert read_snapshot(output, allow_partial=True).records == first.records
    # Counts only; never print hosted-runner software inventory or registry data.
    print(f"native {host} collection and repeated core validation passed")
