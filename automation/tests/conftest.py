import sys
from pathlib import Path
import socket

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("automation tests require explicit local synthetic transport")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
