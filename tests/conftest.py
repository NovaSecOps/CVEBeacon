from __future__ import annotations

import socket

import pytest


@pytest.fixture(autouse=True)
def deterministic_tests_do_not_use_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("deterministic tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
