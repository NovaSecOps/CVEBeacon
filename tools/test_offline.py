"""Run deterministic tests with networking blocked before test collection."""

import socket
import sys


def blocked(*args, **kwargs):
    raise AssertionError("deterministic tests must not access the network")


if __name__ == "__main__":
    socket.socket.connect = blocked
    socket.socket.connect_ex = blocked
    socket.getaddrinfo = blocked
    import pytest

    raise SystemExit(pytest.main(sys.argv[1:]))
