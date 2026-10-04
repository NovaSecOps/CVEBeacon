"""Actual synthetic HTTPS ingestion and bounded transport acceptance on Linux."""

from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time

from cvebeacon_extensions.contract import manifest_path, write_snapshot
from cvebeacon_automation.common import AutomationError, Secret
from cvebeacon_automation.http import HTTPS, TransportError
from cvebeacon_automation.ingest.client import push
from cvebeacon_automation.ingest.protocol import encode_envelope
from cvebeacon_automation.ingest.server import IngestConfig, Server, UploadSource
from cvebeacon_automation.staging import current_snapshot

from support import certificate, local_network_only, tls_fixture


def request_abuse(server, cert, token, pair):
    """Exercise the real stdlib request parser over verified loopback TLS."""
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(str(cert))
    body = encode_envelope("host-a", pair.read_bytes(), manifest_path(pair).read_bytes())
    common = ["Host: 127.0.0.1", "Content-Type: application/json",
              "X-CVEBeacon-Source: host-a", "Authorization: Bearer " + token]

    def raw(extra, payload=b"", *, base=None):
        headers = common if base is None else base
        request = ("POST /v1/snapshots HTTP/1.1\r\n" + "\r\n".join(headers + extra) + "\r\n\r\n").encode() + payload
        with context.wrap_socket(socket.create_connection(("127.0.0.1", server.server_port), timeout=4),
                                 server_hostname="127.0.0.1") as connection:
            connection.settimeout(4)
            connection.sendall(request)
            received = b""
            while True:
                data = connection.recv(8192)
                if not data:
                    break
                received += data
                assert len(received) <= 16384
        assert received.count(b"HTTP/1.0 ") == 1
        assert token.encode() not in received
        return int(received.split(b" ", 2)[1])

    length = "Content-Length: " + str(len(body))
    for extra in ([length, length], [length, "Transfer-Encoding: chunked"],
                  [length, "Transfer-Encoding:"], [length, "Transfer-Encoding:", "Transfer-Encoding: chunked"],
                  [length, "Content-Encoding: gzip"]):
        assert raw(extra, body) == 400
    assert raw([length, "X-Oversized: " + "x" * 20000], body) == 431
    assert raw([length, *["X-Synthetic-" + str(i) + ": x" for i in range(40)]], body) == 431
    folded = [line for line in common if not line.startswith("Authorization:")]
    assert raw([length, "Authorization: Bearer " + token + "\r\n synthetic-fold"], body, base=folded) == 401
    padded = body + b" " * (server.receiver.config.max_body_bytes - len(body))
    assert raw(["Content-Length: " + str(len(padded))], padded) == 200
    assert raw(["Content-Length: " + str(len(padded) + 1)], padded + b" ") == 413
    pipelined = body + b"GET /second-request HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    assert raw([length], pipelined) == 200


def run_protocol(root):
    cert, key = certificate(root)
    token = "synthetic-local-upload-canary-01234567890123456789"
    os.environ["SYNTHETIC_UPLOAD_TOKEN"] = token
    source = UploadSource("host-a", Secret(env="SYNTHETIC_UPLOAD_TOKEN"))
    pair = root / "host.json"
    write_snapshot(pair, [dict(asset_id="synthetic-host", purl="pkg:pypi/example@1.0")], source_id="host-a", collector="synthetic")
    config = IngestConfig(root / "staging", (source,), port=0, certificate=cert, key=key, timeout_seconds=2, max_body_bytes=4096)
    with local_network_only(), Server(config) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = f"https://127.0.0.1:{server.server_port}/v1/snapshots"
            result = push(pair, url, source.credential, ca_file=cert)
            assert result["status"] == "accepted"
            assert push(pair, url, source.credential, ca_file=cert)["status"] == "idempotent"
            assert current_snapshot(config.staging_dir, "host-a").read_bytes() == pair.read_bytes()
            try:
                push(pair, url, source.credential)  # Synthetic CA must not be silently trusted.
            except AutomationError:
                pass
            else:
                raise AssertionError("untrusted TLS certificate accepted")
            request_abuse(server, cert, token, pair)
            client = HTTPS(url, ca_file=cert)
            body = encode_envelope("host-b", pair.read_bytes(), manifest_path(pair).read_bytes())
            headers = {"Authorization": "Bearer " + token, "X-CVEBeacon-Source": "host-a", "Content-Type": "application/json"}
            assert client.request("POST", url, headers=headers, body=body).status == 400
            assert client.request("POST", url, headers={**headers, "Authorization": "Bearer wrong"}, body=body).status == 401
            assert client.request("POST", url, headers={**headers, "X-Forwarded-Proto": "https"}, body=b'{"version":1,"version":1}').status == 400
            # Slow partial authenticated body must be disconnected by total deadline.
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(str(cert))
            connection = context.wrap_socket(socket.create_connection(("127.0.0.1", server.server_port), timeout=5), server_hostname="127.0.0.1")
            started = time.monotonic()
            connection.sendall(("POST /v1/snapshots HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nX-CVEBeacon-Source: host-a\r\nAuthorization: Bearer " + token + "\r\n\r\n{").encode())
            connection.settimeout(4)
            assert connection.recv(1024) == b""
            assert time.monotonic() - started < 3.5
            connection.close()
        finally:
            server.shutdown()
            worker.join(2)
    with local_network_only(), tls_fixture(cert, key, lambda item: (302, {"Location": "https://unapproved.invalid/"}, b"")) as (url, requests):
        result = HTTPS(url, ca_file=cert).request("POST", url + "/credential", headers={"Authorization": "Bearer " + token}, body=b"{}")
        assert result.status == 302 and len(requests) == 1
    with local_network_only(), tls_fixture(cert, key, lambda item: (200, {}, b"X" * 1025)) as (url, requests):
        try:
            HTTPS(url, ca_file=cert, max_response=1024).request("GET", url)
        except TransportError as exc:
            assert exc.transmitted and exc.category == "http_response_limit"
        else:
            raise AssertionError("oversized response accepted")
    os.environ.pop("SYNTHETIC_UPLOAD_TOKEN", None)
    print("verified local TLS ingress/auth/replay/exact-bytes/raw-framing/header/body-bounds/pipelining/slow-body/redirect/response-bounds passed")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="cvebeacon-native-protocol-") as scratch:
        run_protocol(Path(scratch))
