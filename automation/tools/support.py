"""Synthetic local acceptance helpers; never use owner credentials or clusters."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading


def command(argv, *, timeout=120, input=None, expected=0):
    result = subprocess.run(argv, input=input, capture_output=True, timeout=timeout)
    if result.returncode != expected:
        # These argv contain synthetic paths/secrets only; avoid incidental tool stderr.
        raise AssertionError(f"synthetic {argv[0]} command failed with {result.returncode}")
    return result.stdout.decode("utf-8").strip()


def certificate(directory: Path, *, names="IP:127.0.0.1,DNS:localhost"):
    key, cert = directory / "tls.key", directory / "tls.crt"
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
             "-keyout", str(key), "-out", str(cert), "-subj", "/CN=synthetic-local-fixture",
             "-addext", "subjectAltName=" + names, "-addext", "basicConstraints=critical,CA:TRUE"])
    key.chmod(0o600)
    return cert, key


@contextmanager
def local_network_only():
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_resolve = socket.getaddrinfo
    def approved(value):
        if not ipaddress.ip_address(value).is_loopback:
            raise AssertionError("synthetic acceptance attempted non-loopback network")
    def connect(sock, address):
        approved(address[0])
        return original_connect(sock, address)
    def connect_ex(sock, address):
        approved(address[0])
        return original_connect_ex(sock, address)
    def resolve(host, *args, **kwargs):
        approved(host)
        return original_resolve(host, *args, **kwargs)
    socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, resolve
    try:
        yield
    finally:
        socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = original_connect, original_connect_ex, original_resolve


@contextmanager
def tls_fixture(cert, key, behavior):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def log_message(self, *args):
            pass
        def handle_request(self):
            length = int(self.headers.get("Content-Length", "0"))
            assert length <= 48 * 1024 * 1024
            raw = self.rfile.read(length)
            item = dict(method=self.command, path=self.path, headers=dict(self.headers), body=raw)
            requests.append(item)
            status, headers, body = behavior(item)
            if status is None:
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, str(value))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        do_POST = do_PUT = do_GET = handle_request
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield "https://127.0.0.1:" + str(server.server_port), requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
