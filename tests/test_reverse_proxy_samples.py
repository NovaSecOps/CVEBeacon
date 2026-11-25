"""Checks for the shipped reverse-proxy samples."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import ipaddress
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
NGINX = ROOT / "deploy" / "reverse-proxy" / "nginx" / "cvebeacon.conf"
CADDY = ROOT / "deploy" / "reverse-proxy" / "caddy" / "Caddyfile"
GUIDE = ROOT / "docs" / "HTTPS.md"
SAMPLES = (NGINX, CADDY)
DOCUMENTATION_FILES = frozenset(
    {"cvebeacon.conf", "cvebeacon.toml", "fullchain.pem", "internal-ca.crt", "privkey.pem"}
)
HOSTNAME = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
    r"(?![A-Za-z0-9_.-])"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _block(text: str, marker: str) -> str:
    try:
        start = text.index(marker)
    except ValueError:
        raise AssertionError(f"missing block: {marker!r}") from None
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError(f"unclosed block: {marker!r}")


def test_samples_exist():
    for path in SAMPLES:
        assert path.is_file(), path
        assert path.stat().st_size > 0


def test_samples_use_only_documentation_hostnames():
    for path in SAMPLES:
        text = _text(path)
        assert "cvebeacon.example.com" in text
        for match in HOSTNAME.finditer(text):
            hostname = match.group().casefold()
            if hostname in DOCUMENTATION_FILES:
                continue
            assert hostname == "example.com" or hostname.endswith(".example.com"), (path, hostname)


def test_guide_uses_only_documentation_placeholders():
    text = _text(GUIDE)
    for match in HOSTNAME.finditer(text):
        hostname = match.group().casefold()
        if hostname in DOCUMENTATION_FILES:
            continue
        assert hostname == "example.com" or hostname.endswith(".example.com"), (GUIDE, hostname)
    documentation_network = ipaddress.ip_network("203.0.113.0/24")
    for match in re.finditer(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
        address = ipaddress.ip_address(match.group())
        assert address.is_loopback or address.is_unspecified or address in documentation_network, (GUIDE, match.group())
    for match in re.finditer(r"\[([0-9A-Fa-f:]+)\]", text):
        address = ipaddress.ip_address(match.group(1))
        assert address.is_loopback or address.is_unspecified, (GUIDE, match.group())


def test_samples_use_only_loopback_addresses():
    for path in SAMPLES:
        text = _text(path)
        for match in re.finditer(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
            assert ipaddress.ip_address(match.group()) == ipaddress.ip_address("127.0.0.1"), (path, match.group())
        for match in re.finditer(r"\[([0-9A-Fa-f:]+)\]", text):
            assert match.group(1) == "::", (path, match.group())


def test_samples_proxy_only_to_the_loopback_backend():
    nginx = _text(NGINX)
    caddy = _text(CADDY)
    assert re.findall(r"^\s*proxy_pass\s+(\S+);", nginx, flags=re.MULTILINE) == [
        "http://127.0.0.1:8787", "http://127.0.0.1:8787",
    ]
    assert re.findall(r"^\s*reverse_proxy\s+(\S+)", caddy, flags=re.MULTILINE) == ["127.0.0.1:8787"]


def test_samples_send_a_backend_host_header_and_no_forwarded_client_host():
    nginx = _text(NGINX)
    caddy = _text(CADDY)
    assert "proxy_set_header Host 127.0.0.1:8787;" in nginx
    assert "header_up Host {upstream_hostport}" in caddy
    for text in (nginx, caddy):
        assert "$host" not in text
        assert "{host}" not in text
        assert "$proxy_add_x_forwarded_for" not in text
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "X-Forwarded" not in stripped:
                continue
            assert stripped.endswith('"";') or stripped.startswith("header_up -"), stripped


def test_samples_clear_all_client_forwarding_headers():
    nginx = _text(NGINX)
    caddy = _text(CADDY)
    for header in ("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto", "X-Real-IP", "Forwarded"):
        assert f'proxy_set_header {header} "";' in nginx, header
    assert "header_up -X-Forwarded-*" in caddy
    assert "header_up -X-Real-IP" in caddy
    assert "header_up -Forwarded" in caddy


def test_samples_rewrite_backend_redirects_and_keep_the_query_string():
    backend = "http://127.0.0.1:8787/operations/?probe=1"

    nginx = _text(NGINX)
    match = re.search(r"^\s*proxy_redirect\s+(\S+)\s+(\S+);", nginx, re.MULTILINE)
    assert match, "nginx sample has no explicit proxy_redirect"
    source, replacement = match.groups()
    assert backend.startswith(source)
    assert replacement == "/"
    assert backend[len(source):] == "operations/?probe=1"

    caddy = _text(CADDY)
    match = re.search(r'header_down\s+Location\s+"([^"]+)"\s+"([^"]+)"', caddy)
    assert match, "Caddy sample has no Location rewrite"
    pattern, replacement = match.groups()
    assert replacement == "$1"
    assert re.sub(pattern, lambda match: match.group(1), backend) == "/operations/?probe=1"
    assert re.sub(pattern, lambda match: match.group(1), "https://elsewhere.example/x?y=1") == "https://elsewhere.example/x?y=1"


def test_samples_terminate_tls_and_redirect_http():
    nginx = _text(NGINX)
    caddy = _text(CADDY)
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in nginx
    assert "ssl_certificate" in nginx and "/etc/ssl/cvebeacon/fullchain.pem" in nginx
    assert "ssl_certificate_key" in nginx and "/etc/ssl/cvebeacon/privkey.pem" in nginx
    assert "return 301 https://cvebeacon.example.com$request_uri;" in nginx
    assert "tls internal" in caddy
    assert "redir https://cvebeacon.example.com{uri} permanent" in caddy


def test_nginx_http_redirect_hides_the_server_version():
    http_server = _block(_text(NGINX), "server {")
    assert "listen 80;" in http_server
    assert "server_tokens off;" in http_server


def test_caddy_sample_can_be_imported_into_an_existing_caddyfile():
    caddy = _text(CADDY)
    assert not re.search(r"(?m)^\{\s*$", caddy), "global options block prevents importing into an existing Caddyfile"


def test_samples_block_proxy_bootstrap():
    nginx = _block(_text(NGINX), "location = /bootstrap {")
    assert "return 404;" in nginx
    assert re.search(r"(?m)^\s*respond /bootstrap 404\s*$", _text(CADDY))


def test_samples_set_security_headers():
    for path in SAMPLES:
        text = _text(path)
        assert "Strict-Transport-Security" in text
        assert "X-Content-Type-Options" in text
        assert "Referrer-Policy" in text
        assert "frame-ancestors 'none'" in text


def test_caddy_applies_security_headers_to_its_own_errors():
    block = _block(_text(CADDY), "handle_errors {")
    assert "Strict-Transport-Security" in block
    assert "X-Content-Type-Options" in block
    assert "Referrer-Policy" in block
    assert "frame-ancestors 'none'" in block
    assert "-Server" in block


def test_samples_allow_dashboard_uploads_and_slow_queries():
    nginx = _text(NGINX)
    caddy = _text(CADDY)
    assert "client_max_body_size 6m;" in nginx
    assert "proxy_read_timeout 300s;" in nginx
    assert "proxy_send_timeout 300s;" in nginx
    assert "max_size 6MB" in caddy
    assert "response_header_timeout 300s" in caddy
    assert "read_timeout 300s" in caddy
    assert "write_timeout 300s" in caddy


def test_samples_raise_the_body_limit_only_for_client_inventory_uploads():
    nginx = _text(NGINX)
    server = _block(nginx, "server {\n    listen 443 ssl;")
    dashboard = _block(server, "location / {")
    inventory = _block(dashboard, "location ~ ^/watch/clients/[^/]+/upload$ {")
    assert "client_max_body_size 6m;" in server
    assert "client_max_body_size 34m;" in inventory
    assert "proxy_pass http://127.0.0.1:8787;" in inventory
    assert "proxy_pass is not inherited by nested locations" in inventory

    caddy = _text(CADDY)
    path_pattern = r"^/watch/clients/[^/]+/upload$"
    assert f"@inventory_upload path_regexp {path_pattern}" in caddy
    assert f"@other_requests not path_regexp {path_pattern}" in caddy
    assert re.search(r"request_body @inventory_upload\s*\{\s*max_size 34MB\s*\}", caddy)
    assert re.search(r"request_body @other_requests\s*\{\s*max_size 6MB\s*\}", caddy)


REAL_CONNECT = socket.socket.__mro__[1].connect


def loopback_only_connect(sock, address):
    # The suite blocks network access; this test talks only to its own
    # loopback nginx and backend.
    if not (isinstance(address, tuple) and address[0] == "127.0.0.1"):
        raise AssertionError("deterministic tests must not access the network")
    return REAL_CONNECT(sock, address)


def loopback_only_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host != "127.0.0.1":
        raise AssertionError("deterministic tests must not access the network")
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))]


def test_nginx_inventory_location_proxies_with_reference_limits(tmp_path, monkeypatch):
    nginx = shutil.which("nginx")
    if nginx is None:
        pytest.skip("nginx is not installed")
    monkeypatch.setattr(socket.socket, "connect", loopback_only_connect)
    monkeypatch.setattr(socket, "getaddrinfo", loopback_only_getaddrinfo)

    class BackendHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            remaining = int(self.headers.get("Content-Length", "0"))
            while remaining:
                chunk = self.rfile.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            headers = {
                name: self.headers.get(name)
                for name in (
                    "Host", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port",
                    "X-Forwarded-Proto", "X-Real-IP", "Forwarded",
                )
            }
            payload = json.dumps({"path": self.path, "headers": headers}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            pass

    class LocalHTTPServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    try:
        backend = LocalHTTPServer(("127.0.0.1", 0), BackendHandler)
    except OSError as exc:
        pytest.skip(f"loopback sockets are unavailable: {exc}")
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
    backend_thread.start()

    def unused_loopback_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            return listener.getsockname()[1]

    try:
        proxy_port = unused_loopback_port()
    except OSError as exc:
        backend.shutdown()
        backend.server_close()
        backend_thread.join(timeout=2)
        pytest.skip(f"loopback sockets are unavailable: {exc}")
    backend_port = backend.server_address[1]
    prefix = str(tmp_path)
    for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        (tmp_path / name).mkdir()

    reference = _text(NGINX)
    server = _block(reference, "server {\n    listen 443 ssl;")
    server = re.sub(r"(?m)^(\s*)listen 443 ssl;$", rf"\1listen 127.0.0.1:{proxy_port};", server, count=1)
    server = re.sub(r"(?m)^\s*listen \[::\]:443 ssl;\s*\n", "", server)
    server = re.sub(r"(?m)^\s*ssl_[^;]+;\s*\n", "", server)
    server = server.replace("127.0.0.1:8787", f"127.0.0.1:{backend_port}")
    config = tmp_path / "nginx.conf"
    config.write_text(
        f'pid "{tmp_path / "nginx.pid"}";\n'
        f'error_log "{tmp_path / "error.log"}" notice;\n'
        "events { worker_connections 128; }\n"
        "http {\n"
        f'  client_body_temp_path "{tmp_path / "client_body"}";\n'
        f'  proxy_temp_path "{tmp_path / "proxy"}";\n'
        f'  fastcgi_temp_path "{tmp_path / "fastcgi"}";\n'
        f'  uwsgi_temp_path "{tmp_path / "uwsgi"}";\n'
        f'  scgi_temp_path "{tmp_path / "scgi"}";\n'
        "  access_log off;\n"
        f"{server}\n"
        "}\n",
        encoding="utf-8",
    )

    process = None
    try:
        process = subprocess.Popen(
            [nginx, "-p", prefix, "-c", str(config), "-g", "daemon off;"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                if any(message in stderr.casefold() for message in (
                    "operation not permitted", "permission denied", "address family not supported",
                )):
                    pytest.skip(f"nginx cannot bind loopback sockets: {stderr.strip()}")
                pytest.fail(f"nginx exited during startup: {stdout}\n{stderr}")
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            process.terminate()
            stdout, stderr = process.communicate(timeout=3)
            pytest.fail(f"nginx did not start: {stdout}\n{stderr}")

        def request(path, length, *, send_body=False):
            connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=20)
            connection.putrequest("POST", path, skip_host=True)
            connection.putheader("Host", "cvebeacon.example.com")
            connection.putheader("Content-Length", str(length))
            connection.putheader("X-Forwarded-For", "198.51.100.42")
            connection.putheader("X-Forwarded-Host", "attacker.example")
            connection.putheader("X-Forwarded-Port", "443")
            connection.putheader("X-Forwarded-Proto", "https")
            connection.putheader("X-Real-IP", "198.51.100.42")
            connection.putheader("Forwarded", "for=198.51.100.42;host=attacker.example")
            connection.endheaders()
            if send_body:
                connection.send(b"x" * length)
            response = connection.getresponse()
            result = response.status, response.read()
            connection.close()
            return result

        status, body = request("/watch/clients/acme/upload", 7 * 1024 * 1024, send_body=True)
        assert status == 200
        received = json.loads(body)
        assert received["path"] == "/watch/clients/acme/upload"
        assert received["headers"]["Host"] == f"127.0.0.1:{backend_port}"
        assert all(received["headers"][name] is None for name in (
            "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port",
            "X-Forwarded-Proto", "X-Real-IP", "Forwarded",
        ))

        too_large = 34 * 1024 * 1024 + 1
        assert request("/watch/clients/acme/upload", too_large)[0] == 413
        above_default = 6 * 1024 * 1024 + 1
        assert request("/watch/clients/acme/upload/x", above_default)[0] == 413
        assert request("/", above_default)[0] == 413
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        backend.shutdown()
        backend.server_close()
        backend_thread.join(timeout=2)
