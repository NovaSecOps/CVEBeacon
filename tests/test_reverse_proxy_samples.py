"""Checks for the shipped reverse-proxy samples."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
NGINX = ROOT / "deploy" / "reverse-proxy" / "nginx" / "cvebeacon.conf"
CADDY = ROOT / "deploy" / "reverse-proxy" / "caddy" / "Caddyfile"
SAMPLES = (NGINX, CADDY)
CERT_SUFFIXES = (".conf", ".crt", ".key", ".pem", ".toml")
HOSTNAME = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
    r"(?![A-Za-z0-9_.-])"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


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
            if hostname.endswith(CERT_SUFFIXES):
                continue
            assert hostname == "example.com" or hostname.endswith(".example.com"), (path, hostname)


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
    assert re.findall(r"^\s*proxy_pass\s+(\S+);", nginx, flags=re.MULTILINE) == ["http://127.0.0.1:8787"]
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


def test_samples_terminate_tls_and_redirect_http():
    nginx = _text(NGINX)
    caddy = _text(CADDY)
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in nginx
    assert "ssl_certificate" in nginx and "/etc/ssl/cvebeacon/fullchain.pem" in nginx
    assert "ssl_certificate_key" in nginx and "/etc/ssl/cvebeacon/privkey.pem" in nginx
    assert "return 301 https://cvebeacon.example.com$request_uri;" in nginx
    assert "tls internal" in caddy
    assert "redir https://cvebeacon.example.com{uri} permanent" in caddy


def test_samples_set_security_headers():
    for path in SAMPLES:
        text = _text(path)
        assert "Strict-Transport-Security" in text
        assert "X-Content-Type-Options" in text
        assert "Referrer-Policy" in text
        assert "frame-ancestors 'none'" in text


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
