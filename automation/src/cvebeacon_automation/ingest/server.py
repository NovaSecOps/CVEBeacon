"""Bounded authenticated receiver, intentionally independent of pipeline config."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
from pathlib import Path
import socket
from socketserver import ThreadingMixIn
import ssl
import threading
import time
import tomllib

from cvebeacon_extensions.contract import ExtensionError, read_bytes
from ..common import AutomationError, Secret, identifier, regular
from ..config import boolean, keys, number, path, tables
from ..staging import publish
from .protocol import MAX_ENVELOPE, decode_envelope


@dataclass(frozen=True, repr=False)
class UploadSource:
    id: str
    credential: Secret
    max_age_seconds: int = 86400


@dataclass(frozen=True)
class IngestConfig:
    staging_dir: Path
    sources: tuple[UploadSource, ...] = field(repr=False)
    host: str = "127.0.0.1"
    port: int = 8765
    certificate: Path | None = None
    key: Path | None = field(default=None, repr=False)
    proxy_https: bool = False
    max_body_bytes: int = 12 * 1024 * 1024
    timeout_seconds: int = 15
    workers: int = 2


def load_ingest_config(filename):
    filename = Path(filename).absolute()
    try:
        data = tomllib.loads(read_bytes(filename, 1024 * 1024).decode("utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise AutomationError("ingestion_configuration_unreadable") from None
    keys(data, {"ingestion", "sources"})
    item = keys(data.get("ingestion", {}), {"version", "staging_dir", "host", "port", "certificate", "key", "proxy_https", "max_body_bytes", "timeout_seconds", "workers"})
    if type(item.get("version")) is not int or item["version"] != 1:
        raise AutomationError("ingestion_configuration_version")
    host = item.get("host", "127.0.0.1")
    try:
        address = ipaddress.ip_address(host)
        if address.is_multicast or "%" in host:
            raise ValueError()
    except (ValueError, TypeError):
        raise AutomationError("ingestion_bind_address") from None
    certificate = path(filename.parent, item["certificate"]) if "certificate" in item else None
    key = path(filename.parent, item["key"]) if "key" in item else None
    proxy = boolean(item.get("proxy_https", False))
    if bool(certificate) != bool(key) or proxy and not address.is_loopback or not address.is_loopback and not certificate:
        raise AutomationError("ingestion_remote_tls_required")
    sources, names = [], set()
    for source in tables(data.get("sources", [])):
        keys(source, {"id", "credential", "max_age_seconds"})
        name = identifier(source.get("id"), "source_id")
        if name.casefold() in names:
            raise AutomationError("duplicate_source_id")
        names.add(name.casefold())
        sources.append(UploadSource(name, Secret.parse(source.get("credential"), filename.parent),
                                    number(source.get("max_age_seconds", 86400), 1, 31536000)))
    if not sources:
        raise AutomationError("ingestion_authentication_required")
    return IngestConfig(path(filename.parent, item.get("staging_dir", "staging")), tuple(sources), host,
                        number(item.get("port", 8765), 1, 65535), certificate, key, proxy,
                        number(item.get("max_body_bytes", 12 * 1024 * 1024), 4096, MAX_ENVELOPE),
                        number(item.get("timeout_seconds", 15), 1, 120), number(item.get("workers", 2), 1, 8))


class Receiver:
    def __init__(self, config: IngestConfig):
        self.config = config
        self.credentials = {}
        for source in config.sources:
            token = source.credential.resolve()
            if len(token) < 32:
                raise AutomationError("ingestion_credential_too_short")
            if any(hmac.compare_digest(token, prior[1]) for prior in self.credentials.values()):
                raise AutomationError("ingestion_credentials_must_be_independent")
            self.credentials[source.id] = (source, token)
        self.attempts = OrderedDict()
        self.guard = threading.Lock()

    def authenticate(self, source_id, authorization, peer="127.0.0.1"):
        # Bounded per-peer admission: ten failed attempts per minute.
        current = time.monotonic()
        with self.guard:
            expired = [key for key, value in self.attempts.items() if current - value[0] > 60]
            for key in expired:
                del self.attempts[key]
            if peer not in self.attempts and len(self.attempts) >= 1024:
                raise AutomationError("ingestion_rate_limited")
            window, count = self.attempts.setdefault(peer, (current, 0))
            if count >= 10:
                raise AutomationError("ingestion_rate_limited")
        pair = self.credentials.get(source_id) if isinstance(source_id, str) else None
        expected = pair[1] if pair else "0" * 32
        supplied = authorization[7:] if isinstance(authorization, str) and authorization.startswith("Bearer ") and len(authorization) <= 16391 else ""
        valid = supplied.isascii() and hmac.compare_digest(supplied, expected) and pair is not None
        if not valid:
            with self.guard:
                self.attempts[peer] = (window, count + 1)
            raise AutomationError("ingestion_unauthorized")
        return pair[0]

    def accept(self, source: UploadSource, body: bytes):
        claimed, inventory, manifest = decode_envelope(body, self.config.max_body_bytes)
        if claimed != source.id:
            raise AutomationError("source_identity_mismatch")
        return publish(self.config.staging_dir, source.id, inventory, manifest, max_age_seconds=source.max_age_seconds)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "CVEBeacon-Ingest"
    sys_version = ""

    def log_message(self, *args):
        pass  # Request targets/headers may contain secrets; never echo them.

    def send_error(self, code, message=None, explain=None):
        self.reply(code, {"status": "rejected"})

    def reply(self, code, value):
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if code == 429:
            self.send_header("Retry-After", "60")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):
        try:
            if self.path != "/v1/snapshots":
                self.reply(404, {"status": "rejected"})
                return
            if len(self.headers) > 32 or sum(len(k) + len(v) for k, v in self.headers.items()) > 16384:
                self.reply(431, {"status": "rejected"})
                return
            for header in ("Authorization", "X-CVEBeacon-Source", "Content-Length", "Content-Type", "Content-Encoding"):
                if len(self.headers.get_all(header, [])) > 1:
                    raise AutomationError("upload_duplicate_header")
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding", "identity").lower() != "identity" or self.headers.get("Content-Type", "").lower() != "application/json":
                raise AutomationError("upload_encoding_rejected")
            source = self.server.receiver.authenticate(self.headers.get("X-CVEBeacon-Source"), self.headers.get("Authorization"), self.client_address[0])
            length = self.headers.get("Content-Length", "")
            if not length.isdigit() or not 1 <= int(length) <= self.server.receiver.config.max_body_bytes:
                self.reply(413, {"status": "rejected"})
                return
            body = self.rfile.read(int(length))
            if len(body) != int(length):
                raise AutomationError("upload_truncated_body")
            self.reply(200, self.server.receiver.accept(source, body))
        except AutomationError as exc:
            code = 401 if exc.category == "ingestion_unauthorized" else 429 if exc.category == "ingestion_rate_limited" else 409 if exc.category == "snapshot_replay_or_rollback" else 503 if exc.category == "locked" else 400
            self.reply(code, {"status": "rejected", "category": exc.category})
        except (ExtensionError, OSError, ValueError):
            try:
                self.reply(400, {"status": "rejected", "category": "upload_invalid_snapshot"})
            except OSError:
                pass

    def do_GET(self):
        self.reply(405, {"status": "rejected"})


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 8
    allow_reuse_address = False

    def __init__(self, config):
        self.address_family = socket.AF_INET6 if ipaddress.ip_address(config.host).version == 6 else socket.AF_INET
        self.receiver = Receiver(config)
        self.capacity = threading.BoundedSemaphore(config.workers)
        self.tls = None
        if config.certificate:
            try:
                regular(config.certificate)
                regular(config.key)
                if __import__("os").name == "posix" and config.key.stat().st_mode & 0o077:
                    raise AutomationError("secret_file_permissions")
                self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
                self.tls.load_cert_chain(str(config.certificate), str(config.key))
            except (OSError, ssl.SSLError):
                raise AutomationError("ingestion_tls_configuration") from None
        address = ipaddress.ip_address(config.host)
        if not address.is_loopback and not self.tls:
            raise AutomationError("ingestion_remote_tls_required")
        super().__init__((config.host, config.port), Handler)

    def process_request(self, request, client_address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.capacity.release()
            raise

    def process_request_thread(self, request, client_address):
        timer = None
        try:
            def abort():
                try:
                    request.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            request.settimeout(self.receiver.config.timeout_seconds)
            timer = threading.Timer(self.receiver.config.timeout_seconds, abort)
            timer.daemon = True
            timer.start()
            if self.tls:
                request = self.tls.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                request.do_handshake()
            self.finish_request(request, client_address)
        except (OSError, ssl.SSLError):
            pass
        finally:
            if timer:
                timer.cancel()
            self.shutdown_request(request)
            self.capacity.release()

    def handle_error(self, request, client_address):
        pass


def serve(config: IngestConfig):
    with Server(config) as server:
        server.serve_forever(poll_interval=0.5)
