"""Direct verified HTTPS, no redirects/proxies, bounded DNS/IO and safe errors."""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from .common import AutomationError

_RESOLVERS = threading.BoundedSemaphore(4)


class TransportError(AutomationError):
    def __init__(self, category, transmitted=False):
        super().__init__(category)
        self.transmitted = transmitted


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    path: str

    @property
    def origin(self):
        return self.host, self.port


def endpoint(url: str) -> Endpoint:
    try:
        if not isinstance(url, str) or len(url) > 16384 or any(ord(c) <= 32 or ord(c) >= 127 for c in url) or "\\" in url:
            raise ValueError()
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None or parsed.fragment or not parsed.hostname:
            raise ValueError()
        host = parsed.hostname.lower()
        if "%" in host:
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host) or ".." in host:
                raise ValueError()
        port = parsed.port or 443
        if not 1 <= port <= 65535:
            raise ValueError()
        return Endpoint(host, port, (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""))
    except (ValueError, TypeError, AttributeError):
        raise AutomationError("invalid_https_endpoint") from None


def tls_context(ca_file=None):
    # create_default_context can honor SSLKEYLOGFILE; construct explicitly instead.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if ca_file:
        context.load_verify_locations(cafile=str(ca_file))
    else:
        context.load_default_certs()
    return context


def resolve(host, port, timeout):
    if not _RESOLVERS.acquire(blocking=False):
        raise TransportError("dns_capacity")
    results, errors = [], []
    def worker():
        try:
            results.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[:16])
        except OSError:
            errors.append(True)
        finally:
            _RESOLVERS.release()
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive() or errors or not results:
        raise TransportError("dns_failure")
    return results


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


class HTTPS:
    """One request at a time per instance; only the configured origin is reachable."""

    def __init__(self, origin_url, *, ca_file=None, timeout=15, max_body=48 * 1024 * 1024, max_response=1024 * 1024):
        self.allowed = endpoint(origin_url).origin
        if type(timeout) not in (int, float) or not 1 <= timeout <= 120 or not 1 <= max_body <= 48 * 1024 * 1024 or not 1 <= max_response <= 32 * 1024 * 1024:
            raise AutomationError("invalid_http_bound")
        self.context = tls_context(ca_file)
        self.timeout, self.max_body, self.max_response = timeout, max_body, max_response
        self.busy = threading.Lock()

    def request(self, method, url, *, headers=None, body=b""):
        target = endpoint(url)
        if target.origin != self.allowed or method not in {"GET", "POST", "PUT"}:
            raise TransportError("endpoint_outside_allowlist")
        if not isinstance(body, bytes) or len(body) > self.max_body:
            raise TransportError("http_body_limit")
        if not self.busy.acquire(blocking=False):
            raise TransportError("http_capacity")
        connection = http.client.HTTPConnection(target.host, target.port, timeout=self.timeout)
        transmitted = False
        timer = None
        raw_socket = None
        deadline = time.monotonic() + self.timeout
        def remaining():
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError()
            return left
        def abort():
            sock = connection.sock or raw_socket
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        try:
            addresses = resolve(target.host, target.port, remaining())
            timer = threading.Timer(remaining(), abort)
            timer.daemon = True
            timer.start()
            for family, socktype, protocol, _, address in addresses[:4]:
                raw_socket = socket.socket(family, socktype, protocol)
                raw_socket.settimeout(remaining())
                try:
                    raw_socket.connect(address)
                    connection.sock = self.context.wrap_socket(raw_socket, server_hostname=target.host)
                    connection.sock.settimeout(remaining())
                    break
                except (OSError, ssl.SSLError):
                    raw_socket.close()
                    raw_socket = None
            if connection.sock is None:
                raise OSError()
            outgoing = {"Accept-Encoding": "identity", "User-Agent": "CVEBeacon-Automation/0.1", "Connection": "close"}
            outgoing.update(headers or {})
            if len(outgoing) > 16 or any(not re.fullmatch(r"[A-Za-z0-9-]+", key) or not isinstance(value, str) or len(value) > 16384 or any(ord(c) < 32 or ord(c) > 126 for c in value) for key, value in outgoing.items()):
                raise TransportError("http_headers_invalid")
            transmitted = True  # A partial write cannot be proved unsent.
            connection.request(method, target.path, body=body, headers=outgoing)
            response = connection.getresponse()
            pairs = response.getheaders()
            if len(pairs) > 64 or sum(len(k) + len(v) for k, v in pairs) > 65536:
                raise TransportError("http_headers_limit", True)
            received = {}
            for key, value in pairs:
                key = key.lower()
                if key in received and key in {"content-length", "retry-after", "location", "www-authenticate", "link"}:
                    raise TransportError("http_duplicate_header", True)
                received[key] = value
            if received.get("content-encoding", "identity").lower() != "identity":
                raise TransportError("http_encoding_rejected", True)
            length = received.get("content-length")
            if length is not None and (not length.isdigit() or int(length) > self.max_response):
                raise TransportError("http_response_limit", True)
            data = response.read(self.max_response + 1)
            remaining()
            if len(data) > self.max_response:
                raise TransportError("http_response_limit", True)
            if length is not None and len(data) != int(length):
                raise TransportError("http_truncated_response", True)
            return Response(response.status, received, data)
        except TransportError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError, TimeoutError):
            raise TransportError("http_outcome_unknown" if transmitted else "http_connect_failure", transmitted) from None
        finally:
            if timer:
                timer.cancel()
            connection.close()
            if raw_socket:
                raw_socket.close()
            self.busy.release()
