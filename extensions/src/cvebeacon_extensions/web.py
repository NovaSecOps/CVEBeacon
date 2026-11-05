"""Passive, explicitly authorised web technology observation.

One bounded GET per allowlisted asset, plus at most two re-checked redirects.
The HTTP and TLS client lives here because the core client is a general JSON
source client; it is not exposed to untrusted response bodies.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import email.utils
import hashlib
import http.client
import ipaddress
from pathlib import Path
import random
import re
import socket
import ssl
import threading
import time
from typing import Callable, Iterable, Mapping
from urllib.parse import urljoin, urlsplit
import zlib

from cvebeacon.identity import validate_client_name

from . import __version__
from .contract import (ExtensionError, MAX_BYTES, _atomic, _regular, decode_json, json_bytes,
                       label, output_lock, read_bytes, timestamp, utc_now, write_snapshot)
from .webrules import detect, page_from

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
ASSET_TIMEOUT = 20.0
RUN_TIMEOUT = 15 * 60.0
BODY_LIMIT = 2 * 1024 * 1024
WIRE_LIMIT = 4 * 1024 * 1024
HEADER_LIMIT = 64 * 1024
MAX_ASSETS = 1000
MAX_WORKERS = 4
MAX_REDIRECTS = 2
MAX_RETRIES = 2
HOST_INTERVAL = 1.0
USER_AGENT = f"CVEBeacon-web-detect/{__version__}"

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
BLOCKED_STATUSES = {429, 503}
NO_RETRY_STATUSES = {401, 403, 404}
FAILURE_REASONS = {
    "unreachable", "tls-error", "blocked", "redirect-blocked", "timeout", "too-large",
    "unsupported-encoding",
}

_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PATH = re.compile(r"/[!-~]*")
_CHARSET = re.compile(r"charset\s*=\s*[\"']?([^;\"'\s]+)", re.IGNORECASE)


class _FetchFailure(Exception):
    reason = "unreachable"

    def __init__(self, detail: str, *, retry_after: int | None = None, status: int | None = None):
        super().__init__(detail)
        self.detail = detail
        self.retry_after = retry_after
        self.status = status


class _ConnectionFailure(_FetchFailure):
    reason = "unreachable"


class _TlsFailure(_FetchFailure):
    reason = "tls-error"


class _TimeoutFailure(_FetchFailure):
    reason = "timeout"


class _TooLargeFailure(_FetchFailure):
    reason = "too-large"


class _BlockedFailure(_FetchFailure):
    reason = "blocked"


class _RedirectFailure(_FetchFailure):
    reason = "redirect-blocked"


class _UnsupportedEncodingFailure(_FetchFailure):
    reason = "unsupported-encoding"


@dataclass(frozen=True, slots=True)
class Endpoint:
    scheme: str
    hostname: str
    port: int
    path: str

    @property
    def default_port(self) -> int:
        return 443 if self.scheme == "https" else 80

    @property
    def authority(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return host if self.port == self.default_port else f"{host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.path}"


@dataclass(frozen=True, slots=True)
class WebAsset:
    endpoint: Endpoint
    authorized_by: str
    authorized_at: datetime
    expires_at: datetime | None = None
    allow_redirects: bool = True
    max_redirects: int = MAX_REDIRECTS
    allow_private_address: bool = False


@dataclass(frozen=True, slots=True)
class Allowlist:
    client: str
    ca_bundle: Path | None
    assets: tuple[WebAsset, ...]

    @property
    def endpoints(self) -> frozenset[tuple[str, str, int]]:
        return frozenset((asset.endpoint.scheme, asset.endpoint.hostname, asset.endpoint.port)
                         for asset in self.assets)


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    headers: Mapping[str, tuple[str, ...]]
    body: bytes


@dataclass(frozen=True, slots=True)
class _FetchSuccess:
    response: _Response
    redirects: tuple[str, ...]
    observed_at: datetime


def _client(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExtensionError("client must be non-empty text")
    try:
        return validate_client_name(value)
    except ValueError as exc:
        raise ExtensionError(f"invalid client label: {exc}") from exc


def _bounded_text(value: object, field: str, *, maximum: int = 256, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ExtensionError(f"{field} must be text")
    text = value.strip()
    if required and not text:
        raise ExtensionError(f"{field} is required")
    if len(text) > maximum or any(ord(character) < 32 or 0xD800 <= ord(character) <= 0xDFFF for character in text):
        raise ExtensionError(f"{field} must be bounded text without control characters")
    return text


def _boolean(entry: dict, field: str, default: bool) -> bool:
    value = entry.get(field, default)
    if type(value) is not bool:
        raise ExtensionError(f"{field} must be true or false")
    return value


def _port(value: object, scheme: str, field: str = "port") -> int:
    if value is None:
        return 443 if scheme == "https" else 80
    if type(value) is not int or not 1 <= value <= 65535:
        raise ExtensionError(f"{field} must be an integer from 1 to 65535")
    return value


def _path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 2048:
        raise ExtensionError("path must be an absolute URL path of at most 2048 characters")
    if not _PATH.fullmatch(value) or "#" in value or "?" in value:
        raise ExtensionError("path must be one visible ASCII path without query or fragment")
    return value


def _hostname(value: object) -> str:
    if not isinstance(value, str):
        raise ExtensionError("hostname must be text")
    text = value.strip()
    if not text or len(text) > 253:
        raise ExtensionError("hostname must be bounded text")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if any(character.isspace() or character in "/\\@?#" for character in text):
        raise ExtensionError("hostname contains a forbidden character")
    # socket.inet_aton also accepts decimal, hexadecimal and abbreviated IPv4
    # spellings; canonicalise them so the address policy sees the real target.
    try:
        return socket.inet_ntoa(socket.inet_aton(text))
    except OSError:
        pass
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ExtensionError("hostname is not valid IDNA") from exc
    text = text.rstrip(".").lower()
    if not text or len(text) > 253:
        raise ExtensionError("hostname must be bounded text")
    labels = text.split(".")
    if any(not _HOST_LABEL.fullmatch(item) for item in labels):
        raise ExtensionError("hostname is not a valid DNS name or IP address")
    return text


def _scheme(value: object) -> str:
    if not isinstance(value, str) or value.casefold() not in {"http", "https"}:
        raise ExtensionError("scheme must be http or https")
    return value.casefold()


def _endpoint(entry: dict) -> Endpoint:
    if ("hostname" in entry) == ("url" in entry):
        raise ExtensionError("each asset must set exactly one of hostname or url")
    if "url" in entry:
        value = entry["url"]
        if not isinstance(value, str):
            raise ExtensionError("url must be text")
        try:
            parts = urlsplit(value)
            parsed_port = parts.port
            parsed_host = parts.hostname
        except ValueError as exc:
            raise ExtensionError("url is not a valid absolute URL") from exc
        if parts.scheme.casefold() not in {"http", "https"} or not parsed_host:
            raise ExtensionError("url must be an absolute http or https URL")
        if parts.username is not None or parts.password is not None:
            raise ExtensionError("url must not contain credentials")
        if parts.query or parts.fragment:
            raise ExtensionError("url must not contain a query or fragment")
        scheme = _scheme(parts.scheme)
        host = _hostname(parsed_host)
        port = _port(parsed_port, scheme)
        path = _path(parts.path or "/")
        for field, parsed in (("scheme", scheme), ("port", port), ("path", path)):
            if field in entry and entry[field] != parsed:
                raise ExtensionError(f"{field} contradicts the url")
    else:
        scheme = _scheme(entry.get("scheme", "https"))
        host = _hostname(entry["hostname"])
        port = _port(entry.get("port"), scheme)
        path = _path(entry.get("path", "/"))
    return Endpoint(scheme, host, port, path)


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ExtensionError(f"{field} must be an ISO 8601 UTC timestamp")
    try:
        return timestamp(value)
    except ExtensionError as exc:
        raise ExtensionError(f"{field} must be an ISO 8601 UTC timestamp") from exc


_ALLOWED_CONFIG = {"client", "ca_bundle", "assets"}
_ALLOWED_ASSET = {
    "hostname", "url", "scheme", "port", "path", "authorized_by", "authorized_at",
    "expires_at", "allow_redirects", "max_redirects", "allow_private_address",
}


def load_allowlist(path: Path, *, client: str, now: datetime | None = None) -> Allowlist:
    client = _client(client)
    document = decode_json(read_bytes(Path(path)))
    if not isinstance(document, dict):
        raise ExtensionError("asset allowlist must be a JSON object")
    unknown = set(document) - _ALLOWED_CONFIG
    if unknown:
        raise ExtensionError("asset allowlist contains unknown fields: " + ", ".join(sorted(unknown)))
    if "client" in document:
        declared = _client(document["client"])
        if declared != client:
            raise ExtensionError("asset allowlist belongs to a different client")
    ca_bundle = None
    if "ca_bundle" in document:
        value = document["ca_bundle"]
        if not isinstance(value, str) or not value.strip():
            raise ExtensionError("ca_bundle must be a file path")
        ca_bundle = Path(value).expanduser()
        if not ca_bundle.is_absolute():
            ca_bundle = Path(path).parent / ca_bundle
        if ca_bundle.is_symlink() or not ca_bundle.is_file():
            raise ExtensionError("ca_bundle must be a regular file")
        ca_bundle = ca_bundle.resolve()
    raw_assets = document.get("assets")
    if not isinstance(raw_assets, list) or not raw_assets:
        raise ExtensionError("assets must be a non-empty list")
    if len(raw_assets) > MAX_ASSETS:
        raise ExtensionError(f"at most {MAX_ASSETS} assets are allowed per run")
    current = now or utc_now()
    seen = set()
    assets = []
    for index, raw in enumerate(raw_assets):
        if not isinstance(raw, dict):
            raise ExtensionError(f"asset {index} must be an object")
        unknown = set(raw) - _ALLOWED_ASSET
        if unknown:
            raise ExtensionError(f"asset {index} contains unknown fields: " + ", ".join(sorted(unknown)))
        endpoint = _endpoint(raw)
        authorized_by = _bounded_text(raw.get("authorized_by"), f"asset {index} authorized_by")
        authorized_at = _timestamp(raw.get("authorized_at"), f"asset {index} authorized_at")
        if authorized_at > current:
            raise ExtensionError(f"asset {index} authorized_at is in the future")
        expires_at = None
        if "expires_at" in raw:
            expires_at = _timestamp(raw["expires_at"], f"asset {index} expires_at")
            if expires_at <= authorized_at:
                raise ExtensionError(f"asset {index} expires_at must be after authorized_at")
            if expires_at <= current:
                raise ExtensionError(f"asset {index} authorisation has expired")
        allow_redirects = _boolean(raw, "allow_redirects", True)
        max_redirects = raw.get("max_redirects", MAX_REDIRECTS)
        if type(max_redirects) is not int or not 0 <= max_redirects <= MAX_REDIRECTS:
            raise ExtensionError(f"asset {index} max_redirects must be an integer from 0 to {MAX_REDIRECTS}")
        if not allow_redirects:
            max_redirects = 0
        key = (endpoint.scheme, endpoint.hostname, endpoint.port, endpoint.path)
        if key in seen:
            raise ExtensionError(f"asset {index} duplicates another allowlist entry")
        seen.add(key)
        allow_private = _boolean(raw, "allow_private_address", False)
        for previous in assets:
            if ((previous.endpoint.scheme, previous.endpoint.hostname, previous.endpoint.port)
                    == (endpoint.scheme, endpoint.hostname, endpoint.port)
                    and previous.allow_private_address != allow_private):
                raise ExtensionError(f"asset {index} conflicts with another entry for the same endpoint")
        assets.append(WebAsset(endpoint, authorized_by, authorized_at, expires_at, allow_redirects,
                               max_redirects, allow_private))
    return Allowlist(client, ca_bundle, tuple(assets))


def format_plan(allowlist: Allowlist) -> str:
    lines = [f"client: {allowlist.client}", f"assets: {len(allowlist.assets)}"]
    normal = 0
    worst = 0
    for asset in allowlist.assets:
        maximum = 1 + (asset.max_redirects if asset.allow_redirects else 0)
        normal += maximum
        worst += maximum * (1 + MAX_RETRIES)
        lines.append(
            f"{asset.endpoint.url} GET host={asset.endpoint.hostname} port={asset.endpoint.port} "
            f"path={asset.endpoint.path} max_requests={maximum}"
        )
    lines.append(f"planned requests: {len(allowlist.assets)} assets, {normal} requests on "
                 f"the normal path, up to {worst} including connection retries")
    return "\n".join(lines)


def _is_nat64(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv6Address) and any(address in network for network in _NAT64)


def _is_public_unicast(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (address.is_multicast or address.is_reserved or address.is_unspecified
                or address.is_loopback or address.is_link_local or address.is_private) and address.is_global


def _is_global_address(value: str) -> bool:
    text = value.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        if any(address in network for network in _NAT64):
            return False
        if address.ipv4_mapped is not None:
            # IPv4-mapped forms are refused by default, even when the
            # embedded address is public. Only the per-asset attestation
            # relaxes this.
            return False
        if int(address) >> 32 == 0:
            # IPv4-compatible forms, including ::1 and ::, are refused by
            # default for the same reason.
            return False
        if not _is_public_unicast(address):
            return False
        if address.sixtofour is not None and not _is_public_unicast(address.sixtofour):
            return False
        return True
    return _is_public_unicast(address)


def _addresses(value: str, port: int) -> tuple[str, ...]:
    try:
        info = socket.getaddrinfo(value, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise _ConnectionFailure("DNS resolution failed") from exc
    except OSError as exc:
        raise _ConnectionFailure("DNS resolution failed") from exc
    result = []
    for family, _, _, _, address in info:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        candidate = address[0].split("%", 1)[0]
        if candidate not in result:
            result.append(candidate)
    if not result:
        raise _ConnectionFailure("DNS resolution returned no usable address")
    return tuple(result)


def _resolve_bounded(resolver, hostname: str, port: int, deadline: float,
                     clock: Callable[[], float]) -> tuple[str, ...]:
    """Run the resolver in a daemon worker so a wedged lookup cannot hang a run."""
    remaining = deadline - clock()
    if remaining <= 0:
        raise _TimeoutFailure("DNS resolution exceeded the asset time limit")
    outcome: dict[str, object] = {}

    def work() -> None:
        try:
            outcome["value"] = resolver.resolve(hostname, port)
        except BaseException as exc:  # propagated in the calling thread
            outcome["error"] = exc

    worker = threading.Thread(target=work, name="cvebeacon-web-resolve", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - clock()))
    if worker.is_alive():
        raise _TimeoutFailure("DNS resolution exceeded the asset time limit")
    if "error" in outcome:
        error = outcome["error"]
        if isinstance(error, BaseException):
            raise error
        raise _ConnectionFailure("DNS resolution failed")
    value = outcome.get("value", ())
    return tuple(value) if isinstance(value, (list, tuple)) else ()


class SystemResolver:
    def resolve(self, hostname: str, port: int) -> tuple[str, ...]:
        return _addresses(hostname, port)


def _header_size(headers: Iterable[tuple[str, str]]) -> int:
    return sum(len(name) + len(value) + 4 for name, value in headers)


def _check_header_size(headers: Iterable[tuple[str, str]]) -> None:
    if _header_size(headers) > HEADER_LIMIT:
        raise _TooLargeFailure("response headers exceed 64 KiB")


def _header_map(headers: Iterable[tuple[str, str]]) -> dict[str, tuple[str, ...]]:
    result: dict[str, list[str]] = {}
    for name, value in headers:
        result.setdefault(name.casefold(), []).append(value)
    return {name: tuple(values) for name, values in result.items()}


def _content_encoding(headers: Mapping[str, tuple[str, ...]]) -> str:
    values = headers.get("content-encoding", ())
    if not values:
        return ""
    parts = [part.strip().casefold() for part in ",".join(values).split(",") if part.strip()]
    if len(parts) != 1:
        raise _UnsupportedEncodingFailure("stacked content encodings are not supported")
    return parts[0]


class _BodyDecoder:
    def __init__(self, encoding: str):
        self.encoding = encoding
        self._gzip = encoding in {"gzip", "x-gzip"}
        self._deflate = encoding == "deflate"
        self._raw = False
        if self._gzip or self._deflate:
            self._object = self._new()
        else:
            raise _UnsupportedEncodingFailure("unsupported content encoding")

    def _new(self):
        if self._gzip:
            return zlib.decompressobj(16 + zlib.MAX_WBITS)
        if self._raw:
            return zlib.decompressobj(-zlib.MAX_WBITS)
        return zlib.decompressobj()

    def _decompress(self, data: bytes, limit: int) -> bytes:
        try:
            return self._object.decompress(data, limit)
        except zlib.error as exc:
            if self._deflate and not self._raw:
                self._raw = True
                self._object = self._new()
                try:
                    return self._object.decompress(data, limit)
                except zlib.error:
                    pass
            raise _UnsupportedEncodingFailure("invalid compressed response body") from exc

    def feed(self, chunk: bytes, remaining: int) -> bytes:
        output = bytearray()
        data = chunk
        while data:
            if self._object.eof:
                trailing = self._object.unused_data or self._object.unconsumed_tail
                if not trailing:
                    break
                if not self._gzip:
                    raise _UnsupportedEncodingFailure("trailing data after a complete compressed stream")
                self._object = self._new()
                data = trailing
                continue
            part = self._decompress(data, remaining - len(output) + 1)
            output.extend(part)
            if len(output) > remaining:
                raise _TooLargeFailure("decompressed body exceeds 2 MiB")
            if self._object.unconsumed_tail:
                data = self._object.unconsumed_tail
            elif self._object.eof:
                data = self._object.unused_data
            else:
                data = b""
        return bytes(output)

    def finish(self, remaining: int) -> bytes:
        try:
            part = self._object.flush()
        except zlib.error as exc:
            raise _UnsupportedEncodingFailure("invalid compressed response body") from exc
        if len(part) > remaining:
            raise _TooLargeFailure("decompressed body exceeds 2 MiB")
        if not self._object.eof:
            raise _UnsupportedEncodingFailure("compressed response body ended before the stream was complete")
        if self._object.unused_data:
            raise _UnsupportedEncodingFailure("trailing data after a complete compressed stream")
        return part


def read_body(reader, content_encoding: str, *, deadline: float | None = None,
              clock: Callable[[], float] = time.monotonic, limit: int = BODY_LIMIT,
              wire_limit: int = WIRE_LIMIT,
              before_read: Callable[[], None] | None = None) -> bytes:
    """Stream a response body, decoding gzip/deflate with a hard output cap."""
    decoder = None if content_encoding in {"", "identity"} else _BodyDecoder(content_encoding)
    output = bytearray()
    wire = 0
    while True:
        if deadline is not None and clock() >= deadline:
            raise _TimeoutFailure("response exceeded the asset time limit")
        if before_read is not None:
            before_read()
        chunk = reader.read(65536)
        if not chunk:
            break
        wire += len(chunk)
        if wire > wire_limit:
            raise _TooLargeFailure("compressed response body exceeds the wire limit")
        if decoder is None:
            output.extend(chunk)
            if len(output) > limit:
                raise _TooLargeFailure("response body exceeds 2 MiB")
        else:
            output.extend(decoder.feed(chunk, limit - len(output)))
    if decoder is not None:
        output.extend(decoder.finish(limit - len(output)))
    return bytes(output)


class _DeadlineReader:
    """Socket reader that bounds total bytes and checks the deadline per read."""

    def __init__(self, sock: socket.socket, *, deadline: float, clock: Callable[[], float],
                 limit: int, message: str):
        self._sock = sock
        self._deadline = deadline
        self._clock = clock
        self._limit = limit
        self._message = message
        self._buffer = bytearray()
        self._eof = False
        self.count = 0

    def set_limit(self, limit: int, message: str) -> None:
        self._limit = limit
        self._message = message
        self.count = 0

    def _fill(self) -> bool:
        if self._eof:
            return False
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise _TimeoutFailure("response exceeded the asset time limit")
        self._sock.settimeout(min(READ_TIMEOUT, remaining))
        try:
            data = self._sock.recv(65536)
        except (socket.timeout, TimeoutError) as exc:
            raise _TimeoutFailure("network read timed out") from exc
        if not data:
            self._eof = True
            return False
        self._buffer.extend(data)
        return True

    def _consume(self, size: int) -> bytes:
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        self.count += len(data)
        if self.count > self._limit:
            raise _TooLargeFailure(self._message)
        return data

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            while self._fill():
                pass
            return self._consume(len(self._buffer))
        while len(self._buffer) < size and not self._eof:
            if not self._fill():
                break
        return self._consume(min(size, len(self._buffer)))

    def readline(self, size: int = -1) -> bytes:
        limit = None if size is None or size < 0 else size
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                end = newline + 1
                if limit is not None:
                    end = min(end, limit)
                return self._consume(end)
            if limit is not None and len(self._buffer) >= limit:
                return self._consume(limit)
            if not self._fill():
                end = len(self._buffer) if limit is None else min(limit, len(self._buffer))
                return self._consume(end)

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def read1(self, size: int = -1) -> bytes:
        return self.read(size)

    def peek(self, size: int = -1) -> bytes:
        while not self._buffer and not self._eof:
            if not self._fill():
                break
        return bytes(self._buffer if size is None or size < 0 else self._buffer[:size])

    def settimeout(self, timeout: float | None) -> None:
        self._sock.settimeout(timeout)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        # The owning HTTPConnection closes the socket; the response object must
        # be able to detach without racing that close.
        self._buffer.clear()

    def fileno(self) -> int:
        return self._sock.fileno()


class _BoundHTTPResponse(http.client.HTTPResponse):
    def __init__(self, sock: socket.socket, *, deadline: float, clock: Callable[[], float]):
        super().__init__(sock, method="GET")
        self.fp.close()
        self.fp = _DeadlineReader(sock, deadline=deadline, clock=clock, limit=HEADER_LIMIT,
                                  message="response headers exceed 64 KiB")

    def begin(self) -> None:
        super().begin()
        self.fp.set_limit(WIRE_LIMIT, "response body exceeds the wire limit")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, *, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        family = socket.AF_INET6 if ":" in self._address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self._address, self.port))
        except BaseException:
            sock.close()
            raise
        self.sock = sock


class _PinnedHTTPSConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, *, context: ssl.SSLContext,
                 timeout: float, deadline: float, clock: Callable[[], float]):
        super().__init__(host, port, timeout=timeout)
        self._address = address
        self._context = context
        self._deadline = deadline
        self._clock = clock

    @staticmethod
    def _expire(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def connect(self) -> None:
        family = socket.AF_INET6 if ":" in self._address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        timer = None
        try:
            sock.settimeout(self.timeout)
            sock.connect((self._address, self.port))
            remaining = self._deadline - self._clock()
            if remaining <= 0:
                raise _TimeoutFailure("asset exceeded the total time limit")
            sock.settimeout(remaining)
            timer = threading.Timer(remaining, self._expire, args=(sock,))
            timer.daemon = True
            timer.start()
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise
        finally:
            if timer is not None:
                timer.cancel()


class StdlibTransport:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock

    @staticmethod
    def _context(ca_bundle: Path | None) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if ca_bundle is not None:
            context.load_verify_locations(cafile=str(ca_bundle))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def _timeout(self, socket_, deadline: float) -> None:
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise _TimeoutFailure("asset exceeded the total time limit")
        socket_.settimeout(min(READ_TIMEOUT, remaining))

    def fetch(self, endpoint: Endpoint, address: str, *, ca_bundle: Path | None,
              deadline: float, user_agent: str) -> _Response:
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise _TimeoutFailure("asset exceeded the total time limit")
        connect_timeout = min(CONNECT_TIMEOUT, remaining)
        if endpoint.scheme == "https":
            try:
                context = self._context(ca_bundle)
            except (ssl.SSLError, OSError) as exc:
                raise _TlsFailure("TLS trust store could not be loaded") from exc
            connection = _PinnedHTTPSConnection(endpoint.hostname, endpoint.port, address,
                                                context=context, timeout=connect_timeout,
                                                deadline=deadline, clock=self._clock)
        else:
            connection = _PinnedHTTPConnection(endpoint.hostname, endpoint.port, address,
                                               timeout=connect_timeout)
        try:
            connection.connect()
            self._timeout(connection.sock, deadline)
            connection.request("GET", endpoint.path, headers={
                "Host": endpoint.authority,
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Connection": "close",
            })
            response = _BoundHTTPResponse(connection.sock, deadline=deadline, clock=self._clock)
            response.begin()
            items = response.getheaders()
            _check_header_size(items)
            headers = _header_map(items)
            if not 200 <= response.status < 300:
                # Redirect and error bodies are not part of the observation.
                # Reading status first also lets the caller stop a host before
                # any body decoding can fail.
                return _Response(response.status, headers, b"")
            body = read_body(response, _content_encoding(headers), deadline=deadline,
                             clock=self._clock,
                             before_read=lambda: self._timeout(connection.sock, deadline))
            return _Response(response.status, headers, body)
        except ssl.SSLError as exc:
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit") from exc
            raise _TlsFailure("TLS verification or handshake failed") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise _TimeoutFailure("network read timed out") from exc
        except http.client.LineTooLong as exc:
            raise _TooLargeFailure("a response header line exceeded the limit") from exc
        except (ConnectionError, OSError) as exc:
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit") from exc
            raise _ConnectionFailure("connection failed") from exc
        except http.client.HTTPException as exc:
            raise _ConnectionFailure("invalid HTTP response") from exc
        finally:
            connection.close()


class _Pacer:
    def __init__(self, *, sleep: Callable[[float], None], clock: Callable[[], float],
                 interval: float):
        self._sleep = sleep
        self._clock = clock
        self._interval = interval
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, hostname: str, deadline: float | None = None) -> None:
        if self._interval <= 0:
            return
        while True:
            now = self._clock()
            remaining = None if deadline is None else deadline - now
            if remaining is not None and remaining <= 0:
                raise _TimeoutFailure("pacing exceeded the asset time limit")
            with self._lock:
                previous = self._last.get(hostname)
                delay = self._interval - (now - previous) if previous is not None else 0.0
                if delay <= 0:
                    self._last[hostname] = now
                    return
            if remaining is not None:
                delay = min(delay, remaining)
            before = self._clock()
            if delay > 0:
                self._sleep(delay)
            if remaining is not None and self._clock() >= deadline:
                raise _TimeoutFailure("pacing exceeded the asset time limit")
            if self._clock() <= before:
                # A test seam or a clock with insufficient resolution must not
                # spin forever. Real sleeping always advances the clock.
                with self._lock:
                    self._last[hostname] = self._clock()
                return


class Fetcher:
    def __init__(self, *, resolver=None, transport=None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic, now: Callable[[], datetime] = utc_now,
                 rng: random.Random | None = None, host_interval: float = HOST_INTERVAL):
        self.resolver = resolver or SystemResolver()
        self.transport = transport or StdlibTransport(clock=clock)
        self._sleep = sleep
        self._clock = clock
        self._now = now
        self._rng = rng or random.Random()
        self._pacer = _Pacer(sleep=sleep, clock=clock, interval=host_interval)
        self._blocked: dict[str, int | None] = {}
        self._lock = threading.Lock()

    def _blocked_info(self, hostname: str):
        with self._lock:
            return self._blocked.get(hostname, False)

    def _block(self, hostname: str, retry_after: int | None) -> None:
        with self._lock:
            self._blocked[hostname] = retry_after

    @staticmethod
    def _retry_after(value: str | None) -> int | None:
        if not value:
            return None
        text = value.strip()
        try:
            number = float(text)
        except (TypeError, ValueError, OverflowError):
            number = None
        if number is not None:
            if number != number or number in {float("inf"), float("-inf")}:
                return None
            if number <= 0:
                return 0
            return min(int(min(number, 86400.0)), 86400)
        try:
            parsed = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, OverflowError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return min(max(int((parsed - datetime.now(timezone.utc)).total_seconds()), 0), 86400)

    def _address(self, endpoint: Endpoint, asset: WebAsset, deadline: float) -> str:
        addresses = _resolve_bounded(self.resolver, endpoint.hostname, endpoint.port, deadline,
                                     self._clock)
        if not addresses:
            raise _ConnectionFailure("DNS resolution returned no address")
        accepted = []
        for value in addresses:
            if _is_nat64(value):
                raise _BlockedFailure("NAT64 addresses are not authorised")
            if _is_global_address(value):
                accepted.append(value)
            elif asset.allow_private_address:
                accepted.append(value)
            else:
                raise _BlockedFailure("non-global address is not authorised")
        if not accepted:
            raise _BlockedFailure("non-global address is not authorised")
        return accepted[0]

    def _request(self, endpoint: Endpoint, asset: WebAsset, deadline: float,
                 ca_bundle: Path | None) -> _Response:
        attempt = 0
        while True:
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit")
            blocked = self._blocked_info(endpoint.hostname)
            if blocked is not False:
                detail = "host stopped after a rate-limit response"
                raise _BlockedFailure(detail, retry_after=blocked)
            try:
                address = self._address(endpoint, asset, deadline)
                self._pacer.wait(endpoint.hostname, deadline)
                blocked = self._blocked_info(endpoint.hostname)
                if blocked is not False:
                    raise _BlockedFailure("host stopped after a rate-limit response",
                                          retry_after=blocked)
                if self._clock() >= deadline:
                    raise _TimeoutFailure("asset exceeded the total time limit")
                response = self.transport.fetch(endpoint, address, ca_bundle=ca_bundle,
                                                deadline=deadline, user_agent=USER_AGENT)
            except _ConnectionFailure as exc:
                if attempt >= MAX_RETRIES or self._clock() >= deadline:
                    raise
                attempt += 1
                base = min(0.5 * (2 ** (attempt - 1)), max(0.0, deadline - self._clock()))
                delay = base * (0.75 + 0.5 * self._rng.random())
                if delay > 0:
                    self._sleep(delay)
                continue
            if response.status in BLOCKED_STATUSES:
                retry_after = self._retry_after(response.headers.get("retry-after", (None,))[0])
                self._block(endpoint.hostname, retry_after)
                raise _BlockedFailure(f"HTTP {response.status}", retry_after=retry_after,
                                      status=response.status)
            if response.status in {401, 403}:
                raise _BlockedFailure(f"HTTP {response.status}", status=response.status)
            if response.status in NO_RETRY_STATUSES:
                # A missing page is a real HTTP answer, not a clean observation.
                raise _ConnectionFailure(f"HTTP {response.status}", status=response.status)
            return response

    def _redirect(self, current: Endpoint, location: str, allowlist: Allowlist) -> Endpoint:
        try:
            target = urlsplit(urljoin(current.url, location))
            target_port = target.port
            target_host = target.hostname
        except ValueError as exc:
            raise _RedirectFailure("redirect target is not a valid URL") from exc
        if target.scheme.casefold() not in {"http", "https"} or not target_host:
            raise _RedirectFailure("redirect target is not an absolute http or https URL")
        if target.username is not None or target.password is not None:
            raise _RedirectFailure("redirect target contains credentials")
        if target.fragment:
            raise _RedirectFailure("redirect target contains a fragment")
        scheme = target.scheme.casefold()
        if current.scheme == "https" and scheme == "http":
            raise _RedirectFailure("HTTPS to HTTP downgrade is not allowed")
        try:
            hostname = _hostname(target_host)
            port = _port(target_port, scheme)
        except ExtensionError as exc:
            raise _RedirectFailure("redirect target is not a valid host and port") from exc
        path = (target.path or "/") + (("?" + target.query) if target.query else "")
        if len(path) > 2048:
            raise _RedirectFailure("redirect target path and query exceed 2048 characters")
        if not _PATH.fullmatch(target.path or "/") or any(
                ord(character) < 33 or ord(character) > 126 for character in path):
            raise _RedirectFailure("redirect target has an invalid path")
        if (scheme, hostname, port) not in allowlist.endpoints:
            raise _RedirectFailure("redirect target is not an allowlisted host and port")
        return Endpoint(scheme, hostname, port, path)

    def fetch(self, asset: WebAsset, allowlist: Allowlist, *, run_deadline: float | None = None) -> _FetchSuccess:
        deadline = self._clock() + ASSET_TIMEOUT
        if run_deadline is not None:
            deadline = min(deadline, run_deadline)
        current = asset.endpoint
        redirects: list[str] = []
        observed_at = self._now()
        for hop in range(asset.max_redirects + 1):
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit")
            response = self._request(current, asset, deadline, allowlist.ca_bundle)
            if response.status not in REDIRECT_STATUSES:
                if not 200 <= response.status < 300:
                    raise _ConnectionFailure(f"HTTP {response.status}", status=response.status)
                return _FetchSuccess(response, tuple(redirects), observed_at)
            if not asset.allow_redirects or hop >= asset.max_redirects:
                raise _RedirectFailure("redirect limit reached", status=response.status)
            locations = response.headers.get("location", ())
            if not locations:
                raise _RedirectFailure("redirect response has no Location", status=response.status)
            target = self._redirect(current, locations[0], allowlist)
            redirects.append(target.url)
            current = target
        raise _RedirectFailure("redirect limit reached")


def _decode_html(body: bytes, headers: Mapping[str, tuple[str, ...]]) -> str:
    content_type = " ".join(headers.get("content-type", ()))
    charset = _CHARSET.search(content_type)
    candidates = []
    if charset:
        candidates.append(charset.group(1))
    candidates.extend(("utf-8", "cp1252", "latin-1"))
    for encoding in candidates:
        try:
            return body.decode(encoding, errors="replace")
        except (LookupError, UnicodeError):
            continue
    return body.decode("utf-8", errors="replace")


def _system_id(client: str, endpoint: Endpoint) -> str:
    value = f"{client}\0{endpoint.hostname}".encode("utf-8")
    return "web-" + hashlib.sha256(value).hexdigest()[:16]


def _asset_id(client: str, endpoint: Endpoint, vendor: str, product: str) -> str:
    value = "\0".join((client, endpoint.scheme, endpoint.hostname, str(endpoint.port),
                       endpoint.path, vendor, product)).encode("utf-8")
    return "web-" + hashlib.sha256(value).hexdigest()[:32]


def _preferred_version(versions: tuple[str, ...]) -> str | None:
    """Return the most specific version when every value is a prefix of it."""
    if not versions:
        return ""
    ordered = sorted(versions, key=lambda value: (value.count("."), len(value), value))
    longest = ordered[-1]
    for value in ordered[:-1]:
        if longest != value and not longest.startswith(value + ".") and not longest.startswith(value + "-"):
            return None
    return longest


@dataclass(slots=True)
class _AssetResult:
    asset: WebAsset
    rows: list[dict]
    reviews: list[dict]
    omissions: set[str]
    observed_at: datetime | None
    failure: _FetchFailure | None = None


def _observe(asset: WebAsset, allowlist: Allowlist, fetcher: Fetcher, *,
             run_deadline: float) -> _AssetResult:
    system_id = _system_id(allowlist.client, asset.endpoint)
    base = {"asset_id": _asset_id(allowlist.client, asset.endpoint, "", ""),
            "system_id": system_id}
    if fetcher._clock() >= run_deadline:
        failure = _TimeoutFailure("run exceeded the total time limit")
        return _AssetResult(asset, [], [dict(base, reason=failure.reason, detail=failure.detail)],
                            {failure.reason}, None, failure)
    try:
        success = fetcher.fetch(asset, allowlist, run_deadline=run_deadline)
    except _FetchFailure as failure:
        review = dict(base, reason=failure.reason, detail=failure.detail)
        if failure.status is not None:
            review["status"] = failure.status
        if failure.retry_after is not None:
            review["retry_after"] = failure.retry_after
        return _AssetResult(asset, [], [review], {failure.reason}, None, failure)
    page = page_from(success.response.headers, _decode_html(success.response.body,
                                                           success.response.headers))
    detections = detect(page)
    rows: list[dict] = []
    reviews: list[dict] = []
    omissions: set[str] = set()
    if not detections:
        reviews.append(dict(base, reason="no-technologies", detail="fetch succeeded; no direct evidence matched"))
        omissions.add("no-technologies")
    for detection in detections:
        display = f"{detection.vendor}/{detection.product}"
        row_id = _asset_id(allowlist.client, asset.endpoint, detection.vendor,
                           detection.product)
        detail = dict(base, asset_id=row_id)
        preferred = _preferred_version(detection.versions)
        if preferred is None:
            reviews.append(dict(detail, reason="version-conflict", product=display,
                                category=detection.category, versions=list(detection.versions),
                                confidence=detection.confidence))
            omissions.add("version-conflict")
            continue
        version = preferred
        if not version and not detection.cpe:
            # The core product identity requires a version unless an explicit
            # CPE carries the identity. Keep the observation as a review item
            # rather than inventing a version or a CPE.
            reviews.append(dict(detail, reason="version-unknown", product=display,
                                category=detection.category,
                                confidence=detection.confidence))
            omissions.add("version-unknown")
            continue
        rows.append({
            "asset_id": row_id,
            "vendor": detection.vendor,
            "product": detection.product,
            "version": version,
            "category": detection.category,
            "system_id": system_id,
            "ecosystem": "",
            "purl": "",
            "cpe": detection.cpe,
            "repository": "",
            "commit": "",
            "client": allowlist.client,
        })
        if not version:
            reviews.append(dict(detail, reason="version-unknown", product=display,
                                category=detection.category, confidence=detection.confidence))
            omissions.add("version-unknown")
    return _AssetResult(asset, rows, reviews, omissions, success.observed_at)


def _review_path(output: Path) -> Path:
    return Path(str(output) + ".review.json")


def _publish_review(output: Path, client: str, source_id: str, reviews: list[dict]) -> None:
    data = json_bytes(dict(client=client, source_id=source_id, reviews=reviews))
    if len(data) > MAX_BYTES:
        raise ExtensionError("review output exceeds size limit")
    destination = _review_path(output)
    if destination.exists() or destination.is_symlink():
        _regular(destination)
    _atomic(destination, data)


def detect_web(path: Path, output: Path, *, client: str, source_id: str,
               allow_partial: bool = False, plan: bool = False,
               resolver=None, transport=None, sleep: Callable[[float], None] = time.sleep,
               clock: Callable[[], float] = time.monotonic,
               now: Callable[[], datetime] = utc_now,
               host_interval: float = HOST_INTERVAL,
               max_workers: int = MAX_WORKERS) -> dict | None:
    label(source_id)
    output = Path(output)
    destinations = {output.resolve(), Path(str(output) + ".manifest.json").resolve(),
                    _review_path(output).resolve(), Path(str(output) + ".lock").resolve()}
    if Path(path).resolve() in destinations:
        raise ExtensionError("output must not overwrite the asset allowlist")
    allowlist = load_allowlist(Path(path), client=client, now=now())
    if allowlist.ca_bundle is not None and allowlist.ca_bundle.resolve() in destinations:
        raise ExtensionError("output must not overwrite the CA bundle")
    if plan:
        print(format_plan(allowlist))
        return None
    fetcher = Fetcher(resolver=resolver, transport=transport, sleep=sleep, clock=clock,
                      now=now, host_interval=host_interval)
    run_deadline = clock() + RUN_TIMEOUT
    results: list[_AssetResult] = []
    workers = max(1, min(max_workers, MAX_WORKERS, len(allowlist.assets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_observe, asset, allowlist, fetcher, run_deadline=run_deadline)
                   for asset in allowlist.assets]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: item.asset.endpoint.url)
    rows = [row for result in results for row in result.rows]
    reviews = [review for result in results for review in result.reviews]
    reviews.sort(key=lambda item: (item["asset_id"], item["reason"], item.get("product", ""),
                                   item.get("detail", "")))
    omissions = sorted({reason for result in results for reason in result.omissions})
    observed = [result.observed_at for result in results if result.observed_at is not None]
    with output_lock(output):
        _publish_review(output, client, source_id, reviews)
        if not rows:
            raise ExtensionError("no technologies with usable identity; review output written")
        if set(omissions) & FAILURE_REASONS and not allow_partial:
            raise ExtensionError("web detection with fetch failures requires --allow-partial; review output written")
        return write_snapshot(output, rows, source_id=source_id, collector="web-detect",
                              observed_at=min(observed).isoformat() if observed else None,
                              omissions=omissions, lock=False)
