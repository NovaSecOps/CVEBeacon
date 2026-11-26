"""Passive, explicitly authorised web technology observation.

One bounded GET per allowlisted asset, plus at most ten re-checked redirects.
The HTTP and TLS client lives here because the core client is a general JSON
source client; it is not exposed to untrusted response bodies.
"""

from __future__ import annotations

from collections import Counter, deque
from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
    TimeoutError as FutureTimeoutError,
    as_completed,
)
from dataclasses import dataclass, field
from datetime import datetime, timezone
import email.utils
import hashlib
import http.client
from html.parser import HTMLParser
import ipaddress
from pathlib import Path
import queue
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
                       label, output_lock, read_bytes, read_snapshot, timestamp, utc_now,
                       write_snapshot)
from .webrules import Resource, detect, package_url, page_from

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
ASSET_TIMEOUT = 20.0
RUN_TIMEOUT = 60 * 60.0
BODY_LIMIT = 2 * 1024 * 1024
WIRE_LIMIT = 4 * 1024 * 1024
HEADER_LIMIT = 64 * 1024
MAX_ASSETS = 1000
MAX_WORKERS = 4
DEFAULT_REDIRECTS = 2
MAX_REDIRECTS = 10
MAX_RETRIES = 2
HOST_INTERVAL = 1.0
USER_AGENT = f"CVEBeacon-web-detect/{__version__}"

# Browser-referenced resources: at most 300 unique, authorised files per site,
# each with at most 10 MiB decoded and 20 MiB on the wire, and at most 96 MiB
# decoded across the site's files. The resource phase has a 180-second budget,
# with at least 100 ms between same-host requests. A 5-second run-deadline
# margin prevents starting a file that could delay the page's own result.
RESOURCE_MAX_FILES = 300
RESOURCE_FILE_LIMIT = 10 * 1024 * 1024
RESOURCE_WIRE_LIMIT = 20 * 1024 * 1024
RESOURCE_SITE_LIMIT = 96 * 1024 * 1024
RESOURCE_SITE_TIMEOUT = 180.0
RESOURCE_MIN_HOST_INTERVAL = 0.1
RESOURCE_RUN_DEADLINE_GUARD = 5.0

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
BLOCKED_STATUSES = {429, 503}
NO_RETRY_STATUSES = {401, 403, 404}
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PATH = re.compile(r"/[!-~]*")
_CHARSET = re.compile(r"charset\s*=\s*[\"']?([^;\"'\s]+)", re.IGNORECASE)
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]+")


class _FetchFailure(Exception):
    reason = "unreachable"

    def __init__(self, detail: str, *, retry_after: int | None = None, status: int | None = None,
                 redirect_target: dict | None = None, redirects_followed: int | None = None):
        super().__init__(detail)
        self.detail = detail
        self.retry_after = retry_after
        self.status = status
        self.redirect_target = redirect_target
        self.redirects_followed = redirects_followed


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
    max_redirects: int = DEFAULT_REDIRECTS
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
    final_endpoint: Endpoint | None = None


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
        max_redirects = raw.get("max_redirects", DEFAULT_REDIRECTS)
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
    lines.append(f"planned page requests: {len(allowlist.assets)} assets, {normal} requests on "
                 f"the normal path, up to {worst} including connection retries")
    lines.append(f"browser-referenced resources: up to {RESOURCE_MAX_FILES} additional authorised "
                 "files per site; each uses the same redirect, retry and address checks")
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
        if address.sixtofour is not None:
            # Some ipaddress releases classify 2002::/16 as private. Decide
            # the 6to4 policy from the embedded IPv4 address explicitly so it
            # does not vary with the runtime.
            return _is_public_unicast(address.sixtofour)
        if not _is_public_unicast(address):
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


class _ResolverPool:
    """Bounded daemon workers shared by one Fetcher's resolver calls."""

    def __init__(self, workers: int):
        self._workers = max(1, min(int(workers), MAX_WORKERS))
        self._tasks: queue.Queue = queue.Queue()
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._closed = False

    def _start_worker(self) -> None:
        with self._lock:
            if self._closed:
                raise _ConnectionFailure("DNS resolver pool is closed")
            if len(self._threads) >= self._workers:
                return
            worker = threading.Thread(target=self._work, name="cvebeacon-web-resolve",
                                      daemon=True)
            try:
                worker.start()
            except Exception as exc:
                raise _ConnectionFailure("DNS resolver worker could not start") from exc
            self._threads.append(worker)

    def _work(self) -> None:
        while True:
            task = self._tasks.get()
            if task is None:
                return
            resolver, hostname, port, future = task
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(resolver.resolve(hostname, port))
            except BaseException as exc:  # propagated in the calling thread
                future.set_exception(exc)

    def resolve(self, resolver, hostname: str, port: int, deadline: float,
                clock: Callable[[], float]):
        if deadline - clock() <= 0:
            raise _TimeoutFailure("DNS resolution exceeded the asset time limit")
        self._start_worker()
        future: Future = Future()
        try:
            self._tasks.put_nowait((resolver, hostname, port, future))
        except Exception as exc:
            raise _ConnectionFailure("DNS resolution could not be scheduled") from exc
        try:
            return future.result(timeout=max(0.0, deadline - clock()))
        except FutureTimeoutError as exc:
            raise _TimeoutFailure("DNS resolution exceeded the asset time limit") from exc

    def close(self) -> None:
        with self._lock:
            threads = list(self._threads)
            self._threads.clear()
            self._closed = True
        for _ in threads:
            self._tasks.put_nowait(None)


def _resolve_bounded(pool: _ResolverPool, resolver, hostname: str, port: int, deadline: float,
                     clock: Callable[[], float]) -> tuple[str, ...]:
    """Resolve through the bounded pool so a wedged lookup cannot leak workers."""
    value = pool.resolve(resolver, hostname, port, deadline, clock)
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
                if not self._gzip:
                    raise _UnsupportedEncodingFailure("trailing data after a complete compressed stream")
                if trailing:
                    data = trailing
                self._object = self._new()
                continue
            part = self._decompress(data, remaining - len(output) + 1)
            output.extend(part)
            if len(output) > remaining:
                raise _TooLargeFailure("decompressed body exceeds its byte limit")
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
            raise _TooLargeFailure("decompressed body exceeds its byte limit")
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
                raise _TooLargeFailure("response body exceeds its byte limit")
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
            # A read-to-EOF must never buffer past the remaining wire budget.
            while not self._eof and self.count + len(self._buffer) <= self._limit:
                if not self._fill():
                    break
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
    def __init__(self, sock: socket.socket, *, deadline: float, clock: Callable[[], float],
                 wire_limit: int = WIRE_LIMIT):
        super().__init__(sock, method="GET")
        self.fp.close()
        self.fp = _DeadlineReader(sock, deadline=deadline, clock=clock, limit=HEADER_LIMIT,
                                  message="response headers exceed 64 KiB")
        self._wire_limit = wire_limit

    def begin(self) -> None:
        super().begin()
        self.fp.set_limit(self._wire_limit, "response body exceeds the wire limit")

    def _read_next_chunk_size(self) -> int:
        # int(line, 16) accepts signed values, which would turn the following
        # read into an unbounded read-to-EOF. Chunk sizes are unsigned hex.
        line = self.fp.readline(http.client._MAXLINE + 1)
        if len(line) > http.client._MAXLINE:
            raise http.client.LineTooLong("chunk size")
        size = line.split(b";", 1)[0].strip()
        if not _CHUNK_SIZE.fullmatch(size):
            self._close_conn()
            raise ValueError("invalid chunk size")
        return int(size, 16)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, *, timeout: float,
                 connect_deadline: float, clock: Callable[[], float]):
        super().__init__(host, port, timeout=timeout)
        self._address = address
        self._connect_deadline = connect_deadline
        self._clock = clock

    def connect(self) -> None:
        remaining = self._connect_deadline - self._clock()
        if remaining <= 0:
            raise _TimeoutFailure("connection setup exceeded the time limit")
        family = socket.AF_INET6 if ":" in self._address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(min(self.timeout, remaining))
            sock.connect((self._address, self.port))
        except BaseException:
            sock.close()
            raise
        self.sock = sock


class _PinnedHTTPSConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, *, context: ssl.SSLContext,
                 timeout: float, deadline: float, connect_deadline: float,
                 clock: Callable[[], float]):
        super().__init__(host, port, timeout=timeout)
        self._address = address
        self._context = context
        self._deadline = deadline
        self._connect_deadline = connect_deadline
        self._clock = clock

    @staticmethod
    def _expire(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _setup_remaining(self) -> float:
        return min(self._deadline, self._connect_deadline) - self._clock()

    def connect(self) -> None:
        remaining = self._setup_remaining()
        if remaining <= 0:
            raise _TimeoutFailure("connection setup exceeded the time limit")
        family = socket.AF_INET6 if ":" in self._address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        timer = None
        try:
            sock.settimeout(remaining)
            sock.connect((self._address, self.port))
            remaining = self._setup_remaining()
            if remaining <= 0:
                raise _TimeoutFailure("connection setup exceeded the time limit")
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
              deadline: float, user_agent: str,
              request_headers: Mapping[str, str] | None = None,
              body_limit: int = BODY_LIMIT, wire_limit: int = WIRE_LIMIT) -> _Response:
        now = self._clock()
        remaining = deadline - now
        if remaining <= 0:
            raise _TimeoutFailure("asset exceeded the total time limit")
        connect_timeout = min(CONNECT_TIMEOUT, remaining)
        connect_deadline = now + connect_timeout
        if endpoint.scheme == "https":
            try:
                context = self._context(ca_bundle)
            except (ssl.SSLError, OSError) as exc:
                raise _TlsFailure("TLS trust store could not be loaded") from exc
            connection = _PinnedHTTPSConnection(endpoint.hostname, endpoint.port, address,
                                                context=context, timeout=connect_timeout,
                                                deadline=deadline,
                                                connect_deadline=connect_deadline,
                                                clock=self._clock)
        else:
            connection = _PinnedHTTPConnection(endpoint.hostname, endpoint.port, address,
                                               timeout=connect_timeout,
                                               connect_deadline=connect_deadline,
                                               clock=self._clock)
        setup_complete = False
        try:
            connection.connect()
            setup_complete = True
            self._timeout(connection.sock, deadline)
            headers = {
                "Host": endpoint.authority,
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Connection": "close",
            }
            if request_headers:
                for name, value in request_headers.items():
                    if (name.casefold() not in {"accept", "referer"}
                            or any(character in name + value for character in "\r\n")):
                        raise _FetchFailure("request header is not authorised")
                    headers[name] = value
            connection.request("GET", endpoint.path, headers=headers)
            response = _BoundHTTPResponse(connection.sock, deadline=deadline, clock=self._clock,
                                          wire_limit=wire_limit)
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
                             clock=self._clock, limit=body_limit, wire_limit=wire_limit,
                             before_read=lambda: self._timeout(connection.sock, deadline))
            return _Response(response.status, headers, body)
        except ssl.SSLError as exc:
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit") from exc
            if not setup_complete and self._clock() >= connect_deadline:
                raise _TimeoutFailure("connection setup exceeded the time limit") from exc
            raise _TlsFailure("TLS verification or handshake failed") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise _TimeoutFailure("network read timed out") from exc
        except http.client.LineTooLong as exc:
            raise _TooLargeFailure("a response header line exceeded the limit") from exc
        except (ConnectionError, OSError) as exc:
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit") from exc
            if not setup_complete and self._clock() >= connect_deadline:
                raise _TimeoutFailure("connection setup exceeded the time limit") from exc
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

    def wait(self, hostname: str, deadline: float | None = None, *,
             minimum_interval: float = 0.0) -> None:
        interval = max(self._interval, minimum_interval)
        if interval <= 0:
            return
        while True:
            now = self._clock()
            remaining = None if deadline is None else deadline - now
            if remaining is not None and remaining <= 0:
                raise _TimeoutFailure("pacing exceeded the asset time limit")
            with self._lock:
                previous = self._last.get(hostname)
                delay = interval - (now - previous) if previous is not None else 0.0
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


@dataclass(slots=True)
class _ResourceSiteState:
    lock: threading.RLock = field(default_factory=threading.RLock)
    started_at: float | None = None
    deadline: float | None = None
    requested_files: int = 0
    decoded_bytes: int = 0
    seen_urls: set[str] = field(default_factory=set)
    file_metadata: dict[str, tuple[str, int]] = field(default_factory=dict)
    file_detections: dict[str, tuple[object, ...]] = field(default_factory=dict)


class Fetcher:
    def __init__(self, *, resolver=None, transport=None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic, now: Callable[[], datetime] = utc_now,
                 rng: random.Random | None = None, host_interval: float = HOST_INTERVAL):
        self.resolver = resolver or SystemResolver()
        self._resolver_pool = _ResolverPool(MAX_WORKERS)
        self.transport = transport or StdlibTransport(clock=clock)
        self._sleep = sleep
        self._clock = clock
        self._now = now
        self._rng = rng or random.Random()
        self._pacer = _Pacer(sleep=sleep, clock=clock, interval=host_interval)
        self.request_count = 0
        self._blocked: dict[str, int | None] = {}
        self._lock = threading.Lock()
        self._host_locks: dict[str, threading.Lock] = {}
        self._resource_sites: dict[tuple[str, str, int], _ResourceSiteState] = {}

    def close(self) -> None:
        self._resolver_pool.close()

    def _blocked_info(self, hostname: str):
        with self._lock:
            return self._blocked.get(hostname, False)

    def _block(self, hostname: str, retry_after: int | None) -> None:
        with self._lock:
            self._blocked[hostname] = retry_after

    def _host_lock(self, hostname: str) -> threading.Lock:
        with self._lock:
            return self._host_locks.setdefault(hostname, threading.Lock())

    def _resource_site(self, endpoint: Endpoint) -> _ResourceSiteState:
        key = (endpoint.scheme, endpoint.hostname, endpoint.port)
        with self._lock:
            return self._resource_sites.setdefault(key, _ResourceSiteState())

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
        addresses = _resolve_bounded(self._resolver_pool, self.resolver, endpoint.hostname,
                                     endpoint.port, deadline, self._clock)
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
                 ca_bundle: Path | None, *,
                 request_headers: Mapping[str, str] | None = None,
                 body_limit: int = BODY_LIMIT, wire_limit: int = WIRE_LIMIT,
                 minimum_host_interval: float = 0.0) -> _Response:
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
                with self._host_lock(endpoint.hostname):
                    self._pacer.wait(endpoint.hostname, deadline,
                                     minimum_interval=minimum_host_interval)
                    blocked = self._blocked_info(endpoint.hostname)
                    if blocked is not False:
                        raise _BlockedFailure("host stopped after a rate-limit response",
                                              retry_after=blocked)
                    if self._clock() >= deadline:
                        raise _TimeoutFailure("asset exceeded the total time limit")
                    with self._lock:
                        self.request_count += 1
                    kwargs = {}
                    if request_headers is not None:
                        kwargs["request_headers"] = request_headers
                    if body_limit != BODY_LIMIT:
                        kwargs["body_limit"] = body_limit
                    if wire_limit != WIRE_LIMIT:
                        kwargs["wire_limit"] = wire_limit
                    response = self.transport.fetch(endpoint, address, ca_bundle=ca_bundle,
                                                    deadline=deadline, user_agent=USER_AGENT,
                                                    **kwargs)
            except _ConnectionFailure as exc:
                if attempt >= MAX_RETRIES or self._clock() >= deadline:
                    raise
                attempt += 1
                base = 0.5 * (2 ** (attempt - 1))
                delay = base * (0.75 + 0.5 * self._rng.random())
                delay = min(delay, max(0.0, deadline - self._clock()))
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
            raise _RedirectFailure("redirect target is not an allowlisted host and port",
                                   redirect_target={"scheme": scheme, "host": hostname, "port": port})
        return Endpoint(scheme, hostname, port, path)

    def fetch(self, asset: WebAsset, allowlist: Allowlist, *,
              run_deadline: float | None = None,
              request_headers: Mapping[str, str] | None = None,
              body_limit: int = BODY_LIMIT, wire_limit: int = WIRE_LIMIT,
              minimum_host_interval: float = 0.0) -> _FetchSuccess:
        deadline = self._clock() + ASSET_TIMEOUT
        if run_deadline is not None:
            deadline = min(deadline, run_deadline)
        current = asset.endpoint
        redirects: list[str] = []
        observed_at = self._now()
        for hop in range(asset.max_redirects + 1):
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit")
            response = self._request(current, asset, deadline, allowlist.ca_bundle,
                                     request_headers=request_headers,
                                     body_limit=body_limit, wire_limit=wire_limit,
                                     minimum_host_interval=minimum_host_interval)
            if response.status not in REDIRECT_STATUSES:
                if not 200 <= response.status < 300:
                    raise _ConnectionFailure(f"HTTP {response.status}", status=response.status)
                return _FetchSuccess(response, tuple(redirects), observed_at, current)
            if not asset.allow_redirects:
                raise _RedirectFailure("redirects are disabled for this entry", status=response.status,
                                       redirects_followed=len(redirects))
            if hop >= asset.max_redirects:
                raise _RedirectFailure(
                    f"redirect limit reached after {len(redirects)} redirects; check the Maximum redirects field",
                    status=response.status, redirects_followed=len(redirects))
            locations = response.headers.get("location", ())
            if not locations:
                raise _RedirectFailure("redirect response has no Location", status=response.status)
            target = self._redirect(current, locations[0], allowlist)
            redirects.append(target.url)
            current = target
        raise _RedirectFailure(
            f"redirect limit reached after {len(redirects)} redirects; check the Maximum redirects field",
            redirects_followed=len(redirects))


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


_SCRIPT_MIME_TYPES = {
    "application/ecmascript", "application/javascript", "application/x-ecmascript",
    "application/x-javascript", "text/ecmascript", "text/javascript",
    "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
    "text/javascript1.3", "text/javascript1.4", "text/javascript1.5",
    "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript",
}
_HTML_MIME_TYPES = {"text/html", "application/xhtml+xml"}
_UNFETCHABLE_SCHEMES = {"blob", "data", "javascript"}


@dataclass(frozen=True, slots=True)
class _ResourceReference:
    url: str
    kind: str
    module: bool = False


def _strip_css_comments(text: str) -> str:
    result = []
    index = 0
    quote = ""
    while index < len(text):
        character = text[index]
        if quote:
            result.append(character)
            if character == "\\" and index + 1 < len(text):
                index += 1
                result.append(text[index])
            elif character == quote:
                quote = ""
            index += 1
        elif character in {"'", '"'}:
            quote = character
            result.append(character)
            index += 1
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                break
            result.extend("\n" for value in text[index:end + 2] if value == "\n")
            index = end + 2
        else:
            result.append(character)
            index += 1
    return "".join(result)


_CSS_IMPORT = re.compile(
    r"@import\s+(?:url\(\s*)?(?:['\"]([^'\"]+)['\"]|([^\s);]+))\s*\)?",
    re.IGNORECASE,
)
_CSS_URL = re.compile(r"url\(\s*(?:['\"]([^'\"]+)['\"]|([^\s)]+))\s*\)", re.IGNORECASE)


def _css_references(text: str) -> list[_ResourceReference]:
    clean = _strip_css_comments(text)
    references = []
    for match in _CSS_IMPORT.finditer(clean):
        value = match.group(1) or match.group(2)
        if value:
            references.append(_ResourceReference(value.strip(), "style"))
    return references


def _js_tokens(text: str) -> list[tuple[str, str]]:
    """Tokenize enough JavaScript to find literal module specifiers safely."""
    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if character.isspace():
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            index = length if end < 0 else end + 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            value = []
            interpolated = False
            valid = True
            while index < length and text[index] != quote:
                current = text[index]
                if quote == "`" and text.startswith("${", index):
                    interpolated = True
                if current == "\\":
                    if index + 1 >= length:
                        valid = False
                        break
                    escaped = text[index + 1]
                    if escaped in {"\\", "'", '"', "`", "/"}:
                        value.append(escaped)
                    elif escaped in {"\n", "\r"}:
                        pass
                    else:
                        valid = False
                    index += 2
                    continue
                value.append(current)
                index += 1
            if index >= length or text[index] != quote:
                break
            index += 1
            tokens.append(("string" if valid and not interpolated else "other-string",
                           "".join(value) if valid and not interpolated else ""))
            continue
        if character.isalpha() or character in "_$":
            start = index
            index += 1
            while index < length and (text[index].isalnum() or text[index] in "_$"):
                index += 1
            tokens.append(("identifier", text[start:index]))
            continue
        tokens.append(("punctuation", character))
        index += 1
    return tokens


def _module_references(text: str) -> list[_ResourceReference]:
    tokens = _js_tokens(text)
    references = []
    for index, (kind, value) in enumerate(tokens):
        if kind != "identifier" or value not in {"import", "export"}:
            continue
        if value == "import" and index + 1 < len(tokens):
            if tokens[index + 1][0] == "string":
                references.append(_ResourceReference(tokens[index + 1][1], "script", True))
                continue
            if (index + 3 < len(tokens) and tokens[index + 1] == ("punctuation", "(")
                    and tokens[index + 2][0] == "string"
                    and tokens[index + 3] == ("punctuation", ")")):
                references.append(_ResourceReference(tokens[index + 2][1], "script", True))
                continue
        for offset in range(index + 1, min(len(tokens), index + 128)):
            token_kind, token_value = tokens[offset]
            if token_value == ";" or (offset > index + 1 and token_kind == "identifier"
                                        and token_value in {"import", "export"}):
                break
            if token_kind == "identifier" and token_value == "from":
                if offset + 1 < len(tokens) and tokens[offset + 1][0] == "string":
                    references.append(_ResourceReference(tokens[offset + 1][1], "script", True))
                break
    return references


_RUNTIME_MARKER = re.compile(r"__webpack_require__|webpackChunk|webpackJsonp|__vite__|vitePreload",
                             re.IGNORECASE)


def _runtime_references(text: str, module: bool) -> list[_ResourceReference]:
    if not _RUNTIME_MARKER.search(text):
        return []
    references = []
    for kind, value in _js_tokens(text):
        if kind != "string" or not value or "\\" in value:
            continue
        lowered = value.casefold()
        if lowered.endswith(".map"):
            continue
        if re.search(r"\.(?:m?js|css)(?:[?#].*)?$", lowered):
            # A generated expression such as ``chunkId + ".js"`` is not a
            # literal path and must not become a guessed request.
            if lowered in {".js", ".mjs", ".css"}:
                continue
            resource_kind = "style" if re.search(r"\.css(?:[?#].*)?$", lowered) else "script"
            references.append(_ResourceReference(value, resource_kind, module))
    return references


class _ResourceLinkParser(HTMLParser):
    """Collect supported browser script and stylesheet references in document order."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.links: list[_ResourceReference] = []
        self.declares_icon = False
        self.template_depth = 0
        self.noscript_depth = 0
        self.style_depth = 0

    @staticmethod
    def _attributes(attrs) -> dict[str, str]:
        values = {}
        for name, value in attrs:
            if name and value is not None:
                values.setdefault(name.casefold(), value)
        return values

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "template":
            self.template_depth += 1
            return
        if tag == "noscript":
            self.noscript_depth += 1
            return
        if self.template_depth or self.noscript_depth:
            return
        attributes = self._attributes(attrs)
        if attributes.get("style"):
            self.links.extend(_css_references(attributes["style"]))
        if tag == "style":
            self.style_depth += 1
            return
        if tag == "base":
            if self.base_href is None and "href" in attributes:
                self.base_href = attributes["href"]
            return
        if tag == "script":
            src = attributes.get("src")
            script_type = attributes.get("type", "").split(";", 1)[0].strip().casefold()
            if src is not None and (not script_type or script_type == "module"
                                    or script_type in _SCRIPT_MIME_TYPES):
                self.links.append(_ResourceReference(src, "script", script_type == "module"))
            return
        if tag == "link" and "href" in attributes:
            rel = set(attributes.get("rel", "").casefold().split())
            href = attributes["href"]
            if "icon" in rel or "apple-touch-icon" in rel or "mask-icon" in rel:
                self.declares_icon = True
                self.links.append(_ResourceReference(href, "icon"))
            elif "manifest" in rel:
                self.links.append(_ResourceReference(href, "manifest"))
            elif "stylesheet" in rel:
                self.links.append(_ResourceReference(href, "style"))
            elif "modulepreload" in rel:
                self.links.append(_ResourceReference(href, "script", True))
            elif "preload" in rel:
                kind = attributes.get("as", "").casefold()
                if kind in {"script", "style"}:
                    self.links.append(_ResourceReference(href, kind, kind == "script"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "template" and self.template_depth:
            self.template_depth -= 1
        elif tag == "noscript" and self.noscript_depth:
            self.noscript_depth -= 1
        elif tag == "style" and self.style_depth:
            self.style_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.style_depth and not self.template_depth and not self.noscript_depth:
            self.links.extend(_css_references(data))


@dataclass(frozen=True, slots=True)
class _ResourceCandidate:
    endpoint: Endpoint
    url: str
    kind: str
    module: bool
    authorization: WebAsset


def _url_origin(value: str) -> tuple[str, str, int]:
    parts = urlsplit(value)
    scheme = parts.scheme.casefold()
    if scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("unsupported URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL contains credentials")
    hostname = _hostname(parts.hostname)
    return scheme, hostname, _port(parts.port, scheme)


def _resource_endpoint(value: str, allowlist: Allowlist) -> Endpoint:
    parts = urlsplit(value)
    scheme, hostname, port = _url_origin(value)
    path = parts.path or "/"
    path_and_query = path + (("?" + parts.query) if parts.query else "")
    if (len(path_and_query) > 2048 or not _PATH.fullmatch(path)
            or any(ord(character) < 33 or ord(character) > 126 for character in path_and_query)):
        raise ValueError("invalid resource path")
    if (scheme, hostname, port) not in allowlist.endpoints:
        raise PermissionError("resource origin is not authorised")
    return Endpoint(scheme, hostname, port, path_and_query)


def _resource_policy(endpoint: Endpoint, page_asset: WebAsset,
                     allowlist: Allowlist) -> WebAsset | None:
    origin = (endpoint.scheme, endpoint.hostname, endpoint.port)
    page_asset_origin = (page_asset.endpoint.scheme, page_asset.endpoint.hostname,
                         page_asset.endpoint.port)
    if origin == page_asset_origin:
        return page_asset
    return next((asset for asset in allowlist.assets
                 if (asset.endpoint.scheme, asset.endpoint.hostname, asset.endpoint.port) == origin),
                None)


def _resource_candidate(reference: _ResourceReference, base_url: str, page_asset: WebAsset,
                        allowlist: Allowlist, state: _ResourceSiteState, queue,
                        skipped: Counter, cached_detections: list[tuple[object, ...]]) -> None:
    if not reference.url.strip():
        skipped["invalid-url"] += 1
        return
    try:
        absolute = urljoin(base_url, reference.url.strip())
        parts = urlsplit(absolute)
        scheme = parts.scheme.casefold()
        if scheme in _UNFETCHABLE_SCHEMES or scheme not in {"http", "https"}:
            skipped["unsupported-scheme"] += 1
            return
        if parts.username is not None or parts.password is not None:
            skipped["credentials"] += 1
            return
        absolute = parts._replace(fragment="").geturl()
        origin = _url_origin(absolute)
    except (ExtensionError, ValueError, UnicodeError):
        skipped["invalid-url"] += 1
        return
    if origin not in allowlist.endpoints:
        skipped["external-origin"] += 1
        return
    if parts.path.casefold().endswith(".map"):
        skipped["source-map"] += 1
        return
    try:
        endpoint = _resource_endpoint(absolute, allowlist)
    except PermissionError:
        skipped["external-origin"] += 1
        return
    except (ExtensionError, ValueError, UnicodeError):
        skipped["invalid-url"] += 1
        return
    resource_url = endpoint.url
    if resource_url in state.seen_urls:
        skipped["duplicate"] += 1
        if resource_url in state.file_detections:
            cached_detections.append(state.file_detections[resource_url])
        return
    state.seen_urls.add(resource_url)
    policy = _resource_policy(endpoint, page_asset, allowlist)
    if policy is None:
        skipped["unauthorised"] += 1
        return
    if state.requested_files + len(queue) >= RESOURCE_MAX_FILES:
        skipped["file-limit"] += 1
        return
    queue.append(_ResourceCandidate(endpoint, resource_url, reference.kind,
                                    reference.module, policy))


def _resource_references(html: str) -> tuple[_ResourceLinkParser, Counter]:
    parser = _ResourceLinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return parser, Counter({"invalid-html": 1})
    return parser, Counter()


def _decode_resource(body: bytes, headers: Mapping[str, tuple[str, ...]]) -> str:
    content_type = " ".join(headers.get("content-type", ()))
    charset = _CHARSET.search(content_type)
    if charset:
        try:
            return body.decode(charset.group(1), errors="replace")
        except (LookupError, UnicodeError):
            pass
    return body.decode("utf-8", errors="replace")


def _resource_content_type(headers: Mapping[str, tuple[str, ...]], kind: str) -> tuple[str, bool, bool]:
    values = headers.get("content-type", ())
    media_type = values[0].split(";", 1)[0].strip().casefold() if values else ""
    if media_type in _HTML_MIME_TYPES:
        return media_type, False, True
    allowed = {"text/plain", "application/octet-stream"}
    if kind == "style":
        allowed.add("text/css")
    if kind == "script":
        allowed.update(_SCRIPT_MIME_TYPES)
    elif kind == "manifest":
        allowed.update({"application/json", "application/manifest+json", "text/json"})
    elif kind == "icon":
        allowed.update({"image/x-icon", "image/vnd.microsoft.icon", "image/png", "image/svg+xml"})
    return media_type, media_type in allowed, False


def _looks_like_html(body: bytes) -> bool:
    sample = body[:512].lstrip(b"\xef\xbb\xbf\t\r\n\f ").lower()
    return sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def _fetch_resources(html: str, page_success: _FetchSuccess, page_asset: WebAsset,
                     allowlist: Allowlist, fetcher: Fetcher, *,
                     run_deadline: float,
                     on_detections: Callable[[Iterable[object]], None]) -> tuple[int, Counter, dict[str, tuple[str, int]]]:
    page_endpoint = page_success.final_endpoint or page_asset.endpoint
    page_url = page_endpoint.url
    state = fetcher._resource_site(page_endpoint)
    with state.lock:
        now = fetcher._clock()
        if state.started_at is None:
            state.started_at = now
            state.deadline = min(now + RESOURCE_SITE_TIMEOUT, run_deadline)
        else:
            state.deadline = min(state.deadline or run_deadline, run_deadline)
        site_deadline = state.deadline
        parser, skipped = _resource_references(html)
        base_url = page_url
        if parser.base_href is not None:
            try:
                proposed = urljoin(page_url, parser.base_href)
                origin = _url_origin(proposed)
                if origin == (page_endpoint.scheme, page_endpoint.hostname, page_endpoint.port):
                    base_url = urlsplit(proposed)._replace(fragment="").geturl()
            except (ExtensionError, ValueError, UnicodeError):
                pass

        queue = deque()
        cached: list[tuple[object, ...]] = []
        for reference in parser.links:
            _resource_candidate(reference, base_url, page_asset, allowlist, state,
                                queue, skipped, cached)
        authority = f"[{page_endpoint.hostname}]" if ":" in page_endpoint.hostname else page_endpoint.hostname
        site_root = f"{page_endpoint.scheme}://{authority}"
        if page_endpoint.port != page_endpoint.default_port:
            site_root += f":{page_endpoint.port}"
        if not parser.declares_icon:
            _resource_candidate(_ResourceReference(site_root + "/favicon.ico", "icon"),
                                page_url, page_asset, allowlist, state, queue, skipped, cached)
        _resource_candidate(_ResourceReference(site_root + "/robots.txt", "robots"),
                            page_url, page_asset, allowlist, state, queue, skipped, cached)
        for detections in cached:
            on_detections(detections)

        resources_fetched = 0
        while queue:
            now = fetcher._clock()
            if run_deadline - now <= RESOURCE_RUN_DEADLINE_GUARD:
                skipped["run-deadline"] += len(queue)
                break
            if now >= site_deadline:
                skipped["site-time-budget"] += len(queue)
                break
            if state.requested_files >= RESOURCE_MAX_FILES:
                skipped["file-limit"] += len(queue)
                break
            remaining_site_bytes = RESOURCE_SITE_LIMIT - state.decoded_bytes
            if remaining_site_bytes <= 0:
                skipped["site-limit"] += len(queue)
                break
            candidate = queue.popleft()
            state.requested_files += 1
            body_limit = min(RESOURCE_FILE_LIMIT, remaining_site_bytes)
            site_limit_is_tighter = remaining_site_bytes <= RESOURCE_FILE_LIMIT
            request_headers = {
                "Accept": "text/css,*/*;q=0.1" if candidate.kind == "style" else "*/*",
                "Referer": page_url,
            }
            resource_asset = WebAsset(
                candidate.endpoint, candidate.authorization.authorized_by,
                candidate.authorization.authorized_at, candidate.authorization.expires_at,
                candidate.authorization.allow_redirects, candidate.authorization.max_redirects,
                candidate.authorization.allow_private_address,
            )
            try:
                success = fetcher.fetch(
                    resource_asset, allowlist, run_deadline=site_deadline,
                    request_headers=request_headers, body_limit=body_limit,
                    wire_limit=RESOURCE_WIRE_LIMIT,
                    minimum_host_interval=RESOURCE_MIN_HOST_INTERVAL,
                )
            except _TooLargeFailure:
                state.decoded_bytes += remaining_site_bytes if site_limit_is_tighter else body_limit
                skipped["site-limit" if site_limit_is_tighter else "too-large"] += 1
                continue
            except _FetchFailure as failure:
                if fetcher._clock() >= site_deadline:
                    skipped["site-time-budget"] += 1
                elif failure.status is not None and failure.reason == "unreachable":
                    skipped["http-status"] += 1
                else:
                    skipped[failure.reason] += 1
                continue
            except Exception:
                skipped["unreachable"] += 1
                continue

            body = success.response.body
            if len(body) > body_limit:
                state.decoded_bytes += remaining_site_bytes if site_limit_is_tighter else body_limit
                reason = "site-limit" if site_limit_is_tighter and len(body) > remaining_site_bytes else "too-large"
                skipped[reason] += 1
                continue
            state.decoded_bytes += len(body)
            if run_deadline - fetcher._clock() <= RESOURCE_RUN_DEADLINE_GUARD:
                skipped["run-deadline"] += 1
                continue
            if fetcher._clock() > site_deadline:
                skipped["site-time-budget"] += 1
                continue
            if success.response.status != 200:
                skipped["http-status"] += 1
                continue
            media_type, accepted_type, is_html = _resource_content_type(
                success.response.headers, candidate.kind)
            if is_html or _looks_like_html(body):
                skipped["html-response"] += 1
                continue
            if not accepted_type:
                skipped["wrong-content-type"] += 1
                continue

            digest = hashlib.sha256(body).hexdigest()
            state.file_metadata[candidate.url] = (digest, len(body))
            text = "" if candidate.kind == "icon" else _decode_resource(body, success.response.headers)
            resource = Resource(candidate.url, candidate.kind, text)
            try:
                detections = tuple(detect(page_from(success.response.headers, html,
                                                    resources=[resource])))
            except Exception:
                detections = ()
                skipped["analysis-error"] += 1
            state.file_detections[candidate.url] = detections
            on_detections(detections)
            resources_fetched += 1

            nested = []
            if candidate.kind == "style":
                nested.extend(_css_references(text))
            elif candidate.kind == "script" and candidate.module:
                nested.extend(_module_references(text))
            if candidate.kind == "script":
                nested.extend(_runtime_references(text, candidate.module))
            cached = []
            for reference in nested:
                _resource_candidate(reference, candidate.url, page_asset, allowlist,
                                    state, queue, skipped, cached)
            for old_detections in cached:
                on_detections(old_detections)

        return resources_fetched, skipped, dict(state.file_metadata)


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


@dataclass(frozen=True, slots=True)
class _EvidenceRecord:
    kind: str
    source: str
    excerpt: str


@dataclass(frozen=True, slots=True)
class _DetectionSummary:
    vendor: str
    product: str
    category: str
    cpe: str
    confidence: str
    versions: tuple[str, ...]
    evidence_types: tuple[str, ...]
    name: str = ""
    ecosystem: str = ""
    package: str = ""
    implied_by: tuple[str, ...] = ()
    evidence: tuple[_EvidenceRecord, ...] = ()


def _detection_evidence(detection) -> tuple[_EvidenceRecord, ...]:
    result = []
    seen = set()
    allowed_kinds = {"header", "cookie", "meta", "url", "html", "script", "style", "implied"}
    for item in getattr(detection, "evidence", ()):
        try:
            raw_kind, source, excerpt = item.kind, item.source, item.excerpt
        except AttributeError:
            continue
        kind = str(raw_kind)
        if kind not in allowed_kinds:
            kind = "url"
        evidence = _EvidenceRecord(kind, str(source), str(excerpt)[:160])
        key = (evidence.kind, evidence.source, evidence.excerpt)
        if key not in seen:
            result.append(evidence)
            seen.add(key)
        if len(result) >= 20:
            break
    return tuple(result)


def _merge_detections(target: dict[tuple[str, str], _DetectionSummary], detections) -> None:
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    for detection in detections:
        key = (str(detection.vendor).casefold(), str(detection.product).casefold())
        incoming_evidence = _detection_evidence(detection)
        current = target.get(key)
        if current is None:
            target[key] = _DetectionSummary(
                detection.vendor, detection.product, detection.category, detection.cpe,
                detection.confidence, tuple(sorted(set(detection.versions))),
                tuple(sorted(set(detection.evidence_types))), getattr(detection, "name", ""),
                getattr(detection, "ecosystem", ""), getattr(detection, "package", ""),
                tuple(sorted(set(getattr(detection, "implied_by", ())))), incoming_evidence[:20],
            )
            continue
        evidence = list(current.evidence)
        evidence_seen = {(item.kind, item.source, item.excerpt) for item in evidence}
        for item in incoming_evidence:
            identity = (item.kind, item.source, item.excerpt)
            if identity not in evidence_seen and len(evidence) < 20:
                evidence.append(item)
                evidence_seen.add(identity)
        confidence = detection.confidence
        if confidence_rank.get(current.confidence, 0) > confidence_rank.get(confidence, 0):
            confidence = current.confidence
        target[key] = _DetectionSummary(
            current.vendor, current.product, getattr(detection, "category", current.category),
            current.cpe or getattr(detection, "cpe", ""), confidence,
            tuple(sorted(set(current.versions) | set(detection.versions))),
            tuple(sorted(set(current.evidence_types) | set(detection.evidence_types))),
            current.name or getattr(detection, "name", ""),
            current.ecosystem or getattr(detection, "ecosystem", ""),
            current.package or getattr(detection, "package", ""),
            tuple(sorted(set(current.implied_by) | set(getattr(detection, "implied_by", ())))),
            tuple(evidence),
        )


def _public_evidence(detection: _DetectionSummary,
                     file_metadata: Mapping[str, tuple[str, int]]) -> list[dict]:
    result = []
    for evidence in detection.evidence[:20]:
        item = dict(kind=evidence.kind, source=evidence.source, excerpt=evidence.excerpt[:160])
        file_info = file_metadata.get(evidence.source)
        if file_info is not None:
            item["sha256"], item["bytes"] = file_info
        result.append(item)
    return result


@dataclass(slots=True)
class _AssetResult:
    asset: WebAsset
    rows: list[dict]
    reviews: list[dict]
    omissions: set[str]
    observed_at: datetime | None
    failure: _FetchFailure | None = None
    products: list[dict] = field(default_factory=list)
    resources_fetched: int = 0
    resources_skipped: int = 0
    resources_skipped_by_reason: dict[str, int] = field(default_factory=dict)


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
        if failure.redirect_target is not None:
            # Scheme, host and port only: the dashboard offers to authorise this target.
            review["redirect_target"] = failure.redirect_target
        if failure.redirects_followed is not None:
            review["redirects_followed"] = failure.redirects_followed
        return _AssetResult(asset, [], [review], {failure.reason}, None, failure)
    html = _decode_html(success.response.body, success.response.headers)
    merged: dict[tuple[str, str], _DetectionSummary] = {}
    _merge_detections(merged, detect(page_from(success.response.headers, html)))
    try:
        resources_fetched, resources_skipped, file_metadata = _fetch_resources(
            html, success, asset, allowlist, fetcher, run_deadline=run_deadline,
            on_detections=lambda values: _merge_detections(merged, values))
    except Exception:
        # Resource collection is optional evidence. A parser or auxiliary file
        # failure must leave the page observation usable and path-free.
        resources_fetched, resources_skipped, file_metadata = 0, Counter({"unreachable": 1}), {}
    detections = tuple(merged.values())
    products = []
    for item in detections:
        product = dict(asset_id=_asset_id(allowlist.client, asset.endpoint, item.vendor, item.product),
                       hostname=asset.endpoint.hostname, vendor=item.vendor, product=item.product,
                       versions=list(item.versions), category=item.category,
                       evidence_types=list(item.evidence_types), confidence=item.confidence,
                       evidence=_public_evidence(item, file_metadata))
        if item.name:
            product["name"] = item.name
        if item.ecosystem and item.package:
            product["ecosystem"], product["package"] = item.ecosystem, item.package
        if item.implied_by:
            product["implied_by"] = list(item.implied_by)
        products.append(product)
    rows: list[dict] = []
    reviews: list[dict] = []
    omissions: set[str] = set()
    if not detections:
        reviews.append(dict(base, reason="no-technologies", detail="fetch succeeded; no direct evidence matched"))
        omissions.add("no-technologies")
    for detection in detections:
        if detection.implied_by and set(detection.evidence_types) <= {"implied"}:
            # Inferred from another product: listed for people, never a row or a review item.
            continue
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
        purl = package_url(detection.ecosystem, detection.package, version)
        rows.append({
            "asset_id": row_id,
            "vendor": detection.vendor,
            # A package identity names the package itself and never carries a CPE too.
            "product": detection.package if purl else detection.product,
            "version": version,
            "category": detection.category,
            "system_id": system_id,
            "ecosystem": detection.ecosystem if purl else "",
            "purl": purl,
            "cpe": "" if purl else detection.cpe,
            "repository": "",
            "commit": "",
            "client": allowlist.client,
        })
        if not version:
            reviews.append(dict(detail, reason="version-unknown", product=display,
                                category=detection.category, confidence=detection.confidence))
            omissions.add("version-unknown")
    return _AssetResult(
        asset, rows, reviews, omissions, success.observed_at, products=products,
        resources_fetched=resources_fetched, resources_skipped=sum(resources_skipped.values()),
        resources_skipped_by_reason=dict(resources_skipped),
    )


def _review_path(output: Path) -> Path:
    return Path(str(output) + ".review.json")


def _saved_snapshot_time(output: Path, now: datetime) -> str:
    try:
        snapshot = read_snapshot(output, max_age_seconds=2**63 - 1, allow_partial=True, now=now)
    except (ExtensionError, OSError, ValueError):
        return ""
    if snapshot.manifest.get("collector") != "web-detect":
        return ""
    return snapshot.manifest["generated_at"]


def _fetch_failure_message(failures: list[_FetchFailure], site_count: int) -> str:
    counts = Counter(failure.reason for failure in failures)
    if len(counts) == 1 and next(iter(counts.values())) == 1:
        causes = next(iter(counts))
    else:
        causes = ", ".join(f"{reason}: {count}" for reason, count in sorted(counts.items()))
    site_word = "site" if site_count == 1 else "sites"
    return (f"could not fetch {len(failures)} of {site_count} {site_word} ({causes}); "
            "see the review entries")


def _no_usable_message(products: list[dict], products_with_version: int,
                       failures: list[_FetchFailure], site_count: int) -> str:
    count = len(products)
    if count == 0:
        outcome = "no products were recognised"
    elif products_with_version == 0:
        outcome = f"{count} product{'s' if count != 1 else ''} recognised, none with a disclosed version"
    else:
        outcome = f"{count} product{'s' if count != 1 else ''} recognised, none with a consistent usable version"
    suffix = f"; {_fetch_failure_message(failures, site_count)}" if failures else ""
    return f"detection finished: {outcome}{suffix}; nothing was added to the inventory; see the review entries"


def _publish_review(output: Path, client: str, source_id: str, reviews: list[dict], *,
                    products: list[dict], run: dict) -> None:
    data = json_bytes(dict(client=client, source_id=source_id, reviews=reviews, products=products, run=run))
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
    started_at, started = now().isoformat(), clock()
    run_deadline = started + RUN_TIMEOUT
    results: list[_AssetResult] = []
    workers = max(1, min(max_workers, MAX_WORKERS, len(allowlist.assets)))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_observe, asset, allowlist, fetcher, run_deadline=run_deadline)
                       for asset in allowlist.assets]
            for future in as_completed(futures):
                results.append(future.result())
    finally:
        fetcher.close()
    results.sort(key=lambda item: item.asset.endpoint.url)
    rows = [row for result in results for row in result.rows]
    reviews = [review for result in results for review in result.reviews]
    reviews.sort(key=lambda item: (item["asset_id"], item["reason"], item.get("product", ""),
                                   item.get("detail", "")))
    omissions = sorted({reason for result in results for reason in result.omissions})
    observed = [result.observed_at for result in results if result.observed_at is not None]
    fetch_failures = [result.failure for result in results if result.failure is not None]
    fetched_count = len(results) - len(fetch_failures)
    products = [product for result in results for product in result.products]
    resources_fetched = sum(result.resources_fetched for result in results)
    resources_skipped = sum(result.resources_skipped for result in results)
    resources_skipped_by_reason: Counter = Counter()
    for result in results:
        resources_skipped_by_reason.update(result.resources_skipped_by_reason)
    products_with_version = sum(bool(product["versions"]) for product in products)
    fetch_failure_disallows_run = bool(fetch_failures) and (fetched_count == 0 or not allow_partial)
    if fetch_failure_disallows_run:
        status = "failed"
    elif not rows:
        status = "no-usable-versions"
    else:
        status = "partial" if omissions else "success"
    with output_lock(output):
        saved_snapshot_generated_at = _saved_snapshot_time(output, now())
        run = dict(started_at=started_at, ended_at=now().isoformat(), status=status,
                   request_count=fetcher.request_count,
                   duration_seconds=max(0, clock() - started),
                   asset_count=len(allowlist.assets), fetched_count=fetched_count,
                   resources_fetched=resources_fetched, resources_skipped=resources_skipped,
                   resources_skipped_by_reason=dict(sorted(resources_skipped_by_reason.items())),
                   products_recognized=len(products), products_with_version=products_with_version,
                   saved_snapshot_generated_at=saved_snapshot_generated_at, snapshot_updated=False)
        _publish_review(output, client, source_id, reviews,
                        products=products, run=run)
        if fetch_failure_disallows_run:
            raise ExtensionError(_fetch_failure_message(fetch_failures, len(allowlist.assets)))
        if not rows:
            message = _no_usable_message(products, products_with_version, fetch_failures,
                                         len(allowlist.assets))
            print(message)
            return None
        if fetch_failures:
            print(_fetch_failure_message(fetch_failures, len(allowlist.assets)))
        manifest = write_snapshot(output, rows, source_id=source_id, collector="web-detect",
                                  observed_at=min(observed).isoformat() if observed else None,
                                  omissions=omissions, lock=False)
        run["saved_snapshot_generated_at"] = manifest["generated_at"]
        run["snapshot_updated"] = True
        _publish_review(output, client, source_id, reviews, products=products, run=run)
        return manifest
