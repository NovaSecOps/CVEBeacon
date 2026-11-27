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
    wait,
)
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import email.utils
import hashlib
import http.client
from html.parser import HTMLParser
import ipaddress
import inspect
from itertools import islice
import json
import logging
from pathlib import Path
import queue
import random
import re
import socket
import ssl
import threading
import time
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit
import uuid
import zlib

from cvebeacon.errors import InventoryValidationError
from cvebeacon.identity import normalize_asset, validate_client_name
from cvebeacon.models import Asset
from cvebeacon.web_assets import RUN_TIMEOUT, RUN_TIMEOUT_REASON
from cvebeacon.web_inventory import web_asset_id

from . import __version__, webrules
from .contract import (ExtensionError, MAX_BYTES, MAX_RECORDS, MAX_TEXT, _atomic, _regular,
                       canonical_records, decode_json, json_bytes, label, output_lock,
                       read_bytes, read_snapshot, timestamp, utc_now, write_snapshot)
from .webrules import REVIEW_ONLY_VENDORS, Resource, detect, package_url, page_from

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
ASSET_TIMEOUT = 20.0
BODY_LIMIT = 2 * 1024 * 1024
WIRE_LIMIT = 4 * 1024 * 1024
HEADER_LIMIT = 64 * 1024
MAX_ASSETS = 1000
MAX_WORKERS = 4
DEFAULT_REDIRECTS = 2
MAX_REDIRECTS = 10
LOG = logging.getLogger("cvebeacon_extensions.web")
MAX_RETRIES = 2
HOST_INTERVAL = 1.0
USER_AGENT = f"CVEBeacon-web-detect/{__version__}"

# Browser-referenced resources: at most 300 unique, authorised files per site,
# each with at most 10 MiB decoded and 20 MiB on the wire, and at most 96 MiB
# decoded across the site's files. The resource phase has a 180-second budget,
# with at least 100 ms between same-host requests. A 5-second run-deadline
# margin reserves time to publish the completed observations.
RESOURCE_MAX_FILES = 300
RESOURCE_FILE_LIMIT = 10 * 1024 * 1024
RESOURCE_WIRE_LIMIT = 20 * 1024 * 1024
RESOURCE_SITE_LIMIT = 96 * 1024 * 1024
RESOURCE_SITE_TIMEOUT = 180.0
RESOURCE_MIN_HOST_INTERVAL = 0.1
RESOURCE_RUN_DEADLINE_GUARD = 5.0
RESOURCE_MAX_REFERENCES = 4 * RESOURCE_MAX_FILES
MAX_REFERENCE_LENGTH = 4096

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
BLOCKED_STATUSES = {429, 503}
NO_RETRY_STATUSES = {401, 403, 404}
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PATH = re.compile(r"/[!-~]*")
_CHARSET = re.compile(r"charset\s*=\s*[\"']?([^;\"'\s]+)", re.IGNORECASE)
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]+")
# Each setting is the maximum disclosure for same-origin and cross-origin requests.
_DEFAULT_REFERRER_POLICY = (2, 1)
_REFERRER_POLICIES = {
    "no-referrer": (0, 0),
    "same-origin": (2, 0),
    "origin": (1, 1),
    "strict-origin": (1, 1),
    "origin-when-cross-origin": _DEFAULT_REFERRER_POLICY,
    "strict-origin-when-cross-origin": _DEFAULT_REFERRER_POLICY,
    "no-referrer-when-downgrade": _DEFAULT_REFERRER_POLICY,
    "unsafe-url": _DEFAULT_REFERRER_POLICY,
}
_STANDARD_PATHS = {"icon": "/favicon.ico", "robots": "/robots.txt"}
_ANALYSIS_STOP_REASONS = {"site-time-budget", "run-deadline"}
_SENSITIVE_HEADERS = frozenset({"set-cookie", "cookie", "authorization", "proxy-authorization"})
_URL_IN_EXCERPT = re.compile(r"""(?:https?://|(?<![:/])//)[^\s<>"'`]+""", re.IGNORECASE)
_URL_SUFFIX_IN_EXCERPT = re.compile(r"""[?#][^\s<>"'`]*""")
# Query pairs, and an excerpt that starts inside a query string ("name=value" with no
# quote, unlike an HTML attribute), may carry private values from a page's URLs.
_QUERY_PAIRS_IN_EXCERPT = re.compile(r"""[?&][\w.%~+-]{1,256}=[^\s<>"'`&#]*""")
_LEADING_QUERY_IN_EXCERPT = re.compile(r"""^[\w.%~+-]{1,256}=(?!["'])[^\s<>"'`]*""")
_URL_BEARING_KINDS = frozenset({"url", "html", "dom", "text", "meta"})


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


class _ExpiredFailure(_FetchFailure):
    reason = "authorisation expired"


class _RedirectFailure(_FetchFailure):
    reason = "redirect-blocked"


class _ResourceFileLimit(_FetchFailure):
    reason = "file-limit"


class _ResourceByteLimit(_FetchFailure):
    reason = "site-limit"


class _StandardPathAlreadyRequested(_FetchFailure):
    reason = "duplicate"


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
        return self.origin_url + self.path

    @property
    def origin_url(self) -> str:
        return f"{self.scheme}://{self.authority}"

    @property
    def origin(self) -> tuple[str, str, int]:
        return self.scheme, self.hostname, self.port


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
    revision: str = ""

    endpoints: frozenset[tuple[str, str, int]] = field(init=False, repr=False)
    _by_origin: dict[tuple[str, str, int], WebAsset] = field(init=False, repr=False, compare=False)
    _by_endpoint: dict[Endpoint, WebAsset] = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        by_origin = {}
        for asset in self.assets:
            by_origin.setdefault(asset.endpoint.origin, asset)
        object.__setattr__(self, "endpoints", frozenset(by_origin))
        object.__setattr__(self, "_by_origin", by_origin)
        object.__setattr__(self, "_by_endpoint", {asset.endpoint: asset for asset in self.assets})

    def authorization(self, endpoint: Endpoint, originating: WebAsset) -> WebAsset:
        if endpoint.origin == originating.endpoint.origin:
            return originating
        return self._by_endpoint.get(endpoint) or self._by_origin[endpoint.origin]


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
    referrer_policy: tuple[int, int] = _DEFAULT_REFERRER_POLICY
    vary: frozenset[str] = frozenset()


def _header_tokens(headers, name):
    return (token.strip().casefold() for value in headers.get(name, ()) for token in value.split(","))


def _referrer_policy(headers):
    policy = _DEFAULT_REFERRER_POLICY
    for token in _header_tokens(headers, "referrer-policy"):
        if token in _REFERRER_POLICIES:
            policy = _REFERRER_POLICIES[token]
    return policy


def _restrict_referrer(current, other):
    return min(current[0], other[0]), min(current[1], other[1])


def _referer_value(referrer: Endpoint, endpoint: Endpoint, policy: tuple[int, int]) -> str | None:
    disclosure = policy[referrer.origin != endpoint.origin]
    if disclosure == 1:
        return referrer.origin_url + "/"
    if disclosure == 2:
        return referrer.url
    return None


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
    data = read_bytes(Path(path))
    document = decode_json(data)
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
    private_by_endpoint = {}
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
        if private_by_endpoint.setdefault(key[:3], allow_private) != allow_private:
            raise ExtensionError(f"asset {index} conflicts with another entry for the same endpoint")
        assets.append(WebAsset(endpoint, authorized_by, authorized_at, expires_at, allow_redirects,
                               max_redirects, allow_private))
    return Allowlist(client, ca_bundle, tuple(assets), hashlib.sha256(data).hexdigest())


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
    def __init__(self, encoding: str, on_decoded: Callable[[int], None]):
        self.encoding = encoding
        self._on_decoded = on_decoded
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
            self._on_decoded(len(part))
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
        self._on_decoded(len(part))
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
              before_read: Callable[[], None] | None = None,
              on_decoded: Callable[[int], None] = lambda _: None) -> bytes:
    """Stream a response body, decoding gzip/deflate with a hard output cap."""
    decoder = None if content_encoding in {"", "identity"} else _BodyDecoder(content_encoding, on_decoded)
    output = bytearray()
    wire = 0
    while True:
        if deadline is not None and clock() >= deadline:
            raise _TimeoutFailure("response exceeded the asset time limit")
        if before_read is not None:
            before_read()
        size = 65536 if decoder is not None else min(65536, limit - len(output) + 1)
        chunk = reader.read(size)
        if not chunk:
            break
        if decoder is None:
            on_decoded(len(chunk))
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
              body_limit: int = BODY_LIMIT, wire_limit: int = WIRE_LIMIT,
              on_decoded: Callable[[int], None] = lambda _: None) -> _Response:
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
                             before_read=lambda: self._timeout(connection.sock, deadline),
                             on_decoded=on_decoded)
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


@dataclass
class _ResourceBudget:
    deadline: float = float("inf")
    requested_files: int = 0
    decoded_bytes: int = 0


@dataclass
class _OriginResourceBudget(_ResourceBudget):
    lock: threading.Lock = field(default_factory=threading.Lock)
    standard_paths: set[str] = field(default_factory=set)


class _OriginResourceBudgets:
    def __init__(self):
        self._lock = threading.Lock()
        self._budgets: dict[tuple[str, str, int], _OriginResourceBudget] = {}

    def get(self, endpoint: Endpoint, deadline: float = float("inf")) -> _OriginResourceBudget:
        with self._lock:
            budget = self._budgets.get(endpoint.origin)
            if budget is None:
                budget = _OriginResourceBudget(deadline)
                self._budgets[endpoint.origin] = budget
            return budget


@dataclass
class _ResourceSiteState(_ResourceBudget):
    final_budget: _OriginResourceBudget | None = None
    seen_urls: set[tuple] = field(default_factory=set)
    pending_files: Counter = field(default_factory=Counter)
    files: dict[tuple[str, str], _CachedResource] = field(default_factory=dict)

    @property
    def remaining_files(self) -> int:
        final = self.final_budget.requested_files if self.final_budget is not None else 0
        return RESOURCE_MAX_FILES - max(self.requested_files, final)

    @property
    def remaining_bytes(self) -> int:
        final = self.final_budget.decoded_bytes if self.final_budget is not None else 0
        return max(0, RESOURCE_SITE_LIMIT - max(self.decoded_bytes, final))

    def debit(self, size: int) -> None:
        self.decoded_bytes += size
        if self.final_budget is not None:
            self.final_budget.decoded_bytes += size

    def request_file(self) -> None:
        self.requested_files += 1
        if self.final_budget is not None:
            self.final_budget.requested_files += 1


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
        # Destination counters are used under the host lock at the transport boundary.
        self._destination_budgets = _OriginResourceBudgets()

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

    def _address(self, endpoint: Endpoint, allow_private: bool, deadline: float) -> str:
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
            elif allow_private:
                accepted.append(value)
            else:
                raise _BlockedFailure("non-global address is not authorised")
        if not accepted:
            raise _BlockedFailure("non-global address is not authorised")
        return accepted[0]

    def _check_expiry(self, entries: tuple[WebAsset, ...]) -> None:
        now = self._now()
        if any(entry.expires_at is not None and entry.expires_at <= now for entry in entries):
            raise _ExpiredFailure("authorisation expired")

    def _request(self, endpoint: Endpoint, originating: WebAsset, destination: WebAsset,
                 deadline: float,
                 ca_bundle: Path | None, *,
                 request_headers: Mapping[str, str] | None = None,
                 body_limit: int = BODY_LIMIT, wire_limit: int = WIRE_LIMIT,
                 budget: _ResourceSiteState | None = None,
                 page_authorizations: tuple[WebAsset, ...] = (),
                 minimum_host_interval: float = 0.0) -> _Response:
        entries = (originating, destination, *page_authorizations)
        allow_private = originating.allow_private_address and destination.allow_private_address
        attempt = 0
        reserved = False
        origin_budget = self._destination_budgets.get(endpoint) if budget is not None else None
        standard_path = endpoint.path in _STANDARD_PATHS.values()
        while True:
            self._check_expiry(entries)
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit")
            blocked = self._blocked_info(endpoint.hostname)
            if blocked is not False:
                detail = "host stopped after a rate-limit response"
                raise _BlockedFailure(detail, retry_after=blocked)
            try:
                address = self._address(endpoint, allow_private, deadline)
                with self._host_lock(endpoint.hostname):
                    self._pacer.wait(endpoint.hostname, deadline,
                                     minimum_interval=minimum_host_interval)
                    self._check_expiry(entries)
                    blocked = self._blocked_info(endpoint.hostname)
                    if blocked is not False:
                        raise _BlockedFailure("host stopped after a rate-limit response",
                                              retry_after=blocked)
                    if self._clock() >= deadline:
                        raise _TimeoutFailure("asset exceeded the total time limit")
                    kwargs = {}
                    reported = False
                    debit_site = None
                    attempt_limit = body_limit
                    if origin_budget is not None:
                        if not reserved:
                            if standard_path and endpoint.path in origin_budget.standard_paths:
                                raise _StandardPathAlreadyRequested("standard path already requested")
                            if origin_budget.requested_files >= RESOURCE_MAX_FILES:
                                raise _ResourceFileLimit("destination file limit reached")
                        attempt_limit = min(body_limit, budget.remaining_bytes,
                                            RESOURCE_SITE_LIMIT - origin_budget.decoded_bytes)
                        if attempt_limit <= 0:
                            raise _ResourceByteLimit("decoded byte limit reached")

                        debit_site = budget.debit

                        def debit(size: int) -> None:
                            nonlocal reported
                            if debit_site is not None:
                                reported = True
                                debit_site(size)
                                origin_budget.decoded_bytes += size

                        kwargs["on_decoded"] = debit
                    if request_headers is not None:
                        kwargs["request_headers"] = request_headers
                    if attempt_limit != BODY_LIMIT or budget is not None:
                        kwargs["body_limit"] = attempt_limit
                    if wire_limit != WIRE_LIMIT:
                        kwargs["wire_limit"] = wire_limit
                    with self._lock:
                        self._check_expiry(entries)
                        if origin_budget is not None and not reserved:
                            origin_budget.requested_files += 1
                            if standard_path:
                                origin_budget.standard_paths.add(endpoint.path)
                            reserved = True
                        self.request_count += 1
                    try:
                        response = self.transport.fetch(endpoint, address, ca_bundle=ca_bundle,
                                                        deadline=deadline, user_agent=USER_AGENT,
                                                        **kwargs)
                    finally:
                        debit_site = None
                    if budget is not None and 200 <= response.status < 300:
                        if not reported:
                            # Simple transports can return an already-decoded body.
                            size = len(response.body)
                            budget.debit(size)
                            origin_budget.decoded_bytes += size
                        if len(response.body) > attempt_limit:
                            raise _TooLargeFailure("response body exceeds its byte limit")
            except _TooLargeFailure as exc:
                if origin_budget is not None and origin_budget.decoded_bytes >= RESOURCE_SITE_LIMIT:
                    raise _ResourceByteLimit("destination decoded byte limit reached") from exc
                raise
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
        if not _valid_reference(location):
            raise _RedirectFailure("redirect target is not a valid URL")
        try:
            target = urlsplit(location if urlsplit(location).scheme
                              else _resolve_reference(current.url, location))
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
              budget: _ResourceSiteState | None = None,
              endpoint: Endpoint | None = None, referrer: Endpoint | None = None,
              referrer_policy: tuple[int, int] = _DEFAULT_REFERRER_POLICY,
              page_authorizations: tuple[WebAsset, ...] = (),
              minimum_host_interval: float = 0.0) -> _FetchSuccess:
        deadline = self._clock() + ASSET_TIMEOUT
        if run_deadline is not None:
            deadline = min(deadline, run_deadline)
        current = endpoint or asset.endpoint
        redirects: list[str] = []
        observed_at = self._now()
        response_policy = _DEFAULT_REFERRER_POLICY
        vary = set()
        for hop in range(asset.max_redirects + 1):
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit")
            headers = request_headers
            if referrer is not None:
                if referrer.scheme == "https" and current.scheme == "http":
                    raise _RedirectFailure("HTTPS to HTTP downgrade is not allowed")
                policy = _restrict_referrer(referrer_policy, response_policy)
                referer = _referer_value(referrer, current, policy)
                if referer is not None:
                    headers = dict(request_headers or {}, Referer=referer)
            destination = allowlist.authorization(current, asset)
            response = self._request(current, asset, destination, deadline, allowlist.ca_bundle,
                                     request_headers=headers, budget=budget,
                                     page_authorizations=page_authorizations,
                                     body_limit=body_limit, wire_limit=wire_limit,
                                     minimum_host_interval=minimum_host_interval)
            response_policy = _restrict_referrer(response_policy, _referrer_policy(response.headers))
            vary.update(token for token in _header_tokens(response.headers, "vary") if token)
            if response.status not in REDIRECT_STATUSES:
                if not 200 <= response.status < 300:
                    raise _ConnectionFailure(f"HTTP {response.status}", status=response.status)
                return _FetchSuccess(response, tuple(redirects), observed_at, current,
                                     response_policy, frozenset(vary))
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
@dataclass(frozen=True, slots=True)
class _ResourceReference:
    url: str
    kind: str
    module: bool = False
    follow: bool = True
    referrer_policy: tuple[int, int] = _DEFAULT_REFERRER_POLICY


def _valid_reference(value: str) -> bool:
    return (0 < len(value) <= MAX_REFERENCE_LENGTH
            and not any(ord(char) < 32 or 127 <= ord(char) <= 159 or char == "\\"
                        for char in value))


_CSS_RULE = re.compile(r"@(charset|import|layer)(?![\w-])", re.IGNORECASE)
_CSS_IMPORT = re.compile(
    r"""\s*(?:(['"])([^'"\\\r\n]{1,4096})\1|url\(\s*(?:(['"])([^'"\\\r\n]{1,4096})\3|([^\s'"\\()]{1,4096}))\s*\))""",
    re.IGNORECASE,
)


def _css_references(text: str, clock, deadline: float) -> Iterable[_ResourceReference]:
    # Imports apply only before ordinary rules, apart from charset and layer statements.
    position = 0
    while position < len(text) and clock() < deadline:
        if text[position].isspace():
            position += 1
            continue
        if text.startswith("/*", position):
            end = text.find("*/", position + 2)
            if end < 0:
                return
            position = end + 2
            continue
        rule = _CSS_RULE.match(text, position)
        if rule is None:
            return
        quote = ""
        parentheses = 0
        end = rule.end()
        next_check = end + 4096
        while end < len(text):
            if end >= next_check:
                if clock() >= deadline:
                    return
                next_check = end + 4096
            char = text[end]
            if quote:
                if char == "\\":
                    end += 2
                    continue
                if char == quote:
                    quote = ""
            elif char in {"'", '"'}:
                quote = char
            elif text.startswith("/*", end):
                close = text.find("*/", end + 2)
                if close < 0:
                    return
                end = close + 2
                continue
            elif char == "(":
                parentheses += 1
            elif char == ")":
                parentheses -= 1
                if parentheses < 0:
                    return
            elif not parentheses:
                if char in "{}":
                    return
                if char == ";":
                    break
            end += 1
        if quote or parentheses:
            return
        if rule[1].casefold() == "import":
            start = rule.end()
            while start < end:
                if text[start].isspace():
                    start += 1
                elif text.startswith("/*", start):
                    start = text.index("*/", start + 2, end) + 2
                else:
                    break
            value = _CSS_IMPORT.match(text, start, end)
            if value and (value.end() == end or text[value.end()].isspace()
                          or text.startswith("/*", value.end())):
                yield _ResourceReference(value[2] or value[4] or value[5], "style")
        position = end + 1


def _js_tokens(text: str, clock=time.monotonic, deadline=float("inf")) -> Iterable[tuple[str, str]]:
    """Yield bounded literal tokens without retaining a token list for the script."""
    index = 0
    next_check = 0
    length = len(text)
    regex_allowed = True
    while index < length:
        if index >= next_check:
            if clock() >= deadline:
                return
            next_check = index + 4096
        character = text[index]
        if character.isspace():
            index += 1
            continue
        if text.startswith("//", index) or text.startswith("/*", index):
            line = text.startswith("//", index)
            end = text.find("\n" if line else "*/", index + 2)
            index = length if end < 0 else end + (1 if line else 2)
            continue
        if character in {"'", '"', "`", "/"} and (character != "/" or regex_allowed):
            quote = character
            index += 1
            start = index
            valid = quote in {"'", '"'}
            in_class = False
            while index < length:
                if index >= next_check:
                    if clock() >= deadline:
                        return
                    next_check = index + 4096
                current = text[index]
                if current == quote and not in_class:
                    break
                if current == "\\":
                    valid = False
                    index += 2
                    continue
                if quote == "/":
                    if current == "[":
                        in_class = True
                    elif current == "]":
                        in_class = False
                index += 1
            if index >= length:
                return
            if valid and index - start <= MAX_REFERENCE_LENGTH:
                yield "string", text[start:index]
            else:
                yield "other", ""
            index += 1
            regex_allowed = False
            continue
        if character.isalnum() or character in "_$":
            start = index
            index += 1
            while index < length and (text[index].isalnum() or text[index] in "_$"):
                if index >= next_check:
                    if clock() >= deadline:
                        return
                    next_check = index + 4096
                index += 1
            value = text[start:index] if index - start <= MAX_REFERENCE_LENGTH else ""
            yield ("number" if character.isdigit() else "identifier"), value
            regex_allowed = value in {"return", "case", "throw", "yield", "void", "typeof"}
            continue
        yield "punctuation", character
        regex_allowed = character in "({[=,:;!?&|"
        index += 1


_CHUNK_PATH = re.compile(r"\.(m?js|css)(?:[?#].*)?$", re.IGNORECASE)
_MODULE_URL = re.compile(r"^(?:/|\.\.?/|[a-zA-Z][a-zA-Z0-9+.-]*:)")
_WEBPACK_LOADERS = {"u", "miniCssF", "l"}


def _chunk_reference(value: str, module: bool) -> _ResourceReference | None:
    match = _CHUNK_PATH.search(value)
    if match and match.start() > 0:
        return _ResourceReference(value, "style" if match[1].casefold() == "css" else "script",
                                  module)


def _script_references(text: str, module: bool, clock, deadline: float) -> Iterable[_ResourceReference]:
    """Recognise module specifiers and a fixed set of literal runtime loaders."""
    tokens = iter(_js_tokens(text, clock, deadline))
    lookahead = deque(islice(tokens, 12))
    previous = ""
    static_left = 0
    while lookahead and clock() < deadline:
        token_kind, value = lookahead.popleft()
        token = next(tokens, None)
        if token is not None:
            lookahead.append(token)
        count = len(lookahead)
        if module:
            specifier = None
            if token_kind == "identifier" and value in {"import", "export"} and previous != ".":
                static_left = 0
                if value == "import" and count and lookahead[0][0] == "string":
                    specifier = lookahead[0][1]
                elif (value == "import" and count >= 3 and lookahead[0] == ("punctuation", "(")
                      and lookahead[1][0] == "string" and lookahead[2] == ("punctuation", ")")):
                    specifier = lookahead[1][1]
                elif count and (lookahead[0][1] in {"{", "*"}
                                or (value == "import" and lookahead[0][0] == "identifier")):
                    static_left = 128
            elif static_left:
                static_left -= 1
                if token_kind == "identifier" and value == "from" and count and lookahead[0][0] == "string":
                    specifier = lookahead[0][1]
                    static_left = 0
                elif value == ";":
                    static_left = 0
            if specifier and _MODULE_URL.match(specifier):
                yield _ResourceReference(specifier, "script", True)

        if token_kind == "identifier" and previous != ".":
            if (value == "__webpack_require__" and count >= 4
                    and lookahead[0] == ("punctuation", ".")
                    and lookahead[1][0] == "identifier" and lookahead[1][1] in _WEBPACK_LOADERS):
                loader = lookahead[1][1]
                if (loader == "l" and lookahead[2] == ("punctuation", "(")
                        and lookahead[3][0] == "string" and count >= 5
                        and lookahead[4] in {("punctuation", ")"), ("punctuation", ",")}):
                    reference = _chunk_reference(lookahead[3][1], module)
                    if reference:
                        yield reference
                elif loader != "l" and count >= 8 and lookahead[2] == ("punctuation", "="):
                    # Arrow functions returning a literal chunk-id map indexed by the argument.
                    opening = 3
                    wrapped_argument = lookahead[opening] == ("punctuation", "(")
                    opening += wrapped_argument
                    argument = lookahead[opening]
                    arrow = opening + 1 + wrapped_argument
                    if (count > arrow + 3 and argument[0] == "identifier"
                            and (not wrapped_argument or lookahead[opening + 1] == ("punctuation", ")"))
                            and tuple(islice(lookahead, arrow, arrow + 4)) == (
                                ("punctuation", "="), ("punctuation", ">"),
                                ("punctuation", "("), ("punctuation", "{"))):
                        yield from _literal_chunk_map(lookahead, tokens, arrow + 4, module,
                                                      argument[1], clock, deadline)
            elif (value == "__vite__mapDeps" and count >= 2
                  and lookahead[0] == ("punctuation", "=") and lookahead[1] == ("punctuation", "[")):
                yield from _literal_chunk_map(lookahead, tokens, 2, True, None, clock, deadline)
        previous = value


def _literal_chunk_map(lookahead, tokens, start: int, module: bool, argument: str | None,
                       clock, deadline: float) -> Iterable[_ResourceReference]:
    def take():
        current = lookahead.popleft() if lookahead else ("", "")
        following = next(tokens, None)
        if following is not None:
            lookahead.append(following)
        return current

    for _ in range(start):
        take()
    closing = "}" if argument is not None else "]"
    references = []
    for _ in range(RESOURCE_MAX_REFERENCES):
        if clock() >= deadline:
            return
        kind, value = take()
        if kind == "punctuation" and value == closing:
            break
        if argument is not None:
            if kind not in {"identifier", "number", "string"} or take() != ("punctuation", ":"):
                return
            kind, value = take()
        if kind != "string":
            return
        reference = _chunk_reference(value, module)
        if reference:
            references.append(reference)
        delimiter = take()
        if delimiter == ("punctuation", closing):
            break
        if delimiter != ("punctuation", ","):
            return
    else:
        return
    if argument is not None:
        if tuple(islice(lookahead, 4)) != (
                ("punctuation", ")"), ("punctuation", "["),
                ("identifier", argument), ("punctuation", "]")):
            return
    elif lookahead and lookahead[0] not in {("punctuation", ";"), ("punctuation", ",")}:
        return
    yield from references


class _ResourceLinkParser(HTMLParser):
    """Collect supported browser script and stylesheet references in document order."""

    def __init__(self, clock, deadline: float):
        super().__init__(convert_charrefs=True)
        self.clock = clock
        self.deadline = deadline
        self.base_href: str | None = None
        self.referrer_policy = _DEFAULT_REFERRER_POLICY
        self.links: list[_ResourceReference] = []
        self.skipped: Counter = Counter()
        self.declares_icon = False
        self.template_depth = 0
        self.noscript_depth = 0
        self.style_depth = 0

    def _add(self, reference: _ResourceReference) -> None:
        if len(self.links) >= RESOURCE_MAX_REFERENCES:
            self.skipped["discovery-limit"] += 1
        elif not _valid_reference(reference.url):
            self.skipped["invalid-url"] += 1
        else:
            self.links.append(reference)

    @staticmethod
    def _attributes(attrs) -> dict[str, str]:
        values = {}
        for name, value in attrs:
            if name and value is not None:
                values.setdefault(name.casefold(), value)
        return values

    def handle_starttag(self, tag: str, attrs) -> None:
        if self.clock() >= self.deadline:
            raise _TimeoutFailure("resource discovery exceeded the site time limit")
        if tag == "template":
            self.template_depth += 1
            return
        if tag == "noscript":
            self.noscript_depth += 1
            return
        if self.template_depth or self.noscript_depth:
            return
        attributes = self._attributes(attrs)
        if tag == "style":
            if attributes.get("type", "").strip().casefold() in {"", "text/css"}:
                self.style_depth += 1
            return
        if tag == "base":
            if self.base_href is None and "href" in attributes:
                self.base_href = attributes["href"]
            return
        if tag == "meta" and attributes.get("name", "").strip().casefold() == "referrer":
            policy = _REFERRER_POLICIES.get(attributes.get("content", "").strip().casefold())
            if policy is not None:
                self.referrer_policy = _restrict_referrer(self.referrer_policy, policy)
            return
        policy = _REFERRER_POLICIES.get(attributes.get("referrerpolicy", "").strip().casefold(),
                                        _DEFAULT_REFERRER_POLICY)
        if tag == "script":
            src = attributes.get("src")
            script_type = attributes.get("type", "").split(";", 1)[0].strip().casefold()
            if src is not None and (not script_type or script_type == "module"
                                    or script_type in _SCRIPT_MIME_TYPES):
                self._add(_ResourceReference(src, "script", script_type == "module", referrer_policy=policy))
            return
        if tag == "link" and "href" in attributes:
            rel = set(attributes.get("rel", "").casefold().split())
            href = attributes["href"]
            if "icon" in rel or "apple-touch-icon" in rel or "mask-icon" in rel:
                self.declares_icon = True
                self._add(_ResourceReference(href, "icon", referrer_policy=policy))
            elif "manifest" in rel:
                self._add(_ResourceReference(href, "manifest", referrer_policy=policy))
            elif "stylesheet" in rel:
                self._add(_ResourceReference(href, "style", referrer_policy=policy))
            elif "modulepreload" in rel:
                self._add(_ResourceReference(href, "script", True, referrer_policy=policy))
            elif "preload" in rel:
                kind = attributes.get("as", "").casefold()
                if kind in {"script", "style"}:
                    self._add(_ResourceReference(href, kind, follow=False, referrer_policy=policy))

    def handle_endtag(self, tag: str) -> None:
        if tag == "template" and self.template_depth:
            self.template_depth -= 1
        elif tag == "noscript" and self.noscript_depth:
            self.noscript_depth -= 1
        elif tag == "style" and self.style_depth:
            self.style_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.style_depth and not self.template_depth and not self.noscript_depth:
            for reference in _css_references(data, self.clock, self.deadline):
                self._add(reference)
                if len(self.links) >= RESOURCE_MAX_REFERENCES:
                    break


@dataclass(frozen=True, slots=True)
class _ResourceCandidate:
    endpoint: Endpoint
    url: str
    kind: str
    module: bool
    follow: bool
    referrer_policy: tuple[int, int]
    authorization: WebAsset

    @property
    def response_key(self) -> tuple[str, str]:
        return self.url, self.kind

    @property
    def request_key(self) -> tuple:
        return (*self.response_key, self.referrer_policy)


@dataclass(slots=True)
class _CachedResource:
    resource: Resource
    metadata: tuple[str, int]
    detections: tuple
    referrer_policy: tuple[int, int]
    vary: frozenset[str]
    referrer: Endpoint
    request_policy: tuple[int, int]
    authorizations: tuple[WebAsset, ...]
    redirected: bool
    fingerprint_stopped: bool = False
    fingerprint_error: bool = False
    dependencies: dict[tuple[str, str, bool], tuple[_ResourceReference, ...]] = field(default_factory=dict)

    def matches(self, candidate: _ResourceCandidate, referrer: Endpoint,
                authorizations: tuple[WebAsset, ...], now: datetime) -> bool:
        # The response key fixes URL and Accept. The transport's other
        # headers are constant, apart from the per-request Referer.
        if self.vary - {"referer", "accept", "accept-encoding", "user-agent"}:
            return False
        if (_referer_value(self.referrer, candidate.endpoint, self.request_policy)
                != _referer_value(referrer, candidate.endpoint, candidate.referrer_policy)):
            return False
        if self.redirected and (self.referrer, self.request_policy) != (referrer, candidate.referrer_policy):
            return False
        for prior, current in zip(self.authorizations, authorizations, strict=True):
            if (prior.allow_private_address != current.allow_private_address
                    or (current.expires_at is not None and current.expires_at <= now)):
                return False
        return not self.redirected or self.authorizations == authorizations


def _url_origin(value: str) -> tuple[str, str, int]:
    parts = urlsplit(value)
    scheme = parts.scheme.casefold()
    if scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("unsupported URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL contains credentials")
    hostname = _hostname(parts.hostname)
    return scheme, hostname, _port(parts.port, scheme)



def _remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4; keeps empty segments, as browsers do."""
    output: list[str] = []
    while path:
        if path.startswith("../"):
            path = path[3:]
        elif path.startswith("./"):
            path = path[2:]
        elif path.startswith("/./"):
            path = "/" + path[3:]
        elif path == "/.":
            path = "/"
        elif path.startswith("/../"):
            path = "/" + path[4:]
            if output:
                output.pop()
        elif path == "/..":
            path = "/"
            if output:
                output.pop()
        elif path in {".", ".."}:
            path = ""
        else:
            end = path.find("/", 1 if path.startswith("/") else 0)
            end = len(path) if end == -1 else end
            output.append(path[:end])
            path = path[end:]
    return "".join(output)


def _resolve_reference(base: str, reference: str) -> str:
    """Resolve a relative reference against an absolute base (RFC 3986 section 5.2.2)."""
    b = urlsplit(base)
    r = urlsplit(reference)
    before_fragment = reference.split("#", 1)[0]
    has_query = "?" in before_fragment
    if reference.startswith("//"):
        return urlunsplit((b.scheme, r.netloc, _remove_dot_segments(r.path), r.query, r.fragment))
    if not r.path:
        path, query = b.path, (r.query if has_query else b.query)
    else:
        if r.path.startswith("/"):
            merged = r.path
        elif b.netloc and not b.path:
            merged = "/" + r.path
        else:
            merged = b.path[:b.path.rfind("/") + 1] + r.path
        path, query = _remove_dot_segments(merged), r.query
    return urlunsplit((b.scheme, b.netloc, path, query, r.fragment))

def _resource_candidate(reference: _ResourceReference, base_url: str | None, page_asset: WebAsset,
                        allowlist: Allowlist, state: _ResourceSiteState, queue,
                        skipped: Counter, lookup: Callable[[_ResourceCandidate], _CachedResource | None],
                        *, page_scheme: str, referrer_policy: tuple[int, int]) -> None:
    if not _valid_reference(reference.url) or not reference.url.strip():
        skipped["invalid-url"] += 1
        return
    try:
        value = reference.url.strip()
        parsed = urlsplit(value)
        relative = not parsed.scheme
        if relative and (base_url is None or value.startswith("#")
                         or (value.startswith("//") and not parsed.netloc)):
            skipped["invalid-url"] += 1
            return
        # A same-scheme URL like "https:relative.js" is ambiguous across parsers.
        absolute = _resolve_reference(base_url, value) if relative else value
        parts = urlsplit(absolute)
        scheme = parts.scheme.casefold()
        if scheme not in {"http", "https"}:
            skipped["unsupported-scheme"] += 1
            return
        if scheme == "http" and page_scheme == "https":
            skipped["redirect-blocked"] += 1
            return
        if parts.username is not None or parts.password is not None:
            skipped["credentials"] += 1
            return
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
    path = parts.path or "/"
    path_and_query = path + (("?" + parts.query) if parts.query else "")
    if (len(path_and_query) > 2048 or not _PATH.fullmatch(path)
            or any(ord(character) < 33 or ord(character) > 126 for character in path_and_query)):
        skipped["invalid-url"] += 1
        return
    endpoint = Endpoint(*origin, path_and_query)
    policy = _restrict_referrer(referrer_policy, reference.referrer_policy)
    candidate = _ResourceCandidate(endpoint, endpoint.url, reference.kind, reference.module,
                                   reference.follow, policy, allowlist.authorization(endpoint, page_asset))
    use_key = (*candidate.request_key, candidate.follow, candidate.module)
    if use_key in state.seen_urls:
        skipped["duplicate"] += 1
        return
    fetch = lookup(candidate) is None
    if fetch and candidate.request_key not in state.pending_files:
        if len(state.pending_files) >= state.remaining_files:
            skipped["file-limit"] += 1
            return
    state.seen_urls.add(use_key)
    if fetch:
        state.pending_files[candidate.request_key] += 1
    queue.append((candidate, fetch))


def _resource_references(html: str, clock, deadline: float) -> _ResourceLinkParser:
    parser = _ResourceLinkParser(clock, deadline)
    try:
        parser.feed(html)
        parser.close()
    except _TimeoutFailure:
        parser.skipped["site-time-budget"] += 1
    except Exception:
        parser.skipped["invalid-html"] += 1
    return parser


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


def _is_json_object(body: bytes) -> bool:
    if len(body) > RESOURCE_FILE_LIMIT:
        return False
    try:
        return isinstance(json.loads(body.decode("utf-8-sig")), dict)
    except (ValueError, RecursionError):
        return False


def _looks_like_html(body: bytes) -> bool:
    sample = body[:512].lstrip(b"\xef\xbb\xbf\t\r\n\f ").lower()
    return sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def _fetch_resources(html: str, page_endpoint: Endpoint, page_asset: WebAsset,
                     allowlist: Allowlist, fetcher: Fetcher, state: _ResourceSiteState, *,
                     run_deadline: float, deadline: float, page_policy: tuple[int, int],
                     on_detections: Callable[[Iterable[object]], None],
                     fingerprints: _ExternalObservation,
                     skip_details: _SkipDetails | None = None) -> tuple[int, Counter, dict[str, tuple[str, int]]]:
    clock = fetcher._clock
    skipped: Counter = Counter()
    if skip_details is None:
        skip_details = _SkipDetails()

    def skip(reason: str, candidate: _ResourceCandidate, content_type: str = "",
             size: int | None = None) -> None:
        skipped[reason] += 1
        skip_details.add(reason, candidate.kind, candidate.url, content_type, size)

    metadata: dict[str, tuple[str, int]] = {}
    if clock() >= deadline:
        skipped["run-deadline" if deadline == run_deadline else "site-time-budget"] += 1
        return 0, skipped, metadata

    page_url = page_endpoint.url
    page_authorizations = (page_asset, allowlist.authorization(page_endpoint, page_asset))
    parser = _resource_references(html, clock, deadline)
    skipped.update(parser.skipped)
    document_policy = _restrict_referrer(page_policy, parser.referrer_policy)
    base_url = page_url
    if parser.base_href is not None and parser.base_href.strip():
        value = parser.base_href.strip()
        base_url = None
        if _valid_reference(parser.base_href):
            try:
                parts = urlsplit(value)
                if value.startswith("//") and not parts.netloc:
                    raise ValueError("network-path base has no authority")
                proposed = value if parts.scheme else _resolve_reference(page_url, value)
                _url_origin(proposed)
                base_url = urlsplit(proposed)._replace(fragment="").geturl()
            except (ExtensionError, ValueError, UnicodeError):
                pass

    queue = deque()
    state.seen_urls.clear()
    state.pending_files.clear()
    observed = set()
    conflicting_metadata = set()

    def lookup(candidate: _ResourceCandidate) -> _CachedResource | None:
        cached = state.files.get(candidate.response_key)
        if cached is not None and cached.matches(
                candidate, page_endpoint, (candidate.authorization, *page_authorizations), fetcher._now()):
            return cached
        return None

    remaining_references = RESOURCE_MAX_REFERENCES

    def discover(references: Iterable[_ResourceReference], base: str | None, policy) -> None:
        nonlocal remaining_references
        for reference in references:
            if clock() >= deadline:
                break
            if remaining_references <= 0:
                skipped["discovery-limit"] += 1
                break
            remaining_references -= 1
            _resource_candidate(reference, base, page_asset, allowlist, state, queue, skipped,
                                lookup, page_scheme=page_endpoint.scheme, referrer_policy=policy)

    discover(parser.links, base_url, document_policy)
    for kind, path in _STANDARD_PATHS.items():
        if clock() >= deadline:
            break
        if kind != "icon" or not parser.declares_icon:
            _resource_candidate(_ResourceReference(path, kind), page_url, page_asset, allowlist,
                                state, queue, skipped, lookup, page_scheme=page_endpoint.scheme,
                                referrer_policy=document_policy)

    resources_fetched = 0
    fetch_deadline = min(state.deadline, deadline)
    if state.final_budget is not None:
        fetch_deadline = min(fetch_deadline, state.final_budget.deadline)
    time_reason = "run-deadline" if fetch_deadline == run_deadline else "site-time-budget"
    while queue:
        if clock() >= fetch_deadline:
            skipped[time_reason] += len(queue)
            break
        candidate, reserved = queue.popleft()
        if reserved:
            state.pending_files[candidate.request_key] -= 1
            if not state.pending_files[candidate.request_key]:
                del state.pending_files[candidate.request_key]
        cached = lookup(candidate)
        if cached is None:
            if state.remaining_bytes <= 0:
                skip("site-limit", candidate)
                continue
            if state.remaining_files <= 0:
                skip("file-limit", candidate)
                continue
            state.request_file()
            request_headers = {
                "Accept": "text/css,*/*;q=0.1" if candidate.kind == "style" else "*/*",
            }
            try:
                success = fetcher.fetch(
                    candidate.authorization, allowlist, endpoint=candidate.endpoint, referrer=page_endpoint,
                    referrer_policy=candidate.referrer_policy, run_deadline=fetch_deadline,
                    request_headers=request_headers, body_limit=RESOURCE_FILE_LIMIT, wire_limit=RESOURCE_WIRE_LIMIT,
                    budget=state, page_authorizations=page_authorizations,
                    minimum_host_interval=RESOURCE_MIN_HOST_INTERVAL,
                )
            except _TooLargeFailure:
                skip("site-limit" if state.remaining_bytes <= 0 else "too-large", candidate)
                continue
            except _FetchFailure as failure:
                if isinstance(failure, _TimeoutFailure) and clock() >= fetch_deadline:
                    skip(time_reason, candidate)
                elif failure.status is not None and failure.reason == "unreachable":
                    skip("http-status", candidate)
                    if (failure.status in {404, 410}
                            and _STANDARD_PATHS.get(candidate.kind) == candidate.endpoint.path):
                        skip_details.absent_optional += 1
                else:
                    skip(failure.reason, candidate)
                continue
            except Exception:
                skip("unreachable", candidate)
                continue

            body = success.response.body
            content_types = success.response.headers.get("content-type", ())
            response_type = content_types[0] if content_types else ""
            if clock() >= fetch_deadline:
                skip(time_reason, candidate, response_type, len(body))
                continue
            if success.response.status != 200:
                skip("http-status", candidate, response_type, len(body))
                continue
            _, accepted_type, is_html = _resource_content_type(success.response.headers, candidate.kind)
            if is_html or _looks_like_html(body):
                skip("html-response", candidate, response_type, len(body))
                continue
            if not accepted_type and candidate.kind == "manifest" and _is_json_object(body):
                accepted_type = True
            if not accepted_type:
                skip("wrong-content-type", candidate, response_type, len(body))
                continue

            endpoint = success.final_endpoint or candidate.endpoint
            digest = hashlib.sha256(body).hexdigest()
            text = "" if candidate.kind == "icon" else _decode_resource(body, success.response.headers)
            resource = Resource(endpoint.url, candidate.kind, text)
            detections = ()
            if clock() < deadline:
                try:
                    detections = tuple(_detect_builtin(page_from({}, "", resources=[resource]),
                                                       clock=clock, deadline=deadline))
                except Exception:
                    skip("analysis-error", candidate, response_type, len(body))
            legacy_stopped = legacy_error = False
            if fingerprints.legacy and clock() < deadline:
                external_detections, legacy_stopped, legacy_error = fingerprints.legacy_resource(resource)
                detections += external_detections
            cached = _CachedResource(
                resource, (digest, len(body)), detections, success.referrer_policy, success.vary,
                page_endpoint, candidate.referrer_policy, (candidate.authorization, *page_authorizations),
                bool(success.redirects), legacy_stopped, legacy_error,
            )
            resources_fetched += 1
            if clock() < deadline and not legacy_stopped and not legacy_error:
                state.files[candidate.response_key] = cached

        resource = cached.resource
        observation_key = (resource.url, candidate.kind, cached.metadata)
        if observation_key not in observed:
            observed.add(observation_key)
            existing = metadata.get(resource.url)
            if existing is not None and existing != cached.metadata:
                conflicting_metadata.add(resource.url)
                del metadata[resource.url]
            elif resource.url not in conflicting_metadata:
                metadata[resource.url] = cached.metadata
            on_detections(cached.detections)
            fingerprints.stopped |= cached.fingerprint_stopped
            fingerprints.error |= cached.fingerprint_error
            fingerprints.add_resource(resource)
        if candidate.follow and remaining_references > 0 and clock() < deadline:
            graph_key = (resource.url, candidate.kind, candidate.module)
            references = cached.dependencies.get(graph_key)
            if references is None:
                nested = ()
                if candidate.kind == "style":
                    nested = _css_references(resource.text, clock, deadline)
                elif candidate.kind == "script":
                    nested = _script_references(resource.text, candidate.module, clock, deadline)
                references = tuple(islice(nested, remaining_references + 1))
                if len(references) <= remaining_references and clock() < deadline:
                    cached.dependencies[graph_key] = references
            policy = _restrict_referrer(candidate.referrer_policy, cached.referrer_policy)
            discover(references, resource.url, policy)

    return resources_fetched, skipped, metadata


def _system_id(client: str, endpoint: Endpoint) -> str:
    value = f"{client}\0{endpoint.hostname}".encode("utf-8")
    return "web-" + hashlib.sha256(value).hexdigest()[:16]


def _asset_id(client: str, endpoint: Endpoint, vendor: str, product: str) -> str:
    return web_asset_id(client, endpoint.scheme, endpoint.hostname, endpoint.port,
                        endpoint.path, vendor, product)


def _observation_ids(client: str, endpoint: Endpoint) -> dict[str, str]:
    return dict(asset_id=_asset_id(client, endpoint, "", ""),
                system_id=_system_id(client, endpoint))


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
    categories: tuple[str, ...] = ()


def _detection_evidence(detection) -> tuple[_EvidenceRecord, ...]:
    result = []
    seen = set()
    for item in getattr(detection, "evidence", ()):
        evidence = _EvidenceRecord(_review_text(item.kind), _review_text(item.source),
                                   _review_text(item.excerpt))
        key = (evidence.kind, evidence.source, evidence.excerpt)
        if key not in seen:
            result.append(evidence)
            seen.add(key)
        if len(result) >= 20:
            break
    return tuple(result)


def _review_text(value: str) -> str:
    if (not isinstance(value, str) or len(value) > MAX_TEXT
            or any(0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise ExtensionError("invalid detection text")
    return value


def _review_values(values) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)) or len(values) > 64:
        raise ExtensionError("invalid detection values")
    return tuple(sorted({_review_text(value) for value in values}))


def _vendor_product_key(detection) -> tuple[str, ...]:
    return detection.vendor.casefold(), detection.product.casefold()


def _detection_summary(detection) -> _DetectionSummary:
    category = _review_text(detection.category)
    categories = tuple(sorted(set(_review_values(
        getattr(detection, "categories", (category,))
    )) | {category}))
    if any(value not in webrules.CATEGORIES for value in categories):
        raise ExtensionError("invalid detection categories")
    return _DetectionSummary(
        _review_text(detection.vendor), _review_text(detection.product),
        category, webrules.canonical_cpe(_review_text(detection.cpe)),
        _review_text(detection.confidence), _review_values(detection.versions),
        _review_values(detection.evidence_types), _review_text(getattr(detection, "name", "")),
        _review_text(getattr(detection, "ecosystem", "")),
        _review_text(getattr(detection, "package", "")),
        _review_values(getattr(detection, "implied_by", ())), _detection_evidence(detection),
        categories,
    )


def _implied_only(detection: _DetectionSummary) -> bool:
    return bool(detection.implied_by) and set(detection.evidence_types) <= {"implied"}


def _combine_detections(current: _DetectionSummary, incoming: _DetectionSummary) -> _DetectionSummary:
    evidence = list(current.evidence)
    evidence_seen = {(item.kind, item.source, item.excerpt) for item in evidence}
    for item in incoming.evidence:
        identity = (item.kind, item.source, item.excerpt)
        if identity not in evidence_seen and len(evidence) < 20:
            evidence.append(item)
            evidence_seen.add(identity)
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    confidence = max((incoming.confidence, current.confidence),
                     key=lambda value: confidence_rank.get(value, 0))
    versions = tuple(sorted(set(current.versions) | set(incoming.versions)))
    evidence_types = tuple(sorted(set(current.evidence_types) | set(incoming.evidence_types)))
    implied_by = tuple(sorted(set(current.implied_by) | set(incoming.implied_by)))
    categories = tuple(sorted(set(current.categories or (current.category,))
                              | set(incoming.categories or (incoming.category,))))
    if max(len(versions), len(evidence_types), len(implied_by)) > 64:
        raise ValueError("too many merged detection values")
    category = current.category
    if _implied_only(current) and not _implied_only(incoming):
        category = incoming.category
    elif current.category == "application" and incoming.category != "application":
        category = incoming.category
    if len(categories) > 1:
        categories = tuple(value for value in categories if value != "application")
    # A package identity carries no CPE; the other identity's CPE must not leak into its row.
    package_identity = bool((current.ecosystem or incoming.ecosystem)
                            and (current.package or incoming.package))
    cpe = "" if package_identity else min(filter(None, (current.cpe, incoming.cpe)), default="")
    return _DetectionSummary(
        current.vendor, current.product, category, cpe,
        confidence, versions, evidence_types, current.name or incoming.name,
        current.ecosystem or incoming.ecosystem, current.package or incoming.package,
        implied_by, tuple(evidence), categories,
    )


def _merge_detections(target: dict[tuple[str, ...], _DetectionSummary], detections, *,
                      deadline: float = float("inf"), clock=time.monotonic,
                      keep_completed: bool = False, on_invalid=lambda: None) -> None:
    identity_key = getattr(webrules, "identity_key", _vendor_product_key)
    for detection in detections:
        if clock() >= deadline and not keep_completed:
            break
        try:
            incoming = _detection_summary(detection)
            key = identity_key(detection)
            current = target.get(key)
            target[key] = incoming if current is None else _combine_detections(current, incoming)
        except (AttributeError, TypeError, ValueError):
            on_invalid()


def _merge_weak_names(detections: Mapping[tuple[str, ...], _DetectionSummary], on_invalid):
    # Wait until all identity evidence is in. A later CPE should not turn an
    # earlier display-name match into a bridge between distinct identities.
    merged: dict[tuple[str, ...], _DetectionSummary] = {}
    by_name: dict[str, tuple[str, ...]] = {}
    for key, detection in detections.items():
        if key[0] != "npm" and not detection.cpe and detection.name:
            key = by_name.setdefault(detection.name.casefold(), key)
        current = merged.get(key)
        try:
            merged[key] = detection if current is None else _combine_detections(current, detection)
        except ValueError:
            on_invalid()
    return _merge_into_packages(merged, on_invalid)


def _name_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def _merge_into_packages(detections: dict[tuple[str, ...], _DetectionSummary], on_invalid):
    """Fold name-only and application-CPE detections into the npm detection of the same name."""
    index: dict[str, set[tuple[str, ...]]] = {}
    for key, detection in detections.items():
        if key[0] != "npm":
            continue
        for value in (detection.name.casefold(), _name_slug(detection.name),
                      detection.package.casefold()):
            if value:
                index.setdefault(value, set()).add(key)
    if not index:
        return detections
    targets: dict[tuple[str, ...], tuple[str, ...]] = {}
    for key, detection in detections.items():
        if key[0] == "npm" or not detection.name:
            continue
        if detection.cpe:
            fields = webrules._cpe_fields(detection.cpe)
            if not fields or fields[0] != "a":
                continue
        matches: set[tuple[str, ...]] = set()
        for value in {detection.name.casefold(), _name_slug(detection.name)}:
            matches |= index.get(value, set())
        if len(matches) == 1:
            targets[key] = next(iter(matches))
    if not targets:
        return detections
    result = {key: detection for key, detection in detections.items() if key not in targets}
    for key, target in targets.items():
        try:
            result[target] = _combine_detections(result[target], detections[key])
        except ValueError:
            on_invalid()
            result[key] = detections[key]
    return result


_DISPLAY_VERSION = re.compile(r"[A-Za-z][A-Za-z0-9]{0,15}")
_PATH_VERSION_TOKEN_MIN = 3
_PATH_VERSION_EVIDENCE = 20


def _path_versions(detection: _DetectionSummary) -> tuple[str, ...]:
    """Read versions from evidence paths such as /bootstrap@5.3.2/ or bootstrap-5.3.2.min.css."""
    tokens = {detection.package.casefold(), _name_slug(detection.name), detection.product.casefold()}
    tokens = sorted(token for token in tokens if len(token) >= _PATH_VERSION_TOKEN_MIN
                    and len(token) <= 128)
    if not tokens:
        return ()
    pattern = re.compile(
        r"(?:^|[/@])(?:" + "|".join(re.escape(token) for token in tokens)
        + r")(?:@|/|-|\.)v?(\d+\.\d+(?:\.\d+){0,2})(?=$|[/?#._-])", re.IGNORECASE)
    found: set[str] = set()
    for item in detection.evidence[:_PATH_VERSION_EVIDENCE]:
        if item.kind not in {"url", "script", "style"}:
            continue
        texts = (item.source, item.excerpt) if item.source.startswith(("http", "//", "/")) else (item.excerpt,)
        for text in texts:
            for match in pattern.finditer(text[:2048]):
                found.add(match.group(1))
                if len(found) >= 8:
                    break
    return tuple(sorted(found))


def _display_url(value: str) -> str:
    try:
        parts = urlsplit(value)
    except ValueError:
        return "url"
    return parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1], query="", fragment="").geturl()


def _display_evidence(evidence: _EvidenceRecord) -> tuple[str, str]:
    source, excerpt = evidence.source, evidence.excerpt
    header = source.casefold().removeprefix("header:")
    if (source.casefold().startswith("header:") or evidence.kind == "header") and header in _SENSITIVE_HEADERS:
        label = f"header:{header}"
        return label, label
    if evidence.kind == "cookie" or source.casefold().startswith("cookie:"):
        match = re.match(r"cookie:([!#$%&'*+.^_`|~0-9A-Za-z-]+)", source, re.IGNORECASE)
        label = f"cookie:{match[1]}" if match else "cookie"
        return label, label
    if (source.casefold().startswith(("http://", "https://", "//", "/", "./", "../"))
            or (evidence.kind == "url" and ("?" in source or "#" in source))):
        display = _display_url(source)
        if evidence.kind == "url" and source != display and excerpt and excerpt in source:
            # Readers can return a slice that starts inside the private URL fields.
            excerpt = display
        source = display
    excerpt = _URL_IN_EXCERPT.sub(lambda match: _display_url(match[0]), excerpt)
    if evidence.kind == "url" or excerpt.lstrip().startswith(("/", "./", "../")):
        excerpt = _URL_SUFFIX_IN_EXCERPT.sub("", excerpt)
    if evidence.kind in _URL_BEARING_KINDS:
        excerpt = _QUERY_PAIRS_IN_EXCERPT.sub("", excerpt)
        excerpt = _LEADING_QUERY_IN_EXCERPT.sub("", excerpt).strip()
        if not excerpt:
            excerpt = "link on the page" if evidence.kind == "url" else "page markup"
    return source[:512], excerpt[:160]


def _public_evidence(detection: _DetectionSummary,
                     file_metadata: Mapping[str, tuple[str, int]]) -> list[dict]:
    result = []
    for evidence in detection.evidence[:20]:
        file_info = file_metadata.get(evidence.source)
        source, excerpt = _display_evidence(evidence)
        item = dict(kind=evidence.kind, source=source, excerpt=excerpt)
        if file_info is not None:
            item["sha256"], item["bytes"] = file_info
        result.append(item)
    return result


MAX_SKIPPED_RESOURCE_DETAILS = 50


@dataclass(slots=True)
class _SkipDetails:
    """Bounded per-resource skip records, kept for the private review only."""
    entries: list[dict] = field(default_factory=list)
    truncated: int = 0
    absent_optional: int = 0

    def add(self, reason: str, kind: str, url: str, content_type: str = "",
            size: int | None = None) -> None:
        if len(self.entries) >= MAX_SKIPPED_RESOURCE_DETAILS:
            self.truncated += 1
            return
        media_type = content_type.split(";", 1)[0].strip().casefold()[:100]
        self.entries.append(dict(kind=kind, reason=reason, content_type=media_type,
                                 bytes=size if type(size) is int else None,
                                 path=_display_url(url)[:300]))


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
    skip_details: _SkipDetails = field(default_factory=_SkipDetails)
    fingerprint_stopped: bool = False
    fingerprint_error: bool = False
    run_stopped: bool = False
    analysis_stopped: bool = False


def _stopped_observation(asset: WebAsset, client: str) -> _AssetResult:
    review = dict(_observation_ids(client, asset.endpoint), reason="timeout", detail=RUN_TIMEOUT_REASON)
    return _AssetResult(asset, [], [review], {"timeout", "analysis-incomplete"}, None,
                        run_stopped=True, analysis_stopped=True)


def _detect_builtin(page, *, clock, deadline: float):
    if clock() >= deadline:
        return ()
    detector = getattr(webrules, "detect", detect)
    parameters = inspect.signature(detector).parameters
    if "deadline" in parameters:
        kwargs = {"deadline": deadline}
        if "clock" in parameters:
            kwargs["clock"] = clock
        return detector(page, **kwargs)
    return detector(page)


class _ExternalObservation:
    def __init__(self, fingerprints, *, clock, deadline: float):
        self.fingerprints = fingerprints
        self.clock = clock
        self.deadline = deadline
        self.session = None
        self.legacy = False
        self.stopped = False
        self.error = False
        self._resource_keys: dict[tuple[str, str], str | None] = {}
        if fingerprints is not None:
            from . import webfingerprints

            session_class = getattr(webfingerprints, "ExternalSession", None)
            self.legacy = session_class is None
            if not self.legacy and self._active():
                try:
                    self.session = session_class(fingerprints, deadline=deadline, clock=clock)
                except Exception:
                    self.error = True

    def _active(self) -> bool:
        if self.clock() < self.deadline:
            return True
        self.stopped = True
        return False

    def _legacy(self, page, page_url: str = "") -> tuple[tuple, bool, bool]:
        from .webfingerprints import detect_external

        try:
            results = detect_external(page, self.fingerprints, page_url=page_url)
            stats = getattr(results, "stats", None)
            return tuple(results), bool(getattr(stats, "stopped_at_time_limit", False)), False
        except Exception:
            return (), False, True

    def add_page(self, page, page_url: str) -> tuple:
        if self.fingerprints is None or not self._active():
            return ()
        if self.legacy:
            detections, stopped, error = self._legacy(page, page_url)
            self.stopped |= stopped
            self.error |= error
            return detections
        if self.session is not None:
            try:
                self.session.add_page(page, page_url)
            except Exception:
                self.error = True
        return ()

    def add_resource(self, resource: Resource) -> None:
        if self.session is not None and self._active():
            if len(resource.url) >= 512:
                key = resource.kind, resource.url[:512]
                if self._resource_keys.setdefault(key, resource.url) != resource.url:
                    self._resource_keys[key] = None
            try:
                self.session.add_resource(resource)
            except Exception:
                self.error = True

    def legacy_resource(self, resource: Resource) -> tuple[tuple, bool, bool]:
        if not self._active():
            return (), True, False
        detections, stopped, error = self._legacy(page_from({}, "", resources=[resource]))
        if len(resource.url) > 512:
            prefix = resource.url[:512]
            detections = tuple(
                replace(value, evidence=tuple(
                    replace(item, source=resource.url) if item.source == prefix else item
                    for item in value.evidence))
                for value in detections
            )
        return detections, stopped, error

    def finish(self) -> tuple:
        if self.fingerprints is not None:
            self._active()
        if self.session is not None:
            try:
                detections, stats = self.session.finish()
                self.stopped |= bool(stats.get("stopped"))
                self.error |= bool(stats.get("error"))
                return tuple(self._restore_resource_keys(detection) for detection in detections)
            except Exception:
                self.error = True
        return ()

    def _restore_resource_keys(self, detection):
        # Older readers shortened file excerpts' sources. Restore only a unique
        # resource of the same kind. The publication join always uses full keys.
        if not self._resource_keys:
            return detection
        evidence = getattr(detection, "evidence", ())
        restored = []
        for item in evidence:
            source = self._resource_keys.get((item.kind, item.source))
            restored.append(replace(item, source=source) if source and source != item.source else item)
        return replace(detection, evidence=tuple(restored)) if tuple(restored) != evidence else detection


def _observe(asset: WebAsset, allowlist: Allowlist, fetcher: Fetcher, *,
             run_deadline: float, external=None, state: _ResourceSiteState | None = None,
             final_budgets: _OriginResourceBudgets | None = None,
             on_page: Callable[[Callable[[], _AssetResult]], None] | None = None) -> _AssetResult:
    base = _observation_ids(allowlist.client, asset.endpoint)
    clock = fetcher._clock
    try:
        if clock() >= run_deadline:
            raise _TimeoutFailure(RUN_TIMEOUT_REASON)
        success = fetcher.fetch(asset, allowlist, run_deadline=run_deadline)
    except _FetchFailure as failure:
        if isinstance(failure, _TimeoutFailure) and clock() >= run_deadline:
            return _stopped_observation(asset, allowlist.client)
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
        return _AssetResult(asset, [], [review], {failure.reason.replace(" ", "-")}, None,
                            failure)

    deadline = min(clock() + RESOURCE_SITE_TIMEOUT, run_deadline)
    if state is None:
        state = _ResourceSiteState()
    state.deadline = min(state.deadline, deadline)
    page_endpoint = success.final_endpoint or asset.endpoint
    reviews: list[dict] = []
    omissions: set[str] = set()

    def quarantine() -> None:
        _quarantine(reviews, omissions, base)

    merged: dict[tuple[str, ...], _DetectionSummary] = {}

    def merge(values, *, completed=False) -> None:
        _merge_detections(merged, values, clock=clock, deadline=deadline,
                          keep_completed=completed, on_invalid=quarantine)

    html = _decode_html(success.response.body, success.response.headers)
    page = None
    if clock() < deadline:
        page = page_from(success.response.headers, html)
        if {"cookie", "set-cookie"}.intersection(page.headers):
            # Keep names extracted by older rule readers while shielding the
            # raw fields from matching before those readers are upgraded.
            page = replace(page, headers={name: values for name, values in page.headers.items()
                                          if name not in {"cookie", "set-cookie"}})
        merge(_detect_builtin(page, clock=clock, deadline=deadline), completed=True)
    if on_page is not None:
        observed_at = success.observed_at
        page_detections = merged.copy()
        page_reviews = reviews.copy()
        page_omissions = omissions.copy()

        def page_result() -> _AssetResult:
            result = _observation_result(asset, allowlist.client, observed_at, page_detections,
                                         page_reviews, page_omissions,
                                         fingerprint_stopped=external is not None)
            stopped = _stopped_observation(asset, allowlist.client)
            result.reviews.extend(stopped.reviews)
            result.omissions.update(stopped.omissions)
            result.run_stopped = True
            result.analysis_stopped = True
            return result

        on_page(page_result)
    fingerprints = _ExternalObservation(external, clock=clock, deadline=deadline)
    if page is not None:
        merge(fingerprints.add_page(page, page_endpoint.url), completed=True)
    final_budget = (final_budgets.get(page_endpoint, deadline)
                    if final_budgets is not None else _OriginResourceBudget(deadline))
    skip_details = _SkipDetails()
    budget_wait = max(0.0, min(final_budget.deadline, deadline) - clock())
    acquired = final_budget.lock.acquire(timeout=budget_wait)
    try:
        if acquired:
            state.final_budget = final_budget
            resources_fetched, resources_skipped, file_metadata = _fetch_resources(
                html, page_endpoint, asset, allowlist, fetcher, state, run_deadline=run_deadline,
                deadline=deadline, page_policy=success.referrer_policy,
                on_detections=lambda values: merge(values, completed=True), fingerprints=fingerprints,
                skip_details=skip_details)
        else:
            reason = "run-deadline" if clock() >= run_deadline else "site-time-budget"
            resources_fetched, resources_skipped, file_metadata = 0, Counter({reason: 1}), {}
    except Exception:
        # Resource collection is optional evidence. A parser or auxiliary file
        # failure must leave the page observation usable and path-free.
        resources_fetched, resources_skipped, file_metadata = 0, Counter({"analysis-error": 1}), {}
    finally:
        if acquired:
            state.final_budget = None
            final_budget.lock.release()
    merge(fingerprints.finish(), completed=True)
    analysis_stopped = clock() >= deadline or bool(_ANALYSIS_STOP_REASONS.intersection(resources_skipped))
    if analysis_stopped or fingerprints.stopped or fingerprints.error or resources_skipped["analysis-error"]:
        omissions.add("analysis-incomplete")
    return _observation_result(
        asset, allowlist.client, success.observed_at, merged, reviews, omissions,
        resources_fetched=resources_fetched, resources_skipped=resources_skipped,
        file_metadata=file_metadata, skip_details=skip_details,
        fingerprint_stopped=fingerprints.stopped,
        fingerprint_error=fingerprints.error, analysis_stopped=analysis_stopped,
    )


def _quarantine(reviews: list[dict], omissions: set[str], base: dict) -> None:
    omissions.add("invalid-detection")
    reviews.append(dict(base, reason="invalid-detection"))


def _observation_result(asset: WebAsset, client: str, observed_at: datetime,
                        merged: dict[tuple[str, ...], _DetectionSummary], reviews: list[dict],
                        omissions: set[str], *,
                        resources_fetched: int = 0, resources_skipped: Counter | None = None,
                        file_metadata: Mapping[str, tuple[str, int]] | None = None,
                        skip_details: _SkipDetails | None = None,
                        fingerprint_stopped: bool = False, fingerprint_error: bool = False,
                        analysis_stopped: bool = False) -> _AssetResult:
    base = _observation_ids(client, asset.endpoint)
    rows: list[dict] = []
    if resources_skipped is None:
        resources_skipped = Counter()
    if file_metadata is None:
        file_metadata = {}

    if not merged and not reviews:
        reviews.append(dict(base, reason="no-technologies", detail="fetch succeeded; no direct evidence matched"))
        omissions.add("no-technologies")
    products = []
    used_ids = set()
    for key, detection in _merge_weak_names(merged, lambda: _quarantine(reviews, omissions, base)).items():
        if (not detection.versions and detection.vendor not in REVIEW_ONLY_VENDORS
                and not _implied_only(detection)):
            path_versions = _path_versions(detection)
            if path_versions:
                detection = replace(detection, versions=path_versions)
        display = f"{detection.vendor}/{detection.product}"
        if len(display) > MAX_TEXT:
            _quarantine(reviews, omissions, base)
            continue
        # A scoped identity (an OS, hardware or qualified CPE) always takes its own ID, so
        # its row keeps the same ID across scans whatever else is found beside it. The
        # legacy vendor/product ID stays with the plain application identity.
        scoped = isinstance(key, tuple) and len(key) > 3 and key[0] == "product"
        row_id = (_asset_id(client, asset.endpoint, "\0".join(key), "") if scoped
                  else _asset_id(client, asset.endpoint, detection.vendor, detection.product))
        if row_id in used_ids:
            row_id = _asset_id(client, asset.endpoint, "\0".join(key), "")
        used_ids.add(row_id)
        detail = dict(base, asset_id=row_id)
        # A rule-defined label such as "GA4" is shown but is never an inventory version.
        preferred = _preferred_version(tuple(
            v for v in detection.versions if not _DISPLAY_VERSION.fullmatch(v)))
        implied = _implied_only(detection)
        review_only = detection.vendor in REVIEW_ONLY_VENDORS
        row_created = False
        if (not implied and not review_only and preferred is not None
                and (preferred or detection.cpe)):
            try:
                purl = package_url(detection.ecosystem, detection.package, preferred)
                row = {
                    "asset_id": row_id,
                    "vendor": detection.vendor,
                    # A package identity names the package and carries only its PURL.
                    "product": detection.package if purl else detection.product,
                    "version": preferred,
                    "category": detection.category,
                    "system_id": base["system_id"],
                    "ecosystem": detection.ecosystem if purl else "",
                    "purl": purl,
                    "cpe": "" if purl else detection.cpe,
                    "repository": "",
                    "commit": "",
                    "client": client,
                }
                normalize_asset(Asset(**row))
                rows.extend(canonical_records([row]))
                row_created = True
            except (InventoryValidationError, ValueError):
                _quarantine(reviews, omissions, base)
                continue

        product = dict(asset_id=row_id, site_id=base["asset_id"],
                       hostname=asset.endpoint.hostname, vendor=detection.vendor,
                       product=detection.product, versions=list(detection.versions),
                       category=detection.category, evidence_types=list(detection.evidence_types),
                       categories=list(detection.categories or (detection.category,)),
                       confidence=detection.confidence, evidence=_public_evidence(detection, file_metadata),
                       inventory=row_created)
        if detection.name:
            product["name"] = detection.name
        if detection.cpe and not (detection.ecosystem and detection.package):
            # Lets a row added by hand from the dashboard keep the exact CPE identity.
            product["cpe"] = detection.cpe
        if detection.ecosystem and detection.package:
            product["ecosystem"], product["package"] = detection.ecosystem, detection.package
        if detection.implied_by:
            product["implied_by"] = list(detection.implied_by)
        products.append(product)
        if implied or review_only:
            continue
        if preferred is None:
            reviews.append(dict(detail, reason="version-conflict", product=display,
                                category=detection.category, versions=list(detection.versions),
                                confidence=detection.confidence))
            omissions.add("version-conflict")
        elif not preferred:
            reviews.append(dict(detail, reason="version-unknown", product=display,
                                category=detection.category, confidence=detection.confidence))
            omissions.add("version-unknown")
    return _AssetResult(
        asset, rows, reviews, omissions, observed_at, products=products,
        resources_fetched=resources_fetched, resources_skipped=sum(resources_skipped.values()),
        resources_skipped_by_reason=dict(resources_skipped),
        skip_details=skip_details if skip_details is not None else _SkipDetails(),
        fingerprint_stopped=fingerprint_stopped, fingerprint_error=fingerprint_error,
        analysis_stopped=analysis_stopped,
    )


def _observe_origin(assets: list[WebAsset], allowlist: Allowlist, fetcher: Fetcher, *,
                    run_deadline: float, external,
                    final_budgets: _OriginResourceBudgets,
                    record: Callable[[Endpoint, _AssetResult | Callable[[], _AssetResult]], None]) -> None:
    # Grouping starting paths gives the shared budget and cache the lifetime of this worker.
    state = _ResourceSiteState()
    for asset in assets:
        if fetcher._clock() >= run_deadline:
            break

        def on_page(result, endpoint=asset.endpoint):
            record(endpoint, result)

        result = _observe(asset, allowlist, fetcher, run_deadline=run_deadline, external=external,
                          state=state, final_budgets=final_budgets, on_page=on_page)
        record(asset.endpoint, result)


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
                    products: list[dict], run: dict, skipped: list[dict] | None = None,
                    skipped_truncated: int = 0) -> None:
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                               allow_nan=False)
    prefix = json_bytes(dict(client=client, source_id=source_id)).rstrip()[:-1]
    extra = b',"resources_skipped_truncated":' + str(int(skipped_truncated)).encode("ascii")
    suffix = extra + b',"run":' + json_bytes(dict(run, review_truncated=False)).rstrip() + b"}\n"
    data = bytearray(prefix)
    truncated = False
    # Allow room for the fixed envelope and both list delimiters before adding entries.
    limit = MAX_BYTES - len(suffix) - len(b',"reviews":[],"products":[],"resources_skipped":[]')
    for name, entries in ((b"reviews", reviews), (b"products", products),
                          (b"resources_skipped", skipped or [])):
        data.extend(b',"' + name + b'":[')
        separator = b""
        for entry in entries:
            checkpoint = len(data)
            data.extend(separator)
            for part in encoder.iterencode(entry):
                encoded = part.encode("utf-8")
                if len(data) + len(encoded) > limit:
                    del data[checkpoint:]
                    truncated = True
                    break
                data.extend(encoded)
            else:
                separator = b","
                continue
            break
        data.extend(b"]")
    if truncated:
        suffix = extra + b',"run":' + json_bytes(dict(run, review_truncated=True)).rstrip() + b"}\n"
    data.extend(suffix)
    destination = _review_path(output)
    if destination.exists() or destination.is_symlink():
        _regular(destination)
    _atomic(destination, data)


def _load_external_fingerprints(directory: Path | None):
    """Load operator-supplied Wappalyzer-format fingerprints, or return none."""
    if directory is None:
        return None, 0, False
    try:
        directory = Path(directory)
        from .webfingerprints import load_fingerprints
        loaded = load_fingerprints(directory)
        if not loaded.technology_count:
            raise ExtensionError("fingerprint layout contains no usable technologies")
        # Use what loaded, but a file that could not be read or trusted makes the result partial.
        return loaded, loaded.technology_count, bool(getattr(loaded, "incomplete", False))
    except Exception:
        LOG.warning("Web fingerprint files could not be loaded; continuing without them")
        return None, 0, True


def _sync_site_complete(result):
    # A complete observation can still lack a version or any technology. A
    # skipped source of evidence is different, except for intentional skips
    # and standard probes that explicitly returned that the file was absent.
    skipped = result.resources_skipped_by_reason
    harmless = {"duplicate", "external-origin", "source-map", "unsupported-scheme"}
    return (result.observed_at is not None and not result.run_stopped
            and not result.analysis_stopped and not result.fingerprint_stopped
            and not result.fingerprint_error
            and result.omissions <= {"no-technologies", "version-unknown", "version-conflict"}
            and sum(count for reason, count in skipped.items() if reason not in harmless)
            == result.skip_details.absent_optional)


def _previous_sync_run(output):
    try:
        detail = decode_json(read_bytes(_review_path(output)))
        value = detail["run"]["inventory_sync"]["id"]
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value):
            return value
    except (OSError, ExtensionError, TypeError, KeyError, ValueError):
        pass
    return ""


def detect_web(path: Path, output: Path, *, client: str, source_id: str,
               allow_partial: bool = False, plan: bool = False,
               resolver=None, transport=None, sleep: Callable[[float], None] = time.sleep,
               clock: Callable[[], float] = time.monotonic,
               now: Callable[[], datetime] = utc_now,
               host_interval: float = HOST_INTERVAL,
               max_workers: int = MAX_WORKERS,
               fingerprints: Path | None = None) -> dict | None:
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
    started_at, started = now().isoformat(), clock()
    margin = min(RESOURCE_RUN_DEADLINE_GUARD, RUN_TIMEOUT / 2)
    run_deadline = started + RUN_TIMEOUT - margin
    external, fingerprint_count, fingerprint_error = _load_external_fingerprints(fingerprints)
    fetcher = Fetcher(resolver=resolver, transport=transport, sleep=sleep, clock=clock,
                      now=now, host_interval=host_interval)
    observations: dict[Endpoint, _AssetResult | Callable[[], _AssetResult]] = {}
    observation_lock = threading.Lock()

    def record(endpoint, result):
        with observation_lock:
            observations[endpoint] = result
    origins: dict[tuple[str, str, int], list[WebAsset]] = {}
    for asset in allowlist.assets:
        origins.setdefault(asset.endpoint.origin, []).append(asset)
    workers = max(1, min(max_workers, MAX_WORKERS, len(origins)))
    final_budgets = _OriginResourceBudgets()
    pool = ThreadPoolExecutor(max_workers=workers)
    unfinished = set()
    try:
        futures = [pool.submit(_observe_origin, assets, allowlist, fetcher, run_deadline=run_deadline,
                               external=external, final_budgets=final_budgets, record=record)
                   for assets in origins.values()]
        # Let in-flight observers return partial matches briefly after the
        # work cutoff, reserving the rest of the margin for publication.
        finished, unfinished = wait(futures, timeout=max(0.0, run_deadline + margin / 2 - clock()))
        for future in finished:
            future.result()
    finally:
        pool.shutdown(wait=not unfinished, cancel_futures=bool(unfinished))
        fetcher.close()
    with observation_lock:
        finished_observations = observations.copy()
    results = []
    for asset in allowlist.assets:
        result = finished_observations.get(asset.endpoint)
        if result is None:
            result = _stopped_observation(asset, allowlist.client)
        elif callable(result):
            result = result()
        results.append(result)
    results.sort(key=lambda item: item.asset.endpoint.url)
    rows = []
    inventory_bytes = 3  # Opening bracket, closing bracket and final newline.
    for result in results:
        for row in result.rows:
            row_bytes = len(json_bytes([row])) - 3
            if len(rows) == MAX_RECORDS or inventory_bytes + row_bytes > MAX_BYTES:
                result.omissions.add("inventory-limit")
                result.reviews.append(dict(asset_id=row["asset_id"], system_id=row["system_id"],
                                           reason="inventory-limit"))
            else:
                rows.append(row)
                inventory_bytes += row_bytes
    reviews = [review for result in results for review in result.reviews]
    reviews.sort(key=lambda item: (item["asset_id"], item["reason"], item.get("product", ""),
                                   item.get("detail", "")))
    omissions = {reason for result in results for reason in result.omissions}
    if fingerprint_error:
        omissions.add("analysis-incomplete")
    observed = [result.observed_at for result in results if result.observed_at is not None]
    fetch_failures = [result.failure for result in results if result.failure is not None]
    fetched_count = len(observed)
    run_stopped = any(result.run_stopped for result in results)
    products = [product for result in results for product in result.products]
    resources_fetched = sum(result.resources_fetched for result in results)
    resources_skipped = sum(result.resources_skipped for result in results)
    resources_skipped_by_reason: Counter = Counter()
    for result in results:
        resources_skipped_by_reason.update(result.resources_skipped_by_reason)
    skipped_entries: list[dict] = []
    skipped_truncated = 0
    for result in results:
        room = MAX_SKIPPED_RESOURCE_DETAILS - len(skipped_entries)
        skipped_entries.extend(result.skip_details.entries[:room])
        skipped_truncated += result.skip_details.truncated + max(0, len(result.skip_details.entries) - room)
    products_with_version = sum(bool(product["versions"]) for product in products)
    fetch_failure_disallows_run = bool(fetch_failures) and (fetched_count == 0 or not allow_partial)
    if fetch_failure_disallows_run or (run_stopped and not fetched_count):
        status = "failed"
    elif not rows:
        status = "no-usable-versions"
    else:
        status = "partial" if omissions else "success"
    with output_lock(output):
        sites = {}
        for result in results:
            endpoint = result.asset.endpoint
            sites[_asset_id(client, endpoint, "", "")] = [
                endpoint.scheme, endpoint.hostname, endpoint.port, endpoint.path,
                status != "failed" and not (run_stopped or fingerprint_error) and _sync_site_complete(result),
            ]
        sync = {"id": uuid.uuid4().hex, "previous": _previous_sync_run(output),
                "allowlist": allowlist.revision, "sites": sites}
        saved_snapshot_generated_at = _saved_snapshot_time(output, now())
        run = dict(started_at=started_at, ended_at=now().isoformat(), status=status,
                   request_count=fetcher.request_count,
                   duration_seconds=max(0, clock() - started),
                   asset_count=len(allowlist.assets), fetched_count=fetched_count,
                   resources_fetched=resources_fetched, resources_skipped=resources_skipped,
                   resources_skipped_by_reason=dict(sorted(resources_skipped_by_reason.items())),
                   products_recognized=len(products), products_with_version=products_with_version,
                   saved_snapshot_generated_at=saved_snapshot_generated_at, snapshot_updated=False,
                   fingerprint_technologies=fingerprint_count,
                   fingerprint_error=fingerprint_error or any(result.fingerprint_error for result in results),
                   fingerprint_stopped=sum(result.fingerprint_stopped for result in results),
                   analysis_stopped=sum(result.analysis_stopped for result in results))
        # A run with usable rows only releases its sync evidence after its
        # snapshot has been published. A failed final write leaves the review
        # useful for inspection but ineligible for sync.
        if not rows:
            run["inventory_sync"] = sync
        _publish_review(output, client, source_id, reviews,
                        products=products, run=run, skipped=skipped_entries,
                        skipped_truncated=skipped_truncated)
        if fetch_failure_disallows_run:
            raise ExtensionError(_fetch_failure_message(fetch_failures, len(allowlist.assets)))
        if run_stopped and not fetched_count:
            raise ExtensionError(RUN_TIMEOUT_REASON)
        if not rows:
            message = _no_usable_message(products, products_with_version, fetch_failures,
                                         len(allowlist.assets))
            print(message)
            return None
        if fetch_failures:
            print(_fetch_failure_message(fetch_failures, len(allowlist.assets)))
        manifest = write_snapshot(output, rows, source_id=source_id, collector="web-detect",
                                  observed_at=min(observed).isoformat() if observed else None,
                                  omissions=sorted(omissions), lock=False)
        run["saved_snapshot_generated_at"] = manifest["generated_at"]
        run["snapshot_updated"] = True
        run["inventory_sync"] = sync
        _publish_review(output, client, source_id, reviews, products=products, run=run,
                        skipped=skipped_entries, skipped_truncated=skipped_truncated)
        return manifest
