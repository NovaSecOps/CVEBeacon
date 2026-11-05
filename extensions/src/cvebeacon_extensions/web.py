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
                       label, read_bytes, timestamp, utc_now, write_snapshot)
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

# Suffixes that make the last label pair ambiguous. This is deliberately a
# small reviewed list, not a general public-suffix database dependency.
_TWO_LABEL_SUFFIXES = {
    "ac.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.uk", "co.za", "com.ar",
    "com.au", "com.br", "com.cn", "com.hk", "com.mx", "com.pl", "com.sg",
    "com.tr", "com.tw", "com.ua", "edu.au", "gov.uk", "net.au", "net.nz",
    "org.au", "org.uk", "org.za",
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

    def asset_for(self, endpoint: Endpoint) -> WebAsset | None:
        key = (endpoint.scheme, endpoint.hostname, endpoint.port)
        return next((asset for asset in self.assets
                     if (asset.endpoint.scheme, asset.endpoint.hostname, asset.endpoint.port) == key),
                    None)


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
        ca_bundle = ca_bundle.resolve()
        if not ca_bundle.is_file() or ca_bundle.is_symlink():
            raise ExtensionError("ca_bundle must be a regular file")
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
    total = 0
    for asset in allowlist.assets:
        maximum = 1 + (asset.max_redirects if asset.allow_redirects else 0)
        total += maximum
        lines.append(
            f"{asset.endpoint.url} GET host={asset.endpoint.hostname} port={asset.endpoint.port} "
            f"path={asset.endpoint.path} max_requests={maximum}"
        )
    lines.append(f"planned requests: {len(allowlist.assets)} assets, up to {total} requests")
    return "\n".join(lines)


def _registrable_domain(hostname: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    labels = hostname.casefold().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_nat64(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv6Address) and any(address in network for network in _NAT64)


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
            address = address.ipv4_mapped
        elif int(address) >> 32 == 0:
            # IPv4-compatible, including ::1 and ::. Treat the embedded IPv4
            # address as the real destination so it cannot bypass the policy.
            address = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        elif address.sixtofour is not None:
            address = address.sixtofour
    if (address.is_multicast or address.is_reserved or address.is_unspecified
            or address.is_loopback or address.is_link_local or address.is_private):
        return False
    return address.is_global


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
        self._deflate = encoding == "deflate"
        self._raw = False
        if encoding in {"gzip", "x-gzip"}:
            self._object = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif self._deflate:
            self._object = zlib.decompressobj()
        else:
            raise _UnsupportedEncodingFailure("unsupported content encoding")

    def feed(self, chunk: bytes, remaining: int) -> bytes:
        output = bytearray()
        data = chunk
        while data:
            try:
                part = self._object.decompress(data, remaining - len(output) + 1)
            except zlib.error as exc:
                if self._deflate and not self._raw:
                    self._raw = True
                    self._object = zlib.decompressobj(-zlib.MAX_WBITS)
                    continue
                raise _UnsupportedEncodingFailure("invalid compressed response body") from exc
            output.extend(part)
            if len(output) > remaining:
                raise _TooLargeFailure("decompressed body exceeds 2 MiB")
            data = self._object.unconsumed_tail
            if data and not part:
                raise _UnsupportedEncodingFailure("invalid compressed response body")
        return bytes(output)

    def finish(self, remaining: int) -> bytes:
        try:
            part = self._object.flush()
        except zlib.error as exc:
            raise _UnsupportedEncodingFailure("invalid compressed response body") from exc
        if len(part) > remaining:
            raise _TooLargeFailure("decompressed body exceeds 2 MiB")
        return part


def read_body(reader, content_encoding: str, *, deadline: float | None = None,
              clock: Callable[[], float] = time.monotonic, limit: int = BODY_LIMIT,
              wire_limit: int = WIRE_LIMIT) -> bytes:
    """Stream a response body, decoding gzip/deflate with a hard output cap."""
    decoder = None if content_encoding in {"", "identity"} else _BodyDecoder(content_encoding)
    output = bytearray()
    wire = 0
    while True:
        if deadline is not None and clock() >= deadline:
            raise _TimeoutFailure("response exceeded the asset time limit")
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


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, *, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, *, context: ssl.SSLContext,
                 timeout: float):
        super().__init__(host, port, context=context, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class StdlibTransport:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock

    @staticmethod
    def _context(ca_bundle: Path | None) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

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
                                                context=context, timeout=connect_timeout)
        else:
            connection = _PinnedHTTPConnection(endpoint.hostname, endpoint.port, address,
                                               timeout=connect_timeout)
        try:
            connection.connect()
            if connection.sock is not None:
                connection.sock.settimeout(max(0.1, min(READ_TIMEOUT, deadline - self._clock())))
            connection.request("GET", endpoint.path, headers={
                "Host": endpoint.authority,
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Connection": "close",
            })
            response = connection.getresponse()
            items = response.getheaders()
            _check_header_size(items)
            headers = _header_map(items)
            body = read_body(response, _content_encoding(headers), deadline=deadline,
                             clock=self._clock)
            return _Response(response.status, headers, body)
        except ssl.SSLError as exc:
            raise _TlsFailure("TLS verification or handshake failed") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise _TimeoutFailure("network read timed out") from exc
        except http.client.LineTooLong as exc:
            raise _TooLargeFailure("a response header line exceeded the limit") from exc
        except (ConnectionError, OSError) as exc:
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

    def wait(self, hostname: str) -> None:
        if self._interval <= 0:
            return
        while True:
            with self._lock:
                now = self._clock()
                previous = self._last.get(hostname)
                delay = self._interval - (now - previous) if previous is not None else 0.0
                if delay <= 0:
                    self._last[hostname] = now
                    return
            before = self._clock()
            self._sleep(delay)
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

    def _address(self, endpoint: Endpoint, asset: WebAsset) -> str:
        addresses = self.resolver.resolve(endpoint.hostname, endpoint.port)
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
                address = self._address(endpoint, asset)
                self._pacer.wait(endpoint.hostname)
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

    def _redirect(self, current: Endpoint, location: str, asset: WebAsset,
                  allowlist: Allowlist) -> Endpoint:
        try:
            target = urlsplit(urljoin(current.url, location))
            port = target.port
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
        hostname = _hostname(target_host)
        port = _port(port, scheme)
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        if not _PATH.fullmatch(path.split("?", 1)[0]) or any(
                ord(character) < 33 or ord(character) > 126 for character in path):
            raise _RedirectFailure("redirect target has an invalid path")
        if _registrable_domain(current.hostname) != _registrable_domain(hostname):
            raise _RedirectFailure("redirect leaves the registrable domain")
        if (scheme, hostname, port) not in allowlist.endpoints:
            raise _RedirectFailure("redirect target is not in the allowlist")
        return Endpoint(scheme, hostname, port, path)

    def fetch(self, asset: WebAsset, allowlist: Allowlist, *, run_deadline: float | None = None) -> _FetchSuccess:
        deadline = self._clock() + ASSET_TIMEOUT
        if run_deadline is not None:
            deadline = min(deadline, run_deadline)
        current = asset.endpoint
        current_asset = asset
        max_redirects = asset.max_redirects
        redirects: list[str] = []
        observed_at = self._now()
        for hop in range(asset.max_redirects + 1):
            if self._clock() >= deadline:
                raise _TimeoutFailure("asset exceeded the total time limit")
            response = self._request(current, current_asset, deadline, allowlist.ca_bundle)
            if response.status not in REDIRECT_STATUSES:
                if not 200 <= response.status < 300:
                    raise _ConnectionFailure(f"HTTP {response.status}", status=response.status)
                return _FetchSuccess(response, tuple(redirects), observed_at)
            if not asset.allow_redirects or hop >= max_redirects:
                raise _RedirectFailure("redirect limit reached", status=response.status)
            locations = response.headers.get("location", ())
            if not locations:
                raise _RedirectFailure("redirect response has no Location", status=response.status)
            target = self._redirect(current, locations[0], asset, allowlist)
            target_asset = allowlist.asset_for(target)
            if target_asset is None:
                raise _RedirectFailure("redirect target is not in the allowlist")
            redirects.append(target.url)
            current = target
            current_asset = target_asset
            max_redirects = min(max_redirects, target_asset.max_redirects)
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
        if len(detection.versions) > 1:
            reviews.append(dict(detail, reason="version-conflict", product=display,
                                category=detection.category, versions=list(detection.versions),
                                confidence=detection.confidence))
            omissions.add("version-conflict")
            continue
        version = detection.versions[0] if detection.versions else ""
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
    if plan:
        print(format_plan(allowlist))
        return None
    fetcher = Fetcher(resolver=resolver, transport=transport, sleep=sleep, clock=clock,
                      now=now, host_interval=host_interval)
    run_deadline = clock() + RUN_TIMEOUT
    results: list[_AssetResult] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(allowlist.assets)))) as pool:
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
    _publish_review(output, client, source_id, reviews)
    if not rows:
        raise ExtensionError("no technologies with usable identity; review output written")
    if set(omissions) & FAILURE_REASONS and not allow_partial:
        raise ExtensionError("web detection with fetch failures requires --allow-partial; review output written")
    return write_snapshot(output, rows, source_id=source_id, collector="web-detect",
                          observed_at=min(observed).isoformat() if observed else None,
                          omissions=omissions)
