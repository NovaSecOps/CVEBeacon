"""Canonical endpoint fields shared by web detection and inventory sync."""

import ipaddress
import re
import socket
from urllib.parse import urlsplit

_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
VISIBLE_PATH = re.compile(r"/[!-~]*")


def endpoint_port(value: object, scheme: str, field: str = "port") -> int:
    if value is None:
        return 443 if scheme == "https" else 80
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f"{field} must be an integer from 1 to 65535")
    return value


def _path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 2048:
        raise ValueError("path must be an absolute URL path of at most 2048 characters")
    if not VISIBLE_PATH.fullmatch(value) or "#" in value or "?" in value:
        raise ValueError("path must be one visible ASCII path without query or fragment")
    return value


def endpoint_hostname(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("hostname must be text")
    text = value.strip()
    if not text or len(text) > 253:
        raise ValueError("hostname must be bounded text")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if any(character.isspace() or character in "/\\@?#" for character in text):
        raise ValueError("hostname contains a forbidden character")
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
        raise ValueError("hostname is not valid IDNA") from exc
    text = text.rstrip(".").lower()
    if not text or len(text) > 253:
        raise ValueError("hostname must be bounded text")
    labels = text.split(".")
    if any(not _HOST_LABEL.fullmatch(item) for item in labels):
        raise ValueError("hostname is not a valid DNS name or IP address")
    return text


def _scheme(value: object) -> str:
    if not isinstance(value, str) or value.casefold() not in {"http", "https"}:
        raise ValueError("scheme must be http or https")
    return value.casefold()


def canonical_endpoint(entry: dict) -> tuple[str, str, int, str]:
    """Return the endpoint fields used to identify an allowlisted observation."""
    if ("hostname" in entry) == ("url" in entry):
        raise ValueError("each asset must set exactly one of hostname or url")
    if "url" in entry:
        value = entry["url"]
        if not isinstance(value, str):
            raise ValueError("url must be text")
        try:
            parts = urlsplit(value)
            parsed_port = parts.port
            parsed_host = parts.hostname
        except ValueError as exc:
            raise ValueError("url is not a valid absolute URL") from exc
        if parts.scheme.casefold() not in {"http", "https"} or not parsed_host:
            raise ValueError("url must be an absolute http or https URL")
        if parts.username is not None or parts.password is not None:
            raise ValueError("url must not contain credentials")
        if parts.query or parts.fragment:
            raise ValueError("url must not contain a query or fragment")
        scheme = _scheme(parts.scheme)
        host = endpoint_hostname(parsed_host)
        port = endpoint_port(parsed_port, scheme)
        path = _path(parts.path or "/")
        for field, parsed in (("scheme", scheme), ("port", port), ("path", path)):
            if field in entry and entry[field] != parsed:
                raise ValueError(f"{field} contradicts the url")
    else:
        scheme = _scheme(entry.get("scheme", "https"))
        host = endpoint_hostname(entry["hostname"])
        port = endpoint_port(entry.get("port"), scheme)
        path = _path(entry.get("path", "/"))
    return scheme, host, port, path
