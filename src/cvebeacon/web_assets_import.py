"""Bulk import of authorised web sites from CSV or a list of URLs.

Parsing and planning live here as plain functions. The routes reuse the single-site
add rules: one attestation, the companion validator, the permission recheck inside
the users transaction, the operation lock, chained audit entries and private storage.
Nothing here contacts a host.
"""

import csv
from datetime import date, datetime, time, timezone
import hashlib
import io
import ipaddress
import json
import re
import socket
from urllib.parse import urlsplit

from flask import abort, current_app, g, redirect, render_template, request, send_file, url_for

from .dashboard import _text, requires
from .dashboard_ops import require_accounts
from .errors import CVEBeaconError, ConfigurationError
from .locking import OperationLock, RunInProgress
from .publication import PublicationTimeout
from . import web_assets
from .web_assets import client_label, paths, read_allowlist, save_allowlist
from .web_inventory import read_bytes

MAX_ROWS = 1000
MAX_ASSETS = 1000
MAX_IMPORT_BYTES = 256 * 1024
# Posted text travels as a form field and may grow when percent-encoded.
IMPORT_REQUEST_BYTES = 1024 * 1024
TEMPLATE_FIELDS = ("hostname", "scheme", "port", "path", "allow_redirects", "max_redirects",
                   "expires_at", "allow_private_address")
TEMPLATE_ROWS = (
    ("www.example.com", "https", "443", "/", "yes", "2", "", "no"),
    ("shop.example.com", "https", "443", "/", "yes", "2", "", "no"),
)
_KNOWN = frozenset(TEMPLATE_FIELDS) | {"url"}
_BOOLEANS = {"yes": True, "true": True, "1": True, "no": False, "false": False, "0": False}
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PATH = re.compile(r"/[!-~]*")
ADD, SAVED, DUPLICATE, ERROR = "add", "saved", "duplicate", "error"
STATUS_LABELS = {ADD: "Will be added", SAVED: "Already saved", DUPLICATE: "Duplicate in this file",
                 ERROR: "Error"}
STATUS_BADGES = {ADD: "success", SAVED: "neutral", DUPLICATE: "neutral", ERROR: "danger"}
CHANGED = "This list changed; review the import again."


class ImportRefused(ConfigurationError):
    """The whole input is refused; the message is safe to show."""


def template_csv():
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(TEMPLATE_FIELDS)
    writer.writerows(TEMPLATE_ROWS)
    return output.getvalue().encode("utf-8")


def decode_text(data):
    """Strict UTF-8 text (a BOM is allowed), bounded, with no binary content."""
    if len(data) > MAX_IMPORT_BYTES:
        raise ImportRefused("The import is larger than 256 KiB. Split it into smaller files.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImportRefused("The import must be a UTF-8 text file. Save the CSV as UTF-8 and try again.") from None
    if "\x00" in text:
        raise ImportRefused("The import must be a plain text CSV file, not a binary file.")
    return text


def _canonical_host(value):
    """The companion validator's spelling of a host, used for duplicate checks."""
    text = value.strip()
    if not text or len(text) > 253:
        raise ValueError("The hostname is empty or too long.")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "://" in text:
        raise ValueError("The hostname must not include a scheme; put only the site name.")
    if any(character.isspace() or character in "/\\@?#" for character in text):
        raise ValueError("The hostname must be a site name only, with no path, user name or spaces.")
    try:
        return socket.inet_ntoa(socket.inet_aton(text))
    except (OSError, ValueError, UnicodeError):
        pass
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("The hostname is not a valid internationalised name.") from None
    text = text.rstrip(".").lower()
    if (not text or len(text) > 253
            or any(not _HOST_LABEL.fullmatch(label) for label in text.split("."))):
        raise ValueError("The hostname is not a valid DNS name or IP address.")
    return text


def _boolean(value, field, default):
    if not value:
        return default
    try:
        return _BOOLEANS[value.casefold()]
    except KeyError:
        raise ValueError(f"{field} must be yes or no.") from None


def _port(value, scheme):
    if not value:
        return 443 if scheme == "https" else 80
    if not (value.isascii() and value.isdecimal() and len(value) <= 5 and 1 <= int(value) <= 65535):
        raise ValueError("The port must be a number from 1 to 65535.")
    return int(value)


def _path(value):
    if not value:
        return "/"
    if len(value) > 2048:
        raise ValueError("The path is longer than 2,048 characters.")
    if not value.startswith("/"):
        raise ValueError("The path must start with /.")
    if not _PATH.fullmatch(value) or "#" in value or "?" in value:
        raise ValueError("The path must be plain visible characters, without a query or fragment.")
    return value


def _expiry(value, now):
    if not value:
        return ""
    try:
        if len(value) <= 10 and "T" not in value.upper():
            moment = datetime.combine(date.fromisoformat(value), time(23, 59, 59), timezone.utc)
        else:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
            moment = (moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None
                      else moment.astimezone(timezone.utc))
    except ValueError:
        raise ValueError("The expiry must be an ISO date or date and time, such as 2027-01-31.") from None
    if moment <= now:
        raise ValueError("The expiry must be in the future.")
    return moment.isoformat()


def _from_url(value):
    try:
        parts = urlsplit(value)
        port, host = parts.port, parts.hostname
    except ValueError:
        raise ValueError("The URL is not valid.") from None
    scheme = parts.scheme.casefold()
    if scheme not in {"http", "https"} or not host:
        raise ValueError("The URL must start with http:// or https:// and name a site.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("The URL must not contain a user name or password.")
    if parts.query or parts.fragment:
        raise ValueError("The URL must not contain a query or fragment.")
    return scheme, host, "" if port is None else str(port), parts.path or "/"


def _row_entry(cells, now):
    """One validated entry from a mapping of cleaned cells; raises ValueError with a plain reason."""
    url, host = cells.get("url", ""), cells.get("hostname", "")
    if url and host:
        raise ValueError("Give either a hostname or a URL, not both.")
    if not url and not host:
        raise ValueError("A hostname or URL is required.")
    if url:
        if any(cells.get(name) for name in ("scheme", "port", "path")):
            raise ValueError("A URL already sets the scheme, port and path; leave those columns empty.")
        scheme, host, port, path = _from_url(url)
    else:
        scheme, port, path = cells.get("scheme", "").casefold() or "https", cells.get("port", ""), cells.get("path", "")
        if scheme not in {"http", "https"}:
            raise ValueError("The scheme must be http or https.")
    _canonical_host(host)
    redirects = _boolean(cells.get("allow_redirects", ""), "Allow redirects", True)
    maximum = cells.get("max_redirects", "")
    if maximum and not (maximum.isascii() and maximum.isdecimal() and len(maximum) <= 2 and int(maximum) <= 10):
        raise ValueError("Maximum redirects must be a number from 0 to 10.")
    entry = {"hostname": host, "scheme": scheme, "port": _port(port, scheme), "path": _path(path),
             "allow_redirects": redirects, "max_redirects": int(maximum) if maximum else 2,
             "allow_private_address": _boolean(cells.get("allow_private_address", ""),
                                               "Allow private addresses", False)}
    expiry = _expiry(cells.get("expires_at", ""), now)
    if expiry:
        entry["expires_at"] = expiry
    return entry


def parse_rows(text, now):
    """Return (records, unknown_columns). A record is (line number, entry or None, error or None)."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ImportRefused("The import is empty. Add a header and at least one site.")
    reader = csv.reader(io.StringIO(text, newline=""))
    header = None
    try:
        for cells in reader:
            if any(cell.strip() for cell in cells):
                header = [cell.strip().casefold() for cell in cells]
                break
    except csv.Error:
        raise ImportRefused("The CSV could not be read. Check quotes and commas.") from None
    result, unknown = [], []
    if header is not None and ({"hostname", "url"} & set(header)):
        if len(set(header)) != len(header) or "" in header:
            raise ImportRefused("The header repeats or leaves out a column name.")
        unknown = [name for name in header if name not in _KNOWN]
        try:
            for cells in reader:
                if not any(cell.strip() for cell in cells):
                    continue
                if len(result) >= MAX_ROWS:
                    raise ImportRefused("The import has more than 1,000 rows. Split it into smaller files.")
                number = reader.line_num
                if len(cells) > len(header):
                    result.append((number, None, "The row has more cells than the header."))
                    continue
                values = {name: cell.strip() for name, cell in zip(header, cells) if name in _KNOWN}
                try:
                    result.append((number, _row_entry(values, now), None))
                except ValueError as exc:
                    result.append((number, None, str(exc)))
        except csv.Error:
            raise ImportRefused("The CSV could not be read. Check quotes and commas.") from None
        return result, unknown
    # A plain list of URLs, one per line.
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if len(result) >= MAX_ROWS:
            raise ImportRefused("The import has more than 1,000 rows. Split it into smaller files.")
        try:
            result.append((number, _row_entry({"url": line}, now), None))
        except ValueError as exc:
            result.append((number, None, str(exc)))
    return result, unknown


def _entry_key(entry):
    """(scheme, host, port, path) for a saved or new entry, or None if it cannot be read."""
    try:
        if "url" in entry:
            scheme, host, port, path = _from_url(entry["url"])
        else:
            scheme, host = str(entry.get("scheme", "https")).casefold(), entry.get("hostname", "")
            port, path = entry.get("port"), entry.get("path", "/")
        if scheme not in {"http", "https"}:
            return None
        port = int(port) if port not in (None, "") else (443 if scheme == "https" else 80)
        return scheme, _canonical_host(str(host)), port, path or "/"
    except (ValueError, TypeError):
        return None


def display_url(entry):
    scheme, host, port = entry["scheme"], entry["hostname"], entry["port"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}{'' if port == default else ':' + str(port)}{entry['path']}"


def plan(text, current_assets, now):
    """Classify every row. Returns (rows, to_add, unknown_columns); rows carry a status and reason."""
    records, unknown = parse_rows(text, now)
    saved, added, private = set(), set(), {}
    for asset in current_assets:
        key = _entry_key(asset)
        if key is not None:
            saved.add(key)
            private[key[:3]] = bool(asset.get("allow_private_address", False))
    rows, to_add = [], []
    for number, entry, error in records:
        row = {"number": number, "entry": entry, "status": ERROR, "reason": error or ""}
        if entry is not None:
            key = _entry_key(entry)
            if key in saved:
                row["status"] = SAVED
            elif key in added:
                row["status"] = DUPLICATE
            elif private.get(key[:3], entry["allow_private_address"]) != entry["allow_private_address"]:
                row["reason"] = ("Another entry for the same site and port has a different private "
                                 "address setting.")
            else:
                added.add(key)
                private[key[:3]] = entry["allow_private_address"]
                row["status"] = ADD
                to_add.append(entry)
        rows.append(row)
    return rows, to_add, unknown


def digest(entries):
    data = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def register(blueprint, config, render):
    """Add the import routes to the Web assets blueprint."""
    from . import dashboard_web

    @blueprint.get("/import-template")
    @requires("view")
    def import_template():
        return send_file(io.BytesIO(template_csv()), mimetype="text/csv", as_attachment=True,
                         download_name="web-sites-template.csv", max_age=0)

    def posted_text():
        upload = request.files.get("csv_file")
        pasted = request.form.get("csv_text", "")
        if upload is not None and upload.filename:
            if pasted.strip():
                raise ImportRefused("Choose a file or paste text, not both.")
            return decode_text(upload.stream.read(MAX_IMPORT_BYTES + 1))
        return decode_text(_encode_form_text(pasted))

    def client_from_form():
        require_accounts()
        try:
            return client_label(dashboard_web._canonical_client(
                config, _text(request.form, "client", required=True)))
        except ConfigurationError:
            abort(400)

    @blueprint.post("/import/preview")
    @requires("manage_web_assets")
    def import_preview():
        client = client_from_form()
        try:
            text = posted_text()
            path, _ = paths(config, client)
            current, version = read_allowlist(path, client)
            client = current["client"]
            rows, to_add, unknown = plan(text, current["assets"], datetime.now(timezone.utc))
            if len(current["assets"]) + len(to_add) > MAX_ASSETS:
                raise ConfigurationError(
                    f"This would take {client} past 1,000 saved sites. Import fewer sites.")
            if to_add:
                candidate = {**current, "assets": current["assets"] + [
                    {**entry, "authorized_by": g.user.username,
                     "authorized_at": datetime.now(timezone.utc).isoformat()} for entry in to_add]}
                dashboard_web.validate_allowlist(config, path, candidate)
        except (CVEBeaconError, ValueError, OSError) as exc:
            return render(client, error=_message(exc, "The import could not be checked"), status=400)
        counts = {name: sum(1 for row in rows if row["status"] == name) for name in STATUS_LABELS}
        return render_template(
            "web_assets_import.html", client=client, rows=rows, counts=counts, unknown=unknown,
            version=version, digest=digest(to_add), import_text=text, add_count=len(to_add),
            private_count=sum(1 for entry in to_add if entry["allow_private_address"]),
            status_labels=STATUS_LABELS, status_badges=STATUS_BADGES, display_url=display_url,
            available=web_assets.companion_available()), 200

    @blueprint.post("/import/save")
    @requires("manage_web_assets")
    def import_save():
        client = client_from_form()
        version_in = _text(request.form, "version", required=True, limit=64)
        digest_in = _text(request.form, "digest", required=True, limit=64)
        if _text(request.form, "attest") != "yes":
            return render(client, error="Attest authorisation before importing these sites", status=400)
        lock = OperationLock(config, "web-assets")
        if not lock.acquire():
            return render(client, error=str(RunInProgress(lock.holder)), status=409)
        try:
            try:
                text = decode_text(_encode_form_text(request.form.get("csv_text", "")))
                path, _ = paths(config, client)
                current, version = read_allowlist(path, client)
                client = current["client"]
                if version != version_in:
                    raise ConfigurationError(CHANGED)
                stamp_now = datetime.now(timezone.utc)
                _, to_add, _ = plan(text, current["assets"], stamp_now)
                if not to_add or digest(to_add) != digest_in:
                    raise ConfigurationError(CHANGED)
                if (sum(1 for entry in to_add if entry["allow_private_address"])
                        and _text(request.form, "attest_private") != "yes"):
                    raise ConfigurationError(
                        "Confirm the sites that allow private addresses before importing")
                if len(current["assets"]) + len(to_add) > MAX_ASSETS:
                    raise ConfigurationError(
                        f"This would take {client} past 1,000 saved sites. Import fewer sites.")
                authorised = stamp_now.isoformat()
                candidate = {**current, "assets": current["assets"] + [
                    {**entry, "authorized_by": g.user.username, "authorized_at": authorised}
                    for entry in to_add]}
                dashboard_web.validate_allowlist(config, path, candidate)
                users = current_app.extensions["dashboard_users"]
                original = read_bytes(path) if path.exists() or path.is_symlink() else None
                writing = False
                try:
                    with users.transaction() as db:
                        actor = users.require_permission_in(db, g.entry.proof, "manage_web_assets")
                        stamp = datetime.now(timezone.utc).isoformat()

                        def audit(name, detail):
                            if len(detail) > 1024 or any(ord(char) < 32 for char in detail):
                                raise ConfigurationError("invalid audit detail")
                            users._append_audit(db, name + ":" + detail, actor.username, stamp,
                                                actor=actor.username)

                        for entry in to_add:
                            audit("web_asset_add", dashboard_web._audit_detail(client, entry["hostname"]))
                        audit("web_asset_import", json.dumps(
                            {"client": client, "count": len(to_add)}, ensure_ascii=False))
                        writing = True
                        save_allowlist(path, candidate)
                except BaseException:
                    if writing:
                        if original is None:
                            path.unlink(missing_ok=True)
                        else:
                            web_assets.replace_bytes(path, original)
                    raise
            except (CVEBeaconError, ValueError, OSError) as exc:
                return render(client, error=_message(exc, "The sites could not be imported"), status=400)
        finally:
            lock.release()
        return redirect(url_for("web.index", client=client, imported=len(to_add)), code=303)


def _encode_form_text(value):
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise ImportRefused("The import must be a UTF-8 text file.") from None


def _message(exc, fallback):
    return str(exc) if isinstance(exc, (ConfigurationError, PublicationTimeout)) else fallback
