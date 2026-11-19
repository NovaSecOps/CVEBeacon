"""CVE List release imports with bounded archives and independent cursors."""
from __future__ import annotations

from contextlib import closing

import hashlib
import json
import re
import os
import shutil
import sqlite3
import struct
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from ..errors import SourceError
from ..private_storage import private_file
from .directories import ensure_private_directory
from ..sources.common import cve_id, source_payload
from .records import CVSSEntry, Product, Reference, WatchRecord

RELEASE_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
ASSET_PREFIX = "https://github.com/CVEProject/cvelistV5/releases/download/"
REDIRECT_HOSTS = ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
DIRECTORY_CAP = 64 * 1024 * 1024
JSON_CAP = 4 * 1024 * 1024
ARCHIVE_CAP = 1024 * 1024 * 1024
EXPANDED_CAP = 8 * 1024 * 1024 * 1024
MAX_MEMBERS = 1_000_000
MAX_DELTA_DAYS = 7
RELEASE_LIST_LIMIT = 100
BATCH = 100
BATCH_BYTES = 8 * 1024 * 1024
DISK_RESERVE = 64 * 1024 * 1024
STORAGE_MULTIPLIER = 3


def description_text(payload):
    containers = payload.get("containers") or {}
    parts = []
    for container in [containers.get("cna") or {}, *(containers.get("adp") or [])]:
        if not isinstance(container, dict):
            raise SourceError("cve_list", "invalid container")
        if container.get("title"):
            parts.append(str(container["title"]))
        for key in ("descriptions", "rejectedReasons"):
            for item in container.get(key) or []:
                if isinstance(item, dict) and isinstance(item.get("value"), str):
                    parts.append(item["value"])
    return "\n".join(dict.fromkeys(parts))


def _record_date(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise SourceError("cve_list", "invalid record date")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceError("cve_list", "invalid record date") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _record_date_or_none(value):
    try:
        return _record_date(value)
    except SourceError:
        return None


@source_payload("cve_list")
def parse_record(payload):
    if not isinstance(payload, dict):
        raise SourceError("cve_list", "record is not an object")
    metadata = payload.get("cveMetadata")
    if not isinstance(metadata, dict):
        raise SourceError("cve_list", "record omitted metadata")
    identifier = cve_id(metadata.get("cveId"))
    state = metadata.get("state")
    if not identifier or state not in {"PUBLISHED", "REJECTED", "RESERVED"} or payload.get("dataVersion") not in {"5.0", "5.0.0", "5.1", "5.1.0", "5.1.1", "5.2", "5.2.0"}:
        raise SourceError("cve_list", "invalid record metadata")
    containers = payload.get("containers") or {}
    cna = containers.get("cna") or {}
    if state != "RESERVED" and not cna:
        raise SourceError("cve_list", "record omitted CNA container")
    entries, products, references, cwes = [], [], [], []
    for role, container in [("cna", cna), *(("other", item) for item in containers.get("adp") or [])]:
        provider = container.get("providerMetadata") or {}
        name = str(provider.get("shortName") or provider.get("orgId") or role)
        if role != "cna" and ("cisa" in name.casefold() or provider.get("orgId") == "134c704f-9b21-4f2e-91b3-4a467353bcc0"):
            role = "cisa-adp"
        for metric in container.get("metrics") or []:
            for key, version in (("cvssV2_0", "2.0"), ("cvssV3_0", "3.0"), ("cvssV3_1", "3.1"), ("cvssV4_0", "4.0")):
                data = metric.get(key)
                if data:
                    score = data.get("baseScore")
                    if isinstance(score, bool) or not isinstance(score, (float, int)) or not 0 <= score <= 10:
                        raise SourceError("cve_list", "invalid CVSS score")
                    entries.append(CVSSEntry(role, name, version, float(score), data.get("vectorString"), data.get("baseSeverity")))
        for item in container.get("affected") or []:
            products.append(Product(str(item.get("vendor") or ""), str(item.get("product") or "")))
        for item in container.get("references") or []:
            if item.get("url"):
                references.append(Reference(str(item["url"]), tuple(item.get("tags") or ())))
        for item in container.get("problemTypes") or []:
            cwes.extend(str(d["cweId"]) for d in item.get("descriptions") or [] if d.get("cweId"))
    return WatchRecord(identifier, state.lower(), _record_date(metadata.get("datePublished")), _record_date_or_none(metadata.get("dateUpdated") or metadata.get("dateReserved")),
                       description_text(payload) or None,
                       str((cna.get("providerMetadata") or {}).get("shortName") or metadata.get("assignerShortName") or "") or None,
                       tuple(entries), tuple(cwes), tuple(products), tuple(references))


def _json(http, url, *, headers=None, response_headers=None, byte_cap=None):
    data = b"".join(http.stream_bytes(url, source="cve_list", byte_cap=JSON_CAP if byte_cap is None else byte_cap,
                                      headers=headers, response_headers=response_headers,
                                      allow_not_modified=True))
    if not data:
        return None
    try:
        return json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise SourceError("cve_list", "invalid release metadata") from exc


def _validate_asset(asset):
    url = asset.get("browser_download_url", "")
    if not url.startswith(ASSET_PREFIX) or urlsplit(url).username or urlsplit(url).port != urlsplit(ASSET_PREFIX).port:
        raise SourceError("cve_list", "invalid release asset location")
    if type(asset.get("size")) is not int or not 0 < asset["size"] <= ARCHIVE_CAP:
        raise SourceError("cve_list", "archive exceeds size limit")


def _select_assets(assets):
    selected = {}
    for asset in assets if isinstance(assets, list) else ():
        name = asset.get("name", "") if isinstance(asset, dict) else ""
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}_all_CVEs_at_midnight\.zip(?:\.zip)?", name):
            selected["baseline"] = asset
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}_delta_CVEs_at_\d{4}Z\.zip", name):
            selected["delta"] = asset
    return selected


def _hourly_release(releases):
    """Choose the newest hourly release from a bounded release listing.

    GitHub's ``/releases/latest`` can point at the separate end-of-day release.
    Select explicitly by the hourly archive names and their UTC date instead.
    """
    candidates = []
    failures = []
    for item in releases:
        if not isinstance(item, dict) or item.get("draft") or item.get("prerelease"):
            continue
        selected = _select_assets(item.get("assets"))
        if "baseline" not in selected or "delta" not in selected:
            continue
        try:
            for asset in selected.values():
                _validate_asset(asset)
            delta_time = datetime.strptime(selected["delta"]["name"][:10] + selected["delta"]["name"][-9:-5], "%Y-%m-%d%H%M")
            baseline_day = datetime.strptime(selected["baseline"]["name"][:10], "%Y-%m-%d")
            if not timedelta(0) <= delta_time - baseline_day < timedelta(days=2):
                raise ValueError("incoherent release")
        except SourceError as exc:
            failures.append(exc)
            continue
        except (KeyError, TypeError, ValueError):
            continue
        candidates.append((delta_time, selected))
    if not candidates:
        if failures:
            raise failures[-1]
        raise SourceError("cve_list", "release list omitted a coherent hourly baseline and delta archive")
    return max(candidates, key=lambda item: item[0])[1]


@source_payload("cve_list")
def release(http, metadata):
    headers = {"If-None-Match": metadata["cve_list_etag"]} if metadata.get("cve_list_etag") else {}
    response_headers = {}
    payload = _json(http, RELEASE_URL + f"?per_page={RELEASE_LIST_LIMIT}",
                    headers=headers, response_headers=response_headers)
    if payload is None:
        try:
            payload = json.loads(metadata["cve_list_release"])
        except (KeyError, ValueError) as exc:
            raise SourceError("cve_list", "conditional response has no cached release") from exc
        selected = _select_assets(payload.get("assets") if isinstance(payload, dict) else None)
        if "baseline" not in selected or "delta" not in selected:
            raise SourceError("cve_list", "cached release is invalid")
        return selected, {
            "cve_list_release": metadata["cve_list_release"],
            "cve_list_etag": metadata.get("cve_list_etag", ""),
        }
    if not isinstance(payload, list):
        raise SourceError("cve_list", "invalid release list")
    selected = _hourly_release(payload)
    cache = json.dumps({"assets": list(selected.values())}, separators=(",", ":"))
    return selected, {"cve_list_release": cache, "cve_list_etag": response_headers.get("etag", metadata.get("cve_list_etag", ""))}


def _require_disk(directory, needed):
    if directory is not None and shutil.disk_usage(directory).free < needed + DISK_RESERVE:
        raise SourceError("cve_list", "insufficient disk for archive and provider storage")


def _directory_limits(file):
    """Check the exact directory range; reject ambiguous/prefixed layouts."""
    file.seek(0, 2)
    length = file.tell()
    file.seek(max(0, length - 65557))
    tail = file.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        raise SourceError("cve_list", "invalid ZIP directory")
    end = struct.unpack("<4s4H2LH", tail[position:position + 22])
    if position + 22 + end[7] != len(tail) or end[1] or end[2] or end[3] != end[4]:
        raise SourceError("cve_list", "invalid ZIP directory")
    count, size, offset = end[4:7]
    directory_end = length - len(tail) + position
    if count == 65535 or size == 0xffffffff or offset == 0xffffffff:
        file.seek(directory_end - 20)
        locator = struct.unpack("<4sLQL", file.read(20))
        if locator[0] != b"PK\x06\x07" or locator[1] or locator[3] != 1:
            raise SourceError("cve_list", "invalid ZIP64 directory")
        file.seek(locator[2])
        extended = struct.unpack("<4sQ2H2L4Q", file.read(56))
        if (extended[0] != b"PK\x06\x06" or extended[1] != 44
                or extended[4] or extended[5] or extended[6] != extended[7]
                or locator[2] + 56 + 20 != directory_end):
            raise SourceError("cve_list", "invalid ZIP64 directory")
        count, size, offset = extended[7:10]
        directory_end = locator[2]
    if count > MAX_MEMBERS or size > DIRECTORY_CAP or offset + size != directory_end:
        raise SourceError("cve_list", "invalid ZIP directory range or size limit")
    actual = expanded = 0
    for info in _directory_entries(file, offset, size):
        actual += 1
        expanded += info.file_size
        if actual > MAX_MEMBERS or expanded > EXPANDED_CAP:
            raise SourceError("cve_list", "ZIP directory exceeds member or expanded size limit")
    if actual != count:
        raise SourceError("cve_list", "ZIP directory member count mismatch")
    return offset, size, count, expanded


def _directory_entries(file, offset, size):
    """Yield one ZipInfo at a time, never allocate ZipFile's complete index."""
    position = offset
    while position < offset + size:
        file.seek(position)
        header = file.read(46)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise SourceError("cve_list", "invalid ZIP directory entry")
        fields = struct.unpack("<4s6H3L5H2L", header)
        position += 46 + sum(fields[10:13])
        if (position > offset + size or fields[10] > 4096 or fields[13]
                or fields[8] == 0xffffffff or fields[9] == 0xffffffff
                or fields[16] >= offset or fields[2] > zipfile.MAX_EXTRACT_VERSION):
            raise SourceError("cve_list", "invalid ZIP directory member")
        name = file.read(fields[10]).decode("utf-8" if fields[3] & 0x800 else "cp437")
        info = zipfile.ZipInfo(name)
        info.flag_bits, info.compress_type = fields[3:5]
        info.CRC, info.compress_size, info.file_size = fields[7:10]
        info.header_offset = fields[16]
        info._end_offset = offset
        yield info


class _StreamingZip(zipfile.ZipFile):
    """Use stdlib CRC/decompression without its all-members directory index."""
    def __init__(self, file, directory_start):
        self._directory_start = directory_start
        super().__init__(file)

    def _RealGetContents(self):
        self.start_dir = self._directory_start


def _members(file, *, allow_empty=False, nested=False, temporary_directory=None):
    offset, size, count, expanded = _directory_limits(file)
    # Expanded JSON is stored as raw + normalized + search text, with room for
    # indexes and a transaction/WAL. Recheck per batch as actual storage grows.
    _require_disk(temporary_directory, STORAGE_MULTIPLIER * expanded + 4 * size)
    with (_StreamingZip(file, offset) as archive,
          tempfile.TemporaryDirectory(dir=temporary_directory) as seen_directory,
          closing(sqlite3.connect(str(Path(seen_directory) / 'seen.sqlite'))) as seen):
        seen.execute("PRAGMA cache_size=-1024")
        seen.execute("CREATE TABLE seen(name TEXT PRIMARY KEY)")
        found = False
        for info in _directory_entries(file, offset, size):
            name = PurePosixPath(info.filename).name
            if name == "cves.zip":
                if nested or count != 1 or info.file_size > ARCHIVE_CAP:
                    raise SourceError("cve_list", "invalid nested baseline archive")
                _require_disk(temporary_directory, info.file_size)
                with tempfile.TemporaryFile(dir=temporary_directory) as inner, archive.open(info) as member:
                    shutil.copyfileobj(member, inner, 65536)
                    inner.seek(0)
                    yield from _members(inner, allow_empty=allow_empty, nested=True, temporary_directory=temporary_directory)
                return
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}\.json", name):
                continue
            if info.file_size > JSON_CAP or info.flag_bits & 1:
                raise SourceError("cve_list", "invalid archive member")
            try:
                seen.execute("INSERT INTO seen VALUES (?)", (name,))
            except sqlite3.IntegrityError as exc:
                raise SourceError("cve_list", "duplicate archive member") from exc
            found = True
            with archive.open(info) as member:
                raw = member.read(JSON_CAP + 1)
            if len(raw) > JSON_CAP:
                raise SourceError("cve_list", "record exceeds limit")
            payload = json.loads(raw)
            record = parse_record(payload)
            if record.cve_id != name[:-5]:
                raise SourceError("cve_list", "archive member identifier mismatch")
            yield payload
        if not found and not allow_empty:
            raise SourceError("cve_list", "archive contains no CVE records")


def archive_records(http, asset, *, allow_empty=False, cache_directory=None):
    """Keep a verified download for parse retries; bound disk, directory and body.

    Full imports use disk adjacent to the state DB rather than an implicit tmpfs.
    An interrupted body restarts on the next attempt. Completed bodies may be
    reused; any archive validation failure evicts the cache before raising.
    """
    path = None
    try:
        if cache_directory is not None:
            directory = Path(cache_directory)
            ensure_private_directory(directory)
            _require_disk(directory, asset["size"])
            token = hashlib.sha256(json.dumps(asset, sort_keys=True).encode()).hexdigest()[:24]
            path = directory / ("cve-list-" + token + ".zip")
            for old in directory.glob("cve-list-*.zip"):
                if old != path:
                    old.unlink()
            file = os.fdopen(private_file(path, create=True), "r+b")
        else:
            file = tempfile.TemporaryFile()
        with file:
            file.seek(0, 2)
            size = file.tell()
            if size != asset["size"]:
                file.seek(0)
                file.truncate()
                size = 0
                for chunk in http.stream_bytes(asset["browser_download_url"], source="cve_list", byte_cap=ARCHIVE_CAP, redirect_hosts=REDIRECT_HOSTS):
                    size += len(chunk)
                    file.write(chunk)
                file.flush()
            if size != asset["size"]:
                raise SourceError("cve_list", "archive size mismatch")
            file.seek(0)
            digest = hashlib.sha256()
            while chunk := file.read(65536):
                digest.update(chunk)
            expected = asset.get("digest")
            if expected and expected != "sha256:" + digest.hexdigest():
                if path is not None:
                    path.unlink()
                raise SourceError("cve_list", "archive digest mismatch")
            file.seek(0)
            yield from _members(file, allow_empty=allow_empty,
                                temporary_directory=str(path.parent) if path else None)
    except SourceError:
        if path is not None:
            path.unlink(missing_ok=True)
        raise
    except (zipfile.BadZipFile, RuntimeError, ValueError, UnicodeError, OSError, EOFError, NotImplementedError, struct.error) as exc:
        if path is not None:
            path.unlink(missing_ok=True)
        raise SourceError("cve_list", "invalid or incomplete CVE archive") from exc


def _time(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError) as exc:
        raise SourceError("cve_list", "invalid archive timestamp") from exc


def _asset_token(asset):
    """Stable identity for an unchanged release asset.

    GitHub's asset id, name, size and updated_at are immutable release
    metadata. The body digest is included when updated_at is available; older
    or synthetic release metadata may omit updated_at and regenerate equivalent
    bytes with a different digest, so identity falls back to name and size.
    """
    identity = str(asset.get("id") or asset["browser_download_url"])
    parts = [identity, str(asset.get("name", "")), str(asset.get("size", ""))]
    if asset.get("updated_at"):
        parts.append(str(asset["updated_at"]))
        if asset.get("digest"):
            parts.append(str(asset["digest"]))
    return ":".join(parts)


def _delta_time(asset):
    return datetime.strptime(asset["name"][:10] + asset["name"][-9:-5], "%Y-%m-%d%H%M").replace(tzinfo=timezone.utc)


@source_payload("cve_list")
def end_of_day(http, day):
    """The official closed-day release has its own tag, not the 23:00 tag."""
    tag = "cve_" + day.isoformat() + "_at_end_of_day"
    url = RELEASE_URL + "/tags/" + tag
    try:
        payload = _json(http, url)
    except SourceError as exc:
        if exc.status_code == 404:
            return None
        raise
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise SourceError("cve_list", "invalid end-of-day release")
    name = day.isoformat() + "_delta_CVEs_at_end_of_day.zip"
    for asset in payload["assets"]:
        if asset.get("name") == name:
            _validate_asset(asset)
            return asset
    return None


def _import_archive(http, store, watch, asset, at, *, initial=False, after=None, since=None):
    """Commit bounded batches; publish coverage only after validated EOF.

    Evaluation obligations already live in watch_touched. Do not accumulate a
    second full-history ID collection merely to return a summary.
    """
    directory = store.path.parent / (store.path.name + ".cve-list-cache")
    ensure_private_directory(directory)
    batch = []
    batch_bytes = 0
    count = new = changed = 0

    def commit():
        nonlocal count, new, changed, batch_bytes
        _require_disk(directory, STORAGE_MULTIPLIER * batch_bytes)
        result = store.upsert_cve_list(batch, catalogs=watch.sources, initial=initial)
        count += len(batch)
        new += result.new
        changed += result.changed
        batch.clear()
        batch_bytes = 0

    for payload in archive_records(http, asset, allow_empty="_all_CVEs_" not in asset["name"],
                                   cache_directory=directory):
        record = parse_record(payload)
        raw_metadata = payload.get("cveMetadata") if isinstance(payload, dict) else None
        raw_updated = raw_metadata.get("dateUpdated") if isinstance(raw_metadata, dict) else None
        normalized_updated = _record_date_or_none(raw_updated)
        stamp = _time(normalized_updated) if normalized_updated else None
        if stamp is not None:
            if after is not None and stamp < after:
                continue
            if since is not None and stamp < since:
                continue
        size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        if batch and (batch_bytes + size > BATCH_BYTES or len(batch) >= BATCH):
            commit()
        batch.append(payload)
        batch_bytes += size
        if len(batch) >= BATCH or batch_bytes >= BATCH_BYTES:
            commit()
    if batch:
        commit()
    store.set_metadata({"cve_list_cursor": at.isoformat(),
                        "cve_list_archive_asset": _asset_token(asset)})
    return count, new, changed


def sync(http, store, watch, now, *, initial_mode=None):
    """Follow complete cumulative archives with one durable UTC boundary."""
    store.initialize()
    metadata = store.metadata()
    mode = initial_mode or metadata.get("cve_list_initial_mode")
    if (initial_mode is None and mode in ("full", "backfill")
            and metadata.get("initialized_at") and "cve_list_initial_pending" not in metadata
            and not metadata.get("cve_list_cursor")):
        mode = "baseline"
        metadata.pop("cve_list_start", None)
    if not metadata.get("cve_list_start") or initial_mode is not None:
        mode = mode or ("baseline" if metadata.get("initialized_at") else watch.initial)
        start = now - timedelta(days=watch.backfill_days) if mode == "backfill" else now
        if initial_mode is not None:
            with store.transaction() as db:
                db.execute("DELETE FROM watch_meta WHERE key LIKE 'cve_list_%'")
        store.set_metadata({"cve_list_start": start.isoformat(), "cve_list_initial_mode": mode,
                            "cve_list_initial_pending": "0" if mode == "baseline" else "1"})
        metadata = store.metadata()
    assets, cache = release(http, metadata)
    store.set_metadata(cache)
    baseline, delta = assets["baseline"], assets["delta"]
    baseline_time = _time(baseline["name"][:10] + "T00:00:00Z")
    latest = _delta_time(delta)
    cursor = _time(metadata["cve_list_cursor"]) if metadata.get("cve_list_cursor") else None
    try:
        start_time = _time(metadata["cve_list_start"])
    except SourceError:
        start_time = None
    initialising = mode in ("full", "backfill") and (
        cursor is None or metadata.get("cve_list_initial_pending") == "1")
    totals = [0, 0, 0]

    def apply(asset, at, *, initial, after=None, since=None):
        nonlocal cursor
        counts = _import_archive(http, store, watch, asset, at,
                                 initial=initial, after=after, since=since)
        for index, value in enumerate(counts):
            totals[index] += value
        cursor = at

    def filters():
        if initialising:
            return {"initial": True, "since": start_time if mode == "backfill" else None}
        return {"initial": False, "after": cursor}

    if cursor is None:
        if mode == "baseline":
            store.set_metadata({"cve_list_cursor": latest.isoformat(),
                                "cve_list_archive_asset": _asset_token(delta),
                                "cve_list_initial_pending": "0"})
            return 0, 0, 0, ()
        apply(baseline, baseline_time, **filters())

    # A week of closed-day archives bounds ordinary catch-up work and API use.
    # Longer gaps, or a genuinely missing archive, use one full snapshot.
    used_baseline = False
    if not initialising and (latest.date() - cursor.date()).days > MAX_DELTA_DAYS:
        if baseline_time <= cursor:
            raise SourceError("cve_list", "available baseline cannot cover the archive gap")
        apply(baseline, baseline_time, **filters())
        used_baseline = True
    while cursor.date() < latest.date():
        closed = end_of_day(http, cursor.date())
        if closed is None:
            if used_baseline or baseline_time <= cursor:
                raise SourceError("cve_list", "required end-of-day archive is unavailable; baseline is too old")
            apply(baseline, baseline_time, **filters())
            used_baseline = True
            continue
        at = datetime.combine(cursor.date() + timedelta(days=1), datetime.min.time(), timezone.utc)
        apply(closed, at, **filters())
    current = store.metadata()
    if latest >= cursor and current.get("cve_list_archive_asset") != _asset_token(delta):
        apply(delta, latest, **filters())
    if initialising:
        store.set_metadata({"cve_list_initial_pending": "0",
                            "cve_list_initial_sync_completed_at": now.isoformat()})
    return *totals, ()
