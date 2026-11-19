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
import sys
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

RELEASE_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
ASSET_PREFIX = "https://github.com/CVEProject/cvelistV5/releases/download/"
REDIRECT_HOSTS = ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
LOG_CAP = 64 * 1024 * 1024
DIRECTORY_CAP = 64 * 1024 * 1024
MAX_LOOKUPS = 100
MAX_REPAIR_ARCHIVES = 3
JSON_CAP = 4 * 1024 * 1024
ARCHIVE_CAP = 1024 * 1024 * 1024
EXPANDED_CAP = 8 * 1024 * 1024 * 1024
MAX_MEMBERS = 1_000_000
BATCH = 100
BATCH_BYTES = 8 * 1024 * 1024
TOUCHED_BYTES = 16 * 1024 * 1024
DISK_RESERVE = 64 * 1024 * 1024
STORAGE_MULTIPLIER = 8


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
    return WatchRecord(identifier, state.lower(), _record_date(metadata.get("datePublished")), _record_date(metadata.get("dateUpdated") or metadata.get("dateReserved")),
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


@source_payload("cve_list")
def release(http, metadata, *, url=None):
    headers = {"If-None-Match": metadata["cve_list_etag"]} if metadata.get("cve_list_etag") else {}
    response_headers = {}
    payload = _json(http, url or RELEASE_URL, headers=headers, response_headers=response_headers)
    if payload is None:
        try:
            payload = json.loads(metadata["cve_list_release"])
        except (KeyError, ValueError) as exc:
            raise SourceError("cve_list", "conditional response has no cached release") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise SourceError("cve_list", "invalid release envelope")
    selected = {}
    for asset in payload["assets"]:
        name = asset.get("name", "")
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}_all_CVEs_at_midnight\.zip(?:\.zip)?", name):
            selected["baseline"] = asset
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}_delta_CVEs_at_\d{4}Z\.zip", name):
            selected["delta"] = asset
    if "baseline" not in selected or "delta" not in selected:
        raise SourceError("cve_list", "release omitted baseline or delta archive")
    for asset in selected.values():
        url = asset.get("browser_download_url", "")
        if not url.startswith(ASSET_PREFIX) or urlsplit(url).username or urlsplit(url).port != urlsplit(ASSET_PREFIX).port:
            raise SourceError("cve_list", "invalid release asset location")
        if type(asset.get("size")) is not int or not 0 < asset["size"] <= ARCHIVE_CAP:
            raise SourceError("cve_list", "archive exceeds size limit")
    try:
        delta_time = datetime.strptime(selected["delta"]["name"][:10] + selected["delta"]["name"][-9:-5], "%Y-%m-%d%H%M")
        baseline_day = datetime.strptime(selected["baseline"]["name"][:10], "%Y-%m-%d")
        if not timedelta(0) <= delta_time - baseline_day < timedelta(days=2):
            raise ValueError("incoherent release")
    except ValueError as exc:
        raise SourceError("cve_list", "invalid release date") from exc
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
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError) as exc:
        raise SourceError('cve_list','invalid delta timestamp') from exc


def _asset_token(asset):
    return str(asset.get('id') or asset['browser_download_url']) + ':' + str(asset.get('digest') or asset['size'])


def _delta_time(asset):
    return datetime.strptime(asset['name'][:10] + asset['name'][-9:-5],'%Y-%m-%d%H%M').replace(tzinfo=timezone.utc)


@source_payload('cve_list')
def _log(http, since, *, headers=None, minimum_until=None):
    response_headers = {}
    payload = _json(http, DELTA_LOG_URL, headers=headers, response_headers=response_headers, byte_cap=LOG_CAP)
    if payload is None:
        raise SourceError('cve_list', 'unexpected conditional delta-log response')
    if not isinstance(payload, list) or not payload:
        raise SourceError('cve_list','delta log omitted coverage')
    changes = {}
    times = []
    for group in payload:
        timestamp = _time(group['fetchTime'])
        times.append(timestamp)
        items = group['new'] + group['updated']
        if group.get('error') or type(group.get('numberOfChanges')) is not int or group['numberOfChanges'] != len(items):
            raise SourceError('cve_list','incomplete delta log group')
        if timestamp < since:
            continue
        for item in items:
            identifier = cve_id(item['cveId'])
            if not identifier:
                raise SourceError('cve_list','invalid delta identifier')
            revision = _record_date(item.get('dateUpdated'))
            previous = changes.get(identifier)
            if previous is not None and timestamp == previous[0] and revision != previous[1]:
                raise SourceError('cve_list', 'conflicting delta revisions at one observation')
            if previous is None or timestamp >= previous[0]:
                changes[identifier] = (timestamp, revision)
    if max(times) < (minimum_until or since):
        raise SourceError('cve_list', 'delta log is older than the stored cursor')
    if min(times) > since:
        return {}, None, response_headers  # A genuine retention gap.
    return changes, max(times), response_headers


class _RecordHTTP:
    def __init__(self, http):
        self.http = http

    def get_json(self, url, **_):
        return _json(self.http, url)


def sync(http, store, watch, now, *, initial_mode=None):
    """Import daily deltas independently; use the log only for revision hints.

    Unverified records and intervals remain durable obligations. Targeted
    lookups are bounded per run; full snapshots repair initial history or
    an uncovered retention gap without a recurring daily baseline download.
    """
    from ..sources.cve_list import CVEListSource
    store.initialize()
    metadata = store.metadata()
    mode = metadata.get('cve_list_initial_mode')
    start = metadata.get('cve_list_start')
    if (mode in ('full', 'backfill') and metadata.get('initialized_at')
            and 'cve_list_initial_pending' not in metadata
            and not metadata.get('cve_list_cursor')
            and not metadata.get('cve_list_baseline_asset')):
        mode, start = 'baseline', None
    if initial_mode is not None:
        mode, start = initial_mode, None
    if start is None:
        mode = mode or ('baseline' if metadata.get('initialized_at') else watch.initial)
        start = (now-timedelta(days=watch.backfill_days)).isoformat() if mode == 'backfill' else now.isoformat()
        values = {
            'cve_list_start': start, 'cve_list_initial_mode': mode,
            'cve_list_initial_pending': '0' if mode == 'baseline' else '1',
        }
        if initial_mode is not None:
            values.update({key: '' for key in (
                'cve_list_cursor', 'cve_list_baseline_asset', 'cve_list_baseline_until',
                'cve_list_pending_until', 'cve_list_repair_days', 'cve_list_pending_release',
                'cve_list_delta_asset', 'cve_list_log_etag', 'cve_list_pending_etag',
                'cve_list_coverage_gap',
            )})
            with store.transaction() as db:
                db.execute('DELETE FROM watch_cve_list_queue')
        store.set_metadata(values)
        metadata.update(values)
        if mode == 'baseline':
            return 0, 0, 0, ()
    count = new = changed = 0
    touched = set()
    touched_bytes = 0
    cache_directory = store.path.parent / (store.path.name + '.cve-list-cache')

    def apply(records, *, cutoff=None, acknowledge=False, archive_time=None, baseline=False):
        nonlocal count, new, changed
        batch = []
        batch_bytes = 0
        acknowledgments = []
        observations = []

        def commit():
            nonlocal count, new, changed, batch_bytes, touched_bytes
            if batch:
                _require_disk(cache_directory, STORAGE_MULTIPLIER * batch_bytes)
                result = store.upsert_cve_list(batch, catalogs=watch.sources,
                                               initial=metadata.get('cve_list_initial_pending') == '1')
                count += len(batch)
                new += result.new
                changed += result.changed
                for identifier in result.touched_ids:
                    if identifier not in touched:
                        touched_bytes += sys.getsizeof(identifier)
                        touched.add(identifier)
            with store.transaction() as db:
                db.executemany('INSERT OR REPLACE INTO watch_cve_list_observation VALUES (?,?)', observations)
                db.executemany('DELETE FROM watch_cve_list_queue WHERE cve_id=?', acknowledgments)
            batch.clear()
            observations.clear()
            acknowledgments.clear()
            batch_bytes = 0
            if touched and touched_bytes + sys.getsizeof(touched) + 8 * len(touched) >= TOUCHED_BYTES:
                raise SourceError('cve_list', 'per-run change memory budget reached; committed progress retained')

        with store.read() as evidence:
            for payload in records:
                record = parse_record(payload)
                queued = evidence.execute('SELECT fetch_time,expected_revision FROM watch_cve_list_queue WHERE cve_id=?', (record.cve_id,)).fetchone() if acknowledge else None
                can_acknowledge = False
                if queued is not None:
                    # Dates are corrected backwards upstream. Equality with the
                    # revision from the latest log observation is deliberate;
                    # a larger content date is not proof of a newer revision.
                    expected = queued['expected_revision']
                    can_acknowledge = bool(expected and _record_date(record.last_modified) == expected
                                           and (archive_time is None or _time(queued['fetch_time']) <= archive_time))
                    if archive_time is None and not can_acknowledge:
                        continue
                    if archive_time is None:
                        observed = evidence.execute("SELECT o.snapshot_time,p.source_updated FROM watch_cve_list_observation o JOIN watch_provider p ON p.cve_id=o.cve_id AND p.source='cve_list' WHERE o.cve_id=?", (record.cve_id,)).fetchone()
                        if observed and _time(observed['snapshot_time']) >= _time(queued['fetch_time']) and _record_date(observed['source_updated']) != expected:
                            continue
                if archive_time is not None:
                    previous = evidence.execute('SELECT snapshot_time FROM watch_cve_list_observation WHERE cve_id=?', (record.cve_id,)).fetchone()
                    checked = evidence.execute("SELECT checked_at FROM watch_source_check WHERE source='cve_list' AND cve_id=?", (record.cve_id,)).fetchone()
                    if (previous is not None and _time(previous[0]) > archive_time
                            or checked is not None and _time(checked[0]) > archive_time):
                        continue
                    # A reset may encounter records imported before snapshot
                    # ordering was tracked. Never replace those with midnight
                    # data after they were observed later in the day.
                    if baseline and previous is None:
                        legacy = evidence.execute("SELECT checked_at FROM watch_provider WHERE cve_id=? AND source='cve_list'", (record.cve_id,)).fetchone()
                        if legacy and _time(legacy[0]) > archive_time:
                            continue
                if cutoff is not None and (not record.last_modified or _time(record.last_modified) < cutoff):
                    continue
                payload_bytes = len(json.dumps(payload, ensure_ascii=False).encode('utf-8'))
                if batch and (batch_bytes + payload_bytes > BATCH_BYTES or len(batch) >= BATCH):
                    commit()
                batch.append(payload)
                batch_bytes += payload_bytes
                if archive_time is not None:
                    observations.append((record.cve_id, archive_time.isoformat()))
                elif can_acknowledge:
                    observations.append((record.cve_id, queued['fetch_time']))
                if can_acknowledge:
                    acknowledgments.append((record.cve_id,))
                if len(batch) >= BATCH or batch_bytes >= BATCH_BYTES:
                    commit()
            if batch or acknowledgments:
                commit()

    pending = metadata.get('cve_list_pending_until')
    if not pending:
        assets, release_cache = release(http, metadata)
        baseline = assets['baseline']
        baseline_time = _time(baseline['name'][:10] + 'T00:00:00Z')
        cursor = _time(metadata.get('cve_list_cursor')
                       or metadata.get('cve_list_baseline_until') or start)
        initial_history = (mode in ('full', 'backfill')
                           and not metadata.get('cve_list_baseline_asset')
                           and not metadata.get('cve_list_cursor'))
        if initial_history:
            apply(archive_records(http, baseline, cache_directory=cache_directory),
                  cutoff=_time(start) if mode == 'backfill' else None,
                  archive_time=baseline_time, baseline=True)
            values = {
                'cve_list_baseline_asset': _asset_token(baseline),
                'cve_list_baseline_until': baseline_time.isoformat(),
            }
            store.set_metadata(values)
            metadata.update(values)
            cursor = baseline_time
        delta = assets['delta']
        delta_time = _delta_time(delta)
        coverage_gap = bool(metadata.get('cve_list_coverage_gap')) or cursor.date() < delta_time.date()
        same_day = cursor.date() == delta_time.date() == baseline_time.date()
        if same_day and not initial_history and not coverage_gap:
            if metadata.get('cve_list_delta_asset') != _asset_token(delta):
                apply(archive_records(http, delta, allow_empty=True,
                                      cache_directory=cache_directory),
                      archive_time=delta_time)
            values = {
                **release_cache,
                'cve_list_delta_asset': _asset_token(delta),
                'cve_list_cursor': max(cursor, delta_time).isoformat(),
            }
            if metadata.get('cve_list_initial_pending') == '1':
                values.update(cve_list_initial_pending='0',
                              cve_list_initial_sync_completed_at=now.isoformat())
            store.set_metadata(values)
            return count, new, changed, tuple(sorted(touched))

        changes, until, _ = _log(
            http, cursor - timedelta(minutes=watch.overlap_minutes), minimum_until=cursor)
        if until is None:
            # Retention has expired. A bounded full snapshot is the fallback;
            # an apparently complete log alone cannot close an interval.
            if baseline_time <= cursor:
                raise SourceError('cve_list', 'delta log cannot cover the stored cursor')
            apply(archive_records(http, baseline, cache_directory=cache_directory),
                  archive_time=baseline_time, baseline=True)
            store.set_metadata({
                'cve_list_baseline_asset': _asset_token(baseline),
                'cve_list_baseline_until': baseline_time.isoformat(),
            })
            changes, until, _ = _log(http, baseline_time)
            if until is None:
                raise SourceError('cve_list', 'baseline is older than delta-log retention')
            cursor = baseline_time
            coverage_gap = False
        days = []
        day = cursor.date()
        while day < baseline_time.date():
            days.append(day.isoformat())
            day += timedelta(days=1)
        pending = max(cursor, min(until, delta_time)).isoformat()
        with store.transaction() as db:
            db.executemany(
                'INSERT OR REPLACE INTO watch_cve_list_queue'
                '(cve_id,fetch_time,expected_revision) VALUES (?,?,?)',
                ((identifier, observation.isoformat(), revision)
                 for identifier, (observation, revision) in changes.items()))
            store._set_meta(db, {
                'cve_list_pending_until': pending,
                'cve_list_coverage_gap': cursor.isoformat() if coverage_gap else '',
                'cve_list_repair_days': json.dumps(days),
                'cve_list_pending_release': json.dumps(assets),
                **release_cache,
            })
        metadata = store.metadata()
    else:
        assets = json.loads(metadata['cve_list_pending_release'])
    delta = assets['delta']
    if metadata.get('cve_list_delta_asset') != _asset_token(delta):
        # The log is a hint, never a manifest. Every accepted archive is read
        # independently, including IDs omitted by the log.
        apply(archive_records(http, delta, allow_empty=True,
                              cache_directory=cache_directory),
              acknowledge=True, archive_time=_delta_time(delta))
        with store.read() as db:
            pending_records = db.execute('SELECT count(*) FROM watch_cve_list_queue').fetchone()[0]
        if not pending_records:
            store.set_metadata({'cve_list_delta_asset': _asset_token(delta)})
    days = json.loads(metadata.get('cve_list_repair_days') or '[]')
    for _ in range(MAX_REPAIR_ARCHIVES):
        if not days:
            break
        day = days[0]
        tag = 'cve_' + day + '_2300Z'
        try:
            daily, _ = release(http, {}, url=RELEASE_URL.rsplit('/', 1)[0] + '/tags/' + tag)
        except SourceError as exc:
            if exc.status_code != 404:
                raise
        else:
            apply(archive_records(http, daily['delta'], allow_empty=True,
                                  cache_directory=cache_directory),
                  acknowledge=True, archive_time=_delta_time(daily['delta']))
        days.pop(0)
        store.set_metadata({'cve_list_repair_days': json.dumps(days)})
    if days:
        return count, new, changed, tuple(sorted(touched))
    with store.read() as db:
        identifiers = [row[0] for row in db.execute(
            'SELECT cve_id FROM watch_cve_list_queue ORDER BY cve_id LIMIT ?', (MAX_LOOKUPS,))]
    failures = False
    for identifier in identifiers:
        try:
            payload = CVEListSource(_RecordHTTP(http)).record(identifier)
        except SourceError:
            failures = True
            continue
        apply([payload], acknowledge=True)
    with store.read() as db:
        remaining = db.execute('SELECT count(*) FROM watch_cve_list_queue').fetchone()[0]
    if not remaining:
        values = {
            'cve_list_cursor': metadata.get('cve_list_coverage_gap') or pending,
            'cve_list_pending_until': '',
            'cve_list_pending_release': '',
        }
        if (metadata.get('cve_list_initial_pending') == '1'
                and not metadata.get('cve_list_coverage_gap')):
            values.update(cve_list_initial_pending='0',
                          cve_list_initial_sync_completed_at=now.isoformat())
        store.set_metadata(values)
    if failures:
        raise SourceError('cve_list', 'some targeted delta records could not be fetched; progress retained')
    return count, new, changed, tuple(sorted(touched))
