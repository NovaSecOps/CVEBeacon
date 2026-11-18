"""CVE List release imports with bounded archives and independent cursors."""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from ..errors import SourceError
from ..sources.common import cve_id, source_payload
from .records import CVSSEntry, Product, Reference, WatchRecord

RELEASE_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
ASSET_PREFIX = "https://github.com/CVEProject/cvelistV5/releases/download/"
REDIRECT_HOSTS = ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
JSON_CAP = 4 * 1024 * 1024
ARCHIVE_CAP = 1024 * 1024 * 1024
EXPANDED_CAP = 8 * 1024 * 1024 * 1024
MAX_MEMBERS = 1_000_000
BATCH = 100


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


def _json(http, url, *, headers=None, response_headers=None):
    data = b"".join(http.stream_bytes(url, source="cve_list", byte_cap=JSON_CAP,
                                      headers=headers, response_headers=response_headers,
                                      allow_not_modified=True))
    if not data:
        return None
    try:
        return json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise SourceError("cve_list", "invalid release metadata") from exc


@source_payload("cve_list")
def release(http, metadata):
    headers = {"If-None-Match": metadata["cve_list_etag"]} if metadata.get("cve_list_etag") else {}
    response_headers = {}
    payload = _json(http, RELEASE_URL, headers=headers, response_headers=response_headers)
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
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}_all_CVEs_at_midnight\.zip", name):
            selected["baseline"] = asset
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}_delta_CVEs_at_\d{4}Z\.zip", name):
            selected["delta"] = asset
    if "baseline" not in selected or "delta" not in selected:
        raise SourceError("cve_list", "release omitted baseline or delta archive")
    for asset in selected.values():
        url = asset.get("browser_download_url", "")
        if not url.startswith(ASSET_PREFIX) or urlsplit(url).username:
            raise SourceError("cve_list", "invalid release asset location")
        if type(asset.get("size")) is not int or not 0 < asset["size"] <= ARCHIVE_CAP:
            raise SourceError("cve_list", "archive exceeds size limit")
    if selected["baseline"]["name"][:10] != selected["delta"]["name"][:10]:
        raise SourceError("cve_list", "release baseline and delta dates do not match")
    try:
        datetime.strptime(selected["delta"]["name"][:10] + selected["delta"]["name"][-9:-5], "%Y-%m-%d%H%M")
    except ValueError as exc:
        raise SourceError("cve_list", "invalid release date") from exc
    cache = json.dumps({"assets": list(selected.values())}, separators=(",", ":"))
    return selected, {"cve_list_release": cache, "cve_list_etag": response_headers.get("etag", metadata.get("cve_list_etag", ""))}


def _members(file, *, allow_empty=False, nested=False):
    with zipfile.ZipFile(file) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS or sum(info.file_size for info in infos) > EXPANDED_CAP:
            raise SourceError("cve_list", "expanded archive exceeds limit")
        wrapped = [info for info in infos if PurePosixPath(info.filename).name == "cves.zip"]
        if wrapped:
            if nested or len(wrapped) != 1 or len(infos) != 1 or wrapped[0].file_size > ARCHIVE_CAP:
                raise SourceError("cve_list", "invalid nested baseline archive")
            with tempfile.TemporaryFile() as inner, archive.open(wrapped[0]) as member:
                size = 0
                while chunk := member.read(65536):
                    size += len(chunk)
                    if size > ARCHIVE_CAP:
                        raise SourceError("cve_list", "nested archive exceeds limit")
                    inner.write(chunk)
                inner.seek(0)
                yield from _members(inner, allow_empty=allow_empty, nested=True)
            return
        seen = set()
        for info in infos:
            name = PurePosixPath(info.filename).name
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}\.json", name):
                continue
            if info.file_size > JSON_CAP or info.flag_bits & 1 or name in seen:
                raise SourceError("cve_list", "invalid archive member")
            seen.add(name)
            with archive.open(info) as member:
                raw = member.read(JSON_CAP + 1)
            if len(raw) > JSON_CAP:
                raise SourceError("cve_list", "record exceeds limit")
            payload = json.loads(raw)
            record = parse_record(payload)
            if record.cve_id != name[:-5]:
                raise SourceError("cve_list", "archive member identifier mismatch")
            yield payload
        if not seen and not allow_empty:
            raise SourceError("cve_list", "archive contains no CVE records")


def archive_records(http, asset, *, allow_empty=False):
    """Spool compressed bytes to disk, verify, then read one record at a time.

    Nothing is extracted. ZIP directory memory is bounded by the compressed
    cap and member count; expanded records never accumulate. The official
    baseline artifact may wrap a single cves.zip inside another ZIP.
    """
    try:
        with tempfile.TemporaryFile() as file:
            digest = hashlib.sha256()
            size = 0
            for chunk in http.stream_bytes(asset["browser_download_url"], source="cve_list", byte_cap=ARCHIVE_CAP, redirect_hosts=REDIRECT_HOSTS):
                size += len(chunk)
                digest.update(chunk)
                file.write(chunk)
            if size != asset["size"]:
                raise SourceError("cve_list", "archive size mismatch")
            expected = asset.get("digest")
            if expected and expected != "sha256:" + digest.hexdigest():
                raise SourceError("cve_list", "archive digest mismatch")
            file.seek(0)
            yield from _members(file, allow_empty=allow_empty)
    except (zipfile.BadZipFile, RuntimeError, ValueError, UnicodeError, OSError, EOFError, NotImplementedError) as exc:
        raise SourceError("cve_list", "invalid or incomplete CVE archive") from exc


def sync(http, store, watch, now):
    """Retry an incomplete archive idempotently; advance only on completion."""
    metadata = store.metadata()
    start = metadata.get("cve_list_start")
    mode = metadata.get("cve_list_initial_mode") or watch.initial
    if start is None:
        start = (now - timedelta(days=watch.backfill_days)).isoformat() if mode == "backfill" else now.isoformat()
        store.set_metadata({"cve_list_start": start, "cve_list_initial_mode": mode})
        if mode == "baseline":
            store.set_metadata({"cve_list_baseline_day": now.date().isoformat()})
            return 0, 0, 0, ()
    assets, cache = release(http, metadata)
    cutoff = None if mode == "full" else start
    if metadata.get("cve_list_cursor"):
        previous = datetime.fromisoformat(metadata["cve_list_cursor"].replace("Z", "+00:00")) - timedelta(minutes=watch.overlap_minutes)
        cutoff = max(start, previous.isoformat()) if mode != "full" else previous.isoformat()
    count = new = changed = 0
    touched = set()
    baseline_day = assets["baseline"]["name"][:10]
    # A new day's cumulative delta cannot cover a gap across midnight. Replay
    # the daily baseline, filtering modified dates for baseline/backfill modes.
    names = ["baseline"] if metadata.get("cve_list_baseline_day") != baseline_day else []
    names.append("delta")
    for kind in names:
        asset = assets[kind]
        token = str(asset.get("id") or asset["browser_download_url"]) + ":" + str(asset.get("digest") or asset["size"])
        if metadata.get("cve_list_" + kind + "_asset") == token:
            continue
        batch = []
        def commit():
            nonlocal new, changed, count
            result = store.upsert_cve_list(batch, catalogs=watch.sources)
            count += len(batch)
            new += result.new
            changed += result.changed
            touched.update(result.touched_ids)
            batch.clear()
        for payload in archive_records(http, asset, allow_empty=kind == "delta"):
            record = parse_record(payload)
            modified = record.last_modified
            if cutoff is not None:
                if not modified:
                    continue
                try:
                    timestamp = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                    boundary = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
                    if timestamp.replace(tzinfo=timestamp.tzinfo or timezone.utc) < boundary:
                        continue
                except (ValueError, TypeError) as exc:
                    raise SourceError("cve_list", "invalid record date") from exc
            batch.append(payload)
            if len(batch) >= BATCH:
                commit()
        if batch:
            commit()
        store.set_metadata({"cve_list_" + kind + "_asset": token,
                            **({"cve_list_baseline_day": baseline_day} if kind == "baseline" else {})})
    delta_name = assets["delta"]["name"]
    released_at = datetime.strptime(delta_name[:10] + delta_name[-9:-5], "%Y-%m-%d%H%M").replace(tzinfo=timezone.utc)
    store.set_metadata({**cache, "cve_list_cursor": released_at.isoformat()})
    return count, new, changed, tuple(sorted(touched))
