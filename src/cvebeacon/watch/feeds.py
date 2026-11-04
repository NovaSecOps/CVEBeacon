"""Public source adapters for the watch database."""

from __future__ import annotations

import gzip
import io
import re
import zlib
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Iterator

from ..http import HttpClient, Throttle
from ..errors import SourceError
from ..sources.common import as_float, cve_id, source_payload
from ..sources.euvd import SEARCH_URL
from ..sources.kev import KEVSource
from ..sources.nvd import CVE_URL, split_cpe23
from .records import (
    CVSS_VERSIONS,
    CVSSEntry,
    EUVDUpdate,
    KEVFields,
    Product,
    Reference,
    SSVC_EXPLOITATION,
    WatchRecord,
    euvd_datetime,
    normalized_cvss,
)

NVD_PAGE_SIZE = 2000
NVD_WINDOW_DAYS = 120
NVD_WINDOW_ATTEMPTS = 3
NVD_MIN_SPLIT = timedelta(hours=1)
CISA_ADP_SOURCE = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
NVD_PROVIDER_SOURCE = "nvd@nist.gov"
EUVD_PAGE_SIZE = 100
EUVD_CHUNK_DAYS = 30
EUVD_ATTEMPTS = 3
EUVD_MIN_INTERVAL = 1.0
EUVD_SPLIT_TOTAL = 10_000
EPSS_FILE_URL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"
EPSS_BYTE_CAP = 20 * 1024 * 1024
EPSS_DECOMPRESSED_CAP = 64 * 1024 * 1024
EPSS_COMMENT_LIMIT = 4096
EPSS_LINE_LIMIT = 256
EPSS_MAX_ROWS = 1_000_000
EPSS_MIN_ROWS = 100_000

_NVD_TIMESTAMP = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d{1,9}))?$"
)
_EPSS_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_EPSS_DATE_TIMESTAMP = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})(?P<offset>Z|\+00:00)$"
)


@dataclass(frozen=True, slots=True)
class NVDWindowFeed:
    records: tuple[WatchRecord, ...]
    requests: int
    timestamp: datetime | None = None
    split: bool = False


@dataclass(frozen=True, slots=True)
class NVDCVEResult:
    record: WatchRecord
    requests: int


@dataclass(frozen=True, slots=True)
class EUVDFeed:
    updates: tuple[EUVDUpdate, ...]
    requests: int
    ignored: int = 0
    split: bool = False


@dataclass(frozen=True, slots=True)
class EUVDPage:
    updates: tuple[EUVDUpdate, ...]
    page: int
    total: int
    ignored: int = 0


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def iso_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def parse_nvd_timestamp(value: Any) -> datetime | None:
    """Parse NVD's UTC timestamp, with no suffix, ``Z``, or ``+00:00``."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise SourceError("nvd", "source returned an invalid response timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1]
    elif text.endswith("+00:00"):
        text = text[:-6]
    match = _NVD_TIMESTAMP.fullmatch(text)
    if match is None:
        raise SourceError("nvd", "source returned an invalid response timestamp")
    fraction = (match.group("fraction") or "").ljust(6, "0")[:6]
    try:
        parsed = datetime.fromisoformat(
            f"{match.group('date')}T{match.group('time')}.{fraction}"
        )
    except ValueError as exc:
        raise SourceError("nvd", "source returned an invalid response timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def nvd_windows(start: datetime, end: datetime) -> tuple[tuple[datetime, datetime], ...]:
    if end <= start:
        return ()
    windows: list[tuple[datetime, datetime]] = []
    cursor, step = start, timedelta(days=NVD_WINDOW_DAYS)
    while cursor < end:
        following = min(cursor + step, end)
        windows.append((cursor, following))
        cursor = following
    return tuple(windows)


def euvd_chunks(start: date, end: date) -> tuple[tuple[date, date], ...]:
    """Split an inclusive EUVD date range into bounded chunks."""
    if end < start:
        return ()
    chunks: list[tuple[date, date]] = []
    cursor = start
    while cursor <= end:
        following = min(cursor + timedelta(days=EUVD_CHUNK_DAYS - 1), end)
        chunks.append((cursor, following))
        cursor = following + timedelta(days=1)
    return tuple(chunks)


def _nvd_headers(api_key: str | None) -> dict[str, str] | None:
    return {"apiKey": api_key} if api_key else None


def _score(value: Any, maximum: float = 10.0) -> float | None:
    if isinstance(value, bool):
        return None
    number = as_float(value)
    if number is None or not 0 <= number <= maximum:
        return None
    return number


def _nvd_entries(value: Any) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SourceError("nvd", "source returned invalid metric entries")
    return value


def _cvss_provider(source: Any, source_identifier: str | None) -> str:
    text = source if isinstance(source, str) else ""
    if text == NVD_PROVIDER_SOURCE:
        return "nvd"
    if source_identifier and text == source_identifier:
        return "cna"
    if text == CISA_ADP_SOURCE:
        return "cisa-adp"
    return "other"


def _cvss_entries(metrics: dict[str, Any], source_identifier: str | None) -> tuple[CVSSEntry, ...]:
    entries: list[CVSSEntry] = []
    for key, fallback in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        for entry in _nvd_entries(metrics.get(key)):
            if not isinstance(entry, dict):
                raise SourceError("nvd", "source returned a non-object metric entry")
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            score = _score(data.get("baseScore"))
            if score is None:
                continue
            version = str(data.get("version") or fallback)
            if version not in CVSS_VERSIONS:
                version = fallback
            vector = data.get("vectorString")
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            source = entry.get("source")
            entries.append(
                CVSSEntry(
                    provider=_cvss_provider(source, source_identifier),
                    source=str(source) if isinstance(source, str) else "",
                    version=version,
                    score=score,
                    vector=str(vector) if isinstance(vector, str) else None,
                    severity=str(severity) if isinstance(severity, str) and severity else None,
                )
            )
    return normalized_cvss(entries)


def _option_value(options: Any) -> Any:
    if isinstance(options, list):
        for option in options:
            if isinstance(option, dict):
                for key, value in option.items():
                    if str(key).casefold() == "exploitation":
                        return value
    elif isinstance(options, dict):
        for key, value in options.items():
            if str(key).casefold() == "exploitation":
                return value
    return None


def _ssvc_exploitation(metrics: dict[str, Any]) -> str | None:
    for key, entries in metrics.items():
        if not str(key).casefold().startswith("ssvc"):
            continue
        for entry in _nvd_entries(entries):
            if not isinstance(entry, dict):
                raise SourceError("nvd", "source returned a non-object metric entry")
            data = entry.get("ssvcData")
            containers = (data, entry) if isinstance(data, dict) else (entry,)
            for container in containers:
                value = _option_value(container.get("options"))
                if value is None:
                    for name, candidate in container.items():
                        if str(name).casefold() == "exploitation":
                            value = candidate
                if value is not None:
                    text = str(value).strip().casefold()
                    if text in SSVC_EXPLOITATION:
                        return text
    return None


def _cpe_matches(node: Any) -> list[dict[str, Any]]:
    if not isinstance(node, dict):
        return []
    matches = node.get("cpeMatch")
    output = [match for match in matches if isinstance(match, dict)] if isinstance(matches, list) else []
    children = node.get("children")
    if isinstance(children, list):
        for child in children:
            output.extend(_cpe_matches(child))
    return output


def _products(raw: dict[str, Any]) -> tuple[Product, ...]:
    configurations = raw.get("configurations")
    if configurations is None:
        return ()
    if isinstance(configurations, dict):
        configurations = [configurations]
    if not isinstance(configurations, list):
        raise SourceError("nvd", "source returned invalid configuration entries")
    pairs: set[tuple[str, str]] = set()
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        nodes = configuration.get("nodes")
        if isinstance(nodes, dict):
            nodes = [nodes]
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            for match in _cpe_matches(node):
                if match.get("vulnerable") is False:
                    continue
                parts = split_cpe23(str(match.get("criteria") or ""))
                if len(parts) != 11:
                    continue
                vendor, product = parts[1], parts[2]
                if vendor in {"", "*", "-"} or product in {"", "*", "-"}:
                    continue
                pairs.add((vendor, product))
    return tuple(Product(vendor, product) for vendor, product in sorted(pairs))


def _cwes(raw: dict[str, Any]) -> tuple[str, ...]:
    values: set[str] = set()
    weaknesses = raw.get("weaknesses") or []
    if not isinstance(weaknesses, list):
        raise SourceError("nvd", "source returned invalid weakness entries")
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        descriptions = weakness.get("description") or []
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            if not isinstance(description, dict) or description.get("lang") != "en":
                continue
            value = _text(description.get("value"))
            if value and value.startswith("CWE-"):
                values.add(value)
    return tuple(sorted(values))


def _references(raw: dict[str, Any]) -> tuple[Reference, ...]:
    output: list[Reference] = []
    references = raw.get("references") or []
    if not isinstance(references, list):
        raise SourceError("nvd", "source returned invalid reference entries")
    for item in references:
        if not isinstance(item, dict):
            continue
        url = _text(item.get("url"))
        if not url:
            continue
        tags = item.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        output.append(Reference(url, tuple(str(tag) for tag in tags if isinstance(tag, str))))
    return tuple(output)


@source_payload("nvd")
def parse_nvd_cve(raw: dict[str, Any]) -> WatchRecord:
    identifier = cve_id(raw.get("id"))
    if not identifier:
        raise SourceError("nvd", "source returned a vulnerability without a valid identifier")
    metrics = raw.get("metrics") or {}
    if not isinstance(metrics, dict):
        raise SourceError("nvd", "source returned invalid metrics")
    source_identifier = _text(raw.get("sourceIdentifier"))
    description = None
    descriptions = raw.get("descriptions") or []
    if not isinstance(descriptions, list):
        raise SourceError("nvd", "source returned invalid descriptions")
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            description = _text(item.get("value"))
            break
    status = "published"
    raw_status = raw.get("vulnStatus")
    if isinstance(raw_status, list):
        statuses = {
            str(item.get("status", "") if isinstance(item, dict) else item).strip().casefold()
            for item in raw_status
        }
    else:
        statuses = {(str(raw_status).strip().casefold())}
    if "rejected" in statuses:
        status = "rejected"
    return WatchRecord(
        cve_id=identifier,
        status=status,
        published=_text(raw.get("published")),
        last_modified=_text(raw.get("lastModified")),
        description=description,
        source_identifier=source_identifier,
        cvss=_cvss_entries(metrics, source_identifier),
        cwes=_cwes(raw),
        products=_products(raw),
        references=_references(raw),
        ssvc_exploitation=_ssvc_exploitation(metrics),
        cisa_kev_added=_text(raw.get("cisaExploitAdd")),
        cisa_kev_due=_text(raw.get("cisaActionDue")),
        cisa_required_action=_text(raw.get("cisaRequiredAction")),
    )


def _nvd_page(payload: Any, start: int) -> tuple[list[Any], int, int]:
    """Validate one page's structure and return its vulnerabilities, count and total."""
    if not isinstance(payload, dict):
        raise SourceError("nvd", "source returned an invalid response envelope")
    vulnerabilities = payload.get("vulnerabilities")
    if (
        not isinstance(vulnerabilities, list)
        or "totalResults" not in payload
        or "resultsPerPage" not in payload
    ):
        raise SourceError("nvd", "source response omitted required vulnerabilities pagination fields")
    count, total, offset = (payload.get(key) for key in ("resultsPerPage", "totalResults", "startIndex"))
    if any(type(value) is not int or value < 0 for value in (count, total, offset)) or offset != start:
        raise SourceError("nvd", "source returned invalid pagination metadata")
    if len(vulnerabilities) != count:
        raise SourceError("nvd", "source returned an incomplete page")
    return vulnerabilities, count, total


def _nvd_records(
    http: HttpClient,
    *,
    window: dict[str, str],
    api_key: str | None,
    interval: float,
    width: timedelta,
) -> NVDWindowFeed:
    requests_before = http.requests
    for _ in range(NVD_WINDOW_ATTEMPTS):
        records: dict[str, WatchRecord] = {}
        offset = 0
        pinned_total: int | None = None
        timestamp: datetime | None = None
        unstable = False
        while True:
            payload = http.get_json(
                CVE_URL,
                source="nvd",
                params={**window, "startIndex": offset, "resultsPerPage": NVD_PAGE_SIZE},
                headers=_nvd_headers(api_key),
                minimum_interval=interval,
            )
            vulnerabilities, count, total = _nvd_page(payload, offset)
            if offset == 0:
                pinned_total = total
                timestamp = parse_nvd_timestamp(payload.get("timestamp"))
                if total > NVD_PAGE_SIZE and width > NVD_MIN_SPLIT:
                    return NVDWindowFeed(
                        (), http.requests - requests_before, timestamp, split=True
                    )
            elif total != pinned_total:
                unstable = True
                break
            if offset + count > (pinned_total or 0) or (
                count == 0 and offset < (pinned_total or 0)
            ):
                raise SourceError("nvd", "source returned an incomplete page")
            for wrapped in vulnerabilities:
                raw = wrapped.get("cve") if isinstance(wrapped, dict) else None
                if not isinstance(raw, dict):
                    raise SourceError("nvd", "source returned an invalid vulnerability entry")
                record = parse_nvd_cve(raw)
                if record.cve_id in records:
                    unstable = True
                    break
                records[record.cve_id] = record
            if unstable:
                break
            if offset + count >= (pinned_total or 0):
                break
            offset += count
        if not unstable:
            return NVDWindowFeed(
                tuple(records[key] for key in sorted(records)),
                http.requests - requests_before,
                timestamp,
            )
    raise SourceError("nvd", "source returned unstable pagination")


@source_payload("nvd")
def fetch_nvd_window(
    http: HttpClient,
    *,
    start: datetime,
    end: datetime,
    api_key: str | None = None,
    interval: float = 0,
) -> NVDWindowFeed:
    """Fetch one bounded NVD window, or report that it must be split."""
    window = {
        "lastModStartDate": iso_timestamp(start),
        "lastModEndDate": iso_timestamp(end),
    }
    return _nvd_records(
        http,
        window=window,
        api_key=api_key,
        interval=interval,
        width=end - start,
    )


@source_payload("nvd")
def fetch_nvd_cve(
    http: HttpClient, identifier: str, *, api_key: str | None = None, interval: float = 0
) -> NVDCVEResult:
    """Fetch a single CVE by id, used to create rows that other feeds saw first."""
    requests_before = http.requests
    payload = http.get_json(
        CVE_URL,
        source="nvd",
        params={"cveId": identifier},
        headers=_nvd_headers(api_key),
        minimum_interval=interval,
    )
    vulnerabilities, _, total = _nvd_page(payload, 0)
    if total < 1 or not vulnerabilities:
        raise SourceError("nvd", "source returned no vulnerability for a requested identifier")
    matches: list[WatchRecord] = []
    for wrapped in vulnerabilities:
        raw = wrapped.get("cve") if isinstance(wrapped, dict) else None
        if not isinstance(raw, dict):
            raise SourceError("nvd", "source returned an invalid vulnerability entry")
        record = parse_nvd_cve(raw)
        if record.cve_id == identifier:
            matches.append(record)
    if len(matches) != 1:
        raise SourceError("nvd", "source returned no vulnerability for a requested identifier")
    return NVDCVEResult(matches[0], http.requests - requests_before)


def _alias_values(aliases: Any) -> list[str]:
    if aliases is None:
        return []
    if isinstance(aliases, str):
        return aliases.replace(",", "\n").splitlines()
    if isinstance(aliases, list):
        return [str(value) for value in aliases]
    raise SourceError("euvd", "source returned invalid aliases")


def _euvd_cvss(item: dict[str, Any]) -> tuple[CVSSEntry | None, bool]:
    """Return the usable score, and whether an unknown version was ignored."""
    version = _text(item.get("baseScoreVersion"))
    if version is None:
        return None, False
    if version not in CVSS_VERSIONS:
        return None, True
    raw = item.get("baseScore")
    if raw is None:
        return None, False
    if isinstance(raw, bool):
        raise SourceError("euvd", "source returned an invalid CVSS score")
    score = as_float(raw)
    if score is None or not 0 <= score <= 10:
        raise SourceError("euvd", "source returned an invalid CVSS score")
    return CVSSEntry("euvd", "euvd", version, score, _text(item.get("baseScoreVector"))), False


EUVD_PLACEHOLDER_NAMES = frozenset({"n/a", "-"})


def _euvd_name(value: Any) -> str | None:
    if isinstance(value, str):
        name = _text(value)
    elif isinstance(value, dict):
        name = _text(value.get("name"))
    else:
        return None
    if name is None or name.casefold() in EUVD_PLACEHOLDER_NAMES:
        return None
    return name


def _euvd_vendors(item: dict[str, Any]) -> tuple[Product, ...]:
    """Collect vendor and product names from the EUVD identifier fields."""
    pairs: dict[tuple[str, str], Product] = {}
    vendors = item.get("enisaIdVendor") or []
    if isinstance(vendors, list):
        for entry in vendors:
            if not isinstance(entry, dict):
                continue
            name = _euvd_name(entry.get("vendor")) or _euvd_name(entry.get("name"))
            if name:
                pairs.setdefault((name.casefold(), ""), Product(name, ""))
    products = item.get("enisaIdProduct") or []
    if isinstance(products, list):
        for entry in products:
            if not isinstance(entry, dict):
                continue
            product = entry.get("product")
            name = _euvd_name(product) or _euvd_name(entry.get("name"))
            vendor = _euvd_name(product.get("vendor")) if isinstance(product, dict) else None
            vendor = vendor or _euvd_name(entry.get("vendor"))
            if not name and not vendor:
                continue
            pairs.setdefault(
                ((vendor or "").casefold(), (name or "").casefold()),
                Product(vendor or "", name or ""),
            )
    return tuple(pairs[key] for key in sorted(pairs)[:50])


@source_payload("euvd")
def fetch_euvd_page(
    http: HttpClient,
    *,
    start: date,
    end: date,
    page: int,
    throttle: Throttle | None = None,
) -> EUVDPage:
    """Fetch one page of a bounded EUVD window.

    Same-day queries report a total below the items they return, so the end is
    always widened by one day while the committed cursor stays at ``end``.
    """
    if page < 0:
        raise ValueError("EUVD page must not be negative")
    params = {
        "fromUpdatedDate": start.isoformat(),
        "toUpdatedDate": (end + timedelta(days=1)).isoformat(),
    }
    payload = http.get_json(
        SEARCH_URL,
        source="euvd",
        params={**params, "page": page, "size": EUVD_PAGE_SIZE},
        minimum_interval=EUVD_MIN_INTERVAL,
        throttle=throttle,
    )
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise SourceError("euvd", "source returned an invalid search envelope")
    items = payload["items"]
    try:
        total = payload["total"]
        if type(total) is not int or total < 0:
            raise ValueError("invalid count")
    except (KeyError, TypeError, ValueError) as exc:
        raise SourceError("euvd", "source returned an invalid total count") from exc
    expected = min(EUVD_PAGE_SIZE, max(total - page * EUVD_PAGE_SIZE, 0))
    if len(items) != expected:
        raise SourceError("euvd", "source returned an incomplete page")
    updates: list[EUVDUpdate] = []
    ignored = 0
    for item in items:
        if not isinstance(item, dict):
            raise SourceError("euvd", "source returned a non-object search item")
        euvd_id = _text(item.get("id"))
        if euvd_id is None:
            raise SourceError("euvd", "source returned an item without an identifier")
        identifiers = tuple(
            sorted(
                {
                    value
                    for alias in _alias_values(item.get("aliases"))
                    if (value := cve_id(alias))
                }
            )
        )
        cvss, was_ignored = _euvd_cvss(item)
        ignored += 1 if was_ignored else 0
        updates.append(
            EUVDUpdate(
                identifiers,
                euvd_id,
                _text(item.get("exploitedSince")),
                cvss,
                euvd_datetime(item.get("dateUpdated")),
                _euvd_vendors(item),
            )
        )
    return EUVDPage(tuple(updates), page, total, ignored)


@source_payload("euvd")
def fetch_euvd(
    http: HttpClient,
    *,
    start: date,
    end: date,
    throttle: Throttle | None = None,
) -> EUVDFeed:
    """Fetch one complete bounded EUVD window with a pinned result total.

    Sync reads and commits single pages instead, so a throttled run keeps its
    progress. This whole-window form remains for callers that want one result.
    """
    requests_before = http.requests
    for _ in range(EUVD_ATTEMPTS):
        updates: list[EUVDUpdate] = []
        ignored = 0
        page = 0
        pinned_total: int | None = None
        unstable = False
        seen_ids: set[str] = set()
        while True:
            result = fetch_euvd_page(
                http, start=start, end=end, page=page, throttle=throttle
            )
            if page == 0:
                pinned_total = result.total
                if result.total > EUVD_SPLIT_TOTAL and end > start:
                    return EUVDFeed(
                        (), http.requests - requests_before, 0, split=True
                    )
            elif result.total != pinned_total:
                unstable = True
                break
            page_ids = [update.euvd_id for update in result.updates]
            if len(set(page_ids)) != len(page_ids) or any(
                identifier in seen_ids for identifier in page_ids
            ):
                unstable = True
                break
            seen_ids.update(page_ids)
            updates.extend(result.updates)
            ignored += result.ignored
            if (page + 1) * EUVD_PAGE_SIZE >= pinned_total:
                break
            page += 1
        if not unstable and len(seen_ids) == pinned_total:
            return EUVDFeed(
                tuple(updates), http.requests - requests_before, ignored
            )
    raise SourceError("euvd", "source returned unstable pagination")


def cisa_fields(items: dict[str, Any]) -> dict[str, KEVFields]:
    output: dict[str, KEVFields] = {}
    for identifier, evidence in items.items():
        details = evidence.details
        output[identifier] = KEVFields(
            added=_text(details.get("dateAdded")),
            due=_text(details.get("dueDate")),
            required_action=_text(details.get("requiredAction")),
            ransomware=_text(details.get("knownRansomwareCampaignUse")),
        )
    return output


def eu_fields(items: dict[str, Any]) -> dict[str, KEVFields]:
    return {
        identifier: KEVFields(added=_text(evidence.details.get("dateAdded")))
        for identifier, evidence in items.items()
    }


def fetch_kev(
    http: HttpClient, *, eu: bool = False, throttle: Throttle | None = None
) -> dict[str, KEVFields]:
    source = KEVSource(http)
    if eu:
        return eu_fields(source.eu(throttle=throttle))
    return cisa_fields(source.cisa())


def epss_file_url(day: date) -> str:
    return EPSS_FILE_URL.format(day=day.isoformat())


class _ChunkReader(io.RawIOBase):
    """Adapt an iterator of byte chunks to the file object gzip expects."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = iter(chunks)
        self._buffer = bytearray()

    def readable(self) -> bool:
        return True

    def readinto(self, target: bytearray) -> int:
        while not self._buffer:
            try:
                self._buffer.extend(next(self._chunks))
            except StopIteration:
                return 0
        count = min(len(target), len(self._buffer))
        target[:count] = self._buffer[:count]
        del self._buffer[:count]
        return count


class _BoundedReader(io.RawIOBase):
    """Cap the total number of decompressed bytes read from a file object."""

    def __init__(self, source: io.RawIOBase, cap: int) -> None:
        self._source = source
        self._cap = cap
        self._total = 0

    def readable(self) -> bool:
        return True

    def readinto(self, target: bytearray) -> int:
        count = self._source.readinto(target)
        if count:
            self._total += count
            if self._total > self._cap:
                raise SourceError(
                    "epss", "source returned an oversized EPSS score file"
                )
        return count or 0


def _epss_value(value: Any) -> float:
    if isinstance(value, bool):
        raise SourceError("epss", "source returned an invalid EPSS score file")
    number = as_float(value)
    if number is None or not 0 <= number <= 1:
        raise SourceError("epss", "source returned an invalid EPSS score file")
    return number


def _epss_score_date(value: Any) -> date:
    text = str(value or "").strip()
    if _EPSS_DATE_ONLY.fullmatch(text):
        return date.fromisoformat(text)
    match = _EPSS_DATE_TIMESTAMP.fullmatch(text)
    if match is None:
        raise ValueError("invalid EPSS score date")
    try:
        return datetime(
            *map(int, match.group("date").split("-")),
            *map(int, match.group("time").split(":")),
            tzinfo=timezone.utc,
        ).date()
    except ValueError as exc:
        raise ValueError("invalid EPSS score date") from exc


def _epss_line(text: Any, line: str, limit: int, *, allow_final: bool) -> str:
    """Validate one bounded line, allowing a complete final line without newline."""
    if line.endswith("\n"):
        return line
    if len(line) < limit:
        if allow_final:
            return line
        raise SourceError("epss", "source returned an invalid EPSS score file")
    extra = text.read(1)
    if extra == "\n":
        return line + extra
    if not extra and allow_final:
        return line
    raise SourceError("epss", "source returned an invalid EPSS score file")


def _epss_rows(chunks: Iterable[bytes], day: date) -> Iterator[tuple[str, float, float, date]]:
    """Yield validated EPSS rows from a gzip-compressed CSV stream."""
    gzip_file = gzip.GzipFile(fileobj=_ChunkReader(chunks), mode="rb")
    text = io.TextIOWrapper(
        _BoundedReader(gzip_file, EPSS_DECOMPRESSED_CAP),
        encoding="utf-8",
        newline="",
    )
    try:
        comment_line = _epss_line(
            text, text.readline(EPSS_COMMENT_LIMIT), EPSS_COMMENT_LIMIT,
            allow_final=False,
        )
        if not comment_line.startswith("#"):
            raise SourceError("epss", "source returned an invalid EPSS score file")
        fields: dict[str, str] = {}
        for part in comment_line.strip()[1:].split(","):
            if ":" not in part:
                raise SourceError("epss", "source returned an invalid EPSS score file")
            key, value = part.split(":", 1)
            fields[key.strip()] = value.strip()
        if not fields.get("model_version") or not fields.get("score_date"):
            raise SourceError("epss", "source returned an invalid EPSS score file")
        try:
            score_date = _epss_score_date(fields["score_date"])
        except ValueError as exc:
            raise SourceError(
                "epss", "source returned an invalid EPSS score file"
            ) from exc
        if score_date not in (day, day - timedelta(days=1)):
            raise SourceError("epss", "source returned an invalid EPSS score date")
        header_line = _epss_line(
            text, text.readline(EPSS_COMMENT_LIMIT), EPSS_COMMENT_LIMIT,
            allow_final=False,
        )
        header = [value.strip().casefold() for value in header_line.rstrip("\r\n").split(",")]
        if header != ["cve", "epss", "percentile"]:
            raise SourceError("epss", "source returned an invalid EPSS score file")
        count = 0
        while True:
            line = text.readline(EPSS_LINE_LIMIT)
            if not line:
                break
            line = _epss_line(text, line, EPSS_LINE_LIMIT, allow_final=True)
            fields = line.rstrip("\r\n").split(",")
            count += 1
            if count > EPSS_MAX_ROWS:
                raise SourceError("epss", "source returned too many EPSS scores")
            if len(fields) != 3:
                raise SourceError("epss", "source returned an invalid EPSS score file")
            identifier = cve_id(fields[0])
            if identifier is None:
                raise SourceError("epss", "source returned an invalid EPSS score file")
            yield identifier, _epss_value(fields[1]), _epss_value(fields[2]), score_date
        if count < EPSS_MIN_ROWS:
            raise SourceError("epss", "source returned too few EPSS scores")
    except (OSError, EOFError, UnicodeError, zlib.error) as exc:
        raise SourceError("epss", "source returned an invalid EPSS score file") from exc
    finally:
        try:
            text.close()
        except OSError:
            pass


def fetch_epss_file(
    http: HttpClient, *, day: date, counter: list[int]
) -> Iterator[tuple[str, float, float, date]]:
    """Stream one dated EPSS file, keeping only a few rows in memory."""
    chunks = http.stream_bytes(
        epss_file_url(day),
        source="epss",
        byte_cap=EPSS_BYTE_CAP,
        counter=counter,
    )
    yield from _epss_rows(chunks, day)


def fetch_epss_daily(
    http: HttpClient, *, today: date, counter: list[int], fallback: bool = True
) -> Iterator[tuple[str, float, float, date]]:
    """Yield today's EPSS file, or yesterday's when today is not published."""
    days = (today, today - timedelta(days=1)) if fallback else (today,)
    for day in days:
        try:
            yield from fetch_epss_file(http, day=day, counter=counter)
            return
        except SourceError as exc:
            if exc.status_code in (403, 404):
                continue
            raise
    raise SourceError(
        "epss",
        "EPSS score file is not published yet",
        status_code=404,
        requests=counter[0],
    )
