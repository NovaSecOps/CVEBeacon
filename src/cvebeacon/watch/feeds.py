"""Public source adapters for the watch database."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

from ..http import HttpClient
from ..errors import SourceError
from ..sources.common import as_float, cve_id, source_payload
from ..sources.epss import EPSS_URL, EPSSSource, batches
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
    normalized_cvss,
)

NVD_PAGE_SIZE = 2000
NVD_WINDOW_DAYS = 120
NVD_WINDOW_RECORD_LIMIT = 20000
NVD_WINDOW_ATTEMPTS = 3
CISA_ADP_SOURCE = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
NVD_PROVIDER_SOURCE = "nvd@nist.gov"
EUVD_PAGE_SIZE = 100
EUVD_CHUNK_DAYS = 30
EUVD_ATTEMPTS = 3
EPSS_PAGE_SIZE = 10000
EPSS_ATTEMPTS = 3

_NVD_TIMESTAMP = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d{1,6}))?$"
)
_EUVD_TIMESTAMP_FORMATS = ("%b %d, %Y, %I:%M:%S %p",)


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
    """Parse NVD's UTC timestamp, which carries no offset, or return None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise SourceError("nvd", "source returned an invalid response timestamp")
    match = _NVD_TIMESTAMP.fullmatch(value.strip())
    if match is None:
        raise SourceError("nvd", "source returned an invalid response timestamp")
    fraction = (match.group("fraction") or "").ljust(6, "0")
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
    record_limit: int,
    width: timedelta,
) -> NVDWindowFeed:
    requests = 0
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
            requests += 1
            vulnerabilities, count, total = _nvd_page(payload, offset)
            if offset == 0:
                pinned_total = total
                timestamp = parse_nvd_timestamp(payload.get("timestamp"))
                if total > record_limit and width > timedelta(days=1):
                    return NVDWindowFeed((), requests, timestamp, split=True)
            elif total != pinned_total:
                unstable = True
                break
            if offset + count > pinned_total or (count == 0 and offset < pinned_total):
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
            if offset + count >= pinned_total:
                break
            offset += count
        if not unstable:
            return NVDWindowFeed(
                tuple(records[key] for key in sorted(records)), requests, timestamp
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
        record_limit=NVD_WINDOW_RECORD_LIMIT,
        width=end - start,
    )


@source_payload("nvd")
def fetch_nvd_cve(
    http: HttpClient, identifier: str, *, api_key: str | None = None, interval: float = 0
) -> NVDCVEResult:
    """Fetch a single CVE by id, used to create rows that other feeds saw first."""
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
    return NVDCVEResult(matches[0], 1)


def _alias_values(aliases: Any) -> list[str]:
    if aliases is None:
        return []
    if isinstance(aliases, str):
        return aliases.replace(",", "\n").splitlines()
    if isinstance(aliases, list):
        return [str(value) for value in aliases]
    raise SourceError("euvd", "source returned invalid aliases")


def _euvd_datetime(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    for pattern in _EUVD_TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, pattern).isoformat()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError:
        return None


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


@source_payload("euvd")
def fetch_euvd(http: HttpClient, *, start: date, end: date) -> EUVDFeed:
    """Fetch one bounded EUVD chunk with a pinned result total."""
    params = {"fromUpdatedDate": start.isoformat(), "toUpdatedDate": end.isoformat()}
    requests = 0
    for _ in range(EUVD_ATTEMPTS):
        updates: list[EUVDUpdate] = []
        ignored = 0
        page = 0
        pinned_total: int | None = None
        unstable = False
        while True:
            payload = http.get_json(
                SEARCH_URL,
                source="euvd",
                params={**params, "page": page, "size": EUVD_PAGE_SIZE},
            )
            requests += 1
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise SourceError("euvd", "source returned an invalid search envelope")
            items = payload["items"]
            try:
                total = payload["total"]
                if type(total) is not int or total < 0:
                    raise ValueError("invalid count")
            except (KeyError, TypeError, ValueError) as exc:
                raise SourceError("euvd", "source returned an invalid total count") from exc
            if page == 0:
                pinned_total = total
            elif total != pinned_total:
                unstable = True
                break
            expected = min(EUVD_PAGE_SIZE, max(pinned_total - page * EUVD_PAGE_SIZE, 0))
            if len(items) != expected:
                raise SourceError("euvd", "source returned an incomplete page")
            for item in items:
                if not isinstance(item, dict):
                    raise SourceError("euvd", "source returned a non-object search item")
                identifiers = tuple(
                    sorted(
                        {
                            value
                            for alias in _alias_values(item.get("aliases"))
                            if (value := cve_id(alias))
                        }
                    )
                )
                if not identifiers:
                    continue
                cvss, was_ignored = _euvd_cvss(item)
                ignored += 1 if was_ignored else 0
                updates.append(
                    EUVDUpdate(
                        identifiers,
                        _text(item.get("id")),
                        _text(item.get("exploitedSince")),
                        cvss,
                        _euvd_datetime(item.get("dateUpdated")),
                    )
                )
            if (page + 1) * EUVD_PAGE_SIZE >= pinned_total:
                break
            page += 1
        if not unstable:
            return EUVDFeed(tuple(updates), requests, ignored)
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


def fetch_kev(http: HttpClient, *, eu: bool = False) -> dict[str, KEVFields]:
    source = KEVSource(http)
    if eu:
        return eu_fields(source.eu())
    return cisa_fields(source.cisa())


def fetch_epss_scores(
    http: HttpClient, identifiers: Iterable[str]
) -> tuple[dict[str, tuple[float, float, date]], int]:
    values = sorted({value for raw in identifiers if (value := cve_id(raw))})
    if not values:
        return {}, 0
    return EPSSSource(http).scores(values), len(batches(values))


@source_payload("epss")
def fetch_epss_floor(
    http: HttpClient, *, floor: float
) -> tuple[dict[str, tuple[float, float, date]], int]:
    requests = 0
    for _ in range(EPSS_ATTEMPTS):
        scores: dict[str, tuple[float, float, date]] = {}
        offset = 0
        pinned_total: int | None = None
        unstable = False
        while True:
            payload = http.get_json(
                EPSS_URL,
                source="epss",
                params={"epss-gt": floor, "limit": EPSS_PAGE_SIZE, "offset": offset},
            )
            requests += 1
            if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
                raise SourceError("epss", "source returned an invalid response envelope")
            total, echoed = payload.get("total"), payload.get("offset")
            if type(total) is not int or total < 0 or type(echoed) is not int or echoed != offset:
                raise SourceError("epss", "source returned invalid pagination metadata")
            if offset == 0:
                pinned_total = total
            elif total != pinned_total:
                unstable = True
                break
            data = payload["data"]
            expected = min(EPSS_PAGE_SIZE, max(pinned_total - offset, 0))
            if len(data) != expected:
                raise SourceError("epss", "source returned an incomplete page")
            for item in data:
                if not isinstance(item, dict):
                    raise SourceError("epss", "source returned a non-object score entry")
                identifier = cve_id(item.get("cve"))
                raw_score, raw_percentile = item.get("epss"), item.get("percentile")
                if isinstance(raw_score, bool) or isinstance(raw_percentile, bool):
                    raise SourceError("epss", "source returned an invalid probability or identifier")
                score, percentile = as_float(raw_score), as_float(raw_percentile)
                try:
                    score_date = date.fromisoformat(str(item.get("date")))
                except ValueError as exc:
                    raise SourceError("epss", "score entry has an invalid date") from exc
                if (
                    identifier is None
                    or score is None
                    or percentile is None
                    or not 0 <= score <= 1
                    or not 0 <= percentile <= 1
                ):
                    raise SourceError("epss", "source returned an invalid probability or identifier")
                scores[identifier] = (score, percentile, score_date)
            if offset + len(data) >= pinned_total:
                break
            offset += len(data)
        if not unstable:
            return scores, requests
    raise SourceError("epss", "source returned unstable pagination")
