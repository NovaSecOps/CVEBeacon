"""Public source adapters for the watch database."""

from __future__ import annotations

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
CISA_ADP_SOURCE = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
NVD_PROVIDER_SOURCE = "nvd@nist.gov"
EUVD_PAGE_SIZE = 100
EPSS_PAGE_SIZE = 10000


@dataclass(frozen=True, slots=True)
class NVDFeed:
    records: tuple[WatchRecord, ...]
    requests: int


@dataclass(frozen=True, slots=True)
class EUVDFeed:
    updates: tuple[EUVDUpdate, ...]
    requests: int


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


def _validate_nvd_page(payload: Any, start: int) -> tuple[list[Any], int]:
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
    if len(vulnerabilities) != count or start + count > total or (count == 0 and start < total):
        raise SourceError("nvd", "source returned an incomplete page")
    return vulnerabilities, count


@source_payload("nvd")
def fetch_nvd(
    http: HttpClient,
    *,
    start: datetime,
    end: datetime,
    api_key: str | None = None,
    interval: float = 0,
) -> NVDFeed:
    records: dict[str, WatchRecord] = {}
    requests = 0
    headers = _nvd_headers(api_key)
    for window_start, window_end in nvd_windows(start, end):
        window = {
            "lastModStartDate": iso_timestamp(window_start),
            "lastModEndDate": iso_timestamp(window_end),
        }
        offset = 0
        while True:
            payload = http.get_json(
                CVE_URL,
                source="nvd",
                params={**window, "startIndex": offset, "resultsPerPage": NVD_PAGE_SIZE},
                headers=headers,
                minimum_interval=interval,
            )
            requests += 1
            vulnerabilities, count = _validate_nvd_page(payload, offset)
            for wrapped in vulnerabilities:
                raw = wrapped.get("cve") if isinstance(wrapped, dict) else None
                if not isinstance(raw, dict):
                    raise SourceError("nvd", "source returned an invalid vulnerability entry")
                record = parse_nvd_cve(raw)
                records[record.cve_id] = record
            if offset + count >= payload["totalResults"]:
                break
            offset += count
    return NVDFeed(tuple(records[key] for key in sorted(records)), requests)


def _alias_values(aliases: Any) -> list[str]:
    if aliases is None:
        return []
    if isinstance(aliases, str):
        return aliases.replace(",", "\n").splitlines()
    if isinstance(aliases, list):
        return [str(value) for value in aliases]
    raise SourceError("euvd", "source returned invalid aliases")


@source_payload("euvd")
def fetch_euvd(http: HttpClient, *, start: date, end: date) -> EUVDFeed:
    updates: list[EUVDUpdate] = []
    requests = 0
    page = 0
    params = {"fromUpdatedDate": start.isoformat(), "toUpdatedDate": end.isoformat()}
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
        if len(items) != min(EUVD_PAGE_SIZE, max(total - page * EUVD_PAGE_SIZE, 0)):
            raise SourceError("euvd", "source returned an incomplete page")
        for item in items:
            if not isinstance(item, dict):
                raise SourceError("euvd", "source returned a non-object search item")
            identifiers = tuple(
                sorted({value for alias in _alias_values(item.get("aliases")) if (value := cve_id(alias))})
            )
            if not identifiers:
                continue
            score = _score(item.get("baseScore"))
            version = _text(item.get("baseScoreVersion"))
            vector = _text(item.get("baseScoreVector"))
            cvss = None
            if score is not None and version in CVSS_VERSIONS:
                cvss = CVSSEntry("euvd", "euvd", version, score, vector)
            updates.append(
                EUVDUpdate(
                    identifiers,
                    _text(item.get("id")),
                    _text(item.get("exploitedSince")),
                    cvss,
                )
            )
        if (page + 1) * EUVD_PAGE_SIZE >= total:
            break
        page += 1
    return EUVDFeed(tuple(updates), requests)


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
    scores: dict[str, tuple[float, float, date]] = {}
    offset = 0
    requests = 0
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
        data = payload["data"]
        expected = min(EPSS_PAGE_SIZE, max(total - offset, 0))
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
        if offset + len(data) >= total:
            break
        offset += len(data)
    return scores, requests
