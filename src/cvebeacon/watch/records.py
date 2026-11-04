"""Immutable watch records shared by source feeds and storage."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping

CVSS_PROVIDERS = ("nvd", "cna", "cisa-adp", "euvd", "other")
CVSS_VERSIONS = ("2.0", "3.0", "3.1", "4.0")
SSVC_EXPLOITATION = ("none", "poc", "active")
STATUSES = ("published", "rejected")
EPSS_BANDS = (0.1, 0.5, 0.9)
EUVD_TIMESTAMP_FORMATS = ("%b %d, %Y, %I:%M:%S %p",)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def euvd_datetime(value: Any) -> str | None:
    """Normalise an EUVD timestamp to ISO 8601, or None when it is not one."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for pattern in EUVD_TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, pattern).isoformat()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class CVSSEntry:
    provider: str
    source: str
    version: str
    score: float
    vector: str | None = None
    severity: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "source": self.source,
            "version": self.version,
            "score": self.score,
            "vector": self.vector,
            "severity": self.severity,
        }

    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.provider,
            self.source,
            self.version,
            self.score,
            self.vector or "",
            self.severity or "",
        )


def normalized_cvss(entries: Iterable[CVSSEntry]) -> tuple[CVSSEntry, ...]:
    unique = {entry.sort_key(): entry for entry in entries}
    return tuple(unique[key] for key in sorted(unique))


@dataclass(frozen=True, slots=True)
class Product:
    vendor: str
    product: str

    def as_dict(self) -> dict[str, str]:
        return {"vendor": self.vendor, "product": self.product}


@dataclass(frozen=True, slots=True)
class Reference:
    url: str
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tags", tuple(sorted({str(tag) for tag in self.tags if tag})))

    def as_dict(self) -> dict[str, Any]:
        return {"url": self.url, "tags": list(self.tags)}


def _identifier_key(value: str | None) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value or ""))


@dataclass(frozen=True, slots=True)
class EUVDUpdate:
    cve_ids: tuple[str, ...]
    euvd_id: str | None
    exploited_since: str | None
    cvss: CVSSEntry | None = None
    date_updated: str | None = None
    vendors: tuple[Product, ...] = ()

    def rank(self) -> tuple[Any, ...]:
        """Deterministic priority when several EUVD items describe one CVE."""
        return (
            1 if self.exploited_since else 0,
            self.date_updated or "",
            _identifier_key(self.euvd_id),
        )


@dataclass(frozen=True, slots=True)
class KEVFields:
    added: str | None
    due: str | None = None
    required_action: str | None = None
    ransomware: str | None = None


def epss_band(value: float | None) -> int:
    """Return the EPSS band index, or -1 when no score is stored."""
    if value is None:
        return -1
    for index, bound in enumerate(EPSS_BANDS):
        if value < bound:
            return index
    return len(EPSS_BANDS)


@dataclass(frozen=True, slots=True)
class WatchRecord:
    """The NVD-owned part of a CVE, as stored in ``watch_cve``."""

    cve_id: str
    status: str
    published: str | None = None
    last_modified: str | None = None
    description: str | None = None
    source_identifier: str | None = None
    cvss: tuple[CVSSEntry, ...] = ()
    cwes: tuple[str, ...] = ()
    products: tuple[Product, ...] = ()
    references: tuple[Reference, ...] = ()
    ssvc_exploitation: str | None = None
    cisa_kev_added: str | None = None
    cisa_kev_due: str | None = None
    cisa_required_action: str | None = None
    cisa_ransomware: str | None = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError("watch record status must be published or rejected")
        if self.description is not None:
            object.__setattr__(self, "description", self.description[:1000])
        object.__setattr__(self, "cvss", normalized_cvss(self.cvss))
        object.__setattr__(self, "cwes", tuple(sorted({str(value) for value in self.cwes if value})))
        products = {(item.vendor, item.product): item for item in self.products if item.vendor and item.product}
        object.__setattr__(
            self, "products", tuple(products[key] for key in sorted(products))[:1000]
        )
        references = {item.url: item for item in self.references if item.url}
        object.__setattr__(
            self,
            "references",
            tuple(sorted(references.values(), key=lambda item: item.url)[:30]),
        )
        if self.ssvc_exploitation not in SSVC_EXPLOITATION:
            object.__setattr__(self, "ssvc_exploitation", None)

    @property
    def cvss_json(self) -> str:
        return canonical_json([entry.as_dict() for entry in self.cvss])

    @property
    def cwes_json(self) -> str:
        return canonical_json(list(self.cwes))

    @property
    def products_json(self) -> str:
        return canonical_json([item.as_dict() for item in self.products])

    @property
    def references_json(self) -> str:
        return canonical_json([item.as_dict() for item in self.references])

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "WatchRecord":
        return cls(
            cve_id=row["cve_id"],
            status=row["status"],
            published=row["published"],
            last_modified=row["last_modified"],
            description=row["description"],
            source_identifier=row["source_identifier"],
            cvss=tuple(CVSSEntry(**item) for item in json.loads(row["cvss_json"])),
            cwes=tuple(json.loads(row["cwes_json"])),
            products=tuple(Product(**item) for item in json.loads(row["products_json"])),
            references=tuple(
                Reference(item["url"], tuple(item.get("tags") or ()))
                for item in json.loads(row["references_json"])
            ),
            ssvc_exploitation=row["ssvc_exploitation"],
            cisa_kev_added=row["cisa_kev_added"],
            cisa_kev_due=row["cisa_kev_due"],
            cisa_required_action=row["cisa_required_action"],
            cisa_ransomware=row["cisa_ransomware"],
        )


@dataclass(frozen=True, slots=True)
class WatchView:
    """The alert-relevant combination of one CVE and all source tables."""

    cve_id: str
    status: str
    published: str | None = None
    first_seen: str | None = None
    last_modified: str | None = None
    description: str | None = None
    source_identifier: str | None = None
    cvss: tuple[CVSSEntry, ...] = ()
    cwes: tuple[str, ...] = ()
    vendors: tuple[str, ...] = ()
    products: tuple[str, ...] = ()
    references: tuple[Reference, ...] = ()
    ssvc_exploitation: str | None = None
    cisa_kev_added: str | None = None
    cisa_kev_due: str | None = None
    cisa_required_action: str | None = None
    cisa_ransomware: str | None = None
    eu_kev_added: str | None = None
    euvd_id: str | None = None
    euvd_exploited_since: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None

    @property
    def epss_band(self) -> int:
        return epss_band(self.epss)

    def fingerprint(self) -> str:
        """Hash alert-relevant fields; EPSS, identifiers and timestamps are excluded."""
        value = {
            "status": self.status,
            "cvss": [entry.as_dict() for entry in self.cvss],
            "ssvc_exploitation": self.ssvc_exploitation,
            "cisa_kev_added": self.cisa_kev_added,
            "cisa_kev_due": self.cisa_kev_due,
            "cisa_required_action": self.cisa_required_action,
            "cisa_ransomware": self.cisa_ransomware,
            "eu_kev_added": self.eu_kev_added,
            "euvd_exploited_since": self.euvd_exploited_since,
        }
        return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ReportedMark:
    """The current "reported to clients" mark of one CVE."""

    cve_id: str
    by: str
    note: str | None
    at: str
    username: str | None = None


@dataclass(frozen=True, slots=True)
class DeliveryEvent:
    """One stored event with the derived CVE view used for a message."""

    event_id: int
    rule: str
    cve_id: str
    kind: str
    reasons: tuple[str, ...]
    initial: bool
    created_at: str
    view: WatchView
    details: Mapping[str, Any] = field(default_factory=dict)
    status: str = ""
    reported: ReportedMark | None = None


@dataclass(frozen=True, slots=True)
class InitialDigest:
    """The SQL counts and rendered sample for one initial digest.

    ``counts`` holds ``(rule, kind, event count)`` over every selected initial
    row, while ``events`` holds only the sampled rows with a full view.
    """

    events: tuple[DeliveryEvent, ...] = ()
    counts: tuple[tuple[str, str, int], ...] = ()
    cves: int = 0
    total: int = 0
    ambiguous: int = 0


def _names(values: Iterable[str], limit: int = 500) -> tuple[str, ...]:
    unique: dict[str, str] = {}
    for value in values:
        text = str(value).strip()
        if text and text.casefold() not in unique:
            unique[text.casefold()] = text
    return tuple(unique[key] for key in sorted(unique)[:limit])


def build_view(
    record: WatchRecord,
    *,
    euvd: EUVDUpdate | None = None,
    cisa_kev: KEVFields | None = None,
    eu_kev: KEVFields | None = None,
    cisa_catalog: bool = False,
    eu_catalog: bool = False,
    epss: tuple[float, float, str] | None = None,
    first_seen: str | None = None,
) -> WatchView:
    """Combine the raw source rows into one CVE view.

    The CISA catalog owns KEV fields whenever it is configured; otherwise the
    NVD record supplies its own CISA fields. Vendor and product names come from
    NVD CPE products and the selected EUVD item.
    """
    cvss = record.cvss
    if euvd is not None and euvd.cvss is not None:
        cvss = normalized_cvss((*cvss, euvd.cvss))
    if cisa_catalog:
        cisa = cisa_kev or KEVFields(None)
    else:
        cisa = KEVFields(
            record.cisa_kev_added,
            record.cisa_kev_due,
            record.cisa_required_action,
            record.cisa_ransomware,
        )
    eu = eu_kev if eu_catalog else None
    vendors = [item.vendor for item in record.products if item.vendor]
    products = [item.product for item in record.products if item.product]
    if euvd is not None:
        vendors.extend(item.vendor for item in euvd.vendors if item.vendor)
        products.extend(item.product for item in euvd.vendors if item.product)
    return WatchView(
        cve_id=record.cve_id,
        status=record.status,
        published=record.published,
        first_seen=first_seen,
        last_modified=record.last_modified,
        description=record.description,
        source_identifier=record.source_identifier,
        cvss=cvss,
        cwes=record.cwes,
        vendors=_names(vendors),
        products=_names(products),
        references=record.references,
        ssvc_exploitation=record.ssvc_exploitation,
        cisa_kev_added=cisa.added,
        cisa_kev_due=cisa.due,
        cisa_required_action=cisa.required_action,
        cisa_ransomware=cisa.ransomware,
        eu_kev_added=eu.added if eu is not None else None,
        euvd_id=euvd.euvd_id if euvd is not None else None,
        euvd_exploited_since=euvd.exploited_since if euvd is not None else None,
        epss=epss[0] if epss is not None else None,
        epss_percentile=epss[1] if epss is not None else None,
        epss_date=epss[2] if epss is not None else None,
    )
