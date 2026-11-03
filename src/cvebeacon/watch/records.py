"""Immutable watch records shared by source feeds and storage."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

CVSS_PROVIDERS = ("nvd", "cna", "cisa-adp", "euvd", "other")
CVSS_VERSIONS = ("2.0", "3.0", "3.1", "4.0")
SSVC_EXPLOITATION = ("none", "poc", "active")
STATUSES = ("published", "rejected")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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


@dataclass(frozen=True, slots=True)
class EUVDUpdate:
    cve_ids: tuple[str, ...]
    euvd_id: str | None
    exploited_since: str | None
    cvss: CVSSEntry | None = None


@dataclass(frozen=True, slots=True)
class KEVFields:
    added: str | None
    due: str | None = None
    required_action: str | None = None
    ransomware: str | None = None


@dataclass(frozen=True, slots=True)
class WatchRecord:
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
    eu_kev_added: str | None = None
    euvd_id: str | None = None
    euvd_exploited_since: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError("watch record status must be published or rejected")
        if self.description is not None:
            object.__setattr__(self, "description", self.description[:1000])
        object.__setattr__(self, "cvss", normalized_cvss(self.cvss))
        object.__setattr__(self, "cwes", tuple(sorted({str(value) for value in self.cwes if value})))
        products = {(item.vendor, item.product): item for item in self.products if item.vendor and item.product}
        object.__setattr__(
            self, "products", tuple(products[key] for key in sorted(products))[:50]
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
            eu_kev_added=row["eu_kev_added"],
            euvd_id=row["euvd_id"],
            euvd_exploited_since=row["euvd_exploited_since"],
            epss=row["epss"],
            epss_percentile=row["epss_percentile"],
            epss_date=row["epss_date"],
        )
