"""Anonymous OSV package discovery with bounded, per-query pagination."""

from dataclasses import dataclass
import re
from urllib.parse import quote

from ..errors import SourceError
from ..identity import PURL_ECOSYSTEMS, name_key, parse_purl, purl_string
from .common import source_payload

BASE_URL = "https://api.osv.dev/v1"
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{1,199}")


def advisory_id(value):
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ValueError("invalid advisory identifier")
    return value


def query_identity(asset):
    """Allowlist public lookup terms; never serialize an inventory record."""
    if asset.identity_path == "commit":
        return {"commit": asset.commit}
    if asset.purl:
        purl = parse_purl(asset.purl)
        # Qualifiers can contain private URLs, paths or build metadata. Preserve
        # locally; unsupported refinements cannot be dropped to assert identity.
        if purl.qualifiers or purl.subpath or purl.type not in PURL_ECOSYSTEMS:
            return None
        return {"package": {"purl": purl_string(purl._replace(version=None))}}
    if asset.ecosystem:
        # OSV lookups are case-sensitive even for case-insensitive registries.
        # Keep registry spelling in requests, but compare returned identities
        # with the ecosystem's name_key.
        name = name_key(asset.ecosystem, asset.product) if asset.ecosystem == "PyPI" else asset.product
        return {"package": {"ecosystem": asset.ecosystem, "name": name}}
    return None


@dataclass(frozen=True)
class OSVResult:
    records: tuple[dict, ...] = ()
    error: str | None = None
    matched_ids: frozenset[str] = frozenset()


class OSVSource:
    def __init__(self, http):
        self.http = http
        self.cache = {}

    @source_payload("osv")
    def record(self, identifier):
        identifier = advisory_id(identifier)
        if identifier not in self.cache:
            payload = self.http.get_json(f"{BASE_URL}/vulns/{quote(identifier, safe='')}", source="osv")
            if not isinstance(payload, dict) or payload.get("id") != identifier:
                raise SourceError("osv", "advisory response identity mismatch")
            validate_record(payload)
            self.cache[identifier] = payload
        return self.cache[identifier]

    def query_many(self, assets):
        output, eligible = {}, []
        for asset in assets:
            query = query_identity(asset)
            if query is None:
                output[asset.target_key] = OSVResult(error="package identity qualifiers/type are not supported for exact public lookup")
            else:
                eligible.append((asset.target_key, query))
        for start in range(0, len(eligible), 100):
            batch = eligible[start:start + 100]
            active = list(range(len(batch)))
            ids = [set() for _ in batch]
            tokens = [{} for _ in batch]
            seen = [set() for _ in batch]
            errors = {}
            for _ in range(50):
                if not active:
                    break
                try:
                    payload = self.http.post_json(f"{BASE_URL}/querybatch", source="osv",
                        json={"queries": [{**batch[i][1], **tokens[i]} for i in active]})
                    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list) or len(payload["results"]) != len(active):
                        raise SourceError("osv", "batch response is incomplete")
                except SourceError as exc:
                    errors.update({i: str(exc) for i in active})
                    active = []
                    break
                next_active = []
                for i, value in zip(active, payload["results"]):
                    try:
                        if not isinstance(value, dict) or set(value) - {"vulns", "next_page_token"}:
                            raise ValueError("invalid query result")
                        vulns = value.get("vulns", [])
                        if not isinstance(vulns, list):
                            raise ValueError("invalid vulnerability list")
                        ids[i].update(advisory_id(v["id"]) for v in vulns)
                        if len(ids[i]) > 5000:
                            raise ValueError("query exceeds advisory limit")
                        token = value.get("next_page_token")
                        if token is not None and not isinstance(token, str):
                            raise ValueError("invalid page token")
                        if token:
                            if len(token) > 8192 or token in seen[i]:
                                raise ValueError("invalid or repeated page token")
                            seen[i].add(token)
                            tokens[i] = {"page_token": token}
                            next_active.append(i)
                    except (ValueError, TypeError, KeyError):
                        errors[i] = "OSV returned an invalid or incomplete query result"
                active = next_active
            for i in active:
                errors[i] = "OSV pagination exceeded the bounded page limit"
            for i, (key, _) in enumerate(batch):
                records = []
                for identifier in sorted(ids[i]):
                    try:
                        records.append(self.record(identifier))
                    except SourceError as exc:
                        errors[i] = str(exc)
                output[key] = OSVResult(tuple(records), errors.get(i), frozenset(ids[i]))
        return output


def validate_record(value):
    advisory_id(value["id"])
    if not isinstance(value.get("modified"), str) or not value["modified"]:
        raise ValueError("missing modification timestamp")
    version = value.get("schema_version", "1.0.0")
    if not isinstance(version, str) or not re.fullmatch(r"1\.\d+\.\d+", version):
        raise ValueError("unsupported OSV schema version")
    for name in ("aliases", "related", "upstream"):
        items = value.get(name, [])
        if not isinstance(items, list):
            raise ValueError("invalid identifier list")
        for item in items:
            advisory_id(item)
    for name in ("withdrawn", "published", "summary", "details"):
        if name in value and not isinstance(value[name], str):
            raise ValueError("invalid advisory text")
    affected = value.get("affected", [])
    if not isinstance(affected, list) or not all(isinstance(item, dict) for item in affected):
        raise ValueError("invalid affected records")
