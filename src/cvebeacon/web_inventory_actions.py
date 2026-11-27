"""Pure helpers that turn saved web detections into inventory status and inventory rows."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import unicodedata

from packageurl import PackageURL

from .errors import InventoryValidationError
from .identity import normalize_asset, purl_string
from .managed_inventory import encode_records, read_inventory
from .models import Asset

# A row added by hand never reuses the ID of the row a web snapshot would create for the
# same product. If web snapshots are switched on later, both rows can coexist in one scan
# instead of stopping it with an asset ID collision.
MANUAL_SUFFIX = "-m"
GENERIC_VENDORS = frozenset({"banner", "file-name"})
MAX_PICKS = 2000
MAX_VERSION = 100
STATUS_ORDER = {"monitored": 0, "ready": 1, "review": 2}
STATUS_LABELS = {"monitored": "Monitored", "ready": "Ready to add", "review": "Needs review"}
STATUS_BADGES = {"monitored": "success", "ready": "info", "review": "warning"}


class RowRefused(ValueError):
    """A product cannot become an inventory row; the message is safe to show."""


def detected_versions(item):
    return [version.strip() for version in item.get("versions", []) if version.strip()]


def preferred_version(versions):
    """The most specific version when every other one is a prefix of it, else None."""
    if not versions:
        return ""
    ordered = sorted(versions, key=lambda value: (value.count("."), len(value), value))
    longest = ordered[-1]
    for value in ordered[:-1]:
        if longest != value and not longest.startswith(value + ".") and not longest.startswith(value + "-"):
            return None
    return longest


def _implied_only(item):
    return bool(item.get("implied_by")) and set(item.get("evidence_types", [])) <= {"implied"}


def ready_version(item):
    """The version a ready product is added with, or None when the product needs review."""
    versions = detected_versions(item)
    if _implied_only(item):
        return None
    if item.get("in_inventory"):
        # A saved row exists, so the detection already named this version.
        return preferred_version(versions) or None
    if item.get("vendor") in GENERIC_VENDORS or len(set(versions)) != 1:
        return None
    return versions[0]


def _package_purl(item, version):
    package = item.get("package")
    if item.get("ecosystem") != "npm" or not isinstance(package, str) or not package or not version:
        return ""
    namespace, _, name = package.rpartition("/")
    return purl_string(PackageURL(type="npm", namespace=namespace or None, name=name, version=version))


def _identity_keys(item):
    keys = set()
    vendor = str(item.get("vendor", "")).casefold()
    names = {str(item.get(field, "")).casefold() for field in ("product", "package")} - {""}
    cpe = item.get("cpe") if isinstance(item.get("cpe"), str) else ""
    for version in detected_versions(item):
        keys.update(("vpv", vendor, name, version) for name in names)
        if cpe:
            keys.add(("cpe", cpe, version))
        try:
            purl = _package_purl(item, version)
        except ValueError:
            purl = ""
        if purl:
            keys.add(("purl", purl))
    return keys


def _row_keys(asset):
    keys = set()
    if asset.purl:
        keys.add(("purl", asset.purl))
    if asset.cpe:
        keys.add(("cpe", asset.cpe, asset.version))
    if asset.vendor and asset.product and asset.version:
        keys.add(("vpv", asset.vendor.casefold(), asset.product.casefold(), asset.version))
    return keys


class ManagedIndex:
    """Find which rows of a client's managed inventory already cover a detected product."""

    def __init__(self, assets=()):
        self.ids = {}
        self.keys = {}
        for asset in assets:
            self.ids.setdefault(asset.asset_id.casefold(), asset.asset_id)
            for key in _row_keys(asset):
                self.keys.setdefault(key, []).append(asset.asset_id)

    def covering(self, item):
        found = []
        manual = self.ids.get((str(item.get("asset_id", "")) + MANUAL_SUFFIX).casefold())
        if manual:
            found.append(manual)
        for key in _identity_keys(item):
            found.extend(self.keys.get(key, ()))
        return found


def classify(item, *, snapshots_on, managed):
    """Return (status, asset IDs whose scans cover the product)."""
    covered = []
    if snapshots_on and item.get("in_inventory") and item.get("asset_id"):
        covered.append(item["asset_id"])
    covered.extend(managed.covering(item))
    covered = list(dict.fromkeys(covered))
    if covered:
        return "monitored", covered
    return ("ready" if ready_version(item) is not None else "review"), []


def best_status(statuses):
    return min(statuses, key=STATUS_ORDER.__getitem__, default="review")


def typed_version(text):
    value = text.strip() if isinstance(text, str) else ""
    if not value:
        raise RowRefused("Enter a version for this product.")
    if len(value) > MAX_VERSION:
        raise RowRefused("Enter a version of at most 100 characters.")
    if any(unicodedata.category(char) in {"Cc", "Cs"} for char in value):
        raise RowRefused("The version contains an unsupported character.")
    return value


def build_row(item, client, version):
    """Build one validated inventory row from a saved detection, never from form data."""
    try:
        purl = _package_purl(item, version)
        cpe = item.get("cpe") if isinstance(item.get("cpe"), str) and not purl else ""
        asset = normalize_asset(Asset(
            asset_id=str(item["asset_id"]) + MANUAL_SUFFIX,
            vendor=str(item.get("vendor", "")),
            product=item.get("package") if purl else str(item.get("product", "")),
            version=version,
            category=str(item.get("category", "")),
            system_id=str(item.get("hostname", "")),
            ecosystem="npm" if purl else "",
            purl=purl,
            cpe=cpe or "",
            client=client,
        ))
        read_inventory(encode_records([asset]), client=client)
    except (ValueError, InventoryValidationError, KeyError):
        if not version:
            raise RowRefused("Enter a version for this product.") from None
        raise RowRefused("These details cannot be saved as an inventory row.") from None
    return asset


def plan_rows(products, picks, versions, client, *, snapshots_on, managed, everything=False):
    """Decide what to add. Returns (rows, skipped, unknown) from the saved products only.

    ``picks`` are asset IDs and ``versions`` maps an asset ID to the text typed for it.
    Each row is a (product, asset) pair; each skipped entry is (label, reason).
    """
    by_id = {}
    for item in products:
        if item.get("asset_id"):
            by_id.setdefault(item["asset_id"], item)
    wanted = [item["asset_id"] for item in by_id.values()
              if classify(item, snapshots_on=snapshots_on, managed=managed)[0] == "ready"] \
        if everything else list(dict.fromkeys(picks))
    rows, skipped, unknown = [], [], 0
    for asset_id in wanted:
        item = by_id.get(asset_id)
        if item is None:
            unknown += 1
            continue
        name = item.get("name") or f"{item.get('vendor', '')}/{item.get('product', '')}"
        label = f"{name} on {item.get('hostname') or 'a site not recorded'}"
        status, _ = classify(item, snapshots_on=snapshots_on, managed=managed)
        if status == "monitored":
            skipped.append((label, "Already monitored."))
            continue
        try:
            version = ready_version(item) if status == "ready" else typed_version(versions.get(asset_id, ""))
            rows.append((item, build_row(item, client, version)))
        except RowRefused as exc:
            skipped.append((label, str(exc)))
    return rows, skipped, unknown


def digest(assets):
    data = json.dumps([asdict(asset) for asset in assets], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
