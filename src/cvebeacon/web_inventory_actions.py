"""Pure helpers that turn saved web detections into inventory status and inventory rows."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import re
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
STATUS_ORDER = {"monitored": 0, "ready": 1, "review": 2, "service": 3}
STATUS_LABELS = {"monitored": "Monitored", "ready": "Ready to add", "review": "Needs review",
                 "service": "Third-party service"}
STATUS_BADGES = {"monitored": "success", "ready": "info", "review": "warning", "service": "neutral"}
# Hosted services, analytics and CDNs run elsewhere: there is no installed version to confirm.
SERVICE_CATEGORIES = frozenset({"hosted-platform", "analytics", "edge"})
# Rule-defined labels such as "GA4" are display text, never an inventory version.
DISPLAY_VERSION = re.compile(r"[A-Za-z][A-Za-z0-9]{0,15}")


class RowRefused(ValueError):
    """A product cannot become an inventory row; the message is safe to show."""


def detected_versions(item):
    return [version.strip() for version in item.get("versions", []) if version.strip()]


def assignable_versions(item):
    """Detected values that can be stored as an inventory version."""
    return [version for version in detected_versions(item) if not DISPLAY_VERSION.fullmatch(version)]


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
    """The version a ready product is added with, or None when the product needs review.

    An empty string means the product is ready without a version. Only a product
    whose detection produced an inventory row is ready; a conflict between
    unrelated versions still needs a person to choose or confirm.
    """
    if _implied_only(item) or not item.get("in_inventory") or is_service(item):
        return None
    return preferred_version(assignable_versions(item))


def _package_purl(item, version):
    package = item.get("package")
    if item.get("ecosystem") != "npm" or not isinstance(package, str) or not package:
        return ""
    namespace, _, name = package.rpartition("/")
    return purl_string(PackageURL(type="npm", namespace=namespace or None, name=name,
                                  version=version or None))


def _identity_keys(item):
    """Exact keys for one saved detection, with the version as it is.

    An empty version is an exact value: a version-less row covers only a
    version-less detection of the same identity.
    """
    keys = set()
    vendor = str(item.get("vendor", "")).casefold()
    names = {str(item.get(field, "")).casefold() for field in ("product", "package")} - {""}
    versions = assignable_versions(item) or [""]
    cpe = item.get("cpe") if isinstance(item.get("cpe"), str) else ""
    for version in versions:
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
    if asset.vendor and asset.product and (asset.version or not asset.commit):
        keys.add(("vpv", asset.vendor.casefold(), asset.product.casefold(), asset.version))
    return keys


class ManagedIndex:
    """Find which rows of a client's managed inventory already cover a detected product."""

    def __init__(self, assets=(), *, require_same_site=False):
        self.ids = {}
        self.keys = {}
        self.require_same_site = require_same_site
        for asset in assets:
            self.ids.setdefault(asset.asset_id.casefold(), asset.asset_id)
            site = asset.system_id.casefold() if require_same_site else ""
            for key in _row_keys(asset):
                self.keys.setdefault((site, key), []).append(asset.asset_id)

    def covering(self, item):
        found = []
        if asset_id := item.get("asset_id"):
            manual = self.ids.get((asset_id + MANUAL_SUFFIX).casefold())
            if manual:
                found.append(manual)
        site = (item.get("hostname") or "").casefold() if self.require_same_site else ""
        if self.require_same_site and not site:
            return found
        for key in _identity_keys(item):
            found.extend(self.keys.get((site, key), ()))
        return list(dict.fromkeys(found))


def classify(item, *, snapshots_on, snapshot_ids, managed):
    """Return (status, asset IDs whose scans cover the product)."""
    covered = []
    if snapshots_on and item.get("asset_id") in snapshot_ids:
        covered.append(item["asset_id"])
    covered.extend(managed.covering(item))
    covered = list(dict.fromkeys(covered))
    if covered:
        return "monitored", covered
    if is_service(item):
        return "service", []
    if ready_version(item) is not None:
        return "ready", []
    return "review", []


def is_service(item):
    """A third-party service with no package or CPE identity, such as an analytics tag."""
    return (item.get("category") in SERVICE_CATEGORIES and not item.get("package")
            and not item.get("cpe"))


def best_status(statuses):
    return min(statuses, key=STATUS_ORDER.__getitem__, default="review")


def typed_version(text):
    # An absent version is valid, so reject control characters before stripping
    # can turn a control-only value into an empty one.
    if isinstance(text, str) and any(
            unicodedata.category(char) in {"Cc", "Cs"} for char in text):
        raise RowRefused("The version contains an unsupported character.")
    value = text.strip() if isinstance(text, str) else ""
    if not value:
        return ""
    if len(value) > MAX_VERSION:
        raise RowRefused("Enter a version of at most 100 characters.")
    return value


def build_row(item, client, version):
    """Build one validated inventory row from a saved detection, never from form data."""
    try:
        purl = _package_purl(item, version)
        cpe = item.get("cpe") if isinstance(item.get("cpe"), str) and not purl else ""
        asset = normalize_asset(Asset(
            asset_id=str(item["asset_id"]) + MANUAL_SUFFIX,
            # A generic banner or file-name result names no vendor; the product stands in.
            vendor=str(item.get("product", "") if item.get("vendor") in GENERIC_VENDORS
                       else item.get("vendor", "")),
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
        raise RowRefused("These details cannot be saved as an inventory row.") from None
    return asset


def plan_rows(products, picks, versions, client, *, snapshots_on, snapshot_ids, managed, everything=False):
    """Decide what to add. Returns (rows, skipped, unknown) from the saved products only.

    ``picks`` are asset IDs and ``versions`` maps an asset ID to the text typed for it.
    Each row is a (product, asset) pair; each skipped entry is (label, reason).
    """
    by_id = {}
    for item in products:
        if item.get("asset_id"):
            by_id.setdefault(item["asset_id"], item)
    wanted = ([asset_id for asset_id, item in by_id.items()
               if classify(item, snapshots_on=snapshots_on, snapshot_ids=snapshot_ids, managed=managed)[0] == "ready"]
              if everything else list(dict.fromkeys(picks)))
    rows, skipped, unknown = [], [], 0
    for asset_id in wanted:
        item = by_id.get(asset_id)
        if item is None:
            unknown += 1
            continue
        name = item.get("name") or f"{item.get('vendor', '')}/{item.get('product', '')}"
        label = f"{name} on {item.get('hostname') or 'a site not recorded'}"
        status = "ready" if everything else classify(
            item, snapshots_on=snapshots_on, snapshot_ids=snapshot_ids, managed=managed)[0]
        if status == "monitored":
            skipped.append((label, "Already monitored."))
            continue
        if status == "service":
            skipped.append((label, "A third-party service has no installed version to scan."))
            continue
        try:
            auto = ready_version(item)
            if status == "ready" and auto:
                # A ready product already has a detected version; a form value
                # cannot replace it.
                version = auto
            else:
                version = typed_version(versions.get(asset_id, "")) or (auto or "")
            rows.append((item, build_row(item, client, version)))
        except RowRefused as exc:
            skipped.append((label, str(exc)))
    return rows, skipped, unknown


def digest(assets):
    data = json.dumps([asdict(asset) for asset in assets], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
