"""Pure helpers that turn saved web detections into inventory status and inventory rows."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import re
import unicodedata

from packageurl import PackageURL

from .errors import InventoryValidationError
from .identity import normalize_asset, parse_purl, purl_string
from .managed_inventory import encode_records, read_inventory
from .models import Asset
from .sources.nvd import split_cpe23

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


def _cpe_base(cpe):
    fields = list(split_cpe23(cpe, keep_escapes=True))
    if len(fields) != 11:
        return ""
    fields[3] = "*"
    return "cpe:2.3:" + ":".join(fields)


def _identity_keys(item):
    """Exact and product-wide keys for one saved detection.

    Broad coverage uses the strongest identity the detection carries: the full
    CPE scope with the version removed, or the canonical package PURL with only
    the version removed. Vendor/product text is a fallback only when both the
    detection and the inventory row have no structured identity.
    """
    exact, broad = set(), set()
    versions = detected_versions(item)
    cpe = item.get("cpe") if isinstance(item.get("cpe"), str) else ""
    try:
        base_purl = _package_purl(item, "")
    except ValueError:
        base_purl = ""
    if cpe and (scope := _cpe_base(cpe)):
        broad.add(("cpe-base", scope))
        exact.update(("cpe", scope, version) for version in versions)
    elif base_purl:
        broad.add(("purl-base", base_purl))
        for version in versions:
            try:
                purl = _package_purl(item, version)
            except ValueError:
                purl = ""
            if purl:
                exact.add(("purl", purl))
    else:
        vendor = str(item.get("vendor", "")).casefold()
        product = str(item.get("product", "")).casefold()
        if vendor and product:
            broad.add(("vp", vendor, product))
            exact.update(("vpv", vendor, product, version) for version in versions)
    return exact, broad


def _row_keys(asset):
    """Exact and product-wide keys for one managed inventory row."""
    exact, broad = set(), set()
    if asset.purl:
        try:
            purl = parse_purl(asset.purl)
        except ValueError:
            return exact, broad
        version = asset.version or purl.version or ""
        base = purl_string(purl._replace(version=None))
        if version:
            exact.add(("purl", purl_string(purl._replace(version=version))))
        else:
            broad.add(("purl-base", base))
    elif asset.cpe:
        scope = _cpe_base(asset.cpe)
        fields = split_cpe23(asset.cpe, keep_escapes=True)
        version = asset.version or (
            fields[3] if len(fields) == 11 and fields[3] not in {"*", "-"} else "")
        if scope:
            if version:
                exact.add(("cpe", scope, version))
            else:
                broad.add(("cpe-base", scope))
    elif asset.vendor and asset.product:
        if asset.version:
            exact.add(("vpv", asset.vendor.casefold(), asset.product.casefold(), asset.version))
        else:
            broad.add(("vp", asset.vendor.casefold(), asset.product.casefold()))
    return exact, broad


class ManagedIndex:
    """Find which rows of a client's managed inventory already cover a detected product."""

    def __init__(self, assets=(), *, require_same_site=False):
        self.ids = {}
        self.keys = {}
        self.broad = {}
        self.require_same_site = require_same_site
        for asset in assets:
            self.ids.setdefault(asset.asset_id.casefold(), asset.asset_id)
            exact, broad = _row_keys(asset)
            site = asset.system_id.casefold() if require_same_site else ""
            for key in exact:
                self.keys.setdefault((site, key), []).append(asset.asset_id)
            # A product-wide row covers only detections observed at its own site.
            for key in broad:
                self.broad.setdefault((asset.system_id.casefold(), key), []).append(asset.asset_id)

    def coverage(self, item):
        """Return (exact, broad) asset IDs that cover a detection item."""
        exact = []
        if asset_id := item.get("asset_id"):
            manual = self.ids.get((asset_id + MANUAL_SUFFIX).casefold())
            if manual:
                exact.append(manual)
        site = (item.get("hostname") or "").casefold() if self.require_same_site else ""
        if self.require_same_site and not site:
            return list(dict.fromkeys(exact)), []
        exact_keys, broad_keys = _identity_keys(item)
        for key in exact_keys:
            exact.extend(self.keys.get((site, key), ()))
        broad = []
        observed_site = (item.get("hostname") or "").casefold()
        for key in broad_keys:
            broad.extend(self.broad.get((observed_site, key), ()))
        return list(dict.fromkeys(exact)), list(dict.fromkeys(broad))

    def covering(self, item):
        exact, broad = self.coverage(item)
        return list(dict.fromkeys((*exact, *broad)))


def classify(item, *, snapshots_on, snapshot_ids, managed):
    """Return (status, asset IDs whose scans cover the product).

    Exact matches take precedence so a version-less row cannot add its wider
    findings to a detection that already has an exact row.
    """
    exact = []
    if snapshots_on and item.get("asset_id") in snapshot_ids:
        exact.append(item["asset_id"])
    managed_exact, broad = managed.coverage(item)
    exact.extend(managed_exact)
    covered = list(dict.fromkeys(exact)) or list(dict.fromkeys(broad))
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
    value = text.strip() if isinstance(text, str) else ""
    if not value:
        return ""
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
