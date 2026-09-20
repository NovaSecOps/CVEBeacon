"""Explicit component identities, without guessing registry/CPE equivalence."""

from dataclasses import replace
import re
from urllib.parse import unquote, urlsplit

from packaging.utils import canonicalize_name
from packageurl import PackageURL, ValidationSeverity

from .models import Asset
from .sources.nvd import split_cpe23

PURL_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go",
                   "cargo": "crates.io", "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist"}


def parse_purl(value: str) -> PackageURL:
    if re.search(r"%(?![0-9a-fA-F]{2})", value) or any(ord(c) < 32 for c in value):
        raise ValueError("invalid PURL encoding")
    parsed = PackageURL.from_string(value)
    errors = [message for message in parsed.validate() if message.severity == ValidationSeverity.ERROR]
    if errors:
        raise ValueError("invalid PURL type components: " + "; ".join(item.message for item in errors))
    if parsed.type == "npm":
        # packageurl-python 0.17.x still lowercases npm names; the registered
        # type preserves grandfathered mixed-case names. Keep library parsing
        # and encoding, but retain the original name here.
        original = PackageURL.from_string(value, normalize_purl=False)
        parsed = parsed._replace(name=unquote(original.name))
    elif parsed.type == "pypi":
        parsed = parsed._replace(name=canonicalize_name(parsed.name))
    return parsed


def purl_string(value: PackageURL) -> str:
    if value.type == "npm":
        return value._replace(type="generic").to_string().replace("pkg:generic/", "pkg:npm/", 1)
    return value.to_string()


def package_name(value: PackageURL) -> str:
    if value.type == "maven":
        return f"{value.namespace}:{value.name}"
    return "/".join(part for part in (value.namespace, value.name) if part)


def name_key(ecosystem: str, value: str) -> str:
    if ecosystem == "PyPI":
        return canonicalize_name(value)
    if ecosystem == "NuGet":
        return value.casefold()
    return value


def normalize_asset(asset: Asset) -> Asset:
    for name in asset.__dataclass_fields__:
        value = getattr(asset, name)
        if not isinstance(value, str) or any(ord(char) < 32 for char in value):
            raise ValueError(f"{name} must be text without control characters")
    if not asset.asset_id:
        raise ValueError("blank required field: asset_id")
    if asset.purl:
        purl = parse_purl(asset.purl)
        ecosystem = PURL_ECOSYSTEMS.get(purl.type, "")
        if asset.ecosystem and ecosystem and asset.ecosystem != ecosystem:
            raise ValueError("PURL and ecosystem contradict each other")
        if asset.version and purl.version and asset.version != purl.version:
            raise ValueError("PURL and version contradict each other")
        if asset.product and name_key(ecosystem, asset.product) != name_key(ecosystem, package_name(purl)):
            raise ValueError("PURL and package/product contradict each other")
        asset = replace(asset, purl=purl_string(purl), product=asset.product or package_name(purl),
                        ecosystem=asset.ecosystem or ecosystem, version=asset.version or purl.version or "")
    if asset.cpe:
        fields = split_cpe23(asset.cpe)
        if len(fields) != 11 or fields[0] not in {"a", "o", "h"} or any(not x for x in fields):
            raise ValueError("cpe must be a complete CPE 2.3 name")
        if any(x in {"*", "-"} or "*" in x or "?" in x for x in fields[1:3]):
            raise ValueError("explicit cpe must identify a vendor and product")
        if fields[3] not in {"*", "-"} and asset.version and fields[3] != asset.version:
            raise ValueError("CPE and version contradict each other")
        asset = replace(asset, vendor=asset.vendor or fields[1], product=asset.product or fields[2],
                        version=asset.version or (fields[3] if fields[3] not in {"*", "-"} else ""))
    if asset.repository:
        url = urlsplit(asset.repository)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("repository must be an HTTPS URL without credentials, query or fragment")
    if asset.commit:
        if not asset.repository or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", asset.commit):
            raise ValueError("commit requires repository and an exact full-length Git hash")
        asset = replace(asset, commit=asset.commit.lower())
    required = ("vendor", "product", "version") if asset.identity_path == "product" else ("product", "version") if asset.identity_path == "ecosystem" else ()
    for name in required:
        if not getattr(asset, name):
            raise ValueError(f"blank required field: {name}")
    return asset


def identity_conflict(asset: Asset) -> bool:
    # Similar strings are not evidence that different identity systems refer to
    # the same component. Require review until a source establishes equivalence.
    return bool((asset.cpe and (asset.purl or asset.ecosystem)) or
                (asset.commit and (asset.purl or asset.cpe or asset.ecosystem)))
