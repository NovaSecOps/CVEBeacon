"""Conservative OSV evaluation using only declared ecosystem semantics."""

from functools import cmp_to_key

from univers.versions import DebianVersion, MavenVersion, NugetVersion, RpmVersion

from .applicability import Decision, _compare_versions, known_version
from .identity import name_key, parse_purl, package_name, PURL_ECOSYSTEMS
from .models import Applicability as A


def compare(left, right, kind, ecosystem):
    if not isinstance(left, str) or not isinstance(right, str):
        return None
    if kind == "SEMVER":
        if ecosystem == "Go":
            left, right = left.removeprefix("v"), right.removeprefix("v")
        return _compare_versions(left, right, "semver")
    if kind != "ECOSYSTEM":
        return None
    if ecosystem == "PyPI":
        return _compare_versions(left, right, "python")
    if ecosystem in {"npm", "crates.io", "Go"}:
        return compare(left, right, "SEMVER", ecosystem)
    cls = MavenVersion if ecosystem == "Maven" else NugetVersion if ecosystem == "NuGet" else DebianVersion if ecosystem.startswith("Debian:") else RpmVersion if ecosystem.startswith(("AlmaLinux:", "Rocky Linux:", "Red Hat:")) else None
    if cls is None:
        return None
    try:
        a, b = cls(left), cls(right)
        return (a > b) - (a < b)
    except (ValueError, TypeError, AssertionError):
        return None


def range_state(version, value, ecosystem):
    kind, events = value.get("type"), value.get("events")
    if kind not in {"SEMVER", "ECOSYSTEM"} or not isinstance(events, list) or not events:
        return None
    if compare(version, version, kind, ecosystem) is None:
        return None
    parsed = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        key, bound = next(iter(event.items()))
        if key not in {"introduced", "fixed", "last_affected", "limit"} or not isinstance(bound, str):
            return None
        if not (key == "introduced" and bound == "0") and not (key == "limit" and bound == "*") and compare(bound, bound, kind, ecosystem) is None:
            return None
        parsed.append((key, bound))
    keys = {key for key, _ in parsed}
    if "introduced" not in keys or {"fixed", "last_affected"} <= keys:
        return None
    timeline = [(key, bound) for key, bound in parsed if key != "limit"]
    def ordering(a, b):
        if a == b:
            return 0
        if a == ("introduced", "0"):
            return -1
        if b == ("introduced", "0"):
            return 1
        return compare(a[1], b[1], kind, ecosystem)
    # Conflicting events at equivalent boundaries have no safe interpretation.
    for index, event in enumerate(timeline):
        for other in timeline[index + 1:]:
            if event[0] != other[0] and ordering(event, other) == 0:
                return None
    limits = [bound for key, bound in parsed if key == "limit"]
    if limits and not any(bound == "*" or compare(version, bound, kind, ecosystem) == -1 for bound in limits):
        return False
    vulnerable = False
    for key, bound in sorted(timeline, key=cmp_to_key(ordering)):
        comparison = 1 if (key, bound) == ("introduced", "0") else compare(version, bound, kind, ecosystem)
        if key == "introduced" and comparison >= 0:
            vulnerable = True
        elif key == "fixed" and comparison >= 0:
            vulnerable = False
        elif key == "last_affected" and comparison > 0:
            vulnerable = False
    return vulnerable


def evaluate_osv(asset, record, *, commit_match=False):
    if record.get("withdrawn"):
        return Decision(A.NEEDS_REVIEW, "OSV advisory was withdrawn; retained for review")
    if asset.identity_path == "commit":
        matches = [r for item in record.get("affected", []) for r in item.get("ranges", [])
                   if isinstance(r, dict) and r.get("type") == "GIT" and r.get("repo") == asset.repository]
        return Decision(A.AFFECTED if matches and commit_match else A.COVERAGE_UNKNOWN,
                        "OSV exact commit query and repository range match" if matches and commit_match else "exact repository/commit applicability was not established")
    ecosystem, name = asset.ecosystem, asset.product
    if asset.purl:
        purl = parse_purl(asset.purl)
        if purl.qualifiers or purl.subpath or purl.type not in PURL_ECOSYSTEMS:
            return Decision(A.COVERAGE_UNKNOWN, "OSV does not establish this qualified package identity")
        ecosystem, name = PURL_ECOSYSTEMS[purl.type], package_name(purl)
    matches = []
    for item in record.get("affected", []):
        package = item.get("package", {})
        if not isinstance(package, dict):
            return Decision(A.NEEDS_REVIEW, "malformed OSV package identity")
        if package.get("ecosystem") == ecosystem and isinstance(package.get("name"), str) and name_key(ecosystem, package["name"]) == name_key(ecosystem, name):
            matches.append(item)
    if not matches:
        return Decision(A.COVERAGE_UNKNOWN, "OSV record does not establish this exact ecosystem/package identity")
    if not known_version(asset.version):
        return Decision(A.NEEDS_REVIEW, "installed package version is unknown or not exact")
    results = []
    for item in matches:
        versions, ranges = item.get("versions", []), item.get("ranges", [])
        if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions) or not isinstance(ranges, list):
            results.append(None)
            continue
        if asset.version in versions:
            results.append(True)
            continue
        if not ranges:
            # Absence from a list may mean a release is not yet enumerated.
            results.append(None)
            continue
        results.extend(range_state(asset.version, value, ecosystem) if isinstance(value, dict) else None for value in ranges)
    if True in results:
        return Decision(A.AFFECTED, "OSV exact version list or declared package range includes the installed version")
    if not results or None in results:
        return Decision(A.NEEDS_REVIEW, "OSV package identity matches but version evidence cannot safely establish exclusion")
    return Decision(A.NOT_AFFECTED, "all applicable OSV package ranges affirmatively exclude the installed version")
