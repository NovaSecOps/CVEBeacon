"""Offline evaluation of the supported Retire.js passive signatures."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from importlib.resources import files
import re
import time
from urllib.parse import unquote, urlsplit

from .webrules import (
    Detection,
    Evidence,
    Page,
    MAX_PAGE_RESOURCES,
    MAX_URLS,
    _bounded_page,
    _deadline_passed,
    _PACKAGE_PRODUCTS,
    normalize_version,
)


_VERSION_CAPTURE = (
    r"(?P<retire_version>\d{1,8}(?:\.\d{1,8}){0,3}"
    r"(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,23})?)"
)
_BACKREFERENCE = re.compile(r"\\[1-9]")
_COMPONENT_NPM_ALIASES = {"ember": "ember-source"}
_REVIEWED_PATTERN_REWRITES = {
    # react-dom's upstream suffix is an open-ended prerelease marker. Bound it
    # while retaining the version string used by the React DOM release build.
    ("react-dom", "filecontent", 0):
        r'version:"(§§version§§)[a-z0-9\-]{0,128}"[\s,]{0,8}rendererPackageName:"react-dom"',
}
_REVIEWED_FILECONTENT_HINTS = {
    "jquery-migrate:filecontent:1": "migrateversion",
    "jquery.prettyPhoto:filecontent:1": "prettyphoto",
    "knockout:filecontent:0": "knockout javascript library",
    "YUI:filecontent:1": "yui/license",
    "prototypejs:filecontent:1": "prototype",
    "ember:filecontent:2": "ember.version",
    "mustache.js:filecontent:2": "mustache.version",
    "mustache.js:filecontent:3": "exports.name",
    "handlebars:filecontent:1": "handlebars",
    "handlebars:filecontent:2": "this.handlebars",
    "handlebars:filecontent:3": "exports.handlebarsenvironment",
    "moment.js:filecontent:1": "moment.js",
    "vue:filecontent:4": "/npm/vue@",
    "lodash:filecontent:4": "@license",
    "pdf.js:filecontent:0": "pdfjsversion",
    "d3:filecontent:0": "d3js.org",
}


@dataclass(frozen=True, slots=True)
class _Signature:
    key: str
    component: str
    vendor: str
    product: str
    name: str
    ecosystem: str
    package: str
    category: str
    extractor: str
    expression: re.Pattern[str] | None = None
    versioned: bool = False
    digest: str = ""
    hash_version: str = ""
    hint: str = ""


def _safe_pattern(pattern: str) -> bool:
    """Reject pathological constructs before compiling or running upstream regexes."""
    if not pattern or len(pattern) > 2048 or _BACKREFERENCE.search(pattern):
        return False
    if pattern.count(".*") + pattern.count(".+") > 1:
        return False
    if re.search(r"\([^()]*[*+?{][^()]*\)(?:[*+?]|\{)", pattern):
        return False
    # A repeated group containing a quantifier or alternative can backtrack
    # exponentially on minified input. Skip those signatures conservatively.
    in_class = False
    escaped = False
    stack: list[bool] = []
    for index, character in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[":
            in_class = True
            continue
        if character == "]" and in_class:
            in_class = False
            continue
        if in_class:
            continue
        if character == "(":
            stack.append(False)
            continue
        if character in "*+" or character == "{":
            if stack:
                stack[-1] = True
            continue
        if character == "|" and stack:
            stack[-1] = True
            continue
        if character == ")" and stack:
            nested = stack.pop()
            next_character = pattern[index + 1:index + 2]
            if nested and next_character in {"*", "+", "{"}:
                return False
            if nested and stack:
                stack[-1] = True
    return not escaped and not in_class


def _has_unbounded_version_gap(pattern: str) -> bool:
    """Return true when a version placeholder is followed by an open-ended repeat."""
    if "§§version§§" not in pattern:
        return False
    suffix = pattern.split("§§version§§", 1)[1]
    in_class = False
    escaped = False
    index = 0
    while index < len(suffix):
        character = suffix[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\":
            escaped = True
        elif character == "[":
            in_class = True
        elif character == "]" and in_class:
            in_class = False
        elif not in_class and character in "*+":
            return True
        elif not in_class and character == "{":
            end = suffix.find("}", index + 1)
            if end >= 0 and re.fullmatch(r"\d+,\s*", suffix[index + 1:end]):
                return True
        index += 1
    return False


def _literal_hint(pattern: str) -> str:
    """Return a mandatory top-level literal for fast resource prefiltering."""
    if "|" in pattern:
        return ""
    output = []
    run = []
    in_class = False
    escaped = False
    depth = 0

    def flush():
        if len(run) > len(output):
            output[:] = run
        run.clear()

    for character in pattern:
        if escaped:
            if character.isalnum():
                flush()
            elif depth == 0:
                run.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
        elif character == "[":
            flush()
            in_class = True
        elif character == "]" and in_class:
            in_class = False
        elif in_class:
            continue
        elif character == "(":
            flush()
            depth += 1
        elif character == ")":
            flush()
            depth = max(0, depth - 1)
        elif depth:
            continue
        elif character in "*?{":
            if run:
                run.pop()
            flush()
        elif character == "+":
            flush()
        elif character in "()*+?{}|.^$":
            flush()
        else:
            run.append(character)
    flush()
    hint = "".join(output).casefold()
    return hint if len(hint) >= 4 else ""


def _package_for(component: str, metadata: dict) -> tuple[str, str, str, str, str]:
    package = metadata.get("npmname", "")
    folded_component = component.casefold()
    base_purl = metadata.get("basePurl", "")
    if (not package and isinstance(base_purl, str) and base_purl.startswith("pkg:npm/")
            and "@" not in base_purl[len("pkg:npm/"):]):
        package = unquote(base_purl[len("pkg:npm/"):])
    if not package:
        package = _COMPONENT_NPM_ALIASES.get(folded_component, folded_component)
        if package not in _PACKAGE_PRODUCTS:
            package = ""
    if not isinstance(package, str) or not re.fullmatch(
            r"(?:@[a-z0-9._~-]+/)?[a-z0-9][a-z0-9._~-]{0,213}", package):
        package = ""
    if package:
        known = _PACKAGE_PRODUCTS.get(package)
        if known:
            vendor, product, name, category = known
            return vendor, product, name, "npm", package
        display = _component_name(component)
        return "npm", package, display, "npm", package
    return "retirejs", component, _component_name(component), "", ""


def _component_name(value: str) -> str:
    known = {
        "retire-example": "Retire Example", "jquery-migrate": "jQuery Migrate",
        "jquery-validation": "jQuery Validation", "jquery-mobile": "jQuery Mobile",
        "jquery-ui-dialog": "jQuery UI Dialog", "jquery-ui-autocomplete": "jQuery UI Autocomplete",
        "jquery-ui-tooltip": "jQuery UI Tooltip", "jquery.prettyphoto": "prettyPhoto",
        "jplayer": "jPlayer", "tinymce": "TinyMCE", "yui": "YUI",
        "angularjs": "AngularJS", "backbone.js": "Backbone.js", "chart.js": "Chart.js",
        "moment.js": "Moment.js", "react-dom": "React DOM", "vue": "Vue.js",
        "alpinejs": "Alpine.js", "datatables": "DataTables", "handlebars": "Handlebars",
    }
    return known.get(value.casefold(), value.replace("_", " ").replace("-", " ").title())


def _compile_pattern(component: str, extractor: str, index: int, pattern: object,
                     metadata: dict) -> _Signature | None:
    if not isinstance(pattern, str):
        return None
    pattern = _REVIEWED_PATTERN_REWRITES.get((component, extractor, index), pattern)
    if (not _safe_pattern(pattern)
            or _has_unbounded_version_gap(pattern)):
        return None
    versioned = "§§version§§" in pattern
    if pattern.count("§§version§§") > 1:
        return None
    expression_text = pattern.replace("§§version§§", _VERSION_CAPTURE)
    try:
        expression = re.compile(expression_text, re.IGNORECASE)
    except (re.error, OverflowError):
        return None
    vendor, product, name, ecosystem, package = _package_for(component, metadata)
    hint = (_literal_hint(expression_text) or
            _REVIEWED_FILECONTENT_HINTS.get(f"{component}:{extractor}:{index}", "")) \
        if extractor == "filecontent" else ""
    return _Signature(
        f"{component}:{extractor}:{index}", component, vendor, product, name,
        ecosystem, package, "js-library", extractor, expression, versioned,
        hint=hint,
    )


def _load_signatures():
    payload = files("cvebeacon_extensions").joinpath(
        "data/retirejs/jsrepository-master.json").read_text(encoding="utf-8")
    data = json.loads(payload)
    signatures: list[_Signature] = []
    skipped_unbounded_version_gaps = 0
    for component, metadata in data.items():
        if not isinstance(metadata, dict):
            continue
        extractors = metadata.get("extractors", {})
        if not isinstance(extractors, dict):
            continue
        for extractor in ("uri", "filename", "filecontent"):
            patterns = extractors.get(extractor, ())
            if isinstance(patterns, str):
                patterns = (patterns,)
            if not isinstance(patterns, (list, tuple)):
                continue
            for index, pattern in enumerate(patterns):
                if isinstance(pattern, str):
                    pattern = _REVIEWED_PATTERN_REWRITES.get(
                        (component, extractor, index), pattern,
                    )
                if isinstance(pattern, str) and _has_unbounded_version_gap(pattern):
                    skipped_unbounded_version_gaps += 1
                    continue
                compiled = _compile_pattern(component, extractor, index, pattern, metadata)
                if compiled:
                    signatures.append(compiled)
        hashes = extractors.get("hashes", {})
        if isinstance(hashes, dict):
            vendor, product, name, ecosystem, package = _package_for(component, metadata)
            for digest, version in hashes.items():
                if (isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{40}", digest)
                        and isinstance(version, str) and normalize_version(version)):
                    signatures.append(_Signature(
                        f"{component}:hashes:{digest}", component, vendor, product, name,
                        ecosystem, package, "js-library", "hashes", None, False,
                        digest.lower(), normalize_version(version),
                    ))
    return tuple(signatures), skipped_unbounded_version_gaps


SIGNATURES, SKIPPED_UNBOUNDED_VERSION_GAPS = _load_signatures()
_FILECONTENT_BY_HINT: dict[str, tuple[_Signature, ...]] = {}
_FILECONTENT_FALLBACK: tuple[_Signature, ...] = ()
_HINTS: tuple[str, ...] = ()
_hint_groups: dict[str, list[_Signature]] = {}
_fallback = []
for _signature in SIGNATURES:
    if _signature.extractor != "filecontent":
        continue
    if _signature.hint:
        _hint_groups.setdefault(_signature.hint, []).append(_signature)
    else:
        _fallback.append(_signature)
_FILECONTENT_BY_HINT = {key: tuple(value) for key, value in _hint_groups.items()}
_FILECONTENT_FALLBACK = tuple(_fallback)
_HINTS = tuple(sorted(_FILECONTENT_BY_HINT, key=lambda value: (-len(value), value)))
_FILECONTENT_HINT_PREFIXES = tuple(sorted({hint[:2] for hint in _HINTS}))
_FILECONTENT_HINT_PATTERN = re.compile(
    "(?=(" + "|".join(re.escape(value) for value in _HINTS) + "))"
) if _HINTS else None
def _matches(signature: _Signature, text: str):
    match = signature.expression.search(text) if signature.expression else None
    if not match or not match.group(0):
        return None
    version = ""
    if signature.versioned:
        try:
            version = normalize_version(match.group("retire_version"))
        except (IndexError, KeyError):
            version = ""
        if signature.package == "react-dom" and version:
            stable = re.fullmatch(r"(\d+(?:\.\d+){0,3})-next-[0-9A-Za-z._-]+", version,
                                  re.IGNORECASE)
            if stable:
                version = stable.group(1)
    return match, version


def _page_urls(page: Page):
    for url in page.urls[:MAX_URLS]:
        yield url, "page"
    for resource in page.resources[:MAX_PAGE_RESOURCES]:
        if resource.url:
            yield resource.url, resource.url


def _filename(value: str) -> str:
    try:
        return unquote(urlsplit(value).path.rsplit("/", 1)[-1])
    except (ValueError, UnicodeError):
        return ""


def _filecontent_candidates(text: str) -> set[_Signature]:
    candidates = set(_FILECONTENT_FALLBACK)
    folded = text.casefold()
    if (_FILECONTENT_HINT_PATTERN is not None and any(
            folded.find(prefix) >= 0 for prefix in _FILECONTENT_HINT_PREFIXES)):
        for match in _FILECONTENT_HINT_PATTERN.finditer(folded):
            candidates.update(_FILECONTENT_BY_HINT.get(match.group(1), ()))
    return candidates


def _append(findings: dict, signature: _Signature, kind: str, source: str,
            excerpt: str, version: str = ""):
    identity = (signature.vendor.casefold(), signature.product.casefold())
    item = findings.setdefault(identity, {
        "vendor": signature.vendor, "product": signature.product,
        "name": signature.name, "ecosystem": signature.ecosystem,
        "package": signature.package, "category": signature.category,
        "versions": set(), "evidence_types": set(), "confidence": "medium",
        "evidence": [], "evidence_keys": set(),
    })
    if version:
        item["versions"].add(version)
    item["evidence_types"].add(kind)
    key = (signature.key, source)
    if key not in item["evidence_keys"] and len(item["evidence"]) < 20:
        item["evidence_keys"].add(key)
        item["evidence"].append(Evidence(kind, source, excerpt[:160]))


def detect(page: Page, *, deadline=None, clock=time.monotonic) -> tuple[Detection, ...]:
    """Evaluate URI, filename, file-content, and SHA-1 extractors offline."""
    if _deadline_passed(deadline, clock):
        return ()
    page = _bounded_page(page)
    if page is None:
        return ()
    findings: dict[tuple[str, str], dict] = {}
    signatures_by_type: dict[str, list[_Signature]] = {}
    for signature in SIGNATURES:
        signatures_by_type.setdefault(signature.extractor, []).append(signature)

    for url, source in _page_urls(page):
        for extractor, value in (("uri", url), ("filename", _filename(url))):
            for signature in signatures_by_type.get(extractor, ()):
                if _deadline_passed(deadline, clock):
                    break
                result = _matches(signature, value)
                if result:
                    match, version = result
                    _append(findings, signature, "url", source, match.group(0), version)

    for resource in page.resources:
        if _deadline_passed(deadline, clock):
            break
        if resource.kind != "script" or not resource.text:
            continue
        candidates = _filecontent_candidates(resource.text)
        for signature in candidates:
            if _deadline_passed(deadline, clock):
                break
            result = _matches(signature, resource.text)
            if result:
                match, version = result
                _append(findings, signature, "script", resource.url,
                        match.group(0), version)
        digest = hashlib.sha1(resource.text.encode("utf-8")).hexdigest()
        for signature in signatures_by_type.get("hashes", ()):
            if _deadline_passed(deadline, clock):
                break
            if digest == signature.digest:
                _append(findings, signature, "script", resource.url, digest,
                        signature.hash_version)

    return tuple(
        Detection(
            item["vendor"], item["product"], item["category"], "",
            item["confidence"], tuple(sorted(item["versions"])),
            tuple(sorted(item["evidence_types"])), item["name"],
            item["ecosystem"], item["package"], (), tuple(item["evidence"]),
        )
        for _, item in sorted(findings.items())
    )
