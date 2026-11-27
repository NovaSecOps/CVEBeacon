"""Direct-evidence rules for passive web technology detection.

Rules maintained here are written from public product documentation and
published banners. Retire.js signatures are bundled separately under
Apache-2.0 with attribution in the Extensions NOTICE.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import lru_cache
import hashlib
from itertools import islice
import re
import time
from typing import Iterable, Mapping
from urllib.parse import quote, unquote, urlsplit

from cvebeacon.identity import normalize_asset
from cvebeacon.models import Asset
from cvebeacon.sources.nvd import split_cpe23
from cvebeacon.web_inventory import (REVIEWED_ALIASES, valid_npm_name as _npm_name,
                                    web_cpe_fields as _cpe_fields, web_cpe_scope as _cpe_scope,
                                    web_product_key)

CATEGORIES = {
    "web-server",
    "application-server",
    "language",
    "framework",
    "cms",
    "js-library",
    "css-library",
    "edge",
    "ops-tool",
    "hosted-platform",
    "application",
    "reverse-proxy",
    "analytics",
}

MAX_GENERATORS = 4096
MAX_URLS = 16384
MAX_CDN_DETECTIONS = 128
MAX_ANALYSIS_TEXT = 4 * 1_048_576
MAX_RESOURCE_TEXT = 10 * 1_048_576
MAX_PAGE_RESOURCES = 512
MAX_TOTAL_RESOURCE_TEXT = 32 * 1_048_576
MAX_DETECTION_TEXT = 8192
MAX_DETECTION_NAME = 256
MAX_VERSION_CAPTURE_LENGTH = 64
MAX_EVIDENCE_EXCERPT_LENGTH = 160

SENSITIVE_HEADERS = frozenset({"set-cookie", "cookie", "authorization", "proxy-authorization"})

EVIDENCE_KINDS = frozenset({
    "header", "cookie", "meta", "url", "html", "script", "style", "manifest",
    "robots", "icon", "implied", "dom", "text",
})


@dataclass(frozen=True, slots=True)
class Rule:
    key: str
    vendor: str
    product: str
    category: str
    kind: str  # header | cookie | meta | url | html | script | style
    pattern: str
    subject: str = ""  # header name for kind == "header"
    version_pattern: str = ""
    cpe: str = ""
    confidence: str = "medium"
    name: str = ""
    ecosystem: str = ""
    package: str = ""
    hint: str = ""
    version_group: int = 1
    categories: tuple[str, ...] = ()
    # A version the rule itself defines, for example "GA4"; used when the pattern matches.
    fixed_version: str = ""


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    source: str
    excerpt: str


@dataclass(frozen=True, slots=True)
class Detection:
    vendor: str
    product: str
    category: str
    cpe: str
    confidence: str
    versions: tuple[str, ...]
    evidence_types: tuple[str, ...] = ()
    # Human-facing product name, for example "Google Font API". Empty means
    # vendor/product is shown.
    name: str = ""
    # Package identity for package-manager libraries (for example "npm" and
    # "core-js"); when set with a version, the inventory row uses a PURL.
    ecosystem: str = ""
    package: str = ""
    # Keys of the detections that imply this one. An implied-only detection is
    # listed for people to read and never becomes an inventory row.
    implied_by: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    # External fingerprints without a CPE use the name to generate vendor and
    # product slugs for display. The slugs are not independent identity evidence.
    name_only: bool = False
    categories: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.categories, tuple):
            return
        categories = tuple(dict.fromkeys((self.category, *self.categories)))
        object.__setattr__(self, "categories", categories)


@dataclass(frozen=True, slots=True)
class Resource:
    """A page-referenced resource the fetcher read or hashed."""
    url: str
    kind: str  # script | style | manifest | robots | icon
    text: str


def package_identity(ecosystem: str, package: str, version: str = "") -> str:
    """Return a PURL for a supported package, with or without a version."""
    if ecosystem != "npm" or not package:
        return ""
    namespace, _, name = package.rpartition("/")
    path = (quote(namespace, safe="") + "/" if namespace else "") + quote(name, safe="")
    return f"pkg:npm/{path}" + (f"@{quote(version, safe='')}" if version else "")


def package_url(ecosystem: str, package: str, version: str) -> str:
    """Return a PURL for a supported package ecosystem, or an empty string."""
    if not version:
        return ""
    return package_identity(ecosystem, package, version)


_VERSION_BODY = r"\d+(?:\.\d+){0,3}"
# Dot, hyphen or underscore separated identifiers. A separator followed by a
# file-name token (".min.js", "-slim.css") ends the qualifier, so a URL's file
# suffix never becomes part of the version.
_FILE_TOKEN = r"(?:min|slim|bundle|umd|esm|js|mjs|css|map)(?![0-9A-Za-z])"
_VERSION_QUALIFIER = rf"[0-9A-Za-z]+(?:[._-](?!{_FILE_TOKEN})[0-9A-Za-z]+)*"
_VERSION_SUFFIX = (
    rf"(?:[-+]{_VERSION_QUALIFIER}"
    r"|\.(?:alpha|beta|rc|cr|preview|snapshot)\d*"
    r"|\.m\d+)?"
)
_VERSION = re.compile(_VERSION_BODY + _VERSION_SUFFIX, re.IGNORECASE)
_REJECTED_VERSIONS = {"", "*", "-", "unknown", "latest", "n/a", "na", "all", "none"}
_PREFIX = re.compile(r"^(?:v(?=\d)|[A-Za-z][A-Za-z._!-]*(?: [A-Za-z][A-Za-z._!-]*)*[ /](?=\d))")


def _versioned(pattern: str) -> str:
    """Allow a pre-release or build suffix wherever a version is matched."""
    return pattern.replace(_VERSION_BODY, _VERSION_BODY + _VERSION_SUFFIX)


def normalize_version(value: object) -> str:
    """Return a conservative exact version, or an empty string."""
    if not isinstance(value, str) or len(value) > MAX_VERSION_CAPTURE_LENGTH:
        return ""
    text = value.strip()
    if not text:
        return ""
    text = re.sub(r"\s*\([^)]*\)\s*$", "", text).strip()
    if text.casefold() in _REJECTED_VERSIONS:
        return ""
    if any(character in text for character in "<>=~^*,"):
        return ""
    prefix = _PREFIX.match(text)
    if prefix and prefix.end() and re.match(r"\d", text[prefix.end():]):
        text = text[prefix.end():]
    match = _VERSION.fullmatch(text)
    return match.group(0) if match else ""


def _captured_version(match: re.Match[str], group: int | str) -> str:
    try:
        start, end = match.span(group)
    except IndexError:
        return ""
    if start < 0 or end - start > MAX_VERSION_CAPTURE_LENGTH:
        return ""
    return normalize_version(match.string[start:end])


def _validated_cpe(value: str) -> str:
    if not value:
        return ""
    fields = split_cpe23(value)
    if (
        len(fields) != 11
        or fields[0] not in {"a", "o", "h"}
        or any(not field for field in fields)
        or fields[1] in {"*", "-"}
        or fields[2] in {"*", "-"}
        or fields[3] != "*"
    ):
        raise ValueError(f"rule CPE is not a complete versionless CPE 2.3 name: {value}")
    # Reuse the core parser and identity rules so a rule cannot ship a CPE that
    # the inventory contract would reject.
    normalize_asset(Asset(asset_id="rule-probe", cpe=value))
    return value


def _rule(key, vendor, product, category, kind, pattern, *, subject="", version="", cpe="",
          confidence="medium", name="", ecosystem="", package="", hint="", version_group=1,
          categories=(), fixed_version=""):
    if category not in CATEGORIES:
        raise ValueError(f"unknown rule category: {category}")
    if kind not in {"header", "cookie", "meta", "url", "html", "script", "style", "manifest", "robots"}:
        raise ValueError(f"unknown evidence kind: {kind}")
    if kind == "header" and not subject:
        raise ValueError(f"header rule {key} has no header name")
    if confidence not in {"high", "medium", "low"}:
        raise ValueError(f"unknown confidence: {confidence}")
    if type(version_group) is not int or version_group < 1:
        raise ValueError(f"rule {key} has an invalid version capture group")
    if not isinstance(categories, (tuple, list)) or any(
            not isinstance(item, str) or item not in CATEGORIES for item in categories):
        raise ValueError(f"rule {key} has invalid categories")
    if (ecosystem or package) and (ecosystem != "npm" or not package):
        raise ValueError(f"rule {key} has an invalid package identity")
    if fixed_version and (not isinstance(fixed_version, str)
                          or not re.fullmatch(r"[A-Za-z0-9]{1,16}", fixed_version)):
        raise ValueError(f"rule {key} has an invalid fixed version")
    pattern = _versioned(pattern)
    if version:
        version = _versioned(version)
    # Compile at import time so a malformed reviewed rule fails closed.
    re.compile(pattern, re.IGNORECASE)
    if version:
        re.compile(version, re.IGNORECASE)
    if package:
        cpe = ""
    all_categories = tuple(dict.fromkeys((category, *categories)))
    return Rule(key, vendor, product, category, kind, pattern, subject.casefold(), version,
                _validated_cpe(cpe), confidence, name, ecosystem, package, hint.casefold(),
                version_group, all_categories, fixed_version)


RULES: tuple[Rule, ...] = (
    # Web and application servers.
    _rule("nginx", "nginx", "nginx", "web-server", "header", r"^nginx(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)",
          subject="server", version=r"nginx/(\d+(?:\.\d+){0,3})(?!\d|\.\d)", confidence="high",
          categories=("reverse-proxy",)),
    _rule("apache-http-server", "apache", "http_server", "web-server", "header",
          r"^apache(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"apache/(\d+(?:\.\d+){0,3})(?!\d|\.\d)", cpe="cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("microsoft-iis", "microsoft", "internet_information_services", "web-server", "header",
          r"^microsoft-iis(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"microsoft-iis/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("litespeed", "litespeedtech", "litespeed_web_server", "web-server", "header",
          r"^litespeed(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"litespeed/(\d+(?:\.\d+){0,3})(?!\d|\.\d)", confidence="high"),
    _rule("openresty", "openresty", "openresty", "web-server", "header",
          r"^openresty(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"openresty/(\d+(?:\.\d+){0,3})(?!\d|\.\d)", confidence="high"),
    _rule("caddy", "caddyserver", "caddy", "web-server", "header",
          r"^caddy(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"caddy/(\d+(?:\.\d+){0,3})(?!\d|\.\d)", confidence="high"),
    _rule("apache-tomcat", "apache", "tomcat", "application-server", "header",
          r"^apache-coyote(?:/\d+(?:\.\d+){0,3})?(?:\s|$)", subject="server",
          cpe="cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", confidence="medium"),
    _rule("jetty", "eclipse", "jetty", "application-server", "header",
          r"^jetty(?:\((\d+(?:\.\d+){0,3})[^)]*\))?", subject="server",
          version=r"jetty\((\d+(?:\.\d+){0,3})(?!\d|\.\d)", cpe="cpe:2.3:a:eclipse:jetty:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("wildfly", "redhat", "wildfly", "application-server", "header",
          r"^wildfly(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$|[.+-])", subject="server",
          version=r"wildfly/(\d+(?:\.\d+){0,3})(?!\d|\.\d)", confidence="high"),
    _rule("weblogic", "oracle", "weblogic_server", "application-server", "header",
          r"^weblogic(?: server)?(?:[/ ](\d+(?:\.\d+){0,3}))?(?:\s|$|[.+-])", subject="server",
          version=r"weblogic(?: server)?[/ ](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*", confidence="medium"),
    _rule("websphere", "ibm", "websphere_application_server", "application-server", "header",
          r"^websphere application server(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"websphere application server/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:ibm:websphere_application_server:*:*:*:*:*:*:*:*", confidence="medium"),
    _rule("glassfish", "oracle", "glassfish_server", "application-server", "header",
          r"^glassfish(?: server(?: open source edition)?)?(?:[/ ](\d+(?:\.\d+){0,3}))?(?:\s|$)",
          subject="server", version=r"glassfish(?: server(?: open source edition)?)?[/ ](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:oracle:glassfish_server:*:*:*:*:*:*:*:*", confidence="medium"),

    # Languages and frameworks.
    _rule("php-header", "php", "php", "language", "header",
          r"^php(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="x-powered-by",
          version=r"php/(\d+(?:\.\d+){0,3})(?!\d|\.\d)", cpe="cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("php-session", "php", "php", "language", "cookie", r"^phpsessid$", confidence="medium"),
    _rule("aspnet-version", "microsoft", "asp.net", "framework", "header",
          r"^(\d+(?:\.\d+){0,3})(?:\s|$)", subject="x-aspnet-version",
          version=r"^(\d+(?:\.\d+){0,3})(?!\d|\.\d)", confidence="high"),
    _rule("aspnet-powered-by", "microsoft", "asp.net", "framework", "header",
          r"^asp\.net$", subject="x-powered-by", confidence="medium"),
    _rule("express", "expressjs", "express", "framework", "header", r"^express$",
          subject="x-powered-by", cpe="cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("laravel", "laravel", "laravel", "framework", "cookie", r"^laravel_session$",
          cpe="cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("nextjs", "vercel", "next.js", "framework", "html", r"__next_data__",
          cpe="cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("nuxt", "nuxt", "nuxt", "framework", "html", r"__nuxt(?:__)?", confidence="medium"),
    _rule("react", "facebook", "react", "js-library", "url",
          r"(?:^|/)react(?:-dom)?(?:@[^/]+)?(?:\.production)?(?:\.min)?\.js(?:\?|$)",
          version=r"react(?:-dom)?@(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("angular", "angular", "angular", "js-library", "html",
          r"ng-version=[\"'](\d+(?:\.\d+){0,3})",
          version=r"ng-version=[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:angular:angular:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("vue", "vuejs", "vue.js", "js-library", "url",
          r"(?:^|/)vue(?:@[^/]+)?(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js(?:\?|$)",
          version=r"vue@(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:vuejs:vue.js:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("svelte", "svelte", "svelte", "js-library", "url",
          r"(?:^|/)svelte(?:@[^/]+)?(?:\.min)?\.js(?:\?|$)",
          version=r"svelte@(\d+(?:\.\d+){0,3})(?!\d|\.\d)", confidence="medium"),
    _rule("jquery", "jquery", "jquery", "js-library", "url",
          r"(?:^|/)jquery(?:[-.]\d+(?:\.\d+){0,3})?(?:\.min)?\.js(?:\?|$)",
          version=r"jquery[-.](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("bootstrap", "getbootstrap", "bootstrap", "js-library", "url",
          r"(?:^|/)bootstrap(?:[.-]\d+(?:\.\d+){0,3})?(?:\.min)?\.(?:css|js)(?:\?|$)",
          version=r"bootstrap[.-](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*", confidence="high"),

    # Content management and hosted platforms.
    _rule("wordpress", "wordpress", "wordpress", "cms", "meta", r"^wordpress\b",
          version=r"wordpress\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("drupal", "drupal", "drupal", "cms", "meta", r"^drupal\b",
          version=r"drupal\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)", cpe="cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("joomla", "joomla", "joomla", "cms", "meta", r"^joomla!?\b",
          version=r"joomla!?\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)", confidence="high"),
    _rule("magento", "adobe", "magento", "cms", "header", r".+", subject="x-magento-tags",
          confidence="high"),
    _rule("prestashop", "prestashop", "prestashop", "cms", "meta", r"^prestashop\b",
          version=r"prestashop\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:prestashop:prestashop:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("shopify", "shopify", "shopify", "hosted-platform", "header", r"^\d+$",
          subject="x-shopid", confidence="high"),
    _rule("ghost", "ghost", "ghost", "cms", "meta", r"^ghost\b",
          version=r"ghost\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:ghost:ghost:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("typo3", "typo3", "typo3", "cms", "meta", r"^typo3\b",
          version=r"typo3(?:\s+cms)?\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:typo3:typo3:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("umbraco", "umbraco", "umbraco", "cms", "cookie", r"^umb-xsrf-token$",
          confidence="high"),
    _rule("sitecore", "sitecore", "sitecore_experience_platform", "cms", "cookie",
          r"^sc_analytics_global_cookie$", confidence="high"),
    _rule("adobe-experience-manager", "adobe", "experience_manager", "cms", "html",
          r"(?:^|/)etc\.clientlibs/",
          cpe="cpe:2.3:a:adobe:experience_manager:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("sharepoint", "microsoft", "sharepoint_server", "cms", "header", r"^\d+(?:\.\d+){0,3}$",
          subject="microsoftsharepointteamservices",
          cpe="cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*", confidence="high"),

    # Edge and hosted front ends. These are never attributed to the origin.
    _rule("cloudflare", "cloudflare", "cloudflare", "edge", "header", r"^[0-9a-f]+-[a-z]+$",
          subject="cf-ray", confidence="high"),
    _rule("akamai", "akamai", "akamai_ghost", "edge", "header", r"^akamaighost(?:/\d+(?:\.\d+){0,3})?$",
          subject="server", confidence="high"),
    _rule("fastly", "fastly", "fastly", "edge", "header", r"^[A-Za-z0-9-]{8,}$",
          subject="x-fastly-request-id", confidence="high"),
    _rule("f5-big-ip", "f5", "big-ip", "edge", "cookie", r"^bigipserver", confidence="high"),
    _rule("citrix-netscaler", "citrix", "netscaler_application_delivery_controller", "edge",
          "cookie", r"^nsc_", confidence="high"),

    # Operations tools.
    _rule("confluence", "atlassian", "confluence", "application", "html",
          r"ajs-product-name[\s\S]{0,200}?[\"']confluence[\"']",
          version=r"ajs-version-number[\s\S]{0,100}?content=[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          confidence="medium"),
    _rule("jira", "atlassian", "jira", "application", "html",
          r"ajs-product-name[\s\S]{0,200}?[\"']jira[\"']",
          version=r"ajs-version-number[\s\S]{0,100}?content=[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          confidence="medium"),
    _rule("elasticsearch", "elastic", "elasticsearch", "ops-tool", "header",
          r"^elasticsearch$", subject="x-elastic-product",
          cpe="cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("kibana", "elastic", "kibana", "ops-tool", "header",
          r"^(\d+(?:\.\d+){0,3})(?:\s|$)", subject="kbn-version",
          version=r"^(\d+(?:\.\d+){0,3})(?!\d|\.\d)", cpe="cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("grafana", "grafana", "grafana", "ops-tool", "cookie", r"^grafana_session",
          cpe="cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("jenkins", "jenkins", "jenkins", "ops-tool", "header",
          r"^(\d+(?:\.\d+){0,3})(?:\s|$)", subject="x-jenkins",
          version=r"^(\d+(?:\.\d+){0,3})(?!\d|\.\d)", cpe="cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("gitlab", "gitlab", "gitlab", "ops-tool", "cookie", r"^_gitlab_session$",
          cpe="cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("phpmyadmin", "phpmyadmin", "phpmyadmin", "ops-tool", "cookie", r"^phpmyadmin$",
          cpe="cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("cpanel", "cpanel", "cpanel", "ops-tool", "header",
          r"^cpsrvd(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"cpsrvd/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:cpanel:cpanel:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("plesk", "plesk", "plesk", "ops-tool", "header",
          r"^(?:sw-cp-server|plesk)(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"(?:sw-cp-server|plesk)/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:plesk:plesk:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("webmin", "webmin", "webmin", "ops-tool", "header",
          r"^miniserv(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"miniserv/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          cpe="cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*", confidence="high"),
)


_EXISTING_IDENTITIES = {
    "php-header": ("PHP", "", ""),
    "php-session": ("PHP", "", ""),
    "express": ("Express", "npm", "express"),
    "laravel": ("Laravel", "", ""),
    "nextjs": ("Next.js", "npm", "next"),
    "nuxt": ("Nuxt", "npm", "nuxt"),
    "react": ("React", "npm", "react"),
    "angular": ("Angular", "npm", "@angular/core"),
    "vue": ("Vue.js", "npm", "vue"),
    "svelte": ("Svelte", "npm", "svelte"),
    "jquery": ("jQuery", "npm", "jquery"),
    "bootstrap": ("Bootstrap", "npm", "bootstrap"),
    "wordpress": ("WordPress", "", ""),
    "drupal": ("Drupal", "", ""),
    "joomla": ("Joomla", "", ""),
    "magento": ("Magento", "", ""),
    "prestashop": ("PrestaShop", "", ""),
    "typo3": ("TYPO3", "", ""),
    "phpmyadmin": ("phpMyAdmin", "", ""),
}
RULES = tuple(
    replace(rule, name=name, ecosystem=ecosystem, package=package,
            cpe="" if package else rule.cpe)
    for rule in RULES if rule.key in _EXISTING_IDENTITIES
    for name, ecosystem, package in (_EXISTING_IDENTITIES[rule.key],)
) + tuple(rule for rule in RULES if rule.key not in _EXISTING_IDENTITIES)


_BACKBONE_VERSION = (
    r"(?:\bBackbone\.VERSION|\bvar\s+[\w$]+\s*=\s*[\w$]+\.Backbone\s*;\s*"
    r"var\s+[\w$]+\s*=\s*Array\.prototype\.slice\s*;\s*[\w$]+\.VERSION)"
    r"\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)"
)
_UNDERSCORE_VERSION = (
    r"Underscore\.js\s+v?(\d+(?:\.\d+){0,3})(?!\d|\.\d)"
    r"[\s\S]{0,120}?https://underscorejs\.org"
)
_LODASH_MIN_VERSION = (
    r"=\s*[\"'](\d+(?:\.\d+){0,3})[\"']\s*,\s*[\w$]+\s*=\s*200\s*,"
    r"\s*[\w$]+\s*=\s*[\"']Unsupported core-js use\."
)


EXPANDED_RULES: tuple[Rule, ...] = (
    # Product banners and attributes published by front-end libraries.
    _rule("expanded-angular-core", "angular", "angular", "js-library", "script",
          r"@angular/core@(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"@angular/core@(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Angular", ecosystem="npm", package="@angular/core", confidence="high", hint="@angular/core@"),
    _rule("expanded-angularjs-markup", "angular", "angularjs", "js-library", "html",
          r"\bng-(?:app|controller|repeat|view|model|bind|init)\b",
          name="AngularJS", ecosystem="npm", package="angular", confidence="high"),
    _rule("expanded-angularjs-script", "angular", "angularjs", "js-library", "script",
          r"AngularJS\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"AngularJS\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="AngularJS", ecosystem="npm", package="angular", confidence="high", hint="angularjs"),
    _rule("expanded-gatsby-markup", "gatsbyjs", "gatsby", "framework", "html",
          r"(?:id=[\"']___gatsby[\"']|window\.___gatsby)",
          name="Gatsby", ecosystem="npm", package="gatsby", confidence="high"),
    _rule("expanded-react-script", "facebook", "react", "js-library", "script",
          r"(?:@license\s+React\s+v\d+(?:\.\d+){0,3}(?!\d|\.\d)|@license\s+React\s*\n[\s\S]{0,160}?react\.production\.min\.js|react\.production\.min\.js[\s\S]{0,16384}?\.version\s*=\s*[\"']\d+(?:\.\d+){0,3}(?!\d|\.\d))",
          version=r"(?:@license\s+React\s+v|react\.production\.min\.js[\s\S]{0,16384}?\.version\s*=\s*[\"'])(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="React", ecosystem="npm", package="react", confidence="high", hint="@license react"),
    _rule("expanded-react-markup", "facebook", "react", "js-library", "html",
          r"\bdata-react(?:root|id)\s*=",
          name="React", ecosystem="npm", package="react", confidence="high"),
    _rule("expanded-vue-script", "vuejs", "vue.js", "js-library", "script",
          r"Vue(?:\.js)?\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Vue(?:\.js)?\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Vue.js", ecosystem="npm", package="vue", confidence="high", hint="vue"),
    _rule("expanded-vue-markup", "vuejs", "vue.js", "js-library", "html",
          r"(?:\bdata-v-app\s*=|\bv-cloak\b)",
          name="Vue.js", ecosystem="npm", package="vue", confidence="high"),
    _rule("expanded-ember-script", "emberjs", "ember", "js-library", "script",
          r"Ember\.VERSION\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Ember\.VERSION\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Ember", ecosystem="npm", package="ember-source", confidence="high", hint="ember.version"),
    _rule("expanded-ember-markup", "emberjs", "ember", "js-library", "html",
          r"\bember-view\b", name="Ember", ecosystem="npm", package="ember-source", confidence="medium"),
    _rule("expanded-backbone-script", "backbonejs", "backbone", "js-library", "script",
          _BACKBONE_VERSION, version=_BACKBONE_VERSION,
          name="Backbone.js", ecosystem="npm", package="backbone", confidence="high", hint="backbone"),
    _rule("expanded-alpine-markup", "alpinejs", "alpinejs", "js-library", "html",
          r"(?:^|\s)x-(?:data|init|show|bind|on|model|for|if|ref|text|html|transition)\s*=",
          name="Alpine.js", ecosystem="npm", package="alpinejs", confidence="high"),
    _rule("expanded-alpine-script", "alpinejs", "alpinejs", "js-library", "script",
          r"Alpine\.version\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Alpine\.version\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Alpine.js", ecosystem="npm", package="alpinejs", confidence="high", hint="alpine.version"),
    _rule("expanded-htmx-markup", "bigskysoftware", "htmx", "js-library", "html",
          r"(?:^|\s)hx-(?:get|post|put|patch|delete|trigger|target|swap|boost)\s*=",
          name="htmx", ecosystem="npm", package="htmx.org", confidence="high"),
    _rule("expanded-htmx-script", "bigskysoftware", "htmx", "js-library", "script",
          r"(?:htmx\.version\s*=\s*[\"']\d|\bvar\s+htmx\s*=\s*function\(|\bvar\s+htmx\s*=\s*function\(\)[\s\S]{0,8192}?\bversion\s*:\s*[\"']\d)",
          version=r"(?:htmx\.version\s*=\s*[\"']|\bvar\s+htmx\s*=\s*function\(\)[\s\S]{0,8192}?\bversion\s*:\s*[\"'])(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="htmx", ecosystem="npm", package="htmx.org", confidence="high", hint="htmx"),
    _rule("expanded-jquery-script", "jquery", "jquery", "js-library", "script",
          r"jQuery\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)\s+\|",
          version=r"jQuery\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)\s+\|",
          name="jQuery", ecosystem="npm", package="jquery", confidence="high", hint="jquery"),
    _rule("expanded-jquery-ui-script", "jquery", "jquery-ui", "js-library", "script",
          r"jQuery\s+UI\s+-\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"jQuery\s+UI\s+-\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="jQuery UI", ecosystem="npm", package="jquery-ui", confidence="high", hint="jquery ui"),
    _rule("expanded-jquery-migrate-script", "jquery", "jquery-migrate", "js-library", "script",
          r"JQMIGRATE:\s+Migrate is installed, version\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"JQMIGRATE:\s+Migrate is installed, version\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="jQuery Migrate", ecosystem="npm", package="jquery-migrate", confidence="high", hint="jqmigrate:"),
    _rule("expanded-lodash-script", "lodash", "lodash", "js-library", "script",
          r"(?:\blodash\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)|Lodash\s+lodash\.com/license)",
          version=r"\blodash\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Lodash", ecosystem="npm", package="lodash", confidence="high", hint="lodash"),
    _rule("expanded-lodash-minified", "lodash", "lodash", "js-library", "script",
          _LODASH_MIN_VERSION, version=_LODASH_MIN_VERSION,
          name="Lodash", ecosystem="npm", package="lodash", confidence="high", hint="unsupported core-js use"),
    _rule("expanded-underscore-script", "underscorejs", "underscore", "js-library", "script",
          _UNDERSCORE_VERSION, version=_UNDERSCORE_VERSION,
          name="Underscore.js", ecosystem="npm", package="underscore", confidence="high", hint="underscore"),
    _rule("expanded-moment-script", "momentjs", "moment", "js-library", "script",
          r"moment\.js\s+version\s*:\s*(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"moment\.js\s+version\s*:\s*(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Moment.js", ecosystem="npm", package="moment", confidence="high", hint="moment.js version"),
    _rule("expanded-axios-script", "axios", "axios", "js-library", "script",
          r"Axios\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Axios\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Axios", ecosystem="npm", package="axios", confidence="high", hint="axios"),
    _rule("expanded-chartjs-script", "chartjs", "chart.js", "js-library", "script",
          r"Chart\.js\b",
          version=r"Chart\.js\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Chart.js", ecosystem="npm", package="chart.js", confidence="high", hint="chart.js"),
    _rule("expanded-d3-script", "d3js", "d3", "js-library", "script",
          r"d3\.version\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"d3\.version\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="D3", ecosystem="npm", package="d3", confidence="high", hint="d3.version"),
    _rule("expanded-swiper-script", "swiperjs", "swiper", "js-library", "script",
          r"Swiper\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Swiper\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Swiper", ecosystem="npm", package="swiper", confidence="high", hint="swiper"),
    _rule("expanded-select2-script", "select2", "select2", "js-library", "script",
          r"Select2\s+(\d+(?:\.\d+){0,3}(?:-(?:alpha|beta|rc)\.?\d+)?)",
          version=r"Select2\s+(\d+(?:\.\d+){0,3}(?:-(?:alpha|beta|rc)\.?\d+)?)(?!\d|\.\d)",
          name="Select2", ecosystem="npm", package="select2", confidence="high", hint="select2"),
    _rule("expanded-datatables-script", "datatables", "datatables.net", "js-library", "script",
          r"DataTables\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"DataTables\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="DataTables", ecosystem="npm", package="datatables.net", confidence="high", hint="datatables"),
    _rule("expanded-modernizr-script", "modernizr", "modernizr", "js-library", "script",
          r"Modernizr\._version\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Modernizr\._version\s*=\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Modernizr", ecosystem="npm", package="modernizr", confidence="high", hint="modernizr._version"),
    _rule("expanded-requirejs-script", "requirejs", "requirejs", "js-library", "script",
          r"RequireJS\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"RequireJS\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="RequireJS", ecosystem="npm", package="requirejs", confidence="high", hint="requirejs"),
    _rule("expanded-handlebars-script", "handlebarsjs", "handlebars", "js-library", "script",
          r"(?:handlebars\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)|Handlebars\.VERSION\s*=\s*[\"']\d)",
          version=r"(?:handlebars\s+v|Handlebars\.VERSION\s*=\s*[\"'])(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Handlebars", ecosystem="npm", package="handlebars", confidence="high", hint="handlebars"),
    _rule("expanded-rxjs-script", "reactivex", "rxjs", "js-library", "script",
          r"\brxjs@(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"\brxjs@(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="RxJS", ecosystem="npm", package="rxjs", confidence="high", hint="rxjs@"),
    _rule("expanded-rxjs-runtime", "reactivex", "rxjs", "js-library", "script",
          r"""["']ObjectUnsubscribedError["']\s*[,;]\s*this\.message\s*=\s*["']object unsubscribed["']""",
          name="RxJS", ecosystem="npm", package="rxjs", confidence="high", hint="objectunsubscribederror"),
    _rule("expanded-core-js", "core-js", "core-js", "js-library", "script",
          r"__core-js_shared__[\s\S]{0,160}?\.push\(\{\s*version\s*:\s*[\"']\d+(?:\.\d+){0,3}[^}]{0,256}?copyright\s*:\s*[\"']",
          version=r"__core-js_shared__[\s\S]{0,160}?\.push\(\{\s*version\s*:\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)[^}]{0,256}?copyright\s*:\s*[\"']",
          name="core-js", ecosystem="npm", package="core-js", confidence="high", hint="core-js"),
    _rule("expanded-core-js-shared-record", "core-js", "core-js", "js-library", "script",
          r"\.push\(\s*\{\s*version\s*:\s*[\"']\d+\.\d+\.\d+[\"']\s*,\s*mode\s*:[^}]{0,200}?"
          r"copyright\s*:\s*[\"'][^\"'\n]{0,120}?(?:Pushkarev|zloirock)",
          version=r"\.push\(\s*\{\s*version\s*:\s*[\"'](\d+\.\d+\.\d+)[\"']\s*,\s*mode\s*:[^}]{0,200}?"
          r"copyright\s*:\s*[\"'][^\"'\n]{0,120}?(?:Pushkarev|zloirock)",
          name="core-js", ecosystem="npm", package="core-js", confidence="high"),
    _rule("expanded-core-js-2-core", "core-js", "core-js", "js-library", "script",
          r"\{\s*version\s*:\s*[\"']2\.\d+\.\d+[\"']\s*\}\s*;\s*(?:[\"']number[\"']\s*==\s*typeof\s+__e\b"
          r"|if\s*\(\s*typeof\s+__e\s*==\s*[\"']number[\"'])",
          version=r"\{\s*version\s*:\s*[\"'](2\.\d+\.\d+)[\"']\s*\}\s*;\s*(?:[\"']number[\"']\s*==\s*typeof\s+__e\b"
          r"|if\s*\(\s*typeof\s+__e\s*==\s*[\"']number[\"'])",
          name="core-js", ecosystem="npm", package="core-js", confidence="high", hint="__e"),
    _rule("expanded-core-js-shared-store", "core-js", "core-js", "js-library", "script",
          r"\.push\(\{\s*version\s*:\s*[\"']\d+(?:\.\d+){0,3}(?!\d|\.\d)[^}]{0,256}?copyright\s*:\s*[\"'][\s\S]{0,4096}?__core-js_shared__",
          version=r"\.push\(\{\s*version\s*:\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)[^}]{0,256}?copyright\s*:\s*[\"'][\s\S]{0,4096}?__core-js_shared__",
          name="core-js", ecosystem="npm", package="core-js", confidence="high", hint="core-js"),
    _rule("expanded-lit-html", "lit", "lit-html", "js-library", "script",
          r"\blitHtmlVersions\b[\s\S]{0,96}?\.push\(\s*[\"']\d+(?:\.\d+){0,3}(?!\d|\.\d)[\"']",
          version=r"\blitHtmlVersions\b[\s\S]{0,96}?\.push\(\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)[\"']",
          name="lit-html", ecosystem="npm", package="lit-html", confidence="high", hint="lithtmlversions"),
    _rule("expanded-lit-element", "lit", "lit-element", "js-library", "script",
          r"\blitElementVersions\b[\s\S]{0,96}?\.push\(\s*[\"']\d+(?:\.\d+){0,3}(?!\d|\.\d)[\"']",
          version=r"\blitElementVersions\b[\s\S]{0,96}?\.push\(\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)[\"']",
          name="lit-element", ecosystem="npm", package="lit-element", confidence="high", hint="litelementversions"),
    _rule("expanded-lit-reactive-element", "lit", "reactive-element", "js-library", "script",
          r"\breactiveElementVersions\b[\s\S]{0,96}?\.push\(\s*[\"']\d+(?:\.\d+){0,3}(?!\d|\.\d)[\"']",
          version=r"\breactiveElementVersions\b[\s\S]{0,96}?\.push\(\s*[\"'](\d+(?:\.\d+){0,3})(?!\d|\.\d)[\"']",
          name="@lit/reactive-element", ecosystem="npm", package="@lit/reactive-element", confidence="high", hint="reactiveelementversions"),
    _rule("expanded-lit-package", "lit", "lit", "js-library", "script",
          r"(?:from\s*[\"']lit-html[\"'][\s\S]{0,256}?from\s*[\"']lit-element[\"']|from\s*[\"']lit-element[\"'][\s\S]{0,256}?from\s*[\"']lit-html[\"'])",
          name="lit", ecosystem="npm", package="lit", confidence="high", hint="lit-html"),
    _rule("expanded-zonejs-script", "zone.js", "zone.js", "js-library", "script",
          r"zone\.js\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"zone\.js\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="zone.js", ecosystem="npm", package="zone.js", confidence="high", hint="zone.js"),
    _rule("expanded-zonejs-runtime", "zone.js", "zone.js", "js-library", "script",
          r"""["']Already loaded patch: ["']\s*\+""",
          name="zone.js", ecosystem="npm", package="zone.js", confidence="high", hint="__zone_symbol__"),
    _rule("expanded-webpack-runtime", "webpack", "webpack", "js-library", "script",
          r"(?:webpackJsonp|webpackChunk(?!ed)[A-Za-z0-9_$]*\s*=|__webpack_require__)",
          name="webpack", ecosystem="npm", package="webpack", confidence="high", hint="webpack"),
    _rule("expanded-tslib", "microsoft", "tslib", "js-library", "url",
          r"(?:^|/)tslib(?:/|[.-])", name="tslib", ecosystem="npm", package="tslib", confidence="high"),
    _rule("expanded-typescript", "microsoft", "typescript", "js-library", "url",
          r"(?:^|/)typescript@",
          version=r"typescript@(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="TypeScript", ecosystem="npm", package="typescript", confidence="high"),
    _rule("expanded-popper-script", "popperjs", "popper", "js-library", "script",
          r"@popperjs/core\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"@popperjs/core\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Popper", ecosystem="npm", package="@popperjs/core", confidence="high", hint="@popperjs/core"),
    _rule("expanded-bootstrap-script", "getbootstrap", "bootstrap", "js-library", "script",
          r"Bootstrap\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Bootstrap\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Bootstrap", ecosystem="npm", package="bootstrap", confidence="high", hint="bootstrap"),
    _rule("expanded-bootstrap-style", "getbootstrap", "bootstrap", "js-library", "style",
          r"Bootstrap\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Bootstrap\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Bootstrap", ecosystem="npm", package="bootstrap", confidence="high", hint="bootstrap"),
    _rule("expanded-bootstrap-icons-style", "twbs", "bootstrap-icons", "js-library", "style",
          r"Bootstrap\s+Icons\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Bootstrap\s+Icons\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Bootstrap Icons", ecosystem="npm", package="bootstrap-icons", confidence="high",
          hint="bootstrap icons"),
    _rule("expanded-font-awesome-style", "fontawesome", "font-awesome", "js-library", "style",
          r"Font Awesome (?:Free|Pro)\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Font Awesome (?:Free|Pro)\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Font Awesome", ecosystem="npm", package="@fortawesome/fontawesome-free", confidence="high", hint="font awesome"),
    _rule("expanded-font-awesome-url", "fontawesome", "font-awesome", "js-library", "url",
          r"font-awesome/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"font-awesome/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Font Awesome", ecosystem="npm", package="@fortawesome/fontawesome-free", confidence="high"),
    _rule("expanded-tailwind-style", "tailwindcss", "tailwindcss", "js-library", "style",
          r"tailwindcss\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"tailwindcss\s+v(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Tailwind CSS", ecosystem="npm", package="tailwindcss", confidence="high", hint="tailwindcss"),
    _rule("expanded-tailwind-url", "tailwindcss", "tailwindcss", "js-library", "url",
          r"tailwindcss/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"tailwindcss/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Tailwind CSS", ecosystem="npm", package="tailwindcss", confidence="high"),
    _rule("expanded-bulma-style", "bulma", "bulma", "js-library", "style",
          r"(?:Bulma\s+v|bulma\.io\s+v)(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"(?:Bulma\s+v|bulma\.io\s+v)(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Bulma", ecosystem="npm", package="bulma", confidence="high", hint="bulma"),
    _rule("expanded-foundation-style", "zurb", "foundation-sites", "js-library", "style",
          r"Foundation for Sites\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"Foundation for Sites\s+(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Foundation", ecosystem="npm", package="foundation-sites", confidence="high", hint="foundation for sites"),
    _rule("expanded-foundation-media-queries", "zurb", "foundation-sites", "js-library", "style",
          r"""\.foundation-mq\s*\{\s*font-family\s*:\s*["']?small=[^&{}"'\s]{1,32}&medium=""",
          name="Foundation", ecosystem="npm", package="foundation-sites", confidence="high", hint=".foundation-mq"),
    _rule("expanded-animate-style", "animatecss", "animate.css", "js-library", "style",
          r"(?:animate\.css\s+-\s+Version\s+|animate\.css\s+-\s+https://animate\.style/[\s\S]{0,120}?Version\s+-\s+)(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          version=r"(?:animate\.css\s+-\s+Version\s+|animate\.css\s+-\s+https://animate\.style/[\s\S]{0,120}?Version\s+-\s+)(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="Animate.css", ecosystem="npm", package="animate.css", confidence="high", hint="animate.css"),
    _rule("expanded-leaflet-script", "leafletjs", "leaflet", "js-library", "script",
          r"\bLeaflet\s+\d+\.\d+\.\d+(?:\+[^,\n]{0,80})?\s*,\s*a JS library for interactive maps",
          version=r"\bLeaflet\s+(\d+\.\d+\.\d+)(?:\+[^,\n]{0,80})?\s*,\s*a JS library for interactive maps",
          name="Leaflet", ecosystem="npm", package="leaflet", confidence="high", hint="leaflet"),
    _rule("expanded-leaflet-style", "leafletjs", "leaflet", "js-library", "style",
          r"\.leaflet-container\b", name="Leaflet", ecosystem="npm", package="leaflet",
          confidence="medium", hint="leaflet-container"),
    # Third-party services are recognised from link text alone; none is fetched.
    _rule("expanded-google-maps", "google", "google-maps", "hosted-platform", "url",
          r"(?:maps\.googleapis\.com/maps/api/|maps\.google\.com/maps/api/|google\.com/maps/embed)",
          name="Google Maps", confidence="high"),
    _rule("expanded-google-maps-script", "google", "google-maps", "hosted-platform", "script",
          r"(?:maps\.googleapis\.com/maps/api/js|google\.maps\.importLibrary\s*\(|google\.maps\.Map\s*=)",
          name="Google Maps", confidence="high", hint="google"),
    _rule("expanded-google-fonts", "google", "google-font-api", "hosted-platform", "url",
          r"(?:fonts\.googleapis\.com/|fonts\.gstatic\.com/)", name="Google Font API", confidence="high"),
    _rule("expanded-google-analytics", "google", "google-analytics", "analytics", "url",
          r"google-analytics\.com/(?:analytics\.js|ga\.js)", name="Google Analytics",
          confidence="high", fixed_version="UA"),
    _rule("expanded-google-analytics-script", "google", "google-analytics", "analytics", "script",
          r"\bgtag\s*\(\s*[\"']config[\"']\s*,\s*[\"']G-[A-Z0-9]{6,}[\"']",
          name="Google Analytics", confidence="high", hint="gtag", fixed_version="GA4"),
    _rule("expanded-google-analytics-ga4-url", "google", "google-analytics", "analytics", "url",
          r"googletagmanager\.com/gtag/js\?(?:[^\"'\s]*&)?id=G-[A-Z0-9]{6,}",
          name="Google Analytics", confidence="high", fixed_version="GA4"),
    _rule("expanded-google-tag-manager", "google", "tag-manager", "analytics", "url",
          r"googletagmanager\.com/gtm\.js", name="Google Tag Manager", confidence="high"),
    _rule("expanded-google-tag-manager-script", "google", "tag-manager", "analytics", "script",
          r"(?:googletagmanager\.com/gtm\.js|(?-i:\bGTM-[A-Z0-9]{6,}\b))",
          name="Google Tag Manager", confidence="high", hint="gtm"),
    # The Google tag runs on Tag Manager, so loading it is medium evidence of Tag Manager.
    _rule("expanded-google-tag-manager-gtag-url", "google", "tag-manager", "analytics", "url",
          r"googletagmanager\.com/gtag/js", name="Google Tag Manager", confidence="medium"),
    _rule("expanded-google-tag-manager-gtag-script", "google", "tag-manager", "analytics", "script",
          r"googletagmanager\.com/gtag/js", name="Google Tag Manager", confidence="medium",
          hint="googletagmanager"),
    _rule("expanded-google-tag-manager-noscript", "google", "tag-manager", "analytics", "html",
          r"googletagmanager\.com/ns\.html", name="Google Tag Manager", confidence="high",
          hint="googletagmanager"),
    _rule("expanded-google-tag-manager-comment", "google", "tag-manager", "analytics", "html",
          r"<!--\s{0,8}(?:End )?Google Tag Manager\s{0,8}-->", name="Google Tag Manager",
          confidence="high", hint="google tag manager"),
    # Container ids are upper case; class names such as "gtm-link" must not match.
    _rule("expanded-google-tag-manager-id", "google", "tag-manager", "analytics", "html",
          r"(?-i:\bGTM-[A-Z0-9]{4,}\b)", name="Google Tag Manager", confidence="high", hint="gtm-"),
    _rule("expanded-cdn-jsdelivr", "jsdelivr", "cdn", "edge", "url",
          r"cdn\.jsdelivr\.net/", name="jsDelivr", confidence="high"),
    _rule("expanded-cdn-unpkg", "unpkg", "cdn", "edge", "url",
          r"unpkg\.com/", name="unpkg", confidence="high"),
    _rule("expanded-cdnjs-service", "cdnjs", "cdn", "edge", "url",
          r"cdnjs\.cloudflare\.com/", name="cdnjs", confidence="high"),
    _rule("expanded-open-graph", "open-graph", "open-graph", "application", "html",
          r"\bproperty\s*=\s*[\"']og:[a-z][a-z0-9:_-]*[\"']",
          name="Open Graph", confidence="high"),
    _rule("expanded-priority-hints", "web-platform", "priority-hints", "application", "html",
          r"(?:(?<![\w:-])fetchpriority\s*=\s*[\"']?(?:high|low|auto)\b"
          r"|setAttribute\(\s*[\"']fetchpriority[\"']\s*,\s*[\"'](?:high|low|auto)[\"'])",
          name="Priority Hints", confidence="high"),
    _rule("expanded-google-recaptcha", "google", "recaptcha", "hosted-platform", "url",
          r"google\.com/recaptcha/api\.js", name="Google reCAPTCHA", confidence="high"),
    _rule("expanded-hcaptcha", "hcaptcha", "hcaptcha", "hosted-platform", "url",
          r"js\.hcaptcha\.com/\d+/api\.js", name="hCaptcha", confidence="high"),
    _rule("expanded-cloudflare-turnstile", "cloudflare", "turnstile", "hosted-platform", "url",
          r"challenges\.cloudflare\.com/turnstile/v0/api\.js", name="Cloudflare Turnstile", confidence="high"),
    _rule("expanded-cloudflare-web-analytics", "cloudflare", "web-analytics", "analytics", "url",
          r"static\.cloudflareinsights\.com/beacon\.min\.js", name="Cloudflare Web Analytics", confidence="high"),
    _rule("expanded-facebook-pixel", "meta", "facebook-pixel", "hosted-platform", "url",
          r"connect\.facebook\.net/[^/]{1,20}/fbevents\.js", name="Facebook Pixel", confidence="high"),
    _rule("expanded-hotjar", "hotjar", "hotjar", "analytics", "url",
          r"(?:static|script)\.hotjar\.com/", name="Hotjar", confidence="high"),
    _rule("expanded-microsoft-clarity", "microsoft", "clarity", "analytics", "url",
          r"clarity\.ms/tag/", name="Microsoft Clarity", confidence="high"),
    _rule("expanded-matomo", "matomo", "matomo", "analytics", "url",
          r"/(?:matomo|piwik)\.js(?:\?|$)", name="Matomo", confidence="medium"),
    _rule("expanded-stripe-js", "stripe", "stripe-js", "hosted-platform", "url",
          r"js\.stripe\.com/v3(?:/|\?|$)", name="Stripe.js", ecosystem="npm",
          package="@stripe/stripe-js", confidence="high"),
    _rule("expanded-paypal", "paypal", "paypal-sdk", "hosted-platform", "url",
          r"paypal\.com/sdk/js", name="PayPal", confidence="high"),
    _rule("expanded-sentry-browser", "sentry", "sentry-browser", "hosted-platform", "url",
          r"browser\.sentry-cdn\.com/(\d+(?:\.\d+){0,3})(?!\d|\.\d)/",
          version=r"browser\.sentry-cdn\.com/(\d+(?:\.\d+){0,3})(?!\d|\.\d)/",
          name="Sentry", ecosystem="npm", package="@sentry/browser", confidence="high"),
    _rule("expanded-intercom", "intercom", "intercom", "hosted-platform", "url",
          r"(?:widget\.intercom\.io/widget/|js\.intercomcdn\.com/)", name="Intercom",
          ecosystem="npm", package="@intercom/messenger-js-sdk", confidence="high"),
    _rule("expanded-zendesk", "zendesk", "zendesk", "hosted-platform", "url",
          r"(?:static|ekr)\.zdassets\.com/", name="Zendesk", confidence="high"),
    # Direct server-side evidence and framework-specific page markers.
    _rule("expanded-symfony-header", "symfony", "symfony", "framework", "header",
          r".+", subject="x-debug-token", name="Symfony", confidence="high"),
    _rule("expanded-symfony-cookie", "symfony", "symfony", "framework", "cookie",
          r"^(?:_symfony_session|sf_session)$", name="Symfony", confidence="high"),
    _rule("expanded-codeigniter-header", "codeigniter", "codeigniter", "framework", "header",
          r"^codeigniter(?:/(\d+(?:\.\d+){0,3}))?$", subject="x-powered-by",
          version=r"^codeigniter/(\d+(?:\.\d+){0,3})(?!\d|\.\d)",
          name="CodeIgniter", confidence="high"),
    _rule("expanded-codeigniter-cookie", "codeigniter", "codeigniter", "framework", "cookie",
          r"^ci_session$", name="CodeIgniter", confidence="medium"),
    _rule("expanded-django-cookie", "djangoproject", "django", "framework", "cookie",
          r"^(?:csrftoken|django_language)$", name="Django", confidence="medium"),
    _rule("expanded-rails-header", "rubyonrails", "rails", "framework", "header",
          r"^\d+(?:\.\d+)?$", subject="x-runtime", name="Ruby on Rails", confidence="medium"),
    _rule("expanded-livewire-markup", "livewire", "livewire", "framework", "html",
          r"\bwire:(?:id|snapshot)\s*=", name="Livewire", confidence="high"),
    _rule("expanded-inertia-markup", "inertiajs", "inertia.js", "js-library", "html",
          r"data-page\s*=\s*[\"'][^\"']{0,200}(?:&quot;|\")component(?:&quot;|\")",
          name="Inertia.js", ecosystem="npm", package="@inertiajs/core", confidence="high"),
    _rule("expanded-wordpress-robots", "wordpress", "wordpress", "cms", "robots",
          r"Disallow:\s*/wp-admin/|Allow:\s*/wp-admin/admin-ajax\.php",
          name="WordPress", confidence="medium"),
    _rule("expanded-drupal-robots", "drupal", "drupal", "cms", "robots",
          r"Disallow:\s*/(?:core|modules|profiles|sites)/",
          name="Drupal", confidence="medium"),
    _rule("expanded-joomla-robots", "joomla", "joomla", "cms", "robots",
          r"Disallow:\s*/administrator/",
          name="Joomla", confidence="medium"),
    _rule("expanded-angular-manifest", "angular", "angular", "js-library", "manifest",
          r"ngsw-worker\.js", name="Angular", ecosystem="npm", package="@angular/core",
          confidence="medium"),
)
RULES = RULES + EXPANDED_RULES

_DISPLAY_NAMES = {
    ("apache", "http_server"): "Apache HTTP Server",
    ("microsoft", "internet_information_services"): "Microsoft IIS",
    ("microsoft", "asp.net"): "ASP.NET",
    ("litespeedtech", "litespeed_web_server"): "LiteSpeed Web Server",
    ("apache", "tomcat"): "Apache Tomcat",
    ("eclipse", "jetty"): "Jetty",
    ("oracle", "weblogic_server"): "Oracle WebLogic Server",
    ("ibm", "websphere_application_server"): "IBM WebSphere Application Server",
    ("oracle", "glassfish_server"): "GlassFish Server",
    ("php", "php"): "PHP",
    ("microsoft", "typescript"): "TypeScript",
    ("wordpress", "wordpress"): "WordPress",
    ("drupal", "drupal"): "Drupal",
    ("joomla", "joomla"): "Joomla",
    ("adobe", "magento"): "Magento",
    ("prestashop", "prestashop"): "PrestaShop",
    ("typo3", "typo3"): "TYPO3",
    ("microsoft", "sharepoint_server"): "Microsoft SharePoint Server",
    ("adobe", "experience_manager"): "Adobe Experience Manager",
    ("sitecore", "sitecore_experience_platform"): "Sitecore Experience Platform",
    ("cloudflare", "cloudflare"): "Cloudflare",
    ("akamai", "akamai_ghost"): "Akamai Ghost",
    ("citrix", "netscaler_application_delivery_controller"): "Citrix NetScaler",
}


def _rule_display_name(rule: Rule) -> str:
    return (rule.name or _DISPLAY_NAMES.get((rule.vendor.casefold(), rule.product.casefold()))
            or rule.product.replace("_", " ").replace("-", " ").title())


RULES = tuple(replace(rule, name=_rule_display_name(rule)) for rule in RULES)


_IMPLICATIONS = {
    ("laravel", "laravel"): (("php", "php", "PHP", "language", "", ""),),
    ("angular", "angular"): (("microsoft", "typescript", "TypeScript", "language", "npm", "typescript"),),
    ("wordpress", "wordpress"): (("php", "php", "PHP", "language", "", ""),),
    ("drupal", "drupal"): (("php", "php", "PHP", "language", "", ""),),
    ("joomla", "joomla"): (("php", "php", "PHP", "language", "", ""),),
    ("adobe", "magento"): (("php", "php", "PHP", "language", "", ""),),
    ("prestashop", "prestashop"): (("php", "php", "PHP", "language", "", ""),),
    ("typo3", "typo3"): (("php", "php", "PHP", "language", "", ""),),
    ("phpmyadmin", "phpmyadmin"): (("php", "php", "PHP", "language", "", ""),),
    ("symfony", "symfony"): (("php", "php", "PHP", "language", "", ""),),
    ("codeigniter", "codeigniter"): (("php", "php", "PHP", "language", "", ""),),
    ("vercel", "next.js"): (
        ("facebook", "react", "React", "js-library", "npm", "react"),
        ("nodejs", "node.js", "Node.js", "language", "", ""),
    ),
    ("gatsbyjs", "gatsby"): (("facebook", "react", "React", "js-library", "npm", "react"),),
    ("nuxt", "nuxt"): (
        ("vuejs", "vue.js", "Vue.js", "js-library", "npm", "vue"),
        ("nodejs", "node.js", "Node.js", "language", "", ""),
    ),
    ("expressjs", "express"): (("nodejs", "node.js", "Node.js", "language", "", ""),),
    ("livewire", "livewire"): (("laravel", "laravel", "Laravel", "framework", "", ""),),
}


_PACKAGE_PRODUCTS: dict[str, tuple[str, str, str, str]] = {}
for _product_rule in RULES:
    if _product_rule.ecosystem == "npm" and _product_rule.package:
        _PACKAGE_PRODUCTS.setdefault(
            _product_rule.package,
            (_product_rule.vendor, _product_rule.product, _product_rule.name or _product_rule.product,
             _product_rule.category),
        )
_PACKAGE_PRODUCTS.setdefault("react-dom", ("facebook", "react-dom", "React DOM", "js-library"))

# npm identities backed by the bundled Retire.js signatures as well as the
# built-in rules. Extending this set permits URL-only npm detections.
REVIEWED_PACKAGES = frozenset(_PACKAGE_PRODUCTS) | {
    "alasql", "dompurify", "dwr", "easyxdm", "froala-editor", "highlight.js", "jplayer",
    "mootools", "mustache", "pdfjs-dist", "protobufjs", "quill", "three", "tinymce", "yui",
}

_CDNJS_PACKAGES = {
    "angular": "angular", "angular.js": "angular",
    "react": "react", "vue": "vue", "ember.js": "ember-source",
    "backbone.js": "backbone", "alpinejs": "alpinejs", "htmx": "htmx.org",
    "jquery": "jquery", "jquery-ui": "jquery-ui", "jquery-migrate": "jquery-migrate",
    "lodash.js": "lodash", "underscore.js": "underscore", "moment.js": "moment",
    "axios": "axios", "chart.js": "chart.js", "d3": "d3", "swiper": "swiper",
    "select2": "select2", "datatables": "datatables.net", "modernizr": "modernizr",
    "require.js": "requirejs", "handlebars.js": "handlebars", "rxjs": "rxjs",
    "core-js": "core-js", "zone.js": "zone.js", "webpack": "webpack",
    "popper.js": "@popperjs/core", "bootstrap": "bootstrap",
    "bootstrap-icons": "bootstrap-icons",
    "font-awesome": "@fortawesome/fontawesome-free", "tailwindcss": "tailwindcss",
    "bulma": "bulma", "foundation-sites": "foundation-sites", "animate.css": "animate.css",
    "gatsby": "gatsby", "next.js": "next", "nuxt": "nuxt", "typescript": "typescript",
    "tslib": "tslib", "svelte": "svelte", "leaflet": "leaflet",
}


# Exact release checksums are used only for these three published builds, whose
# selected minified artifacts contain no release version string.
BUILT_ARTIFACT_HASHES = {
    # lit@3.3.1, MIT; its compact export entry carries no release string.
    "b1993a57ee9b162bc5af6b2f4bc44623c0bd3496be5119c83d5325b04093b65c":
        ("lit", "lit", "lit", "js-library", "npm", "lit", "3.3.1", "script"),
    # zone.js@0.16.3, MIT; this selected build has no literal release version.
    "4ee0b2fe4733702f3ff1bc453ef5547effdc08e62551904946d2058bdd811ada":
        ("zone.js", "zone.js", "zone.js", "js-library", "npm", "zone.js", "0.16.3", "script"),
    # rxjs@7.8.1, Apache-2.0; this selected build has no literal release version.
    "6508e15edacb9eb2c00b8d3fb8fe3022bef1ca1cdb705519524093d4659b3c23":
        ("reactivex", "rxjs", "RxJS", "js-library", "npm", "rxjs", "7.8.1", "script"),
    # foundation-sites@6.9.0, MIT; this selected stylesheet has no version.
    "c500decbe33468e54180f1b6238850d810e85dcdfbea7f87f56bcb17051a51e4":
        ("zurb", "foundation-sites", "Foundation", "js-library", "npm", "foundation-sites",
         "6.9.0", "style"),
}

# Byte offsets and lengths of the same published artifacts. These anchors
# locate candidates in concatenated bundles. Only a digest match gives a version.
_EMBEDDED_ARTIFACTS = {
    "4ee0b2fe4733702f3ff1bc453ef5547effdc08e62551904946d2058bdd811ada":
        (b"Already loaded patch: ", 1659, 36166),  # zone.js 0.16.3, MIT
    "6508e15edacb9eb2c00b8d3fb8fe3022bef1ca1cdb705519524093d4659b3c23":
        (b"ObjectUnsubscribedError", 52581, 88037),  # RxJS 7.8.1, Apache-2.0
    "c500decbe33468e54180f1b6238850d810e85dcdfbea7f87f56bcb17051a51e4":
        (b".foundation-mq{font-family:", 2346, 131304),  # Foundation 6.9.0, MIT
}
_MAX_ARTIFACT_ANCHORS = 32


@dataclass(frozen=True, slots=True)
class _CompiledRule:
    rule: Rule
    evidence: re.Pattern[str]
    version: re.Pattern[str] | None


COMPILED_RULES: tuple[_CompiledRule, ...] = tuple(
    _CompiledRule(rule, re.compile(rule.pattern, re.IGNORECASE),
                  re.compile(rule.version_pattern, re.IGNORECASE) if rule.version_pattern else None)
    for rule in RULES
)


@dataclass(frozen=True, slots=True)
class Page:
    headers: Mapping[str, tuple[str, ...]]
    cookie_names: tuple[str, ...]
    generators: tuple[str, ...]
    urls: tuple[str, ...]
    html: str
    resources: tuple[Resource, ...] = ()
    truncated: bool = False
    _bounded: bool = field(default=False, init=False, compare=False, repr=False)


def _header_value(headers: Mapping[str, tuple[str, ...]], name: str) -> tuple[str, ...]:
    return headers.get(name.casefold(), ())


def _scalar_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = value[:limit]
    if not text.isascii():
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            return ""
    return text


def is_scalar_text(value: object, limit: int = MAX_DETECTION_TEXT) -> bool:
    """Check a character limit and reject lone Unicode surrogates."""
    if not isinstance(value, str) or len(value) > limit:
        return False
    if value.isascii():
        return True
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def valid_detection_name(value: object) -> bool:
    """Check the dashboard's required name contract when a name is supplied."""
    return isinstance(value, str) and is_scalar_text(value, MAX_DETECTION_NAME) and bool(value.strip())


_COOKIE_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,256}"
_COOKIE_NAME = re.compile(_COOKIE_TOKEN)
_COOKIE_PAIR = re.compile(rf"[ \t]*({_COOKIE_TOKEN})[ \t]*=")
_MAX_COOKIE_NAMES = 4096


def _cookie_names(value: str, *, multiple: bool):
    stop = min(len(value), MAX_ANALYSIS_TEXT)
    if not multiple:
        pair = _COOKIE_PAIR.match(value, endpos=stop)
        if pair:
            yield pair[1]
        return
    start = 0
    while start < stop:
        separator = value.find(";", start, stop)
        end = stop if separator < 0 else separator
        pair = _COOKIE_PAIR.match(value, start, end)
        if pair:
            yield pair[1]
            quotes = value.count('"', pair.end(), end)
            if quotes and (quotes != 2 or value.find("\\", pair.end(), end) >= 0):
                # A malformed quoted value may continue past the separator.
                return
        elif value.find('"', start, end) >= 0:
            return
        start = end + 1


def _tag_end(html: str, start: int) -> int:
    quote_char = ""
    index = start
    while index < len(html):
        character = html[index]
        if quote_char:
            if character == quote_char:
                quote_char = ""
        elif character in {"'", '"'}:
            quote_char = character
        elif character == ">":
            return index + 1
        index += 1
    return len(html)


def _tag_attributes(html: str, start: int, end: int) -> dict[str, str]:
    attributes = {}
    index = start
    while index < end:
        while index < end and (html[index].isspace() or html[index] in "/>\""):
            index += 1
        name_start = index
        while index < end and not (html[index].isspace() or html[index] in "=/>\""):
            index += 1
        if index == name_start:
            index += 1
            continue
        name = html[name_start:index].casefold()
        while index < end and html[index].isspace():
            index += 1
        value = ""
        if index < end and html[index] == "=":
            index += 1
            while index < end and html[index].isspace():
                index += 1
            if index < end and html[index] in {"'", '"'}:
                quote_char = html[index]
                index += 1
                value_start = index
                while index < end and html[index] != quote_char:
                    index += 1
                value = html[value_start:index]
                if index < end:
                    index += 1
            else:
                value_start = index
                while index < end and not html[index].isspace() and html[index] not in "/>\"":
                    index += 1
                value = html[value_start:index]
        if name and name not in attributes:
            attributes[name] = value
    return attributes


def _html_tags(html: str):
    position = 0
    while position < len(html):
        start = html.find("<", position)
        if start < 0:
            return
        index = start + 1
        if index < len(html) and html[index] == "/":
            index += 1
        if index >= len(html) or not html[index].isalpha():
            position = index
            continue
        name_start = index
        while index < len(html) and (html[index].isalnum() or html[index] in ":-"):
            index += 1
        name = html[name_start:index].casefold()
        end = _tag_end(html, index)
        yield name, _tag_attributes(html, index, end)
        position = end


_SCRIPT_OPEN = re.compile(r"<script\b", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.IGNORECASE)
_JAVASCRIPT_TYPES = frozenset({
    "module", "text/javascript", "application/javascript", "text/ecmascript",
    "application/ecmascript",
})


def _inline_script_text(html: str, deadline=None, clock=None, on_truncated=lambda: None) -> str:
    scripts = []
    remaining = MAX_ANALYSIS_TEXT
    position = 0
    index = 0
    while index < MAX_PAGE_RESOURCES and remaining > 0:
        opening = _SCRIPT_OPEN.search(html, position)
        if opening is None or _deadline_passed(deadline, clock):
            break
        attributes_start = opening.end()
        tag_end = _tag_end(html, attributes_start)
        if tag_end >= len(html):
            break
        closing = _SCRIPT_CLOSE.search(html, tag_end)
        if closing is None:
            break
        position = closing.end()
        index += 1
        attributes = _tag_attributes(html, attributes_start, tag_end)
        if "src" in attributes:
            continue
        script_type = attributes.get("type", "").split(";", 1)[0].strip().casefold()
        if script_type and script_type not in _JAVASCRIPT_TYPES:
            continue
        text = _scalar_text(html[tag_end:closing.start()], remaining)
        if len(text) < closing.start() - tag_end:
            on_truncated()
        if text:
            scripts.append(text)
            remaining -= len(text)
    if (index == MAX_PAGE_RESOURCES or remaining == 0) and _SCRIPT_OPEN.search(html, position):
        on_truncated()
    return "\n".join(scripts)


def page_from(headers: Mapping[str, Iterable[str]], html: str,
              resources: Iterable[Resource] = ()) -> Page:
    bounded_html = _scalar_text(html, MAX_ANALYSIS_TEXT)
    truncated = bounded_html != html
    normalized = {}
    cookies: dict[str, None] = {}
    if isinstance(headers, Mapping):
        for index, (raw_name, raw_values) in enumerate(headers.items()):
            if index >= 256:
                truncated = True
                break
            name = _scalar_text(str(raw_name).strip().casefold(), 256)
            if not name:
                continue
            values = (raw_values,) if isinstance(raw_values, str) else raw_values
            try:
                values = tuple(islice(values, 65))
                truncated |= len(values) > 64
                if name in {"set-cookie", "cookie"}:
                    for value in values[:64]:
                        if len(cookies) >= _MAX_COOKIE_NAMES:
                            truncated = True
                            break
                        if isinstance(value, str):
                            truncated |= len(value) > MAX_ANALYSIS_TEXT
                            for cookie_name in _cookie_names(value, multiple=name == "cookie"):
                                if len(cookies) >= _MAX_COOKIE_NAMES:
                                    truncated = True
                                    break
                                cookies.setdefault(cookie_name, None)
                    continue
                raw_text = tuple(str(item) for item in values[:64])
                bounded_values = tuple(_scalar_text(item, MAX_ANALYSIS_TEXT) for item in raw_text)
                truncated |= raw_text != bounded_values
                safe_values = tuple(value for value in bounded_values if value)
            except TypeError:
                continue
            if safe_values:
                normalized[name] = safe_values
    generators = []
    urls = []
    for tag, attributes in _html_tags(bounded_html):
        if tag == "meta" and attributes.get("name", "").strip().casefold() == "generator":
            raw, values, limit = attributes.get("content", ""), generators, MAX_GENERATORS
        elif tag in {"script", "link"}:
            raw = attributes.get("src" if tag == "script" else "href", "")
            values, limit = urls, MAX_URLS
        else:
            continue
        value = _scalar_text(raw, MAX_DETECTION_TEXT)
        truncated |= value != raw
        if value:
            if len(values) < limit:
                values.append(value)
            else:
                truncated = True
        if len(generators) >= MAX_GENERATORS and len(urls) >= MAX_URLS:
            truncated = True
            break

    clean_resources = []
    remaining = MAX_TOTAL_RESOURCE_TEXT
    try:
        for index, resource in enumerate(resources):
            if index == MAX_PAGE_RESOURCES:
                truncated = True
                break
            if not isinstance(resource, Resource) or resource.kind not in {
                    "script", "style", "manifest", "robots", "icon"}:
                continue
            url = resource.url
            if not isinstance(url, str) or not url or not is_scalar_text(url, len(url)):
                continue
            text_limit = min(MAX_RESOURCE_TEXT, remaining)
            text = _scalar_text(resource.text, text_limit) if text_limit else ""
            truncated |= text != resource.text or len(text) > MAX_ANALYSIS_TEXT
            remaining -= len(text)
            clean_resources.append(Resource(url, resource.kind, text))
    except TypeError:
        pass
    page = Page(normalized, tuple(cookies), tuple(generators), tuple(urls), bounded_html,
                tuple(clean_resources), truncated)
    object.__setattr__(page, "_bounded", True)
    return page


def _bounded_page(page: Page) -> Page | None:
    if not isinstance(page, Page):
        return None
    if page._bounded:
        return page
    bounded = page_from(page.headers, page.html, page.resources)
    cookies = tuple(dict.fromkeys(
        value for value in islice(page.cookie_names, _MAX_COOKIE_NAMES)
        if isinstance(value, str) and _COOKIE_NAME.fullmatch(value)
    ))
    generators = tuple(dict.fromkeys(
        value for value in (_scalar_text(item, MAX_DETECTION_TEXT)
                            for item in islice(page.generators, MAX_GENERATORS)) if value
    ))
    urls = tuple(dict.fromkeys(
        value for value in (_scalar_text(item, MAX_DETECTION_TEXT)
                            for item in islice(page.urls, MAX_URLS)) if value
    ))
    bounded_page = Page(
        bounded.headers,
        tuple(dict.fromkeys((*bounded.cookie_names, *cookies)))[:_MAX_COOKIE_NAMES],
        tuple(dict.fromkeys((*bounded.generators, *generators)))[:MAX_GENERATORS],
        tuple(dict.fromkeys((*bounded.urls, *urls)))[:MAX_URLS],
        bounded.html,
        bounded.resources,
        page.truncated or bounded.truncated,
    )
    object.__setattr__(bounded_page, "_bounded", True)
    return bounded_page


def _values(rule: Rule, page: Page, cache: Mapping[str, tuple[str, ...]] | None = None) -> tuple[str, ...]:
    if rule.kind == "header":
        return _header_value(page.headers, rule.subject)
    if rule.kind == "cookie":
        return page.cookie_names
    if rule.kind == "meta":
        return page.generators
    if rule.kind == "url":
        if cache is not None and "url" in cache:
            return cache["url"]
        return ("\n".join(page.urls),) if page.urls else ()
    if rule.kind in {"script", "style"}:
        if cache is not None and rule.kind in cache:
            return cache[rule.kind]
        resources = (resource.text for resource in page.resources if resource.kind == rule.kind)
        joined = "\n".join(resources)
        return (joined,) if joined else ()
    if rule.kind in {"manifest", "robots"}:
        return tuple(resource.text for resource in page.resources if resource.kind == rule.kind)
    return (page.html,)


@lru_cache(maxsize=1)
def _rule_index():
    return COMPILED_RULES


_CANONICAL_ALIAS_KEYS = frozenset(REVIEWED_ALIASES.values())


def canonical_cpe(cpe: str) -> str:
    """Use the reviewed vendor/product spelling and keep other CPE fields."""
    fields = _cpe_fields(cpe)
    if not fields or fields[0] != "a":
        return cpe
    pair = (fields[1].casefold(), fields[2].casefold())
    canonical = REVIEWED_ALIASES.get(pair, pair)
    if canonical not in _CANONICAL_ALIAS_KEYS:
        return cpe
    escaped = tuple(re.sub(r"([^a-z0-9._-])", r"\\\1", item) for item in canonical)
    raw = _cpe_fields(cpe, keep_escapes=True)
    return "cpe:2.3:" + ":".join((raw[0], *escaped, *raw[3:]))


def identity_key(detection: Detection) -> tuple[str, ...]:
    """Return the strongest reviewed identity available for a detection."""
    return web_product_key(detection.vendor, detection.product, cpe=detection.cpe,
                           ecosystem=detection.ecosystem, package=detection.package,
                           name=detection.name, name_only=getattr(detection, "name_only", False))


def _url_parts(value: str):
    if (not isinstance(value, str) or len(value) > MAX_DETECTION_TEXT
            or not _scalar_text(value, MAX_DETECTION_TEXT)
            or "\\" in value or any(ord(character) < 0x20 or ord(character) == 0x7F
                                    for character in value)):
        return None
    try:
        text = "https:" + value if value.startswith("//") else value
        parts = urlsplit(text)
        host = (parts.hostname or "").casefold()
        if parts.scheme.casefold() not in {"http", "https"}:
            return None
        segments = []
        for raw_segment in parts.path.split("/"):
            if not raw_segment:
                continue
            segment = unquote(raw_segment)
            if (not _scalar_text(segment, MAX_DETECTION_TEXT) or "/" in segment
                    or "\\" in segment or "://" in segment
                    or re.match(r"(?i)^(?:https?|ftp|file):", segment)
                    or any(ord(character) < 0x20 or ord(character) == 0x7F
                           for character in segment)):
                return None
            segments.append(segment)
        return host, segments
    except (ValueError, UnicodeError):
        return None


def _npm_path(segments: list[str], start: int = 0) -> tuple[str, str] | None:
    if start >= len(segments):
        return None
    first = segments[start]
    if first.startswith("@"):
        if start + 1 >= len(segments):
            return None
        package_name = first + "/" + segments[start + 1].split("@", 1)[0]
        versioned_name = segments[start + 1]
    else:
        package_name, _, version = first.rpartition("@")
        if not package_name or not version:
            return None
        versioned_name = first
    if first.startswith("@"):
        package, separator, version = versioned_name.rpartition("@")
        if not separator or not version:
            return None
        package_name = first + "/" + package
    if not _npm_name(package_name):
        return None
    return package_name, normalize_version(version)


def _cdn_review_name(package: str, version: str, cdn: str) -> str:
    label = {"jsdelivr": "jsDelivr", "unpkg": "unpkg", "cdnjs": "cdnjs"}.get(cdn, cdn)
    suffix = f", from a {label} link"
    detail = f" {version}" if version else ""
    available = max(1, MAX_DETECTION_NAME - len(detail) - len(suffix))
    return package[:available] + detail + suffix


def _cdn_detection(url: str):
    parsed = _url_parts(url)
    if not parsed:
        return None
    host, segments = parsed
    package_version = None
    if host == "cdn.jsdelivr.net" and len(segments) >= 3 and segments[0] == "npm":
        cdn = "jsdelivr"
        package_version = _npm_path(segments, 1)
    elif host == "unpkg.com":
        cdn = "unpkg"
        package_version = _npm_path(segments)
    elif (host == "cdnjs.cloudflare.com" and len(segments) >= 4
          and segments[:2] == ["ajax", "libs"]):
        library, version = segments[2], normalize_version(segments[3])
        if (not library or len(library) > 128
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", library) is None
                or ".." in library):
            return None
        package = _CDNJS_PACKAGES.get(library.casefold(), "")
        if package in REVIEWED_PACKAGES:
            if not version:
                return None
            details = _PACKAGE_PRODUCTS.get(package)
            if details:
                vendor, product, name, category = details
                return vendor, product, name, category, "npm", package, version
        # Keep package and version readable for review without creating an npm identity.
        return ("cdnjs", "", _cdn_review_name(library, version, "cdnjs"),
                "js-library", "", "", "")
    if not package_version:
        return None
    package, version = package_version
    if package not in REVIEWED_PACKAGES:
        return (cdn, "", _cdn_review_name(package, version, cdn),
                "js-library", "", "", "")
    if not version:
        return None
    details = _PACKAGE_PRODUCTS.get(package)
    if details:
        vendor, product, name, category = details
        return vendor, product, name, category, "npm", package, version
    return "npm", package, package, "js-library", "npm", package, version


def _record(grouped: dict, *, vendor: str, product: str, category: str, confidence: str,
            evidence: str, versions=(), cpe="", name="", ecosystem="", package="",
            implied_by=(), evidence_items=(), rule_key="", categories=()):
    key = (vendor.casefold(), product.casefold(), *_cpe_scope(_cpe_fields(cpe, keep_escapes=True)))
    entry = grouped.setdefault(key, {
        "vendor": vendor, "product": product, "category": category,
        "cpe": "" if ecosystem == "npm" and package else cpe,
        "confidence": confidence, "versions": set(), "evidence_types": set(),
        "name": name, "ecosystem": ecosystem, "package": package,
        "implied_by": set(), "evidence": [], "evidence_keys": set(),
        "categories": set(),
    })
    entry["categories"].add(category)
    entry["categories"].update(categories)
    entry["versions"].update(versions)
    if evidence:
        entry["evidence_types"].add(evidence)
    entry["implied_by"].update(implied_by)
    for item in evidence_items:
        evidence_key = (rule_key, item.source)
        if (evidence_key not in entry["evidence_keys"] and len(entry["evidence"]) < 20):
            entry["evidence_keys"].add(evidence_key)
            entry["evidence"].append(item)
    if name and not entry["name"]:
        entry["name"] = name
    if ecosystem == "npm" and package:
        entry["ecosystem"], entry["package"], entry["cpe"] = "npm", package, ""
    if cpe and not entry["cpe"] and not entry["package"]:
        entry["cpe"] = cpe
    if category != "edge":
        entry["category"] = category
    if confidence == "high":
        entry["confidence"] = "high"
    return key


def _apply_implications(grouped: dict) -> None:
    pending = list(grouped)
    processed = set()
    while pending:
        source_key = pending.pop()
        if source_key in processed:
            continue
        processed.add(source_key)
        source = grouped[source_key]
        targets = _IMPLICATIONS.get(source_key, ())
        source_name = source["name"] or f"{source['vendor']}/{source['product']}"
        for vendor, product, name, category, ecosystem, package in targets:
            target_key = (vendor.casefold(), product.casefold())
            was_present = target_key in grouped
            _record(grouped, vendor=vendor, product=product, name=name, category=category,
                    confidence="low", evidence="" if was_present else "implied",
                    ecosystem=ecosystem, package=package, rule_key="implied:" + source_name,
                    implied_by=(source_name,))
            if not was_present:
                pending.append(target_key)


def _rule_sources(rule: Rule, page: Page, folded_resources: Mapping[int, str] | None = None,
                  inline_script: str = "", folded_inline: str = ""):
    if rule.kind == "header":
        subject = rule.subject.casefold()
        for value in _header_value(page.headers, subject)[:64]:
            if value:
                yield f"header:{subject}", value, None
    elif rule.kind == "cookie":
        for value in page.cookie_names[:_MAX_COOKIE_NAMES]:
            yield f"cookie:{value}", value, None
    elif rule.kind == "meta":
        for value in page.generators[:MAX_GENERATORS]:
            yield "page", value, None
    elif rule.kind == "url":
        for value in page.urls[:MAX_URLS]:
            yield "page", value, None
    elif rule.kind == "html":
        yield "page", page.html, None
    elif rule.kind == "script":
        if inline_script:
            yield "page", inline_script, folded_inline
        for resource in page.resources[:MAX_PAGE_RESOURCES]:
            if resource.kind == "script" and resource.text:
                value = resource.text[:MAX_ANALYSIS_TEXT]
                yield resource.url, value, (folded_resources or {}).get(id(resource))
    elif rule.kind in {"style", "manifest", "robots"}:
        for resource in page.resources[:MAX_PAGE_RESOURCES]:
            if resource.kind == rule.kind and resource.text:
                value = resource.text[:MAX_ANALYSIS_TEXT]
                yield resource.url, value, (folded_resources or {}).get(id(resource))


def _deadline_passed(deadline, clock) -> bool:
    return deadline is not None and clock() >= deadline


def _artifact_matches(resource: Resource, deadline, clock, on_truncated):
    encoded = resource.text.encode("utf-8")
    whole_digest = hashlib.sha256(encoded).hexdigest()
    for digest, entry in BUILT_ARTIFACT_HASHES.items():
        if _deadline_passed(deadline, clock):
            break
        if entry[7] != resource.kind:
            continue
        if digest == whole_digest:
            yield entry, resource.text[:160]
            continue
        if digest not in _EMBEDDED_ARTIFACTS:
            continue
        marker, offset, length = _EMBEDDED_ARTIFACTS[digest]
        if len(encoded) <= length:
            continue
        position = offset
        for _ in range(_MAX_ARTIFACT_ANCHORS):
            if _deadline_passed(deadline, clock):
                break
            position = encoded.find(marker, position, len(encoded) - length + offset + len(marker))
            if position == -1:
                break
            start = position - offset
            if hashlib.sha256(encoded[start:start + length]).hexdigest() == digest:
                yield entry, marker.decode("ascii")
                break
            position += 1
        else:
            if encoded.find(marker, position, len(encoded) - length + offset + len(marker)) != -1:
                on_truncated()


def _valid_detection(detection: Detection) -> bool:
    if (not isinstance(detection.categories, tuple) or not detection.categories
            or len(detection.categories) > 64
            or any(category not in CATEGORIES for category in detection.categories)):
        return False
    values = (detection.vendor, detection.product, detection.category, detection.cpe,
              detection.confidence, detection.ecosystem, detection.package,
              *detection.categories, *detection.versions, *detection.evidence_types,
              *detection.implied_by)
    if any(not is_scalar_text(value) for value in values):
        return False
    if detection.name != "" and not valid_detection_name(detection.name):
        return False
    if any(len(version) > MAX_VERSION_CAPTURE_LENGTH for version in detection.versions):
        return False
    if any(kind not in EVIDENCE_KINDS for kind in detection.evidence_types):
        return False
    if any(not isinstance(item.kind, str) or item.kind not in EVIDENCE_KINDS
           or not isinstance(item.source, str) or not is_scalar_text(item.source, len(item.source))
           or not is_scalar_text(item.excerpt, MAX_EVIDENCE_EXCERPT_LENGTH)
           for item in detection.evidence):
        return False
    return True


_ANGULAR_VERSION_MARKER = "angular v"
_ANGULAR_MARKER_LIMIT = 32
_ANGULAR_VERSION_CONSTRUCTOR = re.compile(
    r"\bnew\s+[\w$]+\s*\(\s*['\"](\d+(?:\.\d+){0,3})(?!\d|\.\d)['\"]"
)
_SERVICE_WORKER_REGISTER = re.compile(
    r"\bnavigator\s*\.\s*serviceWorker\s*\.\s*register\s*\("
)


_NG_VERSION_BODY = r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]{1,20})?)"
_NG_LINKED = re.compile(r"[\"']ng-version[\"']\s*,\s*([A-Za-z_$][\w$]{0,40})\.full\b")
_NG_INLINE = re.compile(
    r"[\"']ng-version[\"']\s*,\s*new\s+[\w$]{1,40}\s*\(\s*[\"']" + _NG_VERSION_BODY
    + r"[\"']\s*\)\s*\.full"
)
_NG_LITERAL = re.compile(
    r"[\"']ng-version[\"']\s*,\s*[\"']" + _NG_VERSION_BODY + r"[\"']\s*\]"
)


_ANGULAR_VARIABLE_LIMIT = 8


def _angular_assignment(text: str, variable: str, *, deadline, clock):
    """The first ``variable=new X("version")`` not preceded by an identifier character."""
    # A literal-first pattern lets the regex engine skip quickly to each candidate.
    lookup = re.compile(re.escape(variable) + r"\s*=\s*new\s+[\w$]{1,40}\s*\(\s*[\"']"
                        + _NG_VERSION_BODY + r"[\"']\s*\)")
    for count, candidate in enumerate(lookup.finditer(text)):
        if count % 1024 == 0 and _deadline_passed(deadline, clock):
            return None
        start = candidate.start()
        if start == 0 or not (text[start - 1].isalnum() or text[start - 1] in "_$."):
            return candidate
    return None


def _angular_unbannered_versions(text: str, *, deadline, clock,
                                  on_truncated=lambda: None) -> list[tuple[str, str]]:
    """Versions from ng-version records in builds that strip the licence banner."""
    found = []
    assignments: dict[str, re.Match | None] = {}
    for pattern in (_NG_LINKED, _NG_INLINE, _NG_LITERAL):
        for index, match in enumerate(pattern.finditer(text)):
            if index >= _ANGULAR_MARKER_LIMIT:
                on_truncated()
                break
            if _deadline_passed(deadline, clock):
                break
            if pattern is _NG_LINKED:
                variable = match.group(1)
                if variable not in assignments:
                    if len(assignments) >= _ANGULAR_VARIABLE_LIMIT:
                        on_truncated()
                        continue
                    assignments[variable] = _angular_assignment(text, variable, deadline=deadline, clock=clock)
                assignment = assignments[variable]
                if not assignment:
                    continue
                version, excerpt = assignment.group(1), (
                    match.group(0) + " \u2026 " + assignment.group(0))
            else:
                version, excerpt = match.group(1), match.group(0)
            normalized = normalize_version(version)
            major = normalized.split(".", 1)[0]
            if normalized and major.isdigit() and 2 <= int(major) <= 99:
                found.append((normalized, excerpt[:MAX_EVIDENCE_EXCERPT_LENGTH]))
    return found


def _record_angular_bundle_versions(grouped: dict, page: Page, inline_script: str,
                                    *, deadline, clock, on_truncated) -> None:
    sources = [("page", inline_script)] if inline_script else []
    sources.extend(
        (resource.url, resource.text[:MAX_RESOURCE_TEXT])
        for resource in page.resources[:MAX_PAGE_RESOURCES]
        if resource.kind == "script" and resource.text
    )
    for source, text in sources:
        if _deadline_passed(deadline, clock):
            return
        folded = text.casefold()
        constructor_versions = set()
        for index, constructor in enumerate(_ANGULAR_VERSION_CONSTRUCTOR.finditer(text)):
            if index >= _ANGULAR_MARKER_LIMIT:
                on_truncated()
                break
            version = normalize_version(constructor.group(1))
            if version:
                constructor_versions.add(version)
        position = 0
        checks = 0
        while checks < _ANGULAR_MARKER_LIMIT:
            if _deadline_passed(deadline, clock):
                return
            marker = folded.find(_ANGULAR_VERSION_MARKER, position)
            if marker < 0:
                break
            version_start = marker + len(_ANGULAR_VERSION_MARKER)
            match = _VERSION.match(text, version_start)
            if match:
                version = normalize_version(match.group(0))
                # A banner alone can appear in compatibility messages. Confirm
                # the same release is constructed in the Angular module code.
                if version and version in constructor_versions:
                    excerpt = text[marker:min(len(text), match.end())]
                    _record(
                        grouped, vendor="angular", product="angular", category="js-library",
                        confidence="high", evidence="script", versions=(version,), name="Angular",
                        ecosystem="npm", package="@angular/core",
                        evidence_items=(Evidence("script", source, excerpt),),
                        rule_key="angular-version-marker",
                    )
            position = marker + len(_ANGULAR_VERSION_MARKER)
            checks += 1
        else:
            if folded.find(_ANGULAR_VERSION_MARKER, position) >= 0:
                on_truncated()
        if _deadline_passed(deadline, clock):
            return
        if "ng-version" not in folded:
            continue
        for version, excerpt in _angular_unbannered_versions(
                text, deadline=deadline, clock=clock, on_truncated=on_truncated):
            _record(
                grouped, vendor="angular", product="angular", category="js-library",
                confidence="high", evidence="script", versions=(version,), name="Angular",
                ecosystem="npm", package="@angular/core",
                evidence_items=(Evidence("script", source, excerpt),),
                rule_key="angular-version-marker",
            )


_LEAFLET_VERSION = re.compile(
    r"\b(?:L\.version|var\s+version)\s*=\s*[\"'](\d+\.\d+\.\d+)[\"']"
)
_LEAFLET_WINDOW = 2000
_LEAFLET_LIMIT = 32


def _record_leaflet_versions(grouped: dict, page: Page, inline_script: str,
                            *, deadline, clock, on_truncated) -> None:
    """A version assignment close to a Leaflet marker, for builds without the banner."""
    sources = [("page", inline_script)] if inline_script else []
    sources.extend(
        (resource.url, resource.text[:MAX_RESOURCE_TEXT])
        for resource in page.resources[:MAX_PAGE_RESOURCES]
        if resource.kind == "script" and resource.text
    )
    for source, text in sources:
        if _deadline_passed(deadline, clock):
            return
        if "leaflet" not in text.casefold():
            continue
        for index, match in enumerate(_LEAFLET_VERSION.finditer(text)):
            if index >= _LEAFLET_LIMIT:
                on_truncated()
                break
            if _deadline_passed(deadline, clock):
                break
            window = text[max(0, match.start() - _LEAFLET_WINDOW):match.end() + _LEAFLET_WINDOW]
            if "leaflet" not in window.casefold():
                continue
            version = normalize_version(match.group(1))
            if not version:
                continue
            _record(
                grouped, vendor="leafletjs", product="leaflet", category="js-library",
                confidence="medium" if match.group(0).startswith("L.") else "low",
                evidence="script", versions=(version,), name="Leaflet", ecosystem="npm",
                package="leaflet",
                evidence_items=(Evidence("script", source, match.group(0)),),
                rule_key="leaflet-version-assignment",
            )
            break


def _has_linked_manifest(html: str) -> bool:
    for tag, attributes in _html_tags(html):
        if (tag == "link" and "manifest" in attributes.get("rel", "").casefold().split()
                and attributes.get("href")):
            return True
    return False


def _record_pwa(grouped: dict, page: Page, inline_script: str, *, deadline, clock) -> None:
    if not _has_linked_manifest(page.html) or _deadline_passed(deadline, clock):
        return
    sources = [("page", inline_script)] if inline_script else []
    sources.extend(
        (resource.url, resource.text)
        for resource in page.resources[:MAX_PAGE_RESOURCES]
        if resource.kind == "script" and resource.text
    )
    for source, text in sources:
        if _deadline_passed(deadline, clock):
            return
        match = _SERVICE_WORKER_REGISTER.search(text)
        if not match:
            continue
        _record(
            grouped, vendor="web", product="pwa", category="application", confidence="high",
            evidence="html", name="PWA",
            evidence_items=(Evidence("html", "page", 'link rel="manifest"'),),
            rule_key="pwa-manifest",
        )
        _record(
            grouped, vendor="web", product="pwa", category="application", confidence="high",
            evidence="script", name="PWA",
            evidence_items=(Evidence("script", source, match.group(0)),),
            rule_key="pwa-service-worker",
        )
        return



# Vendors of generic observations. They are reported as products and never
# become inventory rows.
REVIEW_ONLY_VENDORS = frozenset({"banner", "file-name"})

# Generic, low-confidence observations. They name a library from a preserved
# banner or a versioned file name, never create an inventory row unless the
# name is a reviewed npm package, and never repeat another detection.
_BANNER_LIMIT = 50
_BANNER_HEAD = 300
_GENERIC_LIMIT = 64
_BANNER_REJECTED = frozenset({
    "copyright", "license", "licensed", "version", "build", "author", "date",
    "generated", "core", "main", "app", "bundle",
})
_FILE_REJECTED = frozenset({
    "main", "app", "vendor", "vendors", "runtime", "polyfills", "chunk", "bundle", "index",
    "styles", "style", "scripts", "script", "common", "commons", "framework", "webpack",
})
_BANNER_LICENSE_MARK = re.compile(r"@(?:license|preserve)", re.IGNORECASE)
_BANNER_LEAD = re.compile(r"[!*\s]*(?:@(?:license|preserve)\b[:\s*]*)?", re.IGNORECASE)
_BANNER_NAME_VERSION = re.compile(
    r"([A-Za-z][A-Za-z0-9 ._+-]{1,39}?)\s*[-|:,]?\s*v?(\d+(?:\.\d+){1,3})(?!\d|\.\d)"
)
_FILE_VERSIONED = re.compile(
    r"([a-z][a-z0-9_]*(?:[.-][a-z][a-z0-9_]*){0,4})[-.@_]v?(\d+\.\d+(?:\.\d+){0,2})"
    r"(?:[.-]min)?\.(?:js|mjs|css)",
    re.IGNORECASE,
)
_DIR_VERSION = re.compile(r"v?(\d+\.\d+(?:\.\d+){0,2})", re.IGNORECASE)
_HASH_NAME = re.compile(r"[a-f0-9]{8,}", re.IGNORECASE)


def _generic_key(value: str) -> str:
    return re.sub(r"[\s_.-]+", "", value).casefold()


def _banner_candidates(text: str, on_truncated):
    starts = set()
    position = 0
    while len(starts) < _BANNER_LIMIT:
        position = text.find("/*!", position)
        if position < 0:
            break
        starts.add(position)
        position += 3
    else:
        if text.find("/*!", position) >= 0:
            on_truncated()
    for index, mark in enumerate(_BANNER_LICENSE_MARK.finditer(text)):
        if index >= _BANNER_LIMIT:
            on_truncated()
            break
        opener = text.rfind("/*", max(0, mark.start() - _BANNER_HEAD), mark.start())
        if opener >= 0 and "*/" not in text[opener + 2:mark.start()]:
            starts.add(opener)
    if len(starts) > _BANNER_LIMIT:
        on_truncated()
    return sorted(starts)[:_BANNER_LIMIT]


def _banner_observation(text: str, start: int):
    inner = text[start + 2:start + 2 + _BANNER_HEAD + 100]
    end = inner.find("*/")
    if end >= 0:
        inner = inner[:end]
    inner = inner[:_BANNER_HEAD]
    lead = _BANNER_LEAD.match(inner)
    head = inner[lead.end():] if lead else inner
    match = _BANNER_NAME_VERSION.match(head)
    if not match:
        return None
    name = match.group(1).strip(" \t\r\n-|:,")
    words = name.split()
    if (not 2 <= len(name) <= 40 or not name[0].isalpha() or not words
            or name.casefold() in _BANNER_REJECTED or words[0].casefold() in _BANNER_REJECTED
            or any(word.casefold() in {"license", "licence", "licensed"} for word in words)):
        return None
    version = normalize_version(match.group(2))
    if not version:
        return None
    return name, version, " ".join(text[start:start + 120].split())[:MAX_EVIDENCE_EXCERPT_LENGTH]


def _file_observation(url: str):
    path = url.split("#", 1)[0].split("?", 1)[0]
    segments = path.rstrip("/").rsplit("/", 3)
    filename = segments[-1]
    if not 4 <= len(filename) <= 100:
        return None
    match = _FILE_VERSIONED.fullmatch(filename)
    if match:
        return match.group(1), match.group(2), filename
    if len(segments) >= 3:
        name, version, last = segments[-3], segments[-2], filename
        if (len(name) <= 40 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,39}", name)
                and _DIR_VERSION.fullmatch(version)
                and re.fullmatch(re.escape(name) + r"(?:\.min)?\.(?:js|css)", last, re.IGNORECASE)):
            return name, _DIR_VERSION.fullmatch(version).group(1), "/".join(segments[-3:])
    return None


def _record_generic(grouped: dict, page: Page, *, deadline, clock, on_truncated) -> None:
    known_names = set()
    known_packages = set()
    for entry in grouped.values():
        for value in (entry["name"], entry["product"], entry["package"]):
            if value:
                known_names.add(_generic_key(value))
        if entry["package"]:
            known_packages.add(entry["package"])
    observations = []
    for resource in page.resources[:MAX_PAGE_RESOURCES]:
        if resource.kind not in {"script", "style"} or not resource.text:
            continue
        if _deadline_passed(deadline, clock):
            return
        text = resource.text[:MAX_ANALYSIS_TEXT]
        for start in _banner_candidates(text, on_truncated):
            found = _banner_observation(text, start)
            if found:
                observations.append((resource.kind, resource.url, "banner", *found))
    urls = [(url, "") for url in page.urls[:MAX_URLS]]
    urls.extend((resource.url, resource.kind) for resource in page.resources[:MAX_PAGE_RESOURCES]
                if resource.kind in {"script", "style"})
    for url, kind in urls:
        if _deadline_passed(deadline, clock):
            return
        if not isinstance(url, str) or len(url) > MAX_DETECTION_TEXT:
            continue
        found = _file_observation(url)
        if found:
            observations.append((kind, url, "file", *found))
    recorded = 0
    generic_vendors: dict[str, str] = {}
    for kind, source, origin, name, version, excerpt in observations:
        if recorded >= _GENERIC_LIMIT:
            on_truncated()
            break
        if _deadline_passed(deadline, clock):
            break
        key = _generic_key(name)
        lowered = name.casefold()
        tokens = [token for token in re.split(r"[\s_.-]+", name) if token]
        # A banner such as "Font Awesome Free" repeats a known "Font Awesome".
        if (any(_generic_key("".join(tokens[:count])) in known_names
                for count in range(1, len(tokens) + 1))
                or not key or _HASH_NAME.fullmatch(name)
                or not valid_detection_name(name)):
            continue
        if origin == "file" and lowered in _FILE_REJECTED:
            continue
        package = lowered if origin == "banner" and lowered in REVIEWED_PACKAGES else ""
        if package:
            if package in known_packages:
                continue
            details = _PACKAGE_PRODUCTS.get(package)
            vendor, product, display, category = details or ("npm", package, package, "js-library")
            _record(grouped, vendor=vendor, product=product, category=category,
                    confidence="low", evidence=kind, versions=(version,), name=display,
                    ecosystem="npm", package=package,
                    evidence_items=(Evidence(kind, source, excerpt),),
                    rule_key="generic-banner")
            known_packages.add(package)
        else:
            category = "css-library" if kind == "style" else "js-library"
            evidence = kind or "url"
            if origin == "file":
                evidence = "url"
                category = "css-library" if source.split("?", 1)[0].casefold().endswith(".css") else "js-library"
            vendor = "banner" if origin == "banner" else "file-name"
            # Other versions of the same generic library merge into one detection.
            if generic_vendors.setdefault(key, vendor) != vendor:
                continue
            _record(grouped, vendor=vendor,
                    product=re.sub(r"[^a-z0-9]+", "-", lowered).strip("-"),
                    category=category, confidence="low", evidence=evidence,
                    versions=(version,), name=name,
                    evidence_items=(Evidence(evidence, source, excerpt),),
                    rule_key="generic-" + origin)
            recorded += 1
            continue
        known_names.add(key)
        recorded += 1


def detect(page: Page, *, deadline=None, clock=time.monotonic,
           on_truncated=lambda: None) -> tuple[Detection, ...]:
    """Return bounded passive detections completed before the absolute deadline."""
    if _deadline_passed(deadline, clock):
        return ()
    page = _bounded_page(page)
    if page is None:
        return ()
    grouped: dict[tuple[str, ...], dict] = {}
    folded_resources = {
        id(resource): resource.text[:MAX_ANALYSIS_TEXT].casefold()
        for resource in page.resources
        if resource.kind in {"script", "style"} and resource.text
    }
    if page.truncated:
        on_truncated()
    inline_script = _inline_script_text(page.html, deadline, clock, on_truncated)
    folded_inline = inline_script.casefold()
    for compiled in _rule_index():
        if _deadline_passed(deadline, clock):
            break
        rule = compiled.rule
        sensitive_header = rule.kind == "header" and rule.subject.casefold() in SENSITIVE_HEADERS
        versions: set[str] = set()
        matched = False
        evidence_items = []
        seen_sources = set()
        for source, value, folded in _rule_sources(
                rule, page, folded_resources, inline_script, folded_inline):
            if _deadline_passed(deadline, clock):
                break
            if rule.hint and folded is not None and rule.hint not in folded:
                continue
            found = compiled.evidence.search(value)
            if not found:
                continue
            start, end = found.span()
            if start == end:
                continue
            matched = True
            if rule.fixed_version:
                versions.add(rule.fixed_version)
            if compiled.version is not None and not sensitive_header:
                version_match = compiled.version.search(value)
                if version_match:
                    version = _captured_version(version_match, rule.version_group)
                    if version:
                        versions.add(version)
            if source not in seen_sources:
                seen_sources.add(source)
                excerpt = source if sensitive_header else value[start:min(
                    end, start + MAX_EVIDENCE_EXCERPT_LENGTH,
                )]
                evidence_items.append(Evidence(rule.kind, source, excerpt))
        if not matched:
            continue
        _record(grouped, vendor=rule.vendor, product=rule.product, category=rule.category,
                cpe=rule.cpe, confidence=rule.confidence, evidence=rule.kind,
                versions=versions, name=rule.name, ecosystem=rule.ecosystem,
                package=rule.package, evidence_items=evidence_items, rule_key=rule.key,
                categories=rule.categories)

    if not _deadline_passed(deadline, clock):
        _record_angular_bundle_versions(grouped, page, inline_script,
                                       deadline=deadline, clock=clock, on_truncated=on_truncated)
        _record_pwa(grouped, page, inline_script, deadline=deadline, clock=clock)
        _record_leaflet_versions(grouped, page, inline_script, deadline=deadline, clock=clock,
                                 on_truncated=on_truncated)

    if not _deadline_passed(deadline, clock):
        seen_cdn = set()
        for url in page.urls[:MAX_URLS]:
            if _deadline_passed(deadline, clock):
                break
            match = _cdn_detection(url)
            if not match:
                continue
            vendor, product, name, category, ecosystem, package, version = match
            unique = (vendor, package, version) if package else (vendor, url)
            if unique in seen_cdn:
                continue
            if len(seen_cdn) >= MAX_CDN_DETECTIONS:
                on_truncated()
                break
            seen_cdn.add(unique)
            _record(grouped, vendor=vendor, product=product, name=name, category=category,
                    confidence="high", evidence="url", versions=(version,) if version else (),
                    ecosystem=ecosystem, package=package,
                    evidence_items=(Evidence("url", "page", url[:MAX_EVIDENCE_EXCERPT_LENGTH]),),
                    rule_key=f"cdn:{len(seen_cdn)}")

    if not _deadline_passed(deadline, clock):
        for resource in page.resources:
            if _deadline_passed(deadline, clock):
                break
            for exact, excerpt in _artifact_matches(resource, deadline, clock, on_truncated):
                vendor, product, name, category, ecosystem, package, version, _kind = exact
                _record(grouped, vendor=vendor, product=product, name=name, category=category,
                        confidence="high", evidence=resource.kind, versions=(version,),
                        ecosystem=ecosystem, package=package,
                        evidence_items=(Evidence(resource.kind, resource.url, excerpt),),
                        rule_key=f"artifact-sha256:{package}:{version}")

    if not _deadline_passed(deadline, clock):
        from . import retirejs

        for retired in retirejs.detect(page, deadline=deadline, clock=clock):
            key = _record(grouped, vendor=retired.vendor, product=retired.product,
                          category=retired.category, confidence=retired.confidence,
                          evidence="", versions=retired.versions, cpe=retired.cpe,
                          name=retired.name, ecosystem=retired.ecosystem,
                          package=retired.package, implied_by=retired.implied_by,
                          categories=retired.categories)
            for index, item in enumerate(retired.evidence):
                _record(grouped, vendor=retired.vendor, product=retired.product,
                        category=retired.category, confidence=retired.confidence, cpe=retired.cpe,
                        evidence="", evidence_items=(item,),
                        rule_key=f"retirejs:{index}:{item.kind}")
            grouped[key]["evidence_types"].update(retired.evidence_types)

    _apply_implications(grouped)
    if not _deadline_passed(deadline, clock):
        _record_generic(grouped, page, deadline=deadline, clock=clock, on_truncated=on_truncated)
    detections = tuple(
        Detection(entry["vendor"], entry["product"], entry["category"], entry["cpe"],
                  entry["confidence"], tuple(sorted(entry["versions"])),
                  tuple(sorted(entry["evidence_types"])), entry["name"],
                  entry["ecosystem"], entry["package"], tuple(sorted(entry["implied_by"])),
                  tuple(entry["evidence"]), categories=tuple(sorted(entry["categories"])))
        for _, entry in sorted(grouped.items())
    )
    return tuple(item for item in detections if _valid_detection(item))
