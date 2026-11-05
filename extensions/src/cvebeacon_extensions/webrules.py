"""Reviewed direct-evidence rules for passive web technology detection.

The patterns below were written from public product documentation and the
response conventions those products document (Server and X-Powered-By values,
cookie names, generator metadata, and published asset URLs). No fingerprint
data was copied from another detector project.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import re
from typing import Iterable, Mapping

from cvebeacon.identity import normalize_asset
from cvebeacon.models import Asset
from cvebeacon.sources.nvd import split_cpe23

CATEGORIES = {
    "web-server",
    "application-server",
    "language",
    "framework",
    "cms",
    "js-library",
    "edge",
    "ops-tool",
    "hosted-platform",
    "application",
}

MAX_GENERATORS = 4096
MAX_URLS = 16384


@dataclass(frozen=True, slots=True)
class Rule:
    key: str
    vendor: str
    product: str
    category: str
    kind: str  # header | cookie | meta | url | html
    pattern: str
    subject: str = ""  # header name for kind == "header"
    version_pattern: str = ""
    cpe: str = ""
    confidence: str = "medium"


@dataclass(frozen=True, slots=True)
class Detection:
    vendor: str
    product: str
    category: str
    cpe: str
    confidence: str
    versions: tuple[str, ...]


_VERSION = re.compile(r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z][0-9A-Za-z._-]*)?")
_REJECTED_VERSIONS = {"", "*", "-", "unknown", "latest", "n/a", "na", "all", "none"}
_PREFIX = re.compile(r"^(?:v(?=\d)|[A-Za-z][A-Za-z._!-]*(?: [A-Za-z][A-Za-z._!-]*)*[ /](?=\d))")


def normalize_version(value: object) -> str:
    """Return a conservative exact version, or an empty string."""
    if not isinstance(value, str):
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


def _rule(key, vendor, product, category, kind, pattern, *, subject="", version="", cpe="", confidence="medium"):
    if category not in CATEGORIES:
        raise ValueError(f"unknown rule category: {category}")
    if kind not in {"header", "cookie", "meta", "url", "html"}:
        raise ValueError(f"unknown evidence kind: {kind}")
    if kind == "header" and not subject:
        raise ValueError(f"header rule {key} has no header name")
    if confidence not in {"high", "medium", "low"}:
        raise ValueError(f"unknown confidence: {confidence}")
    # Compile at import time so a malformed reviewed rule fails closed.
    re.compile(pattern, re.IGNORECASE)
    if version:
        re.compile(version, re.IGNORECASE)
    return Rule(key, vendor, product, category, kind, pattern, subject.casefold(), version,
                _validated_cpe(cpe), confidence)


RULES: tuple[Rule, ...] = (
    # Web and application servers.
    _rule("nginx", "nginx", "nginx", "web-server", "header", r"^nginx(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)",
          subject="server", version=r"nginx/(\d+(?:\.\d+){0,3})", confidence="high"),
    _rule("apache-http-server", "apache", "http_server", "web-server", "header",
          r"^apache(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"apache/(\d+(?:\.\d+){0,3})", cpe="cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("microsoft-iis", "microsoft", "internet_information_services", "web-server", "header",
          r"^microsoft-iis(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"microsoft-iis/(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("litespeed", "litespeedtech", "litespeed_web_server", "web-server", "header",
          r"^litespeed(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"litespeed/(\d+(?:\.\d+){0,3})", confidence="high"),
    _rule("openresty", "openresty", "openresty", "web-server", "header",
          r"^openresty(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"openresty/(\d+(?:\.\d+){0,3})", confidence="high"),
    _rule("caddy", "caddyserver", "caddy", "web-server", "header",
          r"^caddy(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"caddy/(\d+(?:\.\d+){0,3})", confidence="high"),
    _rule("apache-tomcat", "apache", "tomcat", "application-server", "header",
          r"^apache-coyote(?:/\d+(?:\.\d+){0,3})?(?:\s|$)", subject="server",
          cpe="cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", confidence="medium"),
    _rule("jetty", "eclipse", "jetty", "application-server", "header",
          r"^jetty(?:\((\d+(?:\.\d+){0,3})[^)]*\))?", subject="server",
          version=r"jetty\((\d+(?:\.\d+){0,3})", cpe="cpe:2.3:a:eclipse:jetty:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("wildfly", "redhat", "wildfly", "application-server", "header",
          r"^wildfly(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$|[.+-])", subject="server",
          version=r"wildfly/(\d+(?:\.\d+){0,3})", confidence="high"),
    _rule("weblogic", "oracle", "weblogic_server", "application-server", "header",
          r"^weblogic(?: server)?(?:[/ ](\d+(?:\.\d+){0,3}))?(?:\s|$|[.+-])", subject="server",
          version=r"weblogic(?: server)?[/ ](\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*", confidence="medium"),
    _rule("websphere", "ibm", "websphere_application_server", "application-server", "header",
          r"^websphere application server(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"websphere application server/(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:ibm:websphere_application_server:*:*:*:*:*:*:*:*", confidence="medium"),
    _rule("glassfish", "oracle", "glassfish_server", "application-server", "header",
          r"^glassfish(?: server(?: open source edition)?)?(?:[/ ](\d+(?:\.\d+){0,3}))?(?:\s|$)",
          subject="server", version=r"glassfish(?: server(?: open source edition)?)?[/ ](\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:oracle:glassfish_server:*:*:*:*:*:*:*:*", confidence="medium"),

    # Languages and frameworks.
    _rule("php-header", "php", "php", "language", "header",
          r"^php(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="x-powered-by",
          version=r"php/(\d+(?:\.\d+){0,3})", cpe="cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("php-session", "php", "php", "language", "cookie", r"^phpsessid$", confidence="medium"),
    _rule("aspnet-version", "microsoft", "asp.net", "framework", "header",
          r"^(\d+(?:\.\d+){0,3})(?:\s|$)", subject="x-aspnet-version",
          version=r"^(\d+(?:\.\d+){0,3})", confidence="high"),
    _rule("aspnet-powered-by", "microsoft", "asp.net", "framework", "header",
          r"^asp\.net$", subject="x-powered-by", confidence="medium"),
    _rule("express", "expressjs", "express", "framework", "header", r"^express$",
          subject="x-powered-by", cpe="cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("laravel", "laravel", "laravel", "framework", "cookie", r"^laravel_session$",
          cpe="cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("nextjs", "vercel", "next.js", "framework", "html", r"__next_data__",
          cpe="cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("nuxt", "nuxt", "nuxt", "framework", "html", r"__nuxt__", confidence="medium"),
    _rule("react", "facebook", "react", "js-library", "url",
          r"(?:^|/)react(?:-dom)?(?:@[^/]+)?(?:\.production)?(?:\.min)?\.js(?:\?|$)",
          version=r"react(?:-dom)?@(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("angular", "angular", "angular", "js-library", "html",
          r"ng-version=[\"'](\d+(?:\.\d+){0,3})",
          version=r"ng-version=[\"'](\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:angular:angular:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("vue", "vuejs", "vue.js", "js-library", "url",
          r"(?:^|/)vue(?:@[^/]+)?(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js(?:\?|$)",
          version=r"vue@(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:vuejs:vue.js:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("svelte", "svelte", "svelte", "js-library", "url",
          r"(?:^|/)svelte(?:@[^/]+)?(?:\.min)?\.js(?:\?|$)",
          version=r"svelte@(\d+(?:\.\d+){0,3})", confidence="medium"),
    _rule("jquery", "jquery", "jquery", "js-library", "url",
          r"(?:^|/)jquery(?:[-.]\d+(?:\.\d+){0,3})?(?:\.min)?\.js(?:\?|$)",
          version=r"jquery[-.](\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("bootstrap", "getbootstrap", "bootstrap", "js-library", "url",
          r"(?:^|/)bootstrap(?:[.-]\d+(?:\.\d+){0,3})?(?:\.min)?\.(?:css|js)(?:\?|$)",
          version=r"bootstrap[.-](\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*", confidence="high"),

    # Content management and hosted platforms.
    _rule("wordpress", "wordpress", "wordpress", "cms", "meta", r"^wordpress\b",
          version=r"wordpress\s+(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("drupal", "drupal", "drupal", "cms", "meta", r"^drupal\b",
          version=r"drupal\s+(\d+(?:\.\d+){0,3})", cpe="cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("joomla", "joomla", "joomla", "cms", "meta", r"^joomla!?\b",
          version=r"joomla!?\s+(\d+(?:\.\d+){0,3})", confidence="high"),
    _rule("magento", "adobe", "magento", "cms", "header", r".+", subject="x-magento-tags",
          confidence="high"),
    _rule("prestashop", "prestashop", "prestashop", "cms", "meta", r"^prestashop\b",
          version=r"prestashop\s+(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:prestashop:prestashop:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("shopify", "shopify", "shopify", "hosted-platform", "header", r"^\d+$",
          subject="x-shopid", confidence="high"),
    _rule("ghost", "ghost", "ghost", "cms", "meta", r"^ghost\b",
          version=r"ghost\s+(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:ghost:ghost:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("typo3", "typo3", "typo3", "cms", "meta", r"^typo3\b",
          version=r"typo3(?:\s+cms)?\s+(\d+(?:\.\d+){0,3})",
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
          version=r"ajs-version-number[\s\S]{0,100}?content=[\"'](\d+(?:\.\d+){0,3})",
          confidence="medium"),
    _rule("jira", "atlassian", "jira", "application", "html",
          r"ajs-product-name[\s\S]{0,200}?[\"']jira[\"']",
          version=r"ajs-version-number[\s\S]{0,100}?content=[\"'](\d+(?:\.\d+){0,3})",
          confidence="medium"),
    _rule("elasticsearch", "elastic", "elasticsearch", "ops-tool", "header",
          r"^elasticsearch$", subject="x-elastic-product",
          cpe="cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("kibana", "elastic", "kibana", "ops-tool", "header",
          r"^(\d+(?:\.\d+){0,3})(?:\s|$)", subject="kbn-version",
          version=r"^(\d+(?:\.\d+){0,3})", cpe="cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("grafana", "grafana", "grafana", "ops-tool", "cookie", r"^grafana_session",
          cpe="cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("jenkins", "jenkins", "jenkins", "ops-tool", "header",
          r"^(\d+(?:\.\d+){0,3})(?:\s|$)", subject="x-jenkins",
          version=r"^(\d+(?:\.\d+){0,3})", cpe="cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
          confidence="high"),
    _rule("gitlab", "gitlab", "gitlab", "ops-tool", "cookie", r"^_gitlab_session$",
          cpe="cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("phpmyadmin", "phpmyadmin", "phpmyadmin", "ops-tool", "cookie", r"^phpmyadmin$",
          cpe="cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("cpanel", "cpanel", "cpanel", "ops-tool", "header",
          r"^cpsrvd(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"cpsrvd/(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:cpanel:cpanel:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("plesk", "plesk", "plesk", "ops-tool", "header",
          r"^(?:sw-cp-server|plesk)(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"(?:sw-cp-server|plesk)/(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:plesk:plesk:*:*:*:*:*:*:*:*", confidence="high"),
    _rule("webmin", "webmin", "webmin", "ops-tool", "header",
          r"^miniserv(?:/(\d+(?:\.\d+){0,3}))?(?:\s|$)", subject="server",
          version=r"miniserv/(\d+(?:\.\d+){0,3})",
          cpe="cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*", confidence="high"),
)


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


def _header_value(headers: Mapping[str, tuple[str, ...]], name: str) -> tuple[str, ...]:
    return headers.get(name.casefold(), ())


def page_from(headers: Mapping[str, Iterable[str]], html: str) -> Page:
    normalized = {str(name).casefold(): tuple(str(value) for value in values)
                  for name, values in headers.items()}
    cookies = []
    for value in normalized.get("set-cookie", ()):
        name = value.split(";", 1)[0].split("=", 1)[0].strip()
        if name and len(name) <= 256:
            cookies.append(name)
    generators = []
    urls = []
    for match in re.finditer(r"<meta\b[^>]*>", html, re.IGNORECASE):
        tag = match.group(0)
        name = re.search(r"\bname\s*=\s*[\"']([^\"']*)[\"']", tag, re.IGNORECASE)
        content = re.search(r"\bcontent\s*=\s*[\"']([^\"']*)[\"']", tag, re.IGNORECASE)
        if name and content and name.group(1).strip().casefold() == "generator":
            generators.append(content.group(1))
            if len(generators) >= MAX_GENERATORS:
                break
    for match in re.finditer(r"<(?:script|link)\b[^>]*>", html, re.IGNORECASE):
        tag = match.group(0)
        attribute = re.search(r"\b(?:src|href)\s*=\s*[\"']([^\"']*)[\"']", tag, re.IGNORECASE)
        if attribute:
            urls.append(attribute.group(1))
            if len(urls) >= MAX_URLS:
                break
    return Page(normalized, tuple(cookies), tuple(generators), tuple(urls), html)


def _values(rule: Rule, page: Page) -> tuple[str, ...]:
    if rule.kind == "header":
        return _header_value(page.headers, rule.subject)
    if rule.kind == "cookie":
        return page.cookie_names
    if rule.kind == "meta":
        return page.generators
    if rule.kind == "url":
        return page.urls
    return (page.html,)


@lru_cache(maxsize=1)
def _rule_index():
    return COMPILED_RULES


def detect(page: Page) -> tuple[Detection, ...]:
    grouped: dict[tuple[str, str], dict] = {}
    for compiled in _rule_index():
        rule = compiled.rule
        versions: set[str] = set()
        matched = False
        for value in _values(rule, page):
            if compiled.evidence.search(value):
                matched = True
                if compiled.version is not None:
                    found = compiled.version.search(value)
                    if found:
                        version = normalize_version(found.group(1))
                        if version:
                            versions.add(version)
        if not matched:
            continue
        key = (rule.vendor.casefold(), rule.product.casefold())
        entry = grouped.setdefault(key, {"vendor": rule.vendor, "product": rule.product,
                                         "category": rule.category, "cpe": rule.cpe,
                                         "confidence": rule.confidence, "versions": set()})
        entry["versions"].update(versions)
        if rule.cpe and not entry["cpe"]:
            entry["cpe"] = rule.cpe
        if rule.category != "edge":
            entry["category"] = rule.category
        if rule.confidence == "high":
            entry["confidence"] = "high"
    return tuple(
        Detection(entry["vendor"], entry["product"], entry["category"], entry["cpe"],
                  entry["confidence"], tuple(sorted(entry["versions"])))
        for _, entry in sorted(grouped.items())
    )
