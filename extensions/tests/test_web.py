import gzip
import io
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
import threading
import time

import pytest

from cvebeacon_extensions import contract
from cvebeacon_extensions.cli import main
from cvebeacon_extensions.contract import ExtensionError, manifest_path, read_snapshot
from cvebeacon_extensions.merge import merge_snapshots
from cvebeacon_extensions.web import (
    BODY_LIMIT,
    HEADER_LIMIT,
    MAX_RETRIES,
    WIRE_LIMIT,
    Allowlist,
    Endpoint,
    Fetcher,
    StdlibTransport,
    _ConnectionFailure,
    _FetchFailure,
    _Response,
    _TlsFailure,
    _TimeoutFailure,
    _TooLargeFailure,
    _UnsupportedEncodingFailure,
    _check_header_size,
    _hostname,
    _is_global_address,
    detect_web,
    format_plan,
    load_allowlist,
    read_body,
)
from cvebeacon_extensions.webrules import RULES, detect, normalize_version, page_from

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
PUBLIC = "93.184.216.34"
REAL_CONNECT = socket.socket.__mro__[1].connect


@pytest.fixture(autouse=True)
def fixed_contract_clock(monkeypatch):
    monkeypatch.setattr(contract, "utc_now", lambda: NOW)


def asset(**overrides):
    value = {
        "hostname": "example.com",
        "authorized_by": "Security Team",
        "authorized_at": "2026-11-01T00:00:00Z",
        "expires_at": "2027-11-01T00:00:00Z",
    }
    value.update(overrides)
    return value


def write_allowlist(tmp_path, assets=None, name="assets.json", **top):
    document = {"client": "acme", "assets": [asset()] if assets is None else assets}
    document.update(top)
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class Resolver:
    def __init__(self, mapping=None, default=None):
        self.mapping = mapping or {}
        self.default = default
        self.calls = []

    def resolve(self, hostname, port):
        self.calls.append((hostname, port))
        value = self.mapping.get(hostname, self.default)
        if value is None:
            value = [PUBLIC]
        if isinstance(value, Exception):
            raise value
        return tuple(value)


class Transport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def fetch(self, endpoint, address, *, ca_bundle, deadline, user_agent):
        self.calls.append((endpoint, address, ca_bundle, user_agent))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def response(status=200, headers=None, body=b"<html>plain</html>"):
    values = {}
    for name, value in (headers or {}).items():
        values[name.casefold()] = tuple(value) if isinstance(value, (list, tuple)) else (value,)
    return _Response(status, values, body)


class _LocalHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(10)
            data = self.request.recv(65536)
            self.server.requests.append(data)
            self.server.responder(self.request, data)
        except OSError:
            pass


class _LocalServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, responder):
        self.responder = responder
        self.requests = []
        super().__init__(("127.0.0.1", 0), _LocalHandler)

    def handle_error(self, request, client_address):
        pass


@contextmanager
def local_server(monkeypatch, responder):
    monkeypatch.setattr(socket.socket, "connect", REAL_CONNECT)
    server = _LocalServer(responder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _TlsLocalServer(_LocalServer):
    def __init__(self, responder, context):
        self.context = context
        super().__init__(responder)

    def get_request(self):
        sock, address = super().get_request()
        return self.context.wrap_socket(sock, server_side=True), address


@contextmanager
def local_tls_server(monkeypatch, responder, certfile, keyfile):
    monkeypatch.setattr(socket.socket, "connect", REAL_CONNECT)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certfile), str(keyfile))
    server = _TlsLocalServer(responder, context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def local_endpoint(server, *, scheme="http", path="/"):
    return Endpoint(scheme, "127.0.0.1", server.server_address[1], path)


def make_certificate(directory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is not available")
    certfile = directory / "cert.pem"
    keyfile = directory / "key.pem"
    completed = subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(keyfile),
         "-out", str(certfile), "-days", "1", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        capture_output=True, text=True,
    )
    if completed.returncode != 0:
        pytest.skip("openssl could not create a test certificate")
    return certfile, keyfile


def run(tmp_path, assets, responses, *, mapping=None, allow_partial=True, client="acme",
        max_workers=1, **kwargs):
    path = write_allowlist(tmp_path, assets)
    resolver = Resolver(mapping)
    transport = Transport(responses)
    output = tmp_path / "snapshot.json"
    result = detect_web(path, output, client=client, source_id=f"{client}-web",
                        allow_partial=allow_partial, resolver=resolver, transport=transport,
                        now=lambda: NOW, host_interval=0, max_workers=max_workers, **kwargs)
    return result, output, resolver, transport


def fixture_page(fixture):
    headers = {}
    html = ""
    if "header" in fixture:
        name, value = fixture["header"]
        headers[name] = [value]
    if "cookie" in fixture:
        headers.setdefault("set-cookie", []).append(f"{fixture['cookie']}=value; Path=/")
    if "meta" in fixture:
        html += f'<meta name="generator" content="{fixture["meta"]}">'
    if "url" in fixture:
        html += f'<script src="{fixture["url"]}"></script>'
    if "html" in fixture:
        html += fixture["html"]
    return page_from(headers, html)


FIXTURES = {
    "nginx": ({"header": ("server", "nginx/1.25.3")}, "1.25.3"),
    "apache-http-server": ({"header": ("server", "Apache/2.4.52 (Ubuntu)")}, "2.4.52"),
    "microsoft-iis": ({"header": ("server", "Microsoft-IIS/10.0")}, "10.0"),
    "litespeed": ({"header": ("server", "LiteSpeed/6.1.1")}, "6.1.1"),
    "openresty": ({"header": ("server", "openresty/1.21.4.3")}, "1.21.4.3"),
    "caddy": ({"header": ("server", "Caddy/2.7.6")}, "2.7.6"),
    "apache-tomcat": ({"header": ("server", "Apache-Coyote/1.1")}, ""),
    "jetty": ({"header": ("server", "Jetty(9.4.43.v20210629)")}, "9.4.43"),
    "wildfly": ({"header": ("server", "WildFly/26.1.2.Final")}, "26.1.2"),
    "weblogic": ({"header": ("server", "WebLogic Server 12.2.1.3.0")}, ""),
    "websphere": ({"header": ("server", "WebSphere Application Server/9.0.5.13")}, "9.0.5.13"),
    "glassfish": ({"header": ("server", "GlassFish Server Open Source Edition 5.1.0")}, "5.1.0"),
    "php-header": ({"header": ("x-powered-by", "PHP/8.2.1")}, "8.2.1"),
    "php-session": ({"cookie": "PHPSESSID"}, ""),
    "aspnet-version": ({"header": ("x-aspnet-version", "4.0.30319")}, "4.0.30319"),
    "aspnet-powered-by": ({"header": ("x-powered-by", "ASP.NET")}, ""),
    "express": ({"header": ("x-powered-by", "Express")}, ""),
    "laravel": ({"cookie": "laravel_session"}, ""),
    "nextjs": ({"html": '<script id="__NEXT_DATA__" type="application/json">{}</script>'}, ""),
    "nuxt": ({"html": "<script>window.__NUXT__={}</script>"}, ""),
    "react": ({"url": "https://cdn.example/react@18.2.0/umd/react.production.min.js"}, "18.2.0"),
    "angular": ({"html": '<app-root ng-version="16.2.12"></app-root>'}, "16.2.12"),
    "vue": ({"url": "https://cdn.example/vue@3.3.4/dist/vue.global.prod.js"}, "3.3.4"),
    "svelte": ({"url": "https://cdn.example/svelte@4.2.0/svelte.min.js"}, "4.2.0"),
    "jquery": ({"url": "https://cdn.example/jquery-3.7.1.min.js"}, "3.7.1"),
    "bootstrap": ({"url": "https://cdn.example/bootstrap-5.3.2.min.css"}, "5.3.2"),
    "wordpress": ({"meta": "WordPress 6.4.2"}, "6.4.2"),
    "drupal": ({"meta": "Drupal 10 (https://www.drupal.org)"}, "10"),
    "joomla": ({"meta": "Joomla! 4.3.2"}, "4.3.2"),
    "magento": ({"header": ("x-magento-tags", "catalog_product_123")}, ""),
    "prestashop": ({"meta": "PrestaShop 8.1.2"}, "8.1.2"),
    "shopify": ({"header": ("x-shopid", "1234567")}, ""),
    "ghost": ({"meta": "Ghost 5.75.0"}, "5.75.0"),
    "typo3": ({"meta": "TYPO3 CMS 12.4.5"}, "12.4.5"),
    "umbraco": ({"cookie": "UMB-XSRF-TOKEN"}, ""),
    "sitecore": ({"cookie": "SC_ANALYTICS_GLOBAL_COOKIE"}, ""),
    "adobe-experience-manager": ({"html": '<link rel="stylesheet" href="/etc.clientlibs/site.css">'}, ""),
    "sharepoint": ({"header": ("microsoftsharepointteamservices", "16.0.0.10337")}, ""),
    "cloudflare": ({"header": ("cf-ray", "8a1b2c3d4e5f6a7b-AMS")}, ""),
    "akamai": ({"header": ("server", "AkamaiGHost")}, ""),
    "fastly": ({"header": ("x-fastly-request-id", "a1b2c3d4e5f6")}, ""),
    "f5-big-ip": ({"cookie": "BIGipServerpool_web"}, ""),
    "citrix-netscaler": ({"cookie": "NSC_AAAC_1234"}, ""),
    "confluence": ({"html": '<meta name="ajs-product-name" content="Confluence"><meta name="ajs-version-number" content="8.5.4">'}, "8.5.4"),
    "jira": ({"html": '<meta name="ajs-product-name" content="Jira"><meta name="ajs-version-number" content="9.4.0">'}, "9.4.0"),
    "elasticsearch": ({"header": ("x-elastic-product", "Elasticsearch")}, ""),
    "kibana": ({"header": ("kbn-version", "8.10.2")}, "8.10.2"),
    "grafana": ({"cookie": "grafana_session"}, ""),
    "jenkins": ({"header": ("x-jenkins", "2.414.1")}, "2.414.1"),
    "gitlab": ({"cookie": "_gitlab_session"}, ""),
    "phpmyadmin": ({"cookie": "phpMyAdmin"}, ""),
    "cpanel": ({"header": ("server", "cpsrvd/11.110.0.14")}, "11.110.0.14"),
    "plesk": ({"header": ("server", "sw-cp-server")}, ""),
    "webmin": ({"header": ("server", "MiniServ/2.111")}, "2.111"),
}


def nonmatch(rule):
    if rule.key == "magento":
        return {}
    if rule.kind == "header":
        return {"header": (rule.subject, "unrelated/1.0")}
    if rule.kind == "cookie":
        return {"cookie": "unrelated_session"}
    if rule.kind == "meta":
        return {"meta": "Unrelated CMS 1.0"}
    if rule.kind == "url":
        return {"url": "https://cdn.example/unrelated-1.0.min.js"}
    return {"html": "<html><body>unrelated</body></html>"}


def matching(detections, rule):
    return [item for item in detections
            if item.vendor.casefold() == rule.vendor.casefold()
            and item.product.casefold() == rule.product.casefold()]


def test_every_rule_has_a_match_and_nonmatch_fixture():
    assert set(FIXTURES) == {rule.key for rule in RULES}
    for rule in RULES:
        fixture, expected = FIXTURES[rule.key]
        found = matching(detect(fixture_page(fixture)), rule)
        assert found, rule.key
        assert found[0].versions == ((expected,) if expected else ()), rule.key
        assert not matching(detect(fixture_page(nonmatch(rule))), rule), rule.key


def test_detection_is_direct_evidence_only():
    page = fixture_page({"meta": "WordPress 6.4.2"})
    found = {item.product for item in detect(page)}
    assert found == {"wordpress"}


@pytest.mark.parametrize("value,expected", [
    ("nginx/1.25.3", "1.25.3"),
    ("Apache/2.4.52 (Ubuntu)", "2.4.52"),
    ("PHP/8.2.1", "8.2.1"),
    ("WordPress 6.4.2", "6.4.2"),
    ("v2.0.1", "2.0.1"),
    ("1.2.3-beta1", "1.2.3-beta1"),
    ("*", ""),
    ("-", ""),
    ("unknown", ""),
    ("latest", ""),
    ("n/a", ""),
    ("all", ""),
    ("1.2 - 1.3", ""),
    ("1.2.3.4.5", ""),
    ("9.4.43.v20210629", ""),
    ("", ""),
    (None, ""),
])
def test_version_normalisation(value, expected):
    assert normalize_version(value) == expected


def test_five_component_server_version_is_unknown_not_truncated():
    page = fixture_page({"header": ("server", "WebLogic Server 12.2.1.3.0")})
    found = matching(detect(page), next(rule for rule in RULES if rule.key == "weblogic"))
    assert found and found[0].versions == ()


def test_prefix_compatible_versions_prefer_the_most_specific(tmp_path):
    manifest, output, resolver, transport = run(
        tmp_path, [asset()],
        [response(headers={"server": ["nginx/1.25.3", "nginx/1.25"]})],
        allow_partial=False)
    assert manifest["status"] == "success"
    records = read_snapshot(output).records
    nginx = [row for row in records if row["product"] == "nginx"]
    assert nginx[0]["version"] == "1.25.3"
    review = json.loads(Path(str(output) + ".review.json").read_bytes())
    assert review["reviews"] == []


def test_disjoint_versions_still_require_review(tmp_path):
    with pytest.raises(ExtensionError, match="no technologies"):
        run(tmp_path, [asset()],
            [response(headers={"server": ["nginx/1.25.3", "nginx/1.26.0"]})],
            allow_partial=True)
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "version-conflict"


def test_every_rule_cpe_is_accepted_by_the_core_parser():
    from cvebeacon.sources.nvd import split_cpe23
    for rule in RULES:
        if not rule.cpe:
            continue
        fields = split_cpe23(rule.cpe)
        assert len(fields) == 11
        assert fields[3] == "*"
        assert fields[1] not in {"*", "-"} and fields[2] not in {"*", "-"}


@pytest.mark.parametrize("cpe", [
    "cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:acme",
    "cpe:2.3:z:acme:widget:*:*:*:*:*:*:*:*",
])
def test_fabricated_or_incomplete_rule_cpes_fail_import(cpe):
    from cvebeacon_extensions import webrules
    with pytest.raises(ValueError):
        webrules._validated_cpe(cpe)


def test_allowlist_accepts_hostname_and_url_forms(tmp_path):
    path = write_allowlist(tmp_path, [
        asset(hostname="example.com", path="/status"),
        {**asset(), "hostname": "second.example", "scheme": "http", "port": 8080,
         "max_redirects": 1, "allow_redirects": True, "allow_private_address": True},
        {"url": "https://third.example/login", "authorized_by": "Owner",
         "authorized_at": "2026-11-01T00:00:00Z"},
    ])
    loaded = load_allowlist(path, client="acme", now=NOW)
    assert loaded.assets[0].endpoint.url == "https://example.com/status"
    assert loaded.assets[1].endpoint.url == "http://second.example:8080/"
    assert loaded.assets[1].max_redirects == 1
    assert loaded.assets[2].endpoint.url == "https://third.example/login"


@pytest.mark.parametrize("change", [
    {"authorized_by": ""},
    {"authorized_by": None},
    {"authorized_at": None},
    {"authorized_at": "2027-01-01T00:00:00Z"},
    {"expires_at": "2026-11-01T00:00:00Z"},
    {"hostname": "*.example.com"},
    {"hostname": "10.0.0.0/8"},
    {"hostname": "bad/name"},
    {"url": "https://example.com/?a=1"},
    {"url": "https://user:pass@example.com/"},
    {"scheme": "ftp"},
    {"max_redirects": 3},
    {"allow_redirects": "yes"},
    {"allow_private_address": 1},
    {"path": "/has space"},
])
def test_allowlist_refuses_unsafe_or_unattested_entries(tmp_path, change):
    path = write_allowlist(tmp_path, [asset(**change)])
    with pytest.raises(ExtensionError):
        load_allowlist(path, client="acme", now=NOW)


@pytest.mark.parametrize("url", ["https://[bad/", "https://example.com:99999/", "https://exa mple.com/"])
def test_allowlist_refuses_malformed_urls(tmp_path, url):
    path = write_allowlist(tmp_path, [{"url": url, "authorized_by": "Owner",
                                       "authorized_at": "2026-11-01T00:00:00Z"}])
    with pytest.raises(ExtensionError):
        load_allowlist(path, client="acme", now=NOW)


def test_allowlist_refuses_client_mismatch_unknown_fields_duplicates_and_expiry(tmp_path):
    path = write_allowlist(tmp_path, [asset()], client="other")
    with pytest.raises(ExtensionError, match="different client"):
        load_allowlist(path, client="acme", now=NOW)
    path = write_allowlist(tmp_path, [asset()], extra=True)
    with pytest.raises(ExtensionError, match="unknown fields"):
        load_allowlist(path, client="acme", now=NOW)
    path = write_allowlist(tmp_path, [asset(), asset()])
    with pytest.raises(ExtensionError, match="duplicates"):
        load_allowlist(path, client="acme", now=NOW)
    path = write_allowlist(tmp_path, [asset(expires_at="2026-11-05T12:00:00Z")])
    with pytest.raises(ExtensionError, match="expired"):
        load_allowlist(path, client="acme", now=NOW)


def test_allowlist_limit_and_ca_bundle(tmp_path, monkeypatch):
    from cvebeacon_extensions import web
    path = write_allowlist(tmp_path, [asset(hostname=f"host{i}.example") for i in range(3)])
    monkeypatch.setattr(web, "MAX_ASSETS", 2)
    with pytest.raises(ExtensionError, match="at most 2"):
        load_allowlist(path, client="acme", now=NOW)
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder", encoding="utf-8")
    path = write_allowlist(tmp_path, [asset()], ca_bundle="ca.pem")
    assert load_allowlist(path, client="acme", now=NOW).ca_bundle == ca.resolve()


def test_ca_bundle_symlink_is_refused(tmp_path):
    target = tmp_path / "real-ca.pem"
    target.write_text("placeholder", encoding="utf-8")
    link = tmp_path / "ca.pem"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are not available")
    path = write_allowlist(tmp_path, [asset()], ca_bundle="ca.pem")
    with pytest.raises(ExtensionError, match="regular file"):
        load_allowlist(path, client="acme", now=NOW)


def test_output_cannot_overwrite_the_ca_bundle(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder", encoding="utf-8")
    path = write_allowlist(tmp_path, [asset()], ca_bundle="ca.pem")
    transport = Transport([response(headers={"server": "nginx/1.25.3"})])
    with pytest.raises(ExtensionError, match="CA bundle"):
        detect_web(path, ca, client="acme", source_id="acme-web", allow_partial=False,
                   resolver=Resolver({"example.com": [PUBLIC]}), transport=transport,
                   now=lambda: NOW, host_interval=0, max_workers=1)
    assert ca.read_text(encoding="utf-8") == "placeholder"
    assert transport.calls == []


def test_ca_bundle_adds_to_default_roots(tmp_path):
    certfile, keyfile = make_certificate(tmp_path)
    context = StdlibTransport._context(certfile)
    defaults = ssl.create_default_context().get_ca_certs()
    if not defaults:
        pytest.skip("the platform has no default trust roots")
    assert len(context.get_ca_certs()) >= len(defaults) + 1


def test_real_tls_uses_the_client_ca_bundle(tmp_path, monkeypatch):
    certfile, keyfile = make_certificate(tmp_path)

    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 2\r\n\r\nok")

    with local_tls_server(monkeypatch, responder, certfile, keyfile) as server:
        endpoint = Endpoint("https", "127.0.0.1", server.server_address[1], "/")
        response = StdlibTransport().fetch(endpoint, "127.0.0.1", ca_bundle=certfile,
                                           deadline=time.monotonic() + 10, user_agent="test")
        assert response.status == 200
        assert response.headers["server"] == ("nginx/1.25.3",)


def test_real_tls_without_the_client_ca_is_a_tls_error(tmp_path, monkeypatch):
    certfile, keyfile = make_certificate(tmp_path)

    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    with local_tls_server(monkeypatch, responder, certfile, keyfile) as server:
        endpoint = Endpoint("https", "127.0.0.1", server.server_address[1], "/")
        with pytest.raises(_TlsFailure):
            StdlibTransport().fetch(endpoint, "127.0.0.1", ca_bundle=None,
                                    deadline=time.monotonic() + 10, user_agent="test")




@pytest.mark.parametrize("hostname", ["2130706433", "0x7f000001", "127.1", "0177.0.0.1"])
def test_numeric_loopback_spellings_are_blocked_without_attestation(tmp_path, hostname):
    path = write_allowlist(tmp_path, [asset(hostname=hostname)])
    assert load_allowlist(path, client="acme", now=NOW).assets[0].endpoint.hostname == "127.0.0.1"
    transport = Transport([response()])
    output = tmp_path / "snapshot.json"
    with pytest.raises(ExtensionError, match="review"):
        detect_web(path, output, client="acme", source_id="acme-web", allow_partial=True,
                   resolver=Resolver({"127.0.0.1": ["127.0.0.1"]}), transport=transport,
                   now=lambda: NOW, host_interval=0, max_workers=1)
    assert transport.calls == []
    reviews = json.loads(Path(str(output) + ".review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "blocked"


@pytest.mark.parametrize("address", [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "224.0.0.1",
    "255.255.255.255",
    "192.0.2.10",
    "0.0.0.0",
    "::1",
    "::ffff:127.0.0.1",
    "::127.0.0.1",
    "::ffff:8.8.8.8",
    "::8.8.8.8",
    "2002:0808:0808::1",
    "64:ff9b::7f00:1",
    "2002:7f00:1::",
    "fd00::1",
    "fe80::1",
    "ff02::1",
])
def test_ssrf_matrix_blocks_every_non_global_answer(tmp_path, address):
    assert _is_global_address(address) is False
    path = write_allowlist(tmp_path, [asset()])
    transport = Transport([response()])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [address]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    assert transport.calls == []


def test_ssrf_matrix_blocks_before_transport(tmp_path):
    path = write_allowlist(tmp_path, [asset()])
    transport = Transport([response()])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": ["10.0.0.1"]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    assert transport.calls == []


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "10.0.0.1", "169.254.169.254",
                                      "fe80::1", "::ffff:8.8.8.8", "::8.8.8.8"])
def test_private_address_attestation_allows_internal_sites(tmp_path, address):
    manifest, output, resolver, transport = run(
        tmp_path, [asset(allow_private_address=True)],
        [response(headers={"server": "nginx/1.25.3"})],
        mapping={"example.com": [address]})
    assert manifest["status"] == "success"
    assert len(transport.calls) == 1
    assert transport.calls[0][0].hostname == "example.com"


def test_dns_rebinding_between_redirects_is_blocked(tmp_path):
    path = write_allowlist(tmp_path, [asset()])
    calls = []

    class Rebinding:
        def resolve(self, hostname, port):
            calls.append(hostname)
            return (PUBLIC,) if len(calls) == 1 else ("127.0.0.1",)

    transport = Transport([response(302, {"location": "https://example.com/next"})])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Rebinding(), transport=transport,
                   now=lambda: NOW, host_interval=0, max_workers=1)
    assert len(calls) == 2
    assert len(transport.calls) == 1
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "blocked"


def test_redirect_to_private_address_is_blocked(tmp_path):
    assets = [asset(), asset(hostname="internal.example.com")]
    path = write_allowlist(tmp_path, assets)
    resolver = Resolver({"example.com": [PUBLIC], "internal.example.com": ["127.0.0.1"]})
    transport = Transport([response(302, {"location": "https://internal.example.com/"})])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=resolver, transport=transport,
                   now=lambda: NOW, host_interval=0, max_workers=1)
    assert len(transport.calls) == 1
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "blocked"


@pytest.mark.parametrize("location", [
    "https://[bad/", "https://example.com:99999/", "https://example.com/bad path",
    "https://bad_host/", "https://example.com:0/",
    "https://user:pass@example.com/", "https://example.com/path#fragment",
])
def test_redirect_with_invalid_location_is_blocked(tmp_path, location):
    path = write_allowlist(tmp_path, [asset()])
    transport = Transport([response(302, {"location": location})])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "redirect-blocked"


def test_redirect_to_unlisted_same_domain_host_is_blocked(tmp_path):
    path = write_allowlist(tmp_path, [asset()])
    transport = Transport([response(302, {"location": "https://www.example.com/"})])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "redirect-blocked"


def test_redirect_may_change_path_and_query_on_an_authorised_host(tmp_path):
    manifest, output, resolver, transport = run(
        tmp_path, [asset(path="/approved")],
        [response(302, {"location": "/unapproved?token=canary"}),
         response(headers={"server": "nginx/1.25.3"})],
        allow_partial=False)
    assert manifest["status"] == "success"
    assert [call[0].path for call in transport.calls] == ["/approved", "/unapproved?token=canary"]


def test_redirect_path_and_query_are_bounded(tmp_path):
    location = "/" + "a" * 3000
    path = write_allowlist(tmp_path, [asset()])
    transport = Transport([response(302, {"location": location})])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    assert len(transport.calls) == 1
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "redirect-blocked"


def test_redirect_policy_comes_from_the_originating_entry(tmp_path):
    assets = [asset(path="/start", max_redirects=2),
              asset(hostname="second.example", path="/middle", max_redirects=0)]
    manifest, output, resolver, transport = run(
        tmp_path, assets,
        [response(302, {"location": "https://second.example/middle"}),
         response(302, {"location": "https://second.example/end"}),
         response(headers={"server": "nginx/1.25.3"}),
         response(headers={"server": "nginx/1.25.3"})],
        mapping={"example.com": [PUBLIC], "second.example": [PUBLIC]},
        allow_partial=False)
    assert manifest["status"] == "success"
    assert [call[0].path for call in transport.calls[:3]] == ["/start", "/middle", "/end"]


def test_redirect_private_address_policy_comes_from_the_originating_entry(tmp_path):
    assets = [asset(path="/start"),
              asset(hostname="internal.example.com", allow_private_address=True)]
    path = write_allowlist(tmp_path, assets)
    resolver = Resolver({"example.com": [PUBLIC], "internal.example.com": ["127.0.0.1"]})
    transport = Transport([response(302, {"location": "https://internal.example.com/"}),
                           response(403), response(403)])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=resolver, transport=transport,
                   now=lambda: NOW, host_interval=0, max_workers=1)
    assert len(transport.calls) == 2
    assert transport.calls[0][0].hostname == "example.com"
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert [item["reason"] for item in reviews] == ["blocked", "blocked"]


def test_redirect_to_other_domain_and_scheme_downgrade_are_blocked(tmp_path):
    path = write_allowlist(tmp_path, [asset(), asset(scheme="http")])
    transport = Transport([response(302, {"location": "http://example.com/"}),
                           response(302, {"location": "https://other.test/"})])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert [item["reason"] for item in reviews] == ["redirect-blocked", "redirect-blocked"]
    assert len(transport.calls) == 2


def test_redirect_limit_and_disabled_redirects(tmp_path):
    path = write_allowlist(tmp_path, [asset(max_redirects=2)])
    transport = Transport([response(302, {"location": "/a"}), response(302, {"location": "/b"}),
                           response(302, {"location": "/c"})])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    assert len(transport.calls) == 3
    path = write_allowlist(tmp_path, [asset(allow_redirects=False)], name="assets2.json")
    transport = Transport([response(302, {"location": "/a"})])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot2.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    assert len(transport.calls) == 1


def test_header_and_body_limits_and_gzip_bomb():
    with pytest.raises(_TooLargeFailure):
        _check_header_size([("x-large", "a" * HEADER_LIMIT)])
    with pytest.raises(_TooLargeFailure):
        read_body(io.BytesIO(b"x" * (BODY_LIMIT + 1)), "")
    bomb = gzip.compress(b"\0" * (BODY_LIMIT + 1))
    assert len(bomb) < BODY_LIMIT
    with pytest.raises(_TooLargeFailure):
        read_body(io.BytesIO(bomb), "gzip")


def test_slow_response_maps_to_timeout():
    ticks = iter([0.0, 1.0, 100.0])
    class Reader:
        def read(self, size):
            return b"x"
    with pytest.raises(_TimeoutFailure):
        read_body(Reader(), "", deadline=50.0, clock=lambda: next(ticks))


def test_slow_dns_resolution_is_bounded_by_the_asset_deadline(tmp_path, monkeypatch):
    from cvebeacon_extensions import web

    class SlowResolver:
        def resolve(self, hostname, port):
            time.sleep(0.4)
            return (PUBLIC,)

    path = write_allowlist(tmp_path, [asset()])
    allowlist = load_allowlist(path, client="acme", now=NOW)
    monkeypatch.setattr(web, "ASSET_TIMEOUT", 0.15)
    fetcher = Fetcher(resolver=SlowResolver(), transport=Transport([]), host_interval=0)
    started = time.monotonic()
    with pytest.raises(_TimeoutFailure):
        fetcher.fetch(allowlist.assets[0], allowlist)
    assert time.monotonic() - started < 0.35


def test_slow_headers_are_bounded_by_the_deadline(monkeypatch):
    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 200 OK\r\n")
        for _ in range(100):
            sock.sendall(b"X")
            time.sleep(0.02)

    with local_server(monkeypatch, responder) as server:
        transport = StdlibTransport()
        started = time.monotonic()
        with pytest.raises(_TimeoutFailure):
            transport.fetch(local_endpoint(server), "127.0.0.1", ca_bundle=None,
                            deadline=time.monotonic() + 0.25, user_agent="test")
        assert time.monotonic() - started < 1.0


def test_slow_body_is_bounded_by_the_deadline(monkeypatch):
    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
        for _ in range(100):
            sock.sendall(b"x")
            time.sleep(0.02)

    with local_server(monkeypatch, responder) as server:
        transport = StdlibTransport()
        started = time.monotonic()
        with pytest.raises(_TimeoutFailure):
            transport.fetch(local_endpoint(server), "127.0.0.1", ca_bundle=None,
                            deadline=time.monotonic() + 0.25, user_agent="test")
        assert time.monotonic() - started < 1.0


def test_pacing_wait_respects_the_asset_deadline():
    clock = [0.0]
    sleeps = []

    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    pacer = Fetcher(sleep=sleep, clock=lambda: clock[0], host_interval=5.0)._pacer
    pacer.wait("example.com", 10.0)
    with pytest.raises(_TimeoutFailure):
        pacer.wait("example.com", 2.0)
    assert sleeps == [2.0]



def test_deflate_roundtrip():
    import zlib
    payload = b"<html>ok</html>" * 100
    assert read_body(io.BytesIO(zlib.compress(payload)), "deflate") == payload


def test_truncated_compressed_stream_is_rejected():
    payload = gzip.compress(b"<html>complete</html>")
    with pytest.raises(_UnsupportedEncodingFailure):
        read_body(io.BytesIO(payload[:-4]), "gzip")
    import zlib
    with pytest.raises(_UnsupportedEncodingFailure):
        read_body(io.BytesIO(zlib.compress(b"<html>complete</html>")[:-4]), "deflate")


def test_concatenated_gzip_members_are_decoded_together():
    payload = gzip.compress(b"first") + gzip.compress(b"-second")
    assert read_body(io.BytesIO(payload), "gzip") == b"first-second"


def test_concatenated_gzip_members_share_one_output_cap():
    small = gzip.compress(b"tiny")
    bomb = gzip.compress(b"\0" * (BODY_LIMIT + 1))
    with pytest.raises(_TooLargeFailure):
        read_body(io.BytesIO(small + bomb), "gzip")



def test_429_stops_the_host_and_records_retry_after(tmp_path):
    assets = [asset(path="/one"), asset(path="/two")]
    path = write_allowlist(tmp_path, assets)
    transport = Transport([response(429, {"retry-after": "60"}), response(200)])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    assert len(transport.calls) == 1
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert [item["reason"] for item in reviews] == ["blocked", "blocked"]
    assert all(item.get("retry_after") == 60 for item in reviews)


@pytest.mark.parametrize("status,reason", [(401, "blocked"), (403, "blocked"), (404, "unreachable")])
def test_auth_and_not_found_responses_are_not_retried(tmp_path, status, reason):
    path = write_allowlist(tmp_path, [asset()])
    transport = Transport([response(status)])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    assert len(transport.calls) == 1
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == reason
    assert reviews[0]["status"] == status


def test_connection_errors_retry_twice_with_backoff(tmp_path):
    sleeps = []
    manifest, output, resolver, transport = run(
        tmp_path, [asset()],
        [_ConnectionFailure("connection reset"), _ConnectionFailure("connection reset"),
         response(headers={"server": "nginx/1.25.3"})],
        sleep=sleeps.append)
    assert manifest["status"] == "success"
    assert len(transport.calls) == 3
    assert len(sleeps) == 2


@pytest.mark.parametrize("failure,reason", [
    (_TlsFailure("certificate verify failed"), "tls-error"),
    (_TimeoutFailure("read timed out"), "timeout"),
    (_TooLargeFailure("body too large"), "too-large"),
    (_ConnectionFailure("connection refused"), "unreachable"),
])
def test_transport_failures_are_reviewed_not_clean(tmp_path, failure, reason):
    path = write_allowlist(tmp_path, [asset()])
    transport = Transport([failure, failure, failure])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == reason


def test_real_transport_bounds_headers_before_parsing(monkeypatch):
    state = {"sent": 0}
    line = b"X-Filler: " + b"a" * 60000 + b"\r\n"

    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 200 OK\r\n")
        try:
            for _ in range(100):
                sock.sendall(line)
                state["sent"] += len(line)
                time.sleep(0.001)
            sock.sendall(b"\r\n")
        except OSError:
            pass

    with local_server(monkeypatch, responder) as server:
        with pytest.raises(_TooLargeFailure):
            StdlibTransport().fetch(local_endpoint(server), "127.0.0.1", ca_bundle=None,
                                    deadline=time.monotonic() + 10, user_agent="test")
    assert state["sent"] < 2_000_000


def test_real_transport_counts_chunk_trailers_in_the_wire_budget(monkeypatch):
    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n")
        trailer = b"X-Trailer: " + b"a" * 60000 + b"\r\n"
        try:
            for _ in range(80):
                sock.sendall(trailer)
            sock.sendall(b"\r\n")
        except OSError:
            pass

    with local_server(monkeypatch, responder) as server:
        with pytest.raises(_TooLargeFailure):
            StdlibTransport().fetch(local_endpoint(server), "127.0.0.1", ca_bundle=None,
                                    deadline=time.monotonic() + 20, user_agent="test")


def test_real_transport_rejects_truncated_gzip(monkeypatch):
    payload = gzip.compress(b"<html>complete</html>")[:-4]

    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
                     + str(len(payload)).encode() + b"\r\n\r\n" + payload)

    with local_server(monkeypatch, responder) as server:
        with pytest.raises(_UnsupportedEncodingFailure):
            StdlibTransport().fetch(local_endpoint(server), "127.0.0.1", ca_bundle=None,
                                    deadline=time.monotonic() + 10, user_agent="test")


def test_real_transport_decodes_concatenated_gzip(monkeypatch):
    payload = gzip.compress(b"first") + gzip.compress(b"-second")

    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
                     + str(len(payload)).encode() + b"\r\n\r\n" + payload)

    with local_server(monkeypatch, responder) as server:
        response = StdlibTransport().fetch(local_endpoint(server), "127.0.0.1",
                                           ca_bundle=None, deadline=time.monotonic() + 10,
                                           user_agent="test")
    assert response.body == b"first-second"


def test_real_429_stops_the_host_before_reading_its_body(tmp_path, monkeypatch):
    def responder(sock, request):
        path = request.split(b" ", 2)[1]
        if path == b"/one":
            sock.sendall(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\n"
                         b"Content-Length: 3145728\r\n\r\n")
            try:
                for _ in range(48):
                    sock.sendall(b"x" * 65536)
            except OSError:
                pass
        else:
            sock.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 2\r\n\r\nok")

    with local_server(monkeypatch, responder) as server:
        port = server.server_address[1]
        assets = [
            asset(hostname="127.0.0.1", scheme="http", port=port, path="/one",
                  allow_private_address=True),
            asset(hostname="127.0.0.1", scheme="http", port=port, path="/two",
                  allow_private_address=True),
        ]
        path = write_allowlist(tmp_path, assets)
        with pytest.raises(ExtensionError):
            detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                       allow_partial=True, resolver=Resolver({"127.0.0.1": ["127.0.0.1"]}),
                       now=lambda: NOW, host_interval=0, max_workers=1)
        assert len(server.requests) == 1
        reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
        assert [item["reason"] for item in reviews] == ["blocked", "blocked"]
        assert all(item.get("retry_after") == 60 for item in reviews)


def test_real_403_with_broken_chunking_is_not_retried(tmp_path, monkeypatch):
    def responder(sock, request):
        sock.sendall(b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n")

    with local_server(monkeypatch, responder) as server:
        port = server.server_address[1]
        path = write_allowlist(tmp_path, [asset(hostname="127.0.0.1", scheme="http",
                                                port=port, allow_private_address=True)])
        with pytest.raises(ExtensionError):
            detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                       allow_partial=True, resolver=Resolver({"127.0.0.1": ["127.0.0.1"]}),
                       now=lambda: NOW, host_interval=0, max_workers=1)
        assert len(server.requests) == 1
        reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
        assert reviews[0]["reason"] == "blocked"
        assert reviews[0]["status"] == 403


def test_review_and_snapshot_share_the_output_lock(tmp_path):
    path = write_allowlist(tmp_path, [asset()])
    output = tmp_path / "snapshot.json"
    Path(str(output) + ".lock").write_text("held", encoding="utf-8")
    transport = Transport([response(headers={"server": "nginx/1.25.3"})])
    with pytest.raises(ExtensionError, match="locked"):
        detect_web(path, output, client="acme", source_id="acme-web", allow_partial=False,
                   resolver=Resolver({"example.com": [PUBLIC]}), transport=transport,
                   now=lambda: NOW, host_interval=0, max_workers=1)
    assert not Path(str(output) + ".review.json").exists()



def test_no_technologies_is_reviewed_and_never_published_as_empty_success(tmp_path):
    with pytest.raises(ExtensionError, match="no technologies"):
        run(tmp_path, [asset()], [response(body=b"<html>nothing here</html>")], allow_partial=True)
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "no-technologies"


def test_versionless_review_publishes_partial_without_fetch_failure(tmp_path):
    manifest, output, resolver, transport = run(
        tmp_path, [asset()], [response(headers={"x-powered-by": "PHP"})],
        allow_partial=False)
    assert manifest["status"] == "partial"
    assert "version-unknown" in manifest["omissions"]
    with pytest.raises(ExtensionError, match="partial"):
        read_snapshot(output)
    records = read_snapshot(output, allow_partial=True).records
    assert records[0]["version"] == ""
    assert records[0]["cpe"].startswith("cpe:2.3:a:php:php:")


def test_versionless_edge_technology_without_cpe_stays_in_review(tmp_path):
    with pytest.raises(ExtensionError, match="no technologies"):
        run(tmp_path, [asset()], [response(headers={"cf-ray": "8a1b2c3d4e5f6a7b-AMS"})],
            allow_partial=True)
    reviews = json.loads((tmp_path / "snapshot.json.review.json").read_bytes())["reviews"]
    assert reviews[0]["reason"] == "version-unknown"


def test_partial_run_requires_explicit_opt_in_and_preserves_previous_snapshot(tmp_path):
    manifest, output, resolver, transport = run(
        tmp_path, [asset()], [response(headers={"server": "nginx/1.25.3"})], allow_partial=False)
    assert manifest["status"] == "success"
    before = (output.read_bytes(), manifest_path(output).read_bytes())
    path = write_allowlist(tmp_path, [asset(), asset(hostname="second.example")], name="assets2.json")
    transport = Transport([response(headers={"server": "nginx/1.25.3"}), response(403)])
    with pytest.raises(ExtensionError, match="allow-partial"):
        detect_web(path, output, client="acme", source_id="acme-web", allow_partial=False,
                   resolver=Resolver({"example.com": [PUBLIC], "second.example": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    assert (output.read_bytes(), manifest_path(output).read_bytes()) == before


def test_partial_snapshot_roundtrips_through_validate_and_merge(tmp_path):
    manifest, output, resolver, transport = run(
        tmp_path, [asset(), asset(hostname="second.example")],
        [response(headers={"server": "nginx/1.25.3"}), response(403)],
        mapping={"example.com": [PUBLIC], "second.example": [PUBLIC]}, allow_partial=True)
    assert manifest["status"] == "partial"
    assert "blocked" in manifest["omissions"]
    with pytest.raises(ExtensionError, match="partial"):
        read_snapshot(output)
    assert main(["validate", str(output), "--allow-partial"]) == 0
    merged = tmp_path / "merged.json"
    assert merge_snapshots([output], merged, source_id="central", allow_partial=True)["record_count"] == 1
    assert read_snapshot(merged, allow_partial=True).manifest["status"] == "partial"


def test_plan_prints_requests_and_sends_nothing(tmp_path, capsys):
    path = write_allowlist(tmp_path, [asset(), asset(hostname="second.example", path="/status", max_redirects=1)])
    class Forbidden:
        def resolve(self, hostname, port):
            raise AssertionError("plan must not resolve")
    class ForbiddenTransport:
        def fetch(self, *args, **kwargs):
            raise AssertionError("plan must not send")
    output = tmp_path / "snapshot.json"
    assert main(["web", "detect", "--client", "acme", "--assets", str(path),
                 "--output", str(output), "--source-id", "acme-web", "--plan"]) == 0
    printed = capsys.readouterr().out
    assert "host=example.com" in printed and "port=443" in printed and "path=/status" in printed
    assert "max_requests=2" in printed
    assert "5 requests on the normal path" in printed
    assert f"up to {5 * (1 + MAX_RETRIES)} including connection retries" in printed
    assert not output.exists()
    assert detect_web(path, output, client="acme", source_id="acme-web", plan=True,
                      resolver=Forbidden(), transport=ForbiddenTransport()) is None


def test_golden_snapshot_and_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(contract, "utc_now", lambda: NOW)
    assets = [asset(hostname="one.example"), asset(hostname="two.example")]
    responses = [
        response(headers={"server": "nginx/1.25.3", "content-type": "text/html"},
                 body=b'<meta name="generator" content="WordPress 6.4.2">'
                      b'<script src="https://cdn.example/jquery-3.7.1.min.js"></script>'),
        response(headers={"server": "Apache/2.4.52 (Ubuntu)", "x-powered-by": "PHP/8.2.1"},
                 body=b"<html></html>"),
    ]
    manifest, output, resolver, transport = run(
        tmp_path, assets, responses,
        mapping={"one.example": [PUBLIC], "two.example": [PUBLIC]}, allow_partial=False)
    fixture = Path(__file__).parent / "fixtures" / "web"
    assert output.read_bytes() == (fixture / "golden-inventory.json").read_bytes()
    assert manifest_path(output).read_bytes() == (fixture / "golden-manifest.json").read_bytes()
    assert manifest["record_count"] == 5
    assert main(["validate", str(output)]) == 0
    merged = merge_snapshots([output], tmp_path / "merged.json", source_id="central")
    assert merged["record_count"] == 5


def test_review_file_is_refreshed_on_a_clean_run(tmp_path):
    manifest, output, resolver, transport = run(
        tmp_path, [asset()], [response(headers={"server": "nginx/1.25.3"})])
    review = json.loads(Path(str(output) + ".review.json").read_bytes())
    assert review["reviews"] == []
    assert manifest["status"] == "success"


def test_review_never_records_cookies_or_body_text(tmp_path):
    path = write_allowlist(tmp_path, [asset()])
    secret = "session-secret-canary"
    transport = Transport([response(403, {"set-cookie": f"sid={secret}; HttpOnly"},
                                    f"<html>{secret}</html>".encode())])
    with pytest.raises(ExtensionError):
        detect_web(path, tmp_path / "snapshot.json", client="acme", source_id="acme-web",
                   allow_partial=True, resolver=Resolver({"example.com": [PUBLIC]}),
                   transport=transport, now=lambda: NOW, host_interval=0, max_workers=1)
    review = (tmp_path / "snapshot.json.review.json").read_text(encoding="utf-8")
    assert secret not in review
    assert "set-cookie" not in review.casefold()


def test_client_label_with_spaces_is_preserved(tmp_path):
    path = write_allowlist(tmp_path, [asset()], client="Acme Corp")
    transport = Transport([response(headers={"server": "nginx/1.25.3"})])
    manifest = detect_web(path, tmp_path / "snapshot.json", client="Acme Corp",
                          source_id="acme-web", allow_partial=False,
                          resolver=Resolver({"example.com": [PUBLIC]}), transport=transport,
                          now=lambda: NOW, host_interval=0, max_workers=1)
    assert manifest["status"] == "success"
    assert read_snapshot(tmp_path / "snapshot.json").records[0]["client"] == "Acme Corp"


def test_endpoint_helpers():
    assert _hostname("[2001:db8::1]") == "2001:db8::1"
    with pytest.raises(Exception):
        _hostname("bad host")
    plan = format_plan(Allowlist("acme", None, ()))
    assert "assets: 0" in plan
