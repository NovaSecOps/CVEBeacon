"""Exercise web assets through a real dashboard CLI with loopback-only fixtures."""

from __future__ import annotations

from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time

import httpx

from cvebeacon.config import load_config
from cvebeacon.dashboard_config import dumps
from cvebeacon.web_assets import paths
from cvebeacon.web_inventory import decode_json, read_bytes, read_web_snapshot
from dashboard_config_smoke import controls

PASSWORD = "Synthetic local web dashboard password 123"
CLIENT = "Local Web Client"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests += 1
        body = b'<meta name="generator" content="WordPress 6.7.1"><p>Synthetic local fixture</p>'
        self.send_response(200)
        self.send_header("Server", "nginx/1.26.2")
        self.send_header("X-Powered-By", "PHP/8.3.12")
        self.send_header("Set-Cookie", "synthetic-secret=NEVER-PERSIST-COOKIE")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_fixture(stack, *, context=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.requests = 0
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def stop():
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    stack.callback(stop)
    return server


def smoke(directory):
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("openssl is required for the local HTTPS fixture")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-days", "1", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    config_path = directory / "config.toml"
    config_path.write_text(dumps({
        "inventory": {"path": "inventory.csv"},
        "state": {"database": "data/state.db"},
        "sources": {name + "_enabled": False for name in
                    ("osv", "nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")},
    }), encoding="utf-8")
    config_path.chmod(0o600)
    (directory / "inventory.csv").write_text("asset_id,vendor,product,version\nsupplied,Example,Widget,1\n", encoding="utf-8")
    with ExitStack() as stack:
        plain = start_fixture(stack)
        secure = start_fixture(stack, context=context)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        log = stack.enter_context((directory / "serve.log").open("wb"))
        process = subprocess.Popen([sys.executable, "-I", "-u", "-m", "cvebeacon", "--config", str(config_path),
                                    "serve", "--host", "127.0.0.1", "--port", str(port)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        def stop_process():
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        stack.callback(stop_process)
        client = stack.enter_context(httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=15))
        deadline = time.monotonic() + 15
        while True:
            try:
                page = client.get("/bootstrap")
                break
            except httpx.ConnectError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("local dashboard failed to start")
                time.sleep(0.05)

        def token(page):
            return re.search(r'name="csrf" value="([^"]+)"', page)[1]

        def login():
            page = client.get("/login")
            assert client.post("/login", data={"csrf": token(page.text), "username": "admin", "password": PASSWORD}).status_code == 303

        assert client.post("/bootstrap", data={"csrf": token(page.text), "username": "admin", "password": PASSWORD}).status_code == 303
        login()
        def account_token():
            return token(client.get("/account").text)

        for scheme, server in (("http", plain), ("https", secure)):
            page = client.get("/web-assets", params={"client": CLIENT})
            version = re.search(r'name="version" value="([^"]+)"', page.text)[1]
            response = client.post("/web-assets/save", data={
                "csrf": account_token(), "version": version, "client": CLIENT, "action": "add",
                "hostname": "127.0.0.1", "scheme": scheme, "port": str(server.server_port), "path": "/",
                "max_redirects": "0", "allow_private_address": "yes", "ca_bundle": str(cert), "attest": "yes",
            })
            assert response.status_code == 303, response.text
        assert plain.requests == secure.requests == 0

        def wait_job(location, *, code):
            deadline = time.monotonic() + 30
            while True:
                page = client.get(location)
                assert page.status_code == 200
                if '<dt>Status</dt><dd>queued</dd>' not in page.text and '<dt>Status</dt><dd>running</dd>' not in page.text:
                    assert f'<dt>Exit code</dt><dd>{code}' in page.text, page.text
                    return page
                assert time.monotonic() < deadline, "job did not finish"
                time.sleep(0.1)

        def web_job(action):
            response = client.post("/web-assets/run", data={"csrf": account_token(), "client": CLIENT, "action": action})
            assert response.status_code == 303, response.text
            return wait_job(response.headers["location"], code=0)

        page = web_job("web-plan")
        assert "planned requests:" in page.text
        assert plain.requests == secure.requests == 0
        print("PASS dashboard allowlist and plan: zero requests")
        web_job("web-detect")
        assert plain.requests == secure.requests == 1
        page = client.get("/web-assets", params={"client": CLIENT})
        assert page.status_code == 200
        assert "1.26.2" in page.text and "header" in page.text and "meta" in page.text
        assert "requests: 2" in page.text and "NEVER-PERSIST-COOKIE" not in page.text
        print("PASS real HTTP/HTTPS detection: two loopback requests, verified client CA, results metadata")
        config = load_config(config_path)
        _, output = paths(config, CLIENT)
        rows, manifest = read_web_snapshot(output)
        detail = decode_json(read_bytes(Path(str(output) + ".review.json")))
        assert all(asset.client == CLIENT for asset in rows)
        assert len(rows) == 6 and detail["run"]["request_count"] == 2
        assert "Synthetic local fixture" not in str(detail)
        print(f"Snapshot: {len(rows)} rows; status={manifest['status']}; products=" +
              ", ".join(sorted({row.product + ' ' + row.version for row in rows})))
        page = client.get("/config/inventory")
        data = controls(page.text, "preview")
        data.update(g0_web_snapshots="true", g0_path="")
        page = client.post("/config/inventory", data=data)
        assert page.status_code == 200, page.text
        data = controls(page.text, "confirm")
        assert client.post("/config/inventory", data=data).status_code == 303
        login()
        config = load_config(config_path)
        assert config.inventory.web_snapshots and config.inventory.path is None
        response = client.post("/operations/run", data={"csrf": account_token(), "operation": "scan"})
        assert response.status_code == 303, response.text
        wait_job(response.headers["location"], code=4)
        page = client.get("/assets")
        assert page.status_code == 200 and CLIENT in page.text and "nginx" in page.text
        assert plain.requests == secure.requests == 1
        print("PASS configuration save to web-only inventory, offline scan (exit 4), client on Assets")
        assert client.get("/audit").status_code == 200
        print("PASS no source sync, notification, installed schedule or external target")


if __name__ == "__main__":
    with TemporaryDirectory(prefix="cvebeacon-web-smoke-") as directory:
        smoke(Path(directory))
