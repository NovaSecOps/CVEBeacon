"""Exercise configuration saves and rollback over loopback HTTP on scratch data."""

from __future__ import annotations

import html
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import threading
import tomllib

import httpx
from werkzeug.serving import make_server, WSGIRequestHandler

from cvebeacon.config import load_config
from cvebeacon.dashboard import create_app


PASSWORD = "Synthetic local smoke password 123"
SECRET = "Synthetic local channel secret 456"


class QuietHandler(WSGIRequestHandler):
    def log_request(self, *args, **kwargs):
        pass


def controls(page, action):
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", page, re.S)
    source = next(source for source in forms if f'name="action" value="{action}"' in source)
    data = {}
    for tag in re.findall(r"<input\b[^>]*>", source):
        attributes = dict(re.findall(r'([\w-]+)="([^"]*)"', tag))
        if attributes.get("type") != "checkbox":
            data[attributes["name"]] = html.unescape(attributes.get("value", ""))
    for name, text in re.findall(r'<textarea name="([^"]+)"[^>]*>(.*?)</textarea>', source, re.S):
        data[name] = html.unescape(text)
    for name, contents in re.findall(r'<select name="([^"]+)"[^>]*>(.*?)</select>', source, re.S):
        options = re.findall(r"<option([^>]*)>(.*?)</option>", contents, re.S)
        attributes, text = next(((attr, text) for attr, text in options if "selected" in attr), options[0])
        match = re.search(r'value="([^"]*)"', attributes)
        data[name] = html.unescape(match[1] if match else text)
    return data


def smoke(directory):
    path = directory / "config.toml"
    path.write_text('[inventory]\npath="inventory.csv"\n[sources]\n' +
                    "\n".join(f"{name}_enabled=false" for name in
                              ("osv", "nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")), encoding="utf-8")
    path.chmod(0o600)
    (directory / "inventory.csv").write_text("asset_id,vendor,product,version\na,Example,Widget,1\n", encoding="utf-8")
    original = tomllib.loads(path.read_text())
    app = create_app(load_config(path))
    server = make_server("127.0.0.1", 0, app, threaded=True, request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{server.server_port}", trust_env=False, timeout=15) as client:
            def token(page):
                return re.search(r'name="csrf" value="([^"]+)"', page)[1]

            def login():
                page = client.get("/login")
                assert page.status_code == 200
                assert client.post("/login", data={"csrf": token(page.text), "username": "admin",
                                                   "password": PASSWORD}).status_code == 303

            page = client.get("/bootstrap")
            assert page.status_code == 200
            assert client.post("/bootstrap", data={"csrf": token(page.text), "username": "admin",
                                                   "password": PASSWORD}).status_code == 303
            login()

            def save(section, **changes):
                page = client.get("/config/" + section)
                assert page.status_code == 200
                data = controls(page.text, "preview")
                data.update(changes)
                page = client.post("/config/" + section, data=data)
                assert page.status_code == 200, "preview failed"
                assert SECRET not in page.text
                assert client.post("/config/" + section, data=controls(page.text, "confirm")).status_code == 303
                assert client.get("/").status_code == 303
                login()

            save("channels", g0_name="soc", g0_type="smtp", g0_host="smtp.example.invalid",
                 g0_from="alerts@example.invalid", g0_to='["soc@example.invalid"]',
                 g0_username="alerts", g0_password_file_new=SECRET)
            config = load_config(path)
            assert config.watch.channels[0].secret("password").file.read_text() == SECRET
            save("rules", g0_name="critical", g0_condition="{ cvss_min = 9.0 }",
                 g0_channels='["soc"]', g0_events='["match"]')
            assert load_config(path).watch.rules[0].name == "critical"
            page = client.get("/config/backups")
            data = controls(page.text, "preview")
            data["backup"] = sorted(app.extensions["dashboard_config"].backups())[0]
            page = client.post("/config/backups", data=data)
            assert page.status_code == 200 and SECRET not in page.text
            assert client.post("/config/backups", data=controls(page.text, "confirm")).status_code == 303
            assert tomllib.loads(path.read_text()) == original
            users = app.extensions["dashboard_users"]
            assert users.verify_audit() is None
            assert SECRET not in str(users.audit_entries())
            assert SECRET not in path.read_text()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        assert not thread.is_alive()


if __name__ == "__main__":
    with TemporaryDirectory(prefix="cvebeacon-config-smoke-") as directory:
        smoke(Path(directory))
    print("PASS configuration preview, file-secret channel, rule, reload and rollback over localhost")
