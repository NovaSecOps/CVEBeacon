"""Exercise configuration UX through a real serve process on scratch data."""

from __future__ import annotations

from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import tomllib

import httpx

from dashboard_config_smoke import PASSWORD, controls
from cvebeacon.dashboard_config import value


def smoke(directory):
    path = directory / "config.toml"
    path.write_text('[watch]\nenabled=true\nsources=["nvd"]\n[sources]\n' +
                    "\n".join(f"{name}_enabled=false" for name in
                              ("osv", "nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss")), encoding="utf-8")
    path.chmod(0o600)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen([sys.executable, "-m", "cvebeacon", "--config", str(path),
                                "serve", "--host", "127.0.0.1", "--port", str(port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=10) as client:
            import re
            def token(page):
                return re.search(r'name="csrf" value="([^"]+)"', page)[1]

            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError("serve exited before startup")
                try:
                    page = client.get("/bootstrap")
                    break
                except httpx.ConnectError:
                    time.sleep(0.1)
            else:
                raise AssertionError("serve did not start")
            assert client.post("/bootstrap", data={"csrf": token(page.text), "username": "admin", "password": PASSWORD}).status_code == 303

            def login():
                page = client.get("/login")
                assert client.post("/login", data={"csrf": token(page.text), "username": "admin", "password": PASSWORD}).status_code == 303

            def preview(section, **changes):
                page = client.get("/config/" + section)
                assert page.status_code == 200
                data = controls(page.text, "preview")
                data.update(changes)
                return client.post("/config/" + section, data=data)

            def confirm(section, page):
                assert page.status_code == 200, page.text
                data = controls(page.text, "confirm")
                if 'name="lockout"' in page.text:
                    data["lockout"] = "yes"
                response = client.post("/config/" + section, data=data)
                assert response.status_code == 303
                return response

            login()
            confirm("channels", preview("channels", g0_name="email", g0_host="smtp.example.com",
                                        g0_from="alerts@example.com", g0_to=" one@example.com, two@example.com, one@example.com "))
            assert client.get("/").status_code == 200
            assert tomllib.loads(path.read_text())["watch"]["channels"]["email"]["to"] == ["one@example.com", "two@example.com"]
            response = confirm("channels", preview("channels", g0_format="html"))
            assert client.get(response.headers["location"]).status_code == 200
            assert "Saved; takes effect on the next run" in client.get(response.headers["location"]).text
            assert client.get("/").status_code == 200
            bad = preview("rules", g0_name="example", g0_condition="{ kev = true }", g0_channels='["email"]')
            assert bad.status_code == 400
            assert "watch.rules[0].condition.kev must be one of cisa, eu, any" in bad.text
            assert "{ kev = true }" in bad.text
            recipients = ['"Doe, John" <john@example.com>']
            confirm("channels", preview("channels", g0_to=value(recipients)))
            confirm("channels", preview("channels"))
            assert tomllib.loads(path.read_text())["watch"]["channels"]["email"]["to"] == recipients
            pasted = "https://secret.example/token/SYNTHETIC-CREDENTIAL"
            for section, changes in [
                ("sources", {"g0_nvd_api_key_file": pasted, "g0_minimum_request_interval": "oops"}),
                ("watch", {"g0_initial": pasted}),
                ("rules", {"g0_name": "example", "g0_channels": '["email"]', "g0_condition": '{ kev = "' + pasted + '" }'}),
            ]:
                refused = preview(section, **changes)
                assert refused.status_code == 400
                assert pasted not in refused.text
            confirm("notifications", preview("notifications", g1_recipients='["example-distribution", "one@example.com, two@example.com"]'))
            confirm("notifications", preview("notifications"))
            assert tomllib.loads(path.read_text())["notifications"]["email"]["recipients"] == ["example-distribution", "one@example.com, two@example.com"]
            confirm("dashboard", preview("dashboard", g0_session_idle_seconds="120"))
            assert client.get("/").status_code == 303
            login()
            assert client.get("/").status_code == 200
    finally:
        process.terminate()
        try:
            process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


if __name__ == "__main__":
    with TemporaryDirectory(prefix="cvebeacon-config-ux-") as directory:
        smoke(Path(directory))
    print("PASS real serve: channel format preserves login, dashboard change ends login, exact KEV error, recipient round-trips, legacy recipients and credential-error redaction")
