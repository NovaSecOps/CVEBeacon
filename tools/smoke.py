"""Offline source/package acceptance checks from an independent working directory."""

import argparse
from contextlib import closing
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import socket
from http.cookiejar import CookieJar
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor, ProxyHandler, Request

from openpyxl import load_workbook
from werkzeug.security import generate_password_hash


def prepare(directory: Path) -> Path:
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "examples", directory / "examples")
    text = (root / "cvebeacon.example.toml").read_text(encoding="utf-8")
    for source in ("nvd", "cve", "euvd", "cisa_kev", "eu_kev", "epss", "osv"):
        text = text.replace(f"{source}_enabled = true", f"{source}_enabled = false")
    config = directory / "offline.toml"
    config.write_text(text, encoding="utf-8")
    return config


def smoke(directory: Path, executable: Path | None) -> None:
    config = prepare(directory)
    prefix = [str(executable)] if executable else [sys.executable, "-m", "cvebeacon"]
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(name, None)
    env.pop("CVEBEACON_DASHBOARD_PASSWORD_HASH", None)
    if executable:
        env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32") if os.name == "nt" else "/usr/bin:/bin"

    def check(args, expected=0):
        result = subprocess.run(prefix + args, cwd=directory, env=env, capture_output=True, text=True, timeout=120)
        assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
        print("PASS", " ".join(args))
        return result.stdout

    check(["--help"])
    check(["inventory", "inspect", "examples/inventory.xlsx"])
    common = ["--config", str(config)]
    for sample in ("offline.toml", "examples/json.toml", "examples/yaml.toml", "examples/xlsx.toml"):
        assert "valid:" in check(["--config", sample, "inventory", "validate"])
    assert json.loads(check(common + ["doctor"]))["state"] == "ok"
    check(common + ["scan", "--report", "xlsx"], 4)
    check(common + ["history"])
    health = json.loads(check(common + ["source-status"]))
    assert health and all(row["status"] == "disabled" for row in health)
    schedule = check(common + ["schedule", "install", "--every", "4", "--dry-run"])
    assert str(config.resolve()) in schedule, schedule
    if executable:
        assert str(executable) in schedule
    for fmt in ("json", "xlsx"):
        check(common + ["export", "--format", fmt, "--output", f"report.{fmt}"])
    payload = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    assert payload
    book = load_workbook(directory / "report.xlsx", read_only=True)
    assert book["Summary"]["H2"].value == "coverage_unknown"
    book.close()
    with closing(sqlite3.connect(directory / ".cvebeacon/state.db")) as db:
        assert db.execute("SELECT status FROM runs").fetchone()[0] == "failed"
        assert db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0
    serve_smoke(directory, prefix, common, env)
    password = "Synthetic package smoke password"
    env["CVEBEACON_DASHBOARD_PASSWORD_HASH"] = generate_password_hash(password)
    serve_smoke(directory, prefix, common, env, password=password)


def serve_smoke(directory, prefix, common, env, password=None):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
    base = f"http://127.0.0.1:{port}"
    def get(path):
        with opener.open(base + path, timeout=10) as response:
            assert response.status == 200
            return response.read().decode("utf-8")
    def state():
        with closing(sqlite3.connect(directory / ".cvebeacon/state.db")) as db:
            return list(db.iterdump())
    with (directory / "serve.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(prefix + common + ["serve", "--port", str(port)], cwd=directory, env=env,
                                   stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            deadline = time.monotonic() + 45
            while True:
                assert process.poll() is None, "dashboard exited before readiness"
                try:
                    assert ("Dashboard login" if password else "Monitoring overview") in get("/")
                    break
                except URLError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.2)
            if password:
                for path in ("/findings", "/history", "/assets", "/sources", "/query", "/reports"):
                    assert "Dashboard login" in get(path)
                token = re.search(r'name="csrf" value="([^"]+)"', get("/login"))[1]
                with opener.open(Request(base + "/login", data=urlencode({"csrf": token, "password": password}).encode("ascii")), timeout=15) as response:
                    assert "Monitoring overview" in response.read().decode("utf-8")
            for path in ("/findings", "/history", "/assets", "/query", "/reports", "/sources", "/static/dashboard.css"):
                get(path)
            before = state()
            for path, fields in (("/query", {"vendor": "Acme", "product": "Widget", "version": "unknown"}), ("/reports", {"format": "json"})):
                token = re.search(r'name="csrf" value="([^"]+)"', get(path))[1]
                request = Request(base + path, data=urlencode({"csrf": token, **fields}).encode("ascii"))
                with opener.open(request, timeout=15) as response:
                    assert response.status == 200
                    assert "coverage_unknown" in response.read().decode("utf-8")
            assert state() == before, "web investigation modified monitoring state"
            if password:
                token = re.search(r'name="csrf" value="([^"]+)"', get("/"))[1]
                with opener.open(Request(base + "/logout", data=urlencode({"csrf": token}).encode("ascii")), timeout=15) as response:
                    assert "Dashboard login" in response.read().decode("utf-8")
                assert "Dashboard login" in get("/findings")
            print("PASS serve: pages, static assets, manual query, report, monitoring-state isolation; auth=" + str(bool(password)))
        finally:
            if os.name == "nt" and process.poll() is None:
                # A one-file bundle has a bootloader parent and an application child.
                # Stop only this test's tree, so the child cannot retain the listener/log.
                stopped = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                                          "/PID", str(process.pid), "/T", "/F"], capture_output=True,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                assert stopped.returncode == 0 or process.poll() is not None, "could not stop test process tree"
            elif process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            with socket.socket() as probe:
                probe.settimeout(2)
                assert probe.connect_ex(("127.0.0.1", port)) != 0, "test dashboard listener remains running"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=lambda value: Path(value).resolve())
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="cvebeacon-smoke-") as temp:
        smoke(Path(temp), args.executable)
