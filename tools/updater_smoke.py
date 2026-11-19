"""Exercise signed native upgrades locally with real wheels and loopback HTTP.

Supply a prepared dependency wheelhouse. No external request is permitted by
the release transport. No systemd command or privileged path is used. The only
relaxed guard is root ownership: the scratch tree belongs to the invoking user.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
from urllib.parse import urlsplit

import httpx

from cvebeacon.config import HttpConfig, UpdateConfig, load_config
from cvebeacon.http import HttpClient
from cvebeacon import updater as u

ROOT = Path(__file__).resolve().parents[1]


def run(arguments, **kwargs):
    result = subprocess.run([str(a) for a in arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace")[-4000:])
    return result.stdout


def build(source, assets, version):
    for project in (source, source / "extensions", source / "automation"):
        text = (project / "pyproject.toml").read_text()
        import re
        text = re.sub(r'^version = "[^"]+"', f'version = "{version}"', text, count=1, flags=re.MULTILINE)
        (project / "pyproject.toml").write_text(text)
    run([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation", "--wheel-dir", assets,
         source, source / "extensions", source / "automation"])


class LocalTransport(httpx.BaseTransport):
    def __init__(self, port):
        self.port = port
        self.transport = httpx.HTTPTransport(trust_env=False)

    def handle_request(self, request):
        if request.url.host not in {"api.github.com", "github.com"}:
            raise AssertionError("acceptance check refused an external host")
        local = request.url.copy_with(scheme="http", host="127.0.0.1", port=self.port)
        forwarded = httpx.Request(request.method, local, headers={"Host": "127.0.0.1"}, stream=request.stream, extensions=request.extensions)
        return self.transport.handle_request(forwarded)

    def close(self):
        self.transport.close()


class ScratchNative(u.Native):
    def __init__(self, policy, port, log):
        super().__init__(policy)
        self.port, self.log, self.dashboard = port, log, None
        self.force_failure = False
        self.external_pid = None

    def active(self, unit):
        return True

    def stop(self, units):
        pass

    def freeze(self, units):
        if self.external_pid is not None:
            os.kill(self.external_pid, 15)
            self.external_pid = None
        if self.dashboard is not None:
            self.dashboard.terminate()
            self.dashboard.wait(timeout=15)
            self.dashboard = None

    def start(self, units):
        if self.policy.dashboard_unit not in units:
            return
        binary = self.policy.prefix / "current/.venv/bin/cvebeacon"
        self.dashboard = subprocess.Popen([str(binary), "--config", str(self.policy.config), "serve", "--host", "127.0.0.1", "--port", str(self.port)],
                                          env=u.SAFE_ENV, cwd="/", stdout=self.log, stderr=self.log)

    def managed_cron(self):
        pass  # Never read or change a real schedule in scratch acceptance.

    def dashboard_pid(self):
        if self.external_pid is not None:
            os.kill(self.external_pid, 0)
            return self.external_pid
        if self.dashboard is None or self.dashboard.poll() is not None:
            raise u.UpdateError("scratch dashboard is not running")
        return self.dashboard.pid

    def probe(self, expected_version=None):
        super().probe(expected_version)
        if self.force_failure and expected_version == "0.1.2":
            self.force_failure = False
            # Real health succeeded first. Modify all state to prove restoration.
            with sqlite3.connect(self.policy.data / "ledger.sqlite3") as db:
                db.execute("UPDATE sentinel SET value='failed migration'")
            raise u.UpdateError("forced failure after successful loopback health")


def acceptance(wheelhouse):
    with ExitStack() as stack:
        scratch = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="cvebeacon-update-acceptance-")))
        prefix, data, source = [scratch / name for name in ("prefix", "data", "source")]
        for path in (prefix, data, source):
            path.mkdir()
        data.chmod(0o700)
        for name in ("src", "extensions", "automation"):
            shutil.copytree(ROOT / name, source / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build", "dist", ".venv"))
        for name in ("pyproject.toml", "README.md", "LICENSE", "NOTICE"):
            shutil.copyfile(ROOT / name, source / name)
        key = scratch / "signing-key"
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
        signers = scratch / "signers"
        signers.write_text('cvebeacon-release namespaces="cvebeacon-release" ' + key.with_suffix(".pub").read_text())
        releases = {}
        for version in ("0.1.0", "0.1.1", "0.1.2"):
            assets = scratch / version
            assets.mkdir()
            for wheel in wheelhouse.glob("*.whl"):
                if not wheel.name.startswith("cvebeacon"):
                    shutil.copyfile(wheel, assets / wheel.name)
            build(source, assets, version)
            manifest = assets / "SHA256SUMS"
            import hashlib
            manifest.write_text("".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
                                        for path in sorted(assets.iterdir())))
            run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", "cvebeacon-release", manifest])
            releases[version] = assets
        print("Built and signed three local release versions.", flush=True)
        advertised = ["0.1.1"]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                path = urlsplit(self.path).path
                if path.startswith("/repos/"):
                    target = path.rsplit("/v", 1)[1] if "/tags/v" in path else advertised[0]
                    directory = releases[target]
                    row = {"tag_name": "v" + target, "draft": False, "prerelease": False, "body": "Local signed release",
                           "assets": [{"name": p.name} for p in directory.iterdir()]}
                    body = json.dumps(row if "/tags/" in path else [row]).encode()
                else:
                    version, name = path.split("/download/v", 1)[1].split("/", 1)
                    body = (releases[version] / name).read_bytes()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        stack.callback(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        stack.callback(server.shutdown)
        # Ask the OS for a free dashboard port; only a scratch dashboard binds it.
        import socket
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config_path = data / "cvebeacon.toml"
        config_path.write_text('[state]\ndatabase="state.db"\n[watch]\nenabled=true\ndatabase="watch.db"\nsources=["nvd"]\n[update]\nenabled=true\n')
        config_path.chmod(0o600)
        config = load_config(config_path)
        with sqlite3.connect(data / "ledger.sqlite3") as db:
            db.execute("CREATE TABLE sentinel(value)")
            db.execute("INSERT INTO sentinel VALUES ('preserved')")
        policy = u.Policy(prefix, config_path, data, pwd.getpwuid(os.geteuid()).pw_name,
                          signers=signers, probe=f"http://127.0.0.1:{port}/healthz")
        log = stack.enter_context((scratch / "dashboard.log").open("wb"))
        native = ScratchNative(policy, port, log)
        stack.callback(native.freeze, policy.units)
        native.install(prefix / ".venv", releases["0.1.0"], list(u.PACKAGES), "0.1.0")
        transport = stack.enter_context(httpx.Client(transport=LocalTransport(server.server_port)))
        http = HttpClient(HttpConfig(retries=0), client=transport)
        remote = u.Releases(UpdateConfig(enabled=True), http)
        # Ownership is tested separately. This harness is deliberately rootless.
        stack.enter_context(patch.object(u, "protected", lambda path, **kwargs: Path(path)))
        updater = u.Updater(policy, native, remote)
        assert updater.adopt()["version"] == "0.1.0"
        native.start(policy.units)
        native.probe("0.1.0")
        state = u.check(config, http=http)
        assert state["available"] == "0.1.1"
        assert updater.apply("0.1.1")["result"] == "updated"
        assert updater.current().name == "0.1.1"
        print("Adopt, API check, signature verification, offline install, migration and HTTP health passed.", flush=True)
        advertised[0] = "0.1.2"
        # A separate updater process dies after a real migration, before switch.
        context = scratch / "interruption.json"
        context.write_text(json.dumps({"prefix": str(prefix), "config": str(config_path), "data": str(data),
                                       "user": policy.user, "signers": str(signers), "port": port,
                                       "api_port": server.server_port, "dashboard_pid": native.dashboard.pid}))
        interrupted = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--interrupt-context", str(context)], stdout=log, stderr=log)
        if interrupted.returncode != 77:
            raise AssertionError("interrupted update did not reach migration: " + (scratch / "dashboard.log").read_text()[-4000:])
        if native.dashboard is not None:
            native.dashboard.wait(timeout=15)
            native.dashboard = None
        pending = json.loads((prefix / "update-journal.json").read_text())
        assert pending["phase"] == "migrating" and updater.current().name == "0.1.1"
        blocked = subprocess.run([str(prefix / "current/.venv/bin/cvebeacon"), "--config", str(config_path), "watch", "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=u.SAFE_ENV)
        assert blocked.returncode == 2 and b"recovery" in blocked.stderr
        assert u.Updater(policy, native, remote).recover()["result"] == "rolled-back"
        with sqlite3.connect(data / "ledger.sqlite3") as db:
            assert db.execute("SELECT value FROM sentinel").fetchone()[0] == "preserved"
            assert [row[1] for row in db.execute("PRAGMA table_info(sentinel)")] == ["value"]
        native.probe("0.1.1")
        print("Forced process interruption after migration blocked writers and recovered the original schema, data and dashboard.", flush=True)
        shutil.rmtree(prefix / "releases/0.1.2")  # Only the failed scratch staging directory.
        updater = u.Updater(policy, native, remote)
        native.force_failure = True
        try:
            updater.apply("0.1.2")
        except u.UpdateError as error:
            assert "previous release and state restored" in str(error)
        else:
            raise AssertionError("forced update failure was not rolled back")
        assert updater.current().name == "0.1.1"
        with sqlite3.connect(data / "ledger.sqlite3") as db:
            assert db.execute("SELECT value FROM sentinel").fetchone()[0] == "preserved"
        native.probe("0.1.1")
        assert json.loads((prefix / "update-result.json").read_text())["result"] == "rolled-back"
        print("Forced failure restored the previous symlink, SQLite state and healthy dashboard.", flush=True)


def interrupt_apply(context):
    values = json.loads(context.read_text())
    prefix, data, config = [Path(values[key]) for key in ("prefix", "data", "config")]
    policy = u.Policy(prefix, config, data, values["user"], signers=Path(values["signers"]), probe=f"http://127.0.0.1:{values['port']}/healthz")
    with ExitStack() as stack:
        log = stack.enter_context((context.parent / "interrupted-dashboard.log").open("wb"))
        native = ScratchNative(policy, values["port"], log)
        native.external_pid = values["dashboard_pid"]
        http = HttpClient(HttpConfig(retries=0), client=stack.enter_context(httpx.Client(transport=LocalTransport(values["api_port"]))))
        stack.enter_context(patch.object(u, "protected", lambda path, **kwargs: Path(path)))
        command = native.command
        def interrupted(release, operation):
            result = command(release, operation)
            if operation == "migrate":
                with sqlite3.connect(data / "ledger.sqlite3") as db:
                    db.execute("UPDATE sentinel SET value='interrupted migration'")
                    db.execute("ALTER TABLE sentinel ADD COLUMN introduced TEXT")
                os._exit(77)
            return result
        native.command = interrupted
        u.Updater(policy, native, u.Releases(UpdateConfig(enabled=True), http)).apply("0.1.2")
        raise AssertionError("interruption was not reached")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--interrupt-context", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.interrupt_context:
        interrupt_apply(args.interrupt_context)
    elif args.wheelhouse:
        acceptance(args.wheelhouse.resolve(strict=True))
    else:
        parser.error("--wheelhouse is required")
