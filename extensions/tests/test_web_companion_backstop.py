"""Offline coverage of the parent process enforcing the web run limit."""

import subprocess
import re

import pytest

from cvebeacon import web_assets
from cvebeacon.config import AppConfig
from cvebeacon.errors import ConfigurationError
from cvebeacon_extensions import web


@pytest.mark.parametrize("ignores_terminate", [False, True])
def test_parent_process_backstop_terminates_then_kills_if_needed(tmp_path, monkeypatch,
                                                               ignores_terminate):
    calls = []
    class Child:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def wait(self, timeout=None):
            calls.append(("wait", timeout))
            if timeout == web.RUN_TIMEOUT + 300 or (timeout == 10 and ignores_terminate):
                raise subprocess.TimeoutExpired(["fixture"], timeout)
            return 1
        def terminate(self):
            calls.append(("terminate",))
        def kill(self):
            calls.append(("kill",))
    monkeypatch.setattr(web_assets, "read_allowlist", lambda *_: ({"client": "acme", "assets": [{}]}, ""))
    monkeypatch.setattr(web_assets, "paths", lambda *_: (tmp_path / "assets.json", tmp_path / "out.json"))
    monkeypatch.setattr(web_assets, "child_environment", lambda _: {})
    monkeypatch.setattr(web_assets, "companion_command", lambda *args, **kwargs: ["fixture"])
    monkeypatch.setattr(web_assets.subprocess, "call", lambda *args, **kwargs: 0)
    monkeypatch.setattr(web_assets.subprocess, "Popen", lambda *args, **kwargs: Child())
    config = AppConfig(tmp_path / "config.toml", None, tmp_path / "state.db", tmp_path)
    with pytest.raises(ConfigurationError, match="^detection stopped at the run time limit$"):
        web_assets.run_detection(config, "acme")
    assert calls[:3] == [("wait", web.RUN_TIMEOUT + 300), ("terminate",), ("wait", 10)]
    assert calls[3:] == ([("kill",), ("wait", 10)] if ignores_terminate else [])


def test_parent_backstop_never_enters_an_unbounded_wait(tmp_path, monkeypatch):
    calls = []

    class Child:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            calls.append("context exit")

        def wait(self, timeout=None):
            calls.append(timeout)
            raise subprocess.TimeoutExpired(["fixture"], timeout)

        def terminate(self):
            calls.append("terminate")

        def kill(self):
            calls.append("kill")

    monkeypatch.setattr(web_assets, "read_allowlist", lambda *_: ({"client": "acme", "assets": [{}]}, ""))
    monkeypatch.setattr(web_assets, "paths", lambda *_: (tmp_path / "assets.json", tmp_path / "out.json"))
    monkeypatch.setattr(web_assets, "companion_command", lambda *args, **kwargs: ["fixture"])
    monkeypatch.setattr(web_assets, "child_environment", lambda _: {})
    monkeypatch.setattr(web_assets.subprocess, "Popen", lambda *args, **kwargs: Child())
    with pytest.raises(ConfigurationError, match="^detection stopped at the run time limit$"):
        web_assets.run_detection(AppConfig(tmp_path / "config.toml", None, tmp_path / "state.db", tmp_path), "acme")
    assert calls == [web.RUN_TIMEOUT + 300, "terminate", 10, "kill", 10]


def test_companion_never_follows_a_fingerprint_directory_link(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "web-fingerprints"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    calls = []

    class Child:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(web_assets, "read_allowlist", lambda *_: ({"client": "acme", "assets": [{}]}, ""))
    monkeypatch.setattr(web_assets, "paths", lambda *_: (tmp_path / "assets.json", tmp_path / "out.json"))
    monkeypatch.setattr(web_assets, "companion_command",
                        lambda *args, **kwargs: calls.append(kwargs) or ["fixture"])
    monkeypatch.setattr(web_assets, "child_environment", lambda _: {})
    monkeypatch.setattr(web_assets.subprocess, "Popen", lambda *args, **kwargs: Child())
    assert web_assets.run_detection(AppConfig(tmp_path / "config.toml", None, tmp_path / "state.db", tmp_path), "acme") == 0
    (options,) = calls
    assert re.fullmatch(r"[a-f0-9]{32}", options.pop("run_id"))
    assert options == {"plan": False, "fingerprints": None}
