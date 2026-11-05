"""Windows readers must permit atomic publication while locks retain their inode."""

from contextlib import contextmanager
import ctypes
import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from cvebeacon.private_storage import private_file
from cvebeacon.web_assets import save_allowlist


@pytest.mark.parametrize("owner_only", [True, False])
def test_windows_read_handles_share_delete_but_writers_do_not(monkeypatch, owner_only):
    class Library:
        def __getattr__(self, name):
            return lambda *args: 123
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: Library(), raising=False)
    spec = importlib.util.spec_from_file_location("cvebeacon._windows_storage_test",
        Path(__file__).parents[1] / "src/cvebeacon/windows_private.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "_create", lambda *args: calls.append(args) or 123)
    monkeypatch.setattr(module, "validate_handle", lambda *a, **k: None)
    @contextmanager
    def attributes():
        yield module._Attributes()
    monkeypatch.setattr(module, "_attributes", attributes)
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=lambda *args: 456))
    monkeypatch.setattr(os, "O_BINARY", 0, raising=False)
    module.open_file(Path("snapshot.json"), readonly=True, owner_only=owner_only)
    module.open_file(Path("run.lock"), readonly=False, owner_only=owner_only)
    assert calls[0][2] == 7  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    assert calls[1][2] == 3  # An active writer/lock still prevents replacement.


@pytest.mark.skipif(os.name != "nt", reason="native Windows sharing semantics")
def test_windows_publication_with_an_open_private_reader(tmp_path):
    target = tmp_path / "snapshot.json"
    save_allowlist(target, {"value": "old"})
    with os.fdopen(private_file(target, readonly=True), "rb") as reader:
        save_allowlist(target, {"value": "new"})
        assert b'old' in reader.read()
    assert b'new' in target.read_bytes()
