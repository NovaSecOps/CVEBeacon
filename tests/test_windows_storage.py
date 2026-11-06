"""Windows readers must permit atomic publication while locks retain their inode."""

from contextlib import contextmanager
import ctypes
import importlib.util
import os
from pathlib import Path
import sys
import threading
import time
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
def test_windows_publication_with_an_open_private_reader(tmp_path, monkeypatch):
    target = tmp_path / "snapshot.json"
    save_allowlist(target, {"value": "old"})
    reader = os.fdopen(private_file(target, readonly=True), "rb")
    attempted = threading.Event()
    released = threading.Event()
    replace = os.replace
    def publication_attempt(source, destination):
        attempted.set()
        replace(source, destination)
    monkeypatch.setattr(os, "replace", publication_attempt)
    def release_reader():
        try:
            if attempted.wait(3):
                time.sleep(0.1)
        finally:
            reader.close()
            released.set()
    thread = threading.Thread(target=release_reader)
    thread.start()
    try:
        save_allowlist(target, {"value": "new"})
        assert attempted.is_set() and released.wait(1)
    finally:
        thread.join()
        reader.close()
    assert b'new' in target.read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="native Windows sharing semantics")
def test_windows_publication_reports_reader_held_past_bound(tmp_path):
    target = tmp_path / "snapshot.json"
    save_allowlist(target, {"value": "old"})
    started = time.monotonic()
    with os.fdopen(private_file(target, readonly=True), "rb") as reader:
        with pytest.raises(PermissionError, match="publication.*2 seconds.*readers"):
            save_allowlist(target, {"value": "new"})
        assert b'old' in reader.read()
    assert 1.8 <= time.monotonic() - started < 5
    assert b'old' in target.read_bytes()
    assert not list(tmp_path.glob(".web-assets-*.tmp"))


@pytest.mark.parametrize("publication", ["allowlist", "snapshot", "manifest", "review"])
@pytest.mark.parametrize("release", [True, False])
def test_windows_publications_retry_permission_errors(tmp_path, monkeypatch, publication, release):
    from cvebeacon import publication as publication_io
    if publication != "allowlist":
        _atomic = pytest.importorskip("cvebeacon_extensions.contract")._atomic
    target = tmp_path / ("web.json" + {"allowlist": "", "snapshot": "", "manifest": ".manifest.json",
                                     "review": ".review.json"}[publication])
    save_allowlist(target, {"value": "old"})
    replace = os.replace
    elapsed, attempts = [0.0], []
    def blocked(source, destination):
        attempts.append(elapsed[0])
        if not release or elapsed[0] < 0.1:
            raise PermissionError("reader is open")
        replace(source, destination)
    monkeypatch.setattr(publication_io, "os", SimpleNamespace(name="nt", replace=blocked))
    monkeypatch.setattr(publication_io, "time", SimpleNamespace(
        monotonic=lambda: elapsed[0], sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay)))
    def publish():
        if publication == "allowlist":
            save_allowlist(target, {"value": "new"})
        else:
            _atomic(target, b'{"value":"new"}')
    if release:
        publish()
        assert b'new' in target.read_bytes()
        assert 0.1 <= elapsed[0] < 2
    else:
        with pytest.raises(PermissionError, match="publication.*2 seconds.*readers"):
            publish()
        assert b'old' in target.read_bytes()
        assert elapsed[0] == pytest.approx(2)
    assert len(attempts) > 1
    assert not list(tmp_path.glob("*.tmp")) and not list(tmp_path.glob(".cvebeacon-*"))


@pytest.mark.parametrize("platform,error", [("posix", PermissionError), ("nt", OSError)])
def test_publication_does_not_retry_other_failures(monkeypatch, platform, error):
    from cvebeacon import publication
    attempts = []
    def fail(*args):
        attempts.append(True)
        raise error("publication refused")
    monkeypatch.setattr(publication, "os", SimpleNamespace(name=platform, replace=fail))
    monkeypatch.setattr(publication.time, "sleep", lambda _: pytest.fail("unexpected retry"))
    with pytest.raises(error, match="publication refused"):
        publication.replace_file("source", "destination")
    assert attempts == [True]
