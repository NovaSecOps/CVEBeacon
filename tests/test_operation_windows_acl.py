"""Exercise native ACL policy without requiring a Windows host."""

from contextlib import contextmanager
import ctypes
import importlib.util
from pathlib import Path
import struct

import pytest

from cvebeacon.errors import StateError


@pytest.fixture
def windows_acl(monkeypatch):
    class Library:
        def __getattr__(self, name):
            def function(*args):
                return 1
            return function
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: Library(), raising=False)
    source = Path(__file__).resolve().parents[1] / "src/cvebeacon/windows_private.py"
    spec = importlib.util.spec_from_file_location("cvebeacon._test_windows_private", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configure_acl(module, monkeypatch, entries, *, owner=1, null=False):
    # Stable synthetic SID addresses; only equality and SID text are used.
    names = {1: "S-1-5-21-123", 2: "S-1-5-18", 3: "S-1-5-32-544",
             4: "S-1-1-0", 5: "S-1-5-32-545", 6: "S-1-5-11"}
    acl = ctypes.create_string_buffer(struct.pack("<BBHHH", 2, 0, 8, len(entries), 0))
    aces = [ctypes.create_string_buffer(struct.pack("<BBHII", kind, flags, 12, mask, sid))
            for kind, flags, mask, sid in entries]
    sid_at = {ctypes.addressof(ace) + 8: entries[i][3] for i, ace in enumerate(aces)}
    @contextmanager
    def identity():
        yield 1
    def get_security(handle, kind, flags, out_owner, group, out_acl, sacl, descriptor):
        out_owner._obj.value = owner
        out_acl._obj.value = None if null else ctypes.addressof(acl)
        return 0
    def get_ace(acl, index, output):
        output._obj.value = ctypes.addressof(aces[index])
        return 1
    def sid_number(sid):
        value = sid.value if isinstance(sid, ctypes.c_void_p) else sid
        return sid_at.get(value, value)
    monkeypatch.setattr(module, "_identity", identity)
    monkeypatch.setattr(module, "_get_security", get_security)
    monkeypatch.setattr(module, "_get_ace", get_ace)
    monkeypatch.setattr(module, "_equal_sid", lambda a, b: sid_number(a) == sid_number(b))
    monkeypatch.setattr(module, "_sid_name",
                        lambda sid: names[sid_number(sid)], raising=False)
    monkeypatch.setattr(module, "_free", lambda *a: None)
    return acl, aces  # Keep native buffers alive through validation.


@pytest.mark.parametrize("owner", [1, 2, 3])
def test_directory_accepts_profile_and_data_acls(windows_acl, monkeypatch, owner):
    buffers = configure_acl(windows_acl, monkeypatch, [
        (0, 0, 0x1F01FF, 1), (0, 0, 0x1F01FF, 2), (0, 0, 0x1F01FF, 3),
        (0, 0, 0x1200A9, 5),  # Users: read and execute.
        (1, 0, 2, 4),  # A deny entry grants no write access.
        (0, 8, 0x1F01FF, 6),  # Inherit-only grant does not apply here.
    ], owner=owner)
    windows_acl.validate_handle(123, owner_only=False)


@pytest.mark.parametrize("principal", [4, 5, 6])
@pytest.mark.parametrize("mask", [2, 4, 0x40, 0x100, 0x10000, 0x40000, 0x80000,
                                  0x10000000, 0x40000000])
def test_directory_accepts_broad_write_grants(windows_acl, monkeypatch, principal, mask):
    buffers = configure_acl(windows_acl, monkeypatch, [(0, 0, mask, principal)])
    windows_acl.validate_handle(123, owner_only=False)


def test_directory_accepts_null_dacl(windows_acl, monkeypatch):
    buffers = configure_acl(windows_acl, monkeypatch, [], null=True)
    windows_acl.validate_handle(123, owner_only=False)


@pytest.mark.parametrize("owner,entries", [
    (2, [(0, 0, 0x1F01FF, 1)]),
    (1, [(0, 0, 0x1F01FF, 1), (0, 0, 0x1F01FF, 5)]),
])
def test_file_still_requires_current_owner_and_private_acl(windows_acl, monkeypatch, owner, entries):
    buffers = configure_acl(windows_acl, monkeypatch, entries, owner=owner)
    with pytest.raises(StateError):
        windows_acl.validate_handle(123)


def test_relaxed_file_validation_accepts_foreign_owner_and_broad_acl(windows_acl, monkeypatch):
    buffers = configure_acl(windows_acl, monkeypatch, [
        (0, 0, 0x1F01FF, 4), (0, 0, 0x1F01FF, 2),
    ], owner=2)
    windows_acl.validate_handle(123, owner_only=False)
