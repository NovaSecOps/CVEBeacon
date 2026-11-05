"""Native owner-only creation and ACL checks for operation storage on Windows."""

from contextlib import contextmanager
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import struct

from .errors import StateError


_kernel = c.WinDLL("kernel32", use_last_error=True)
_security = c.WinDLL("advapi32", use_last_error=True)


def _bind(library, name, args, result=w.BOOL):
    function = getattr(library, name)
    function.argtypes = args
    function.restype = result
    return function


_process = _bind(_kernel, "GetCurrentProcess", [], w.HANDLE)
_close = _bind(_kernel, "CloseHandle", [w.HANDLE])
_free = _bind(_kernel, "LocalFree", [c.c_void_p], c.c_void_p)
_token = _bind(_security, "OpenProcessToken", [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)])
_token_info = _bind(_security, "GetTokenInformation", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)])
_sid_text = _bind(_security, "ConvertSidToStringSidW", [c.c_void_p, c.POINTER(c.c_void_p)])
_from_sddl = _bind(_security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p])
_get_security = _bind(_security, "GetSecurityInfo", [w.HANDLE, c.c_int, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p, c.POINTER(c.c_void_p), c.c_void_p, c.POINTER(c.c_void_p)], w.DWORD)
_get_ace = _bind(_security, "GetAce", [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)])
_equal_sid = _bind(_security, "EqualSid", [c.c_void_p, c.c_void_p])


class _Attributes(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]


_create = _bind(_kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, c.POINTER(_Attributes), w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
_mkdir = _bind(_kernel, "CreateDirectoryW", [w.LPCWSTR, c.POINTER(_Attributes)])


def _check(success):
    if not success:
        raise c.WinError(c.get_last_error())


@contextmanager
def _identity():
    token = w.HANDLE()
    _check(_token(_process(), 8, c.byref(token)))
    try:
        size = w.DWORD()
        _token_info(token, 1, None, 0, c.byref(size))
        buffer = c.create_string_buffer(size.value)
        _check(_token_info(token, 1, buffer, size, c.byref(size)))
        sid = c.cast(buffer, c.POINTER(c.c_void_p))[0]
        yield sid
    finally:
        _close(token)


@contextmanager
def _attributes(*, directory=False):
    with _identity() as sid:
        text = c.c_void_p()
        _check(_sid_text(sid, c.byref(text)))
        try:
            name = c.wstring_at(text)
        finally:
            _free(text)
        descriptor = c.c_void_p()
        flags = "OICI" if directory else ""
        _check(_from_sddl(f"O:{name}D:P(A;{flags};FA;;;{name})", 1, c.byref(descriptor), None))
        try:
            yield _Attributes(c.sizeof(_Attributes), descriptor, False)
        finally:
            _free(descriptor)


def _sid_name(sid):
    text = c.c_void_p()
    _check(_sid_text(sid, c.byref(text)))
    try:
        return c.wstring_at(text)
    finally:
        _free(text)


def validate_handle(handle, *, owner_only=True):
    owner, acl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
    result = _get_security(handle, 1, 5, c.byref(owner), None, c.byref(acl), None, c.byref(descriptor))
    if result:
        raise c.WinError(result)
    try:
        with _identity() as sid:
            if not acl.value and not owner_only:
                raise StateError("operation storage directory must not grant unrestricted Windows access")
            if (owner_only and not _equal_sid(owner, sid)) or not acl.value:
                raise StateError("operation storage must have an owner-only Windows ACL")
            count = struct.unpack("<BBHHH", c.string_at(acl, 8))[3]
            if owner_only and not count:
                raise StateError("operation storage ACL grants no owner access")
            for index in range(count):
                ace = c.c_void_p()
                _check(_get_ace(acl, index, c.byref(ace)))
                kind, flags, size, mask = struct.unpack("<BBHI", c.string_at(ace, 8))
                if not owner_only:
                    # Inherit-only and deny entries grant no access here.
                    if flags & 8 or kind == 1:
                        continue
                    if kind != 0:
                        raise StateError("operation storage ACL contains an unsupported entry")
                    broad = {"S-1-1-0", "S-1-5-32-545", "S-1-5-11"}
                    # Data/child creation, deletion, attributes, ACL/owner
                    # changes, and generic write/all are all write access.
                    writable = 0x40000000 | 0x10000000 | 0xD0156
                    if _sid_name(ace.value + 8) in broad and mask & writable:
                        raise StateError("operation storage directory is writable by broad Windows principals")
                    continue
                if kind != 0:
                    raise StateError("operation storage ACL contains an unsupported entry")
                allowed = bool(_equal_sid(ace.value + 8, sid))
                if not allowed:
                    raise StateError("operation storage must have an owner-only Windows ACL")
    finally:
        _free(descriptor)


def open_file(path, *, create=False, exclusive=False, readonly=False):
    import msvcrt
    with _attributes() as attributes:
        disposition = 1 if exclusive else 4 if create else 3
        # OPEN_REPARSE_POINT refuses redirection; the caller also checks lstat.
        handle = _create(str(path), 0x80000000 | (0 if readonly else 0x40000000),
                         3, c.byref(attributes), disposition, 0x00200000, None)
        if handle == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
    try:
        validate_handle(handle)
        return msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDONLY if readonly else os.O_RDWR))
    except BaseException:
        _close(handle)
        raise


def private_directory(path: Path):
    current = path.absolute()
    while True:
        try:
            details = current.lstat()
        except FileNotFoundError:
            pass
        else:
            if details.st_file_attributes & 0x400:
                raise StateError("operation storage directory must not be a link")
        if current.parent == current:
            break
        current = current.parent
    if not path.exists():
        if path.parent == path:
            raise StateError("operation storage volume does not exist")
        private_directory(path.parent)
        with _attributes(directory=True) as attributes:
            if not _mkdir(str(path), c.byref(attributes)) and c.get_last_error() != 183:
                raise c.WinError(c.get_last_error())
    if path.lstat().st_file_attributes & 0x400 or not path.is_dir():
        raise StateError("operation storage directory must not be a link")
    handle = _create(str(path), 0x80000000, 3, None, 3, 0x02200000, None)
    if handle == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        validate_handle(handle, owner_only=False)
    finally:
        _close(handle)
