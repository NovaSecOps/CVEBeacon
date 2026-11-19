"""Test source and documentation reads must not depend on the locale."""

from pathlib import Path


def test_security_documentation_reads_utf8_with_a_windows_default(monkeypatch):
    from test_dashboard_accounts import test_security_recovery_and_permission_boundaries_are_documented
    original = Path.open
    def windows_open(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        if "b" not in mode and encoding in (None, "locale"):
            encoding = "cp1252"
        return original(path, mode=mode, buffering=buffering, encoding=encoding, errors=errors, newline=newline)
    monkeypatch.setattr(Path, "open", windows_open)
    test_security_recovery_and_permission_boundaries_are_documented()
