"""Deploy files stay loadable and keep their documented hardening."""

from __future__ import annotations

import configparser
from pathlib import Path

ROOT = Path(__file__).parents[1]


def read_unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(ROOT / "deploy" / "systemd" / name, encoding="utf-8")
    return parser


def test_systemd_dashboard_unit_has_expected_service_settings():
    unit = read_unit("cvebeacon-dashboard.service")
    assert unit["Unit"]["Description"] == "CVEBeacon dashboard"
    service = unit["Service"]
    assert service["User"] == "cvebeacon"
    assert service["Group"] == "cvebeacon"
    assert service["Restart"] == "on-failure"
    assert service["NoNewPrivileges"] == "yes"
    assert service["ProtectSystem"] == "strict"
    assert "/var/lib/cvebeacon" in service["ReadWritePaths"]
    command = service["ExecStart"]
    assert command.endswith(
        "cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml "
        "serve --host 127.0.0.1 --port 8787"
    )
    assert unit["Install"]["WantedBy"] == "multi-user.target"
