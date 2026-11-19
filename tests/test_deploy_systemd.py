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
    assert unit["Unit"]["StartLimitIntervalSec"] == "0"
    service = unit["Service"]
    assert service["User"] == "cvebeacon"
    assert service["Group"] == "cvebeacon"
    assert service["Restart"] == "on-failure"
    assert service["NoNewPrivileges"] == "yes"
    assert service["ProtectSystem"] == "strict"
    assert "/var/lib/cvebeacon" in service["ReadWritePaths"]
    assert service["ExecStartPre"].endswith(
        "/opt/cvebeacon/current/.venv/bin/cvebeacon update guard --role serve"
    )
    command = service["ExecStart"]
    assert command.startswith("/opt/cvebeacon/current/.venv/bin/cvebeacon ")
    assert command.endswith(
        "--config /var/lib/cvebeacon/cvebeacon.toml "
        "serve --host 127.0.0.1 --port 8787"
    )
    assert unit["Install"]["WantedBy"] == "multi-user.target"


def test_dashboard_docs_ship_a_complete_crontab_dropin_and_upgrade_sequence():
    deploy = (ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
    scheduling = (ROOT / "docs" / "SCHEDULING.md").read_text(encoding="utf-8")
    for text in (deploy, scheduling):
        assert "NoNewPrivileges=no" in text
        assert "/var/spool/cron/crontabs" in text
        assert "/var/spool/cron`" in text
        assert "read or update" in text
    assert "cvebeacon-dashboard.service.d/crontab.conf" in deploy
    assert "EnvironmentFile" in deploy
    assert "ProtectHome=yes" in deploy
    assert "/opt/cvebeacon/current/.venv/bin/cvebeacon" in deploy
    assert "deploy/systemd/cvebeacon.timer" in deploy
    assert (ROOT / "deploy" / "systemd" / "cvebeacon.timer").exists()
    assert "DEPLOY.md#schedule-it" in scheduling
    upgrade = deploy.split("### Upgrade", 1)[1].split("### Windows", 1)[0]
    assert "[upgrading](UPGRADING.md)" in upgrade


def test_upgrading_guide_drains_jobs_before_stopping_services():
    upgrading = (ROOT / "docs" / "UPGRADING.md").read_text(encoding="utf-8")
    manual = upgrading.split("## Manual upgrades", 1)[1].split("## Adopt", 1)[0]
    manual = " ".join(manual.split())
    assert "schedule remove --yes" in manual
    assert "stop the systemd timer" in manual
    assert "sudo pgrep -u cvebeacon -af '[c]vebeacon'" in manual
    assert "grep -F '/opt/cvebeacon'" in manual
    assert "grep -vE '(^| )serve( |$)'" in manual
    assert "systemctl is-active cvebeacon.service" in manual
    assert "must print nothing" in manual
    assert "Change `/opt/cvebeacon` and the `-u` service account" in manual
    disable_scheduler = manual.index("schedule remove --yes")
    disable_timer = manual.index("stop the systemd timer")
    wait_for_processes = manual.index("sudo pgrep -u cvebeacon")
    stop_dashboard = manual.index(
        "Stop the dashboard and other data writers"
    )
    backup = manual.index("SQLite's online backup")
    install_packages = manual.index("pip --isolated install")
    migrate = manual.index("cvebeacon --config CONFIG migrate")
    restart = manual.index("restart the dashboard and re-enable")
    check = manual.index("Check `doctor`")
    assert (
        disable_scheduler
        < wait_for_processes
        < stop_dashboard
        < backup
        < install_packages
        < migrate
        < restart
        < check
    )
    assert disable_timer < wait_for_processes


def test_watch_and_user_guides_list_the_state_directory_in_doctor_checks():
    watch = (ROOT / "docs" / "WATCH.md").read_text(encoding="utf-8")
    user_guide = (ROOT / "docs" / "USER_GUIDE.md").read_text(encoding="utf-8")
    assert "watch and state data directories" in watch
    assert "watch and state data directories" in user_guide
    assert "migrates automatically is reported as `ok`" in watch
