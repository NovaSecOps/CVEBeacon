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
    assert "stop cvebeacon-dashboard.service" in deploy
    assert "start cvebeacon-dashboard.service" in deploy
    assert "DEPLOY.md#schedule-it" in scheduling


def test_dashboard_upgrade_sequence_drains_jobs_before_stopping_services():
    deploy = (ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
    upgrade = deploy.split("### Upgrade", 1)[1].split("### Windows", 1)[0]
    assert "run one line" not in upgrade
    assert "when installed" not in upgrade
    assert "sudo pgrep -u cvebeacon -af '[c]vebeacon'" in upgrade
    assert "grep -F '/opt/cvebeacon'" in upgrade
    assert "grep -vE '(^| )serve( |$)'" in upgrade
    assert "systemctl is-active cvebeacon.service" in upgrade
    assert "must print nothing" in upgrade
    assert "no job is running or queued" in upgrade
    disable_scheduler = upgrade.index("cb schedule remove --yes")
    disable_timer = upgrade.index("sudo systemctl stop cvebeacon.timer")
    wait_for_processes = upgrade.index("sudo pgrep -u cvebeacon")
    stop_dashboard = upgrade.index(
        "sudo systemctl stop cvebeacon-dashboard.service"
    )
    install_packages = upgrade.index("pip install")
    start_dashboard = upgrade.index(
        "sudo systemctl start cvebeacon-dashboard.service"
    )
    restore_scheduler = upgrade.index("cb schedule install")
    assert (
        disable_scheduler
        < wait_for_processes
        < stop_dashboard
        < install_packages
        < start_dashboard
        < restore_scheduler
    )
    assert disable_timer < wait_for_processes
    assert restore_scheduler < upgrade.index("Then rerun the checks")
    assert "[Check the result](#check-the-result)" in upgrade
    for number in range(1, 8):
        assert f"\n{number}. " in upgrade


def test_watch_and_user_guides_list_the_state_directory_in_doctor_checks():
    watch = (ROOT / "docs" / "WATCH.md").read_text(encoding="utf-8")
    user_guide = (ROOT / "docs" / "USER_GUIDE.md").read_text(encoding="utf-8")
    assert "watch and state data directories" in watch
    assert "watch and state data directories" in user_guide
    assert "migrates automatically is reported as `ok`" in watch
