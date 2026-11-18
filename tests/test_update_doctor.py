"""An update health check must cover existing watch-only installations."""
import json

from cvebeacon import cli, updater as u
from watch_support import write_config


def test_doctor_accepts_watch_only_and_migrates_existing_stores(tmp_path):
    config = write_config(tmp_path, inventory=False)
    assert cli.main(["--config", str(config.config_path), "doctor", "--allow-watch-only"]) == 0
    assert config.watch.database.is_file()


def test_windows_check_status_uses_portable_atomic_publication(tmp_path, monkeypatch):
    monkeypatch.setattr(u.platform, "system", lambda: "Windows")
    path = tmp_path / u.STATUS
    u.atomic_json(path, {"available": "0.1.1"})
    assert json.loads(path.read_text()) == {"available": "0.1.1"}
    assert not list(tmp_path.glob(".update-*"))
    assert "Windows" in u.unsupported_reason()
