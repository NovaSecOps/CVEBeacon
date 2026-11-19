"""The setup selector must not route the new bot type to generic webhooks."""

from cvebeacon.config import load_config
from test_setup import run_watch
from test_watch_teams_bot import APP, SECRET, TENANT, USER


def test_bot_setup_writes_only_a_file_secret(tmp_path, monkeypatch):
    assert run_watch(
        tmp_path, monkeypatch,
        channel=["", "teams_bot", TENANT, APP, USER, "n"], secrets=[SECRET],
    ) == 0
    path = tmp_path / "cvebeacon.toml"
    config = load_config(path)
    result = config.watch.channels[0]
    assert result.type == "teams_bot"
    assert result.options["app_id"] == APP
    assert result.options["tenant_id"] == TENANT
    assert result.options["recipients"] == (USER,)
    assert result.secret("client_secret").resolve() == SECRET
    assert SECRET not in path.read_text()
    assert "client_secret_env" not in path.read_text()
