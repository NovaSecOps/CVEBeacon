"""Secret-reference loader diagnostics never repeat normalized target paths."""

import html
from pathlib import Path
import tomllib

import pytest

from cvebeacon import dashboard_config as dc
from cvebeacon.config import load_config
from cvebeacon.errors import ConfigurationError
from test_dashboard import setup
from test_dashboard_config import accounts, account_fixture, preview, confirm
from test_dashboard_accounts import login


TOKEN = "SYNTHETIC-CREDENTIAL"
URL = "https://secret.example/token/" + TOKEN


@pytest.mark.parametrize("reference", [URL, URL + "/", "../" + TOKEN, "~/" + TOKEN])
def test_source_reference_only_loader_error_does_not_echo_normalized_path(accounts, reference):
    config, users, _, client = accounts
    login(client, "admin")
    before, audit = config.config_path.read_bytes(), users.audit_count()
    response = preview(client, "sources", g0_nvd_api_key_file=reference)
    assert response.status_code == 400
    assert "sources.nvd_api_key_file" in response.text
    assert TOKEN not in html.unescape(response.text)
    assert str(Path(reference).expanduser().resolve()) not in html.unescape(response.text)
    assert config.config_path.read_bytes() == before and users.audit_count() == audit


def test_source_reference_directory_error_omits_resolved_path(tmp_path):
    target = tmp_path / TOKEN
    target.mkdir()
    path = tmp_path / "config.toml"
    path.write_text(dc.dumps({"inventory": {"path": "inventory.csv"}, "sources": {"nvd_api_key_file": str(target)}}))
    with pytest.raises(ConfigurationError) as error:
        load_config(path)
    assert "sources.nvd_api_key_file must be a file" in str(error.value)
    assert TOKEN not in str(error.value)
    assert str(target) not in str(error.value)


def test_rollback_reference_error_does_not_echo_normalized_path(accounts):
    config, users, app, client = accounts
    login(client, "admin")
    assert confirm(client, preview(client, g0_retries="4")).status_code == 303
    editor = app.extensions["dashboard_config"]
    backup = editor.backup_dir / editor.backups()[0]
    document = tomllib.loads(backup.read_text())
    document.setdefault("sources", {})["nvd_api_key_file"] = URL
    backup.write_text(dc.dumps(document))
    before, audit = config.config_path.read_bytes(), users.audit_count()
    response = preview(client, "backups")
    assert response.status_code == 400
    assert TOKEN not in html.unescape(response.text)
    assert config.config_path.read_bytes() == before and users.audit_count() == audit
