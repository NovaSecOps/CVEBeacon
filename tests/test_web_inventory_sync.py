"""Inventory sync uses saved observations and publishes reversible client changes."""

import pytest

from cvebeacon.config import load_config
from cvebeacon.errors import ConfigurationError

from test_web_assets_inventory import blank


def test_global_settings_are_validated(tmp_path):
    path = tmp_path / "config.toml"
    base = '[inventory]\nmanaged = true\n'
    path.write_text(base, encoding="utf-8", newline="\n")
    assert load_config(path).web.inventory_sync == "off"
    assert load_config(path).web.removal_grace_days == 30
    for mode in ("off", "review", "auto"):
        path.write_text(base + f'[web]\ninventory_sync = "{mode}"\nremoval_grace_days = 0\n',
                        encoding="utf-8", newline="\n")
        assert load_config(path).web.inventory_sync == mode
        assert load_config(path).web.removal_grace_days == 0
    for field in ('inventory_sync = "unknown"', 'inventory_sync = true',
                  'removal_grace_days = true', 'removal_grace_days = -1',
                  'removal_grace_days = 366', 'removal_grace_days = 1.5'):
        path.write_text(base + "[web]\n" + field + "\n", encoding="utf-8", newline="\n")
        with pytest.raises(ConfigurationError, match=r"web\."):
            load_config(path)


def test_inventory_settings_form_shows_sync_options(blank):
    response = blank[3].get("/config/inventory")
    assert response.status_code == 200
    assert 'name="g1_inventory_sync"' in response.text
    assert 'name="g1_removal_grace_days"' in response.text
    assert 'min="0"' in response.text and 'max="365"' in response.text
