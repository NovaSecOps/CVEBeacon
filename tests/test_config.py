from __future__ import annotations

from pathlib import Path

import pytest

from cvebeacon.config import load_config
from cvebeacon.errors import ConfigurationError


BASE = """
[inventory]
path = "inventory.csv"
[inventory.columns]
asset_id = "asset_id"
vendor = "vendor"
product = "product"
version = "version"
[state]
database = "state/state.db"
[output]
directory = "reports"
"""


def test_relative_paths_resolve_from_configuration(tmp_path):
    path = tmp_path / "config.toml"; path.write_text(BASE, encoding="utf-8")
    config = load_config(path)
    assert config.inventory.path == (tmp_path / "inventory.csv").resolve()
    assert config.database_path == (tmp_path / "state/state.db").resolve()


def test_inventory_client_column_is_accepted(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        BASE.replace(
            'version = "version"', 'version = "version"\nclient = "Client"'
        ),
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.inventory.columns["client"] == "Client"


def test_container_example_loads_with_and_without_watch(tmp_path):
    example = Path(__file__).parents[1] / "deploy/container/cvebeacon.example.toml"
    config = load_config(example)
    assert config.watch.enabled is False
    assert config.watch.database == config.database_path.parent / "cvebeacon-watch.db"
    text = example.read_text(encoding="utf-8").replace(
        "[watch]\nenabled = false", "[watch]\nenabled = true"
    )
    assert "enabled = true" in text
    path = tmp_path / "cvebeacon.toml"
    path.write_text(text, encoding="utf-8")
    config = load_config(path)
    assert config.watch.enabled is True
    assert [rule.name for rule in config.watch.rules] == ["critical"]
    assert [channel.name for channel in config.watch.channels] == ["soc-webhook"]


def test_boolean_strings_are_rejected(tmp_path):
    path = tmp_path / "config.toml"; path.write_text(BASE + "\n[sources]\nnvd_enabled = \"false\"\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="true or false"): load_config(path)


def test_invalid_mapping_is_rejected(tmp_path):
    text = BASE.replace('version = "version"', 'version = ""')
    path = tmp_path / "config.toml"; path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="missing mappings"): load_config(path)


def test_enabled_email_requires_addresses(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(BASE + "\n[notifications.email]\nenabled = true\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="sender"):
        load_config(path)
