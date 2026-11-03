from __future__ import annotations

import pytest

from cvebeacon.config import load_config
from cvebeacon.errors import ConfigurationError

BASE = """
[inventory]
path = "inventory.csv"
[state]
database = "state/state.db"
[output]
directory = "reports"
"""


def write(tmp_path, extra: str):
    path = tmp_path / "config.toml"
    path.write_text(BASE + extra, encoding="utf-8")
    return load_config(path)


def test_old_config_without_watch_still_loads(tmp_path):
    config = write(tmp_path, "")
    assert config.watch.enabled is False
    assert config.watch.database == (tmp_path / "cvebeacon-watch.db").resolve()
    assert config.watch.sources == ("nvd", "euvd", "cisa_kev", "eu_kev", "epss")
    assert config.watch.initial == "baseline"
    assert config.watch.backfill_days == 7
    assert config.watch.overlap_minutes == 15
    assert config.watch.epss_floor == 0.1


def test_watch_table_parses_and_resolves_the_database_path(tmp_path):
    config = write(
        tmp_path,
        """
[watch]
enabled = true
database = "watch/history.db"
sources = ["nvd", "EUVD", "epss"]
initial = "backfill"
backfill_days = 30
overlap_minutes = 0
epss_floor = 0.25
""",
    )
    assert config.watch.enabled is True
    assert config.watch.database == (tmp_path / "watch/history.db").resolve()
    assert config.watch.sources == ("nvd", "euvd", "epss")
    assert config.watch.initial == "backfill"
    assert config.watch.backfill_days == 30
    assert config.watch.overlap_minutes == 0
    assert config.watch.epss_floor == 0.25


def test_watch_sources_must_include_nvd(tmp_path):
    with pytest.raises(ConfigurationError, match="must include nvd"):
        write(tmp_path, '\n[watch]\nsources = ["euvd", "epss"]\n')


def test_watch_unknown_source_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="unknown watch source"):
        write(tmp_path, '\n[watch]\nsources = ["nvd", "osv"]\n')


def test_watch_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="unknown watch setting"):
        write(tmp_path, "\n[watch]\nmagic = true\n")


@pytest.mark.parametrize(
    "setting,match",
    [
        ("enabled = 'true'", "true or false"),
        ("enabled = 1", "true or false"),
        ('database = ""', "nonempty path"),
        ("initial = 'weekly'", "baseline"),
        ("backfill_days = true", "integer"),
        ("backfill_days = 0", "integer"),
        ("backfill_days = 121", "integer"),
        ("overlap_minutes = -1", "integer"),
        ("overlap_minutes = 1441", "integer"),
        ("epss_floor = '0.1'", "must be a number"),
        ("epss_floor = true", "must be a number"),
        ("epss_floor = -0.1", "between 0 and 1"),
        ("epss_floor = 1.1", "between 0 and 1"),
        ("epss_floor = nan", "between 0 and 1"),
        ("epss_floor = inf", "between 0 and 1"),
    ],
)
def test_watch_settings_are_strict(tmp_path, setting, match):
    with pytest.raises(ConfigurationError, match=match):
        write(tmp_path, f"\n[watch]\n{setting}\n")


@pytest.mark.parametrize("value", ['"nvd"', "[1]", "[]"])
def test_watch_sources_shape_is_strict(tmp_path, value):
    with pytest.raises(ConfigurationError):
        write(tmp_path, f"\n[watch]\nsources = {value}\n")


def test_watch_must_be_a_table(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("watch = true\n" + BASE, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="must be a table"):
        load_config(path)
