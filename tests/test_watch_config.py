from __future__ import annotations

import os

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

[watch.channels.soc-email]
type = "webhook"
enabled = false
url = "https://example.invalid/cvebeacon"
"""


def write(tmp_path, extra: str):
    path = tmp_path / "config.toml"
    path.write_text(BASE + extra, encoding="utf-8")
    return load_config(path)


def test_old_config_without_watch_still_loads(tmp_path):
    config = write(tmp_path, "")
    assert config.watch.enabled is False
    assert config.watch.database == (tmp_path / "state" / "cvebeacon-watch.db").resolve()
    assert config.watch.sources == ("nvd", "euvd", "cisa_kev", "eu_kev", "epss")
    assert config.watch.initial == "baseline"
    assert config.watch.backfill_days == 7
    assert config.watch.overlap_minutes == 15


def test_watch_database_defaults_beside_an_absolute_state_database(tmp_path):
    state = tmp_path / "var" / "state" / "state.db"
    path = tmp_path / "config.toml"
    path.write_text(
        '[inventory]\npath = "inventory.csv"\n'
        f'[state]\ndatabase = "{state.as_posix()}"\n',
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.watch.database == (state.parent / "cvebeacon-watch.db").resolve()


def test_watch_database_defaults_under_the_state_directory(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[inventory]\npath = "inventory.csv"\n', encoding="utf-8")
    config = load_config(path)
    assert config.watch.database == (
        tmp_path / ".cvebeacon" / "cvebeacon-watch.db"
    ).resolve()


def test_explicit_absolute_watch_database_is_unchanged(tmp_path):
    database = tmp_path / "elsewhere" / "watch.db"
    config = write(tmp_path, f'\n[watch]\ndatabase = "{database.as_posix()}"\n')
    assert config.watch.database == database.resolve()


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
""",
    )
    assert config.watch.enabled is True
    assert config.watch.database == (tmp_path / "watch/history.db").resolve()
    assert config.watch.sources == ("nvd", "euvd", "epss")
    assert config.watch.initial == "backfill"
    assert config.watch.backfill_days == 30
    assert config.watch.overlap_minutes == 0


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
        ("epss_floor = 0.1", "unknown watch setting"),
    ],
)
def test_watch_settings_are_strict(tmp_path, setting, match):
    with pytest.raises(ConfigurationError, match=match):
        write(tmp_path, f"\n[watch]\n{setting}\n")


def test_oversized_float_settings_raise_configuration_errors(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(BASE + "\n[sources]\nminimum_request_interval = " + "9" * 1000 + "\n")
    with pytest.raises(ConfigurationError, match="greater than 0"):
        load_config(path)


@pytest.mark.parametrize("value", ['"nvd"', "[1]", "[]"])
def test_watch_sources_shape_is_strict(tmp_path, value):
    with pytest.raises(ConfigurationError):
        write(tmp_path, f"\n[watch]\nsources = {value}\n")


def test_watch_must_be_a_table(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        'watch = true\n[inventory]\npath = "inventory.csv"\n', encoding="utf-8"
    )
    with pytest.raises(ConfigurationError, match="must be a table"):
        load_config(path)


def test_watch_only_config_without_inventory_loads(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
[watch]
enabled = true
database = "watch.db"
sources = ["nvd", "epss"]

[watch.channels.soc-email]
type = "webhook"
enabled = false
url = "https://example.invalid/cvebeacon"

[[watch.rules]]
name = "critical-or-likely"
condition = { any = [ { cvss_min = 9.0 }, { epss_min = 0.5 } ] }
channels = ["soc-email"]
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.inventory is None
    assert config.watch.enabled is True
    assert len(config.watch.rules) == 1
    rule = config.watch.rules[0]
    assert rule.name == "critical-or-likely"
    assert rule.channels == ("soc-email",)
    assert rule.enabled is True
    assert rule.events[0] == "match"


def test_inventory_is_still_required_without_watch(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("[state]\ndatabase = \"state.db\"\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="inventory.path is required"):
        load_config(path)


def test_watch_rules_are_validated_while_loading(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
[watch]
enabled = true

[[watch.rules]]
name = "bad"
condition = { all = [] }
channels = ["soc-email"]
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="watch rule 'bad' condition.all"):
        load_config(path)


def test_rule_sources_are_checked_against_the_configured_watch_sources(tmp_path):
    with pytest.raises(ConfigurationError, match="eu_kev is not in watch.sources"):
        write(
            tmp_path,
            """
[watch]
sources = ["nvd"]

[[watch.rules]]
name = "eu-only"
condition = { kev = "eu" }
channels = ["soc-email"]
""",
        )
    with pytest.raises(ConfigurationError, match="euvd is not in watch.sources"):
        write(
            tmp_path,
            """
[watch]
sources = ["nvd"]

[[watch.rules]]
name = "euvd-only"
condition = { cvss_min = 1 }
channels = ["soc-email"]
cvss_providers = ["euvd"]
""",
        )
    write(
        tmp_path,
        """
[watch]
sources = ["nvd", "cisa_kev"]

[[watch.rules]]
name = "cisa-only"
condition = { kev = "cisa" }
channels = ["soc-email"]
""",
    )


def test_rule_options_are_validated_while_loading(tmp_path):
    with pytest.raises(ConfigurationError, match="old_cves"):
        write(
            tmp_path,
            """
[watch]
enabled = true

[[watch.rules]]
name = "old"
condition = { cvss_min = 1 }
channels = ["soc-email"]
old_cves = "loud"
""",
        )
    with pytest.raises(ConfigurationError, match="at least one event kind"):
        write(
            tmp_path,
            """
[watch]
enabled = true

[[watch.rules]]
name = "silent"
condition = { cvss_min = 1 }
channels = ["soc-email"]
events = []
""",
        )


def test_watch_rules_store_normalized_cwe_values(tmp_path):
    config = write(
        tmp_path,
        """
[watch]
enabled = true

[[watch.rules]]
name = "cwe"
condition = { cwe = ["79", "cwe-80", "CWE-81"] }
channels = ["soc-email"]
""",
    )
    assert config.watch.rules[0].condition.leaves == (
        ("cwe", ("CWE-79", "CWE-80", "CWE-81")),
    )


def test_epss_min_requires_the_epss_source(tmp_path):
    with pytest.raises(
        ConfigurationError,
        match="watch rule 'likely' uses epss_min but epss is not in watch.sources",
    ):
        write(
            tmp_path,
            """
[watch]
sources = ["nvd"]

[[watch.rules]]
name = "likely"
condition = { any = [ { cvss_min = 9 }, { not = { epss_min = 0.5 } } ] }
channels = ["soc-email"]
""",
        )
    config = write(
        tmp_path,
        """
[watch]
sources = ["nvd", "epss"]

[[watch.rules]]
name = "likely"
condition = { epss_min = 0.5 }
channels = ["soc-email"]
""",
    )
    assert config.watch.rules[0].name == "likely"


def test_nvd_api_key_file_is_loaded(tmp_path, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    key = tmp_path / "nvd-key"
    key.write_text("secret", encoding="utf-8")
    os.chmod(key, 0o600)
    config = write(tmp_path, '\n[sources]\nnvd_api_key_file = "nvd-key"\n')
    assert config.sources.nvd_api_key_file == key.resolve()
    assert config.nvd_api_key() == "secret"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission check")
def test_nvd_api_key_file_must_not_be_group_accessible(tmp_path):
    key = tmp_path / "nvd-key"
    key.write_text("secret", encoding="utf-8")
    os.chmod(key, 0o644)
    with pytest.raises(ConfigurationError, match="group or other accessible"):
        write(tmp_path, '\n[sources]\nnvd_api_key_file = "nvd-key"\n')


def test_watch_language_defaults_to_english(tmp_path):
    assert write(tmp_path, "").watch.language == "en"


def test_watch_language_accepts_european_portuguese(tmp_path):
    config = write(tmp_path, '\n[watch]\nlanguage = "pt-PT"\n')
    assert config.watch.language == "pt-PT"
    assert write(tmp_path, '\n[watch]\nlanguage = "PT-pt"\n').watch.language == (
        "pt-PT"
    )


@pytest.mark.parametrize("value", ('"pt-BR"', '"fr"', "1", '["pt-PT"]'))
def test_watch_language_rejects_unknown_values(tmp_path, value):
    with pytest.raises(ConfigurationError, match="watch.language must be one of en, pt-PT"):
        write(tmp_path, f"\n[watch]\nlanguage = {value}\n")


def test_channel_language_overrides_the_watch_language(tmp_path):
    config = write(
        tmp_path,
        """
[watch]
language = "pt-PT"

[watch.channels.portuguese]
type = "webhook"
enabled = false
url = "https://example.invalid/cvebeacon"
language = "en"

[watch.channels.soc-chat]
type = "slack"
enabled = false
webhook_url_env = "CVEBEACON_TEST_SLACK_WEBHOOK"
language = "PT-pt"
""",
    )
    channels = {channel.name: channel for channel in config.watch.channels}
    assert config.watch.language == "pt-PT"
    assert channels["portuguese"].language == "en"
    assert channels["soc-chat"].language == "pt-PT"


def test_channel_language_rejects_unknown_values(tmp_path):
    with pytest.raises(ConfigurationError, match="watch channel 'chat' language"):
        write(
            tmp_path,
            """
[watch.channels.chat]
type = "slack"
webhook_url_env = "CVEBEACON_TEST_SLACK_WEBHOOK"
language = "pt-BR"
""",
        )


def test_channel_format_defaults_to_text_and_accepts_html_for_email(tmp_path):
    config = write(
        tmp_path,
        """
[watch.channels.mail]
type = "smtp"
host = "smtp.example.org"
from = "alerts@example.org"
to = ["soc@example.org"]
format = "html"

[watch.channels.graph]
type = "graph"
tenant_id = "tenant"
client_id = "client"
client_secret_env = "GRAPH_SECRET"
sender = "alerts@example.org"
to = ["soc@example.org"]
format = "TEXT"
""",
    )
    channels = {channel.name: channel for channel in config.watch.channels}
    assert channels["mail"].format == "html"
    assert channels["graph"].format == "text"
    assert channels["soc-email"].format == "text"


def test_channel_format_is_rejected_for_non_email_channels(tmp_path):
    with pytest.raises(ConfigurationError, match="unknown key 'format'"):
        write(
            tmp_path,
            """
[watch.channels.chat]
type = "slack"
webhook_url_env = "CVEBEACON_TEST_SLACK_WEBHOOK"
format = "html"
""",
        )


def test_channel_format_rejects_unknown_values(tmp_path):
    with pytest.raises(ConfigurationError, match="must be text or html"):
        write(
            tmp_path,
            """
[watch.channels.mail]
type = "smtp"
host = "smtp.example.org"
from = "alerts@example.org"
to = ["soc@example.org"]
format = "markdown"
""",
        )


@pytest.mark.parametrize("value", ('""', '"   "'))
def test_channel_format_rejects_explicitly_empty_values(tmp_path, value):
    with pytest.raises(ConfigurationError, match="format must not be empty"):
        write(
            tmp_path,
            f"""
[watch.channels.mail]
type = "smtp"
host = "smtp.example.org"
from = "alerts@example.org"
to = ["soc@example.org"]
format = {value}
""",
        )


@pytest.mark.parametrize("value", ('""', '"   "'))
def test_channel_language_rejects_explicitly_empty_values(tmp_path, value):
    with pytest.raises(ConfigurationError, match="language must not be empty"):
        write(
            tmp_path,
            f"""
[watch.channels.chat]
type = "slack"
webhook_url_env = "CVEBEACON_TEST_SLACK_WEBHOOK"
language = {value}
""",
        )
