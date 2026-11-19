"""Per-field contracts checked against validator identities and loader output."""

import os
from dataclasses import replace

import pytest

from cvebeacon import dashboard_config as dc
from cvebeacon.config import load_config
from cvebeacon.errors import ConfigurationError
from test_dashboard_config_fix1 import email_channel


def test_dashboard_reference_help_states_administrator_boundary():
    spec = dc.FIELD_METADATA["dashboard.password_hash_env"]
    assert "administrator" in spec.help.lower()



def test_enum_mutation_is_caught_per_identity(monkeypatch):
    from test_dashboard_config_ux import test_enum_metadata_covers_validator_enums
    spec = dc.FIELD_METADATA["watch.language"]
    monkeypatch.setitem(dc.FIELD_METADATA, "watch.language", replace(spec, kind="string", choices=()))
    with pytest.raises(AssertionError):
        test_enum_metadata_covers_validator_enums()



def test_positive_bound_metadata_marks_exclusion():
    spec = dc.FIELD_METADATA["http.connect_timeout"]
    assert getattr(spec, "minimum_exclusive", False)



def test_all_enum_validation_sites_are_bound_to_fields():
    from config_metadata_contracts import test_discovered_enum_sites_have_field_contracts
    test_discovered_enum_sites_have_field_contracts()



@pytest.mark.parametrize("identity", ["watch.language", "watch.channels.smtp.language", "watch.rules.events"])
def test_each_enum_identity_has_its_own_contract(monkeypatch, identity):
    from config_metadata_contracts import assert_enum_metadata
    spec = dc.FIELD_METADATA[identity]
    monkeypatch.setitem(dc.FIELD_METADATA, identity, replace(spec, choices=(), item_choices=(), kind="string"))
    with pytest.raises(AssertionError):
        assert_enum_metadata()



@pytest.mark.parametrize("key", ["session_idle_seconds", "session_lifetime_seconds"])
def test_dashboard_bounds_match_loader(tmp_path, key):
    path = tmp_path / "config.toml"
    spec = dc.FIELD_METADATA["dashboard." + key]
    assert spec.step == "1"
    for number, accepted in ((spec.minimum - 1, False), (spec.minimum, True),
                             (spec.maximum, True), (spec.maximum + 1, False)):
        path.write_text(dc.dumps({"inventory": {"path": "inventory.csv"}, "dashboard": {key: number}}))
        if accepted:
            assert getattr(load_config(path).dashboard, key) == number
        else:
            with pytest.raises(ConfigurationError):
                load_config(path)



@pytest.mark.parametrize("identity", ["http.connect_timeout", "http.read_timeout", "http.backoff_seconds", "sources.minimum_request_interval"])
def test_positive_only_bounds_match_loader(tmp_path, identity):
    path = tmp_path / "config.toml"
    spec = dc.FIELD_METADATA[identity]
    assert getattr(spec, "minimum_exclusive", False), identity
    assert spec.maximum is None and spec.step == "any"
    section, key = identity.split(".")
    for number, accepted in ((spec.minimum, False), (spec.minimum + 0.001, True)):
        path.write_text(dc.dumps({"inventory": {"path": "inventory.csv"}, section: {key: number}}))
        if accepted:
            assert getattr(getattr(load_config(path), section), key) == number
        else:
            with pytest.raises(ConfigurationError):
                load_config(path)



def test_defaults_match_minimal_loader_output(tmp_path):
    from pathlib import Path
    path = tmp_path / "config.toml"
    path.write_text('[inventory]\npath="inventory.csv"\n')
    loaded = load_config(path)
    for specs in dc.SCHEMAS.values():
        for section, schema in specs:
            for key in schema:
                if (section, key) == ("inventory", "path"):
                    continue  # Required input has no loader default.
                spec = dc.FIELD_METADATA[section + "." + key]
                if section == "state":
                    actual = loaded.database_path
                elif section == "output":
                    actual = loaded.output_dir
                elif section == "watch.reporting":
                    actual = loaded.watch.reporting_identity
                else:
                    owner = loaded.teams if section == "notifications.teams" else loaded.email if section == "notifications.email" else getattr(loaded, section)
                    actual = getattr(owner, key)
                if isinstance(actual, tuple):
                    actual = list(actual)
                if isinstance(actual, Path):
                    if section == "watch":
                        assert actual == loaded.database_path.parent / spec.default
                        continue
                    expected = (tmp_path / spec.default).resolve()
                else:
                    expected = spec.default
                assert actual == expected, section + "." + key



def channel_rows(tmp_path):
    secret = tmp_path / "teams-secret"
    if not secret.exists():
        secret.write_text("synthetic-private-secret", encoding="utf-8")
        if os.name == "posix":
            secret.chmod(0o600)
    return {
        "smtp": email_channel(),
        "graph": {"type": "graph", "tenant_id": "example", "client_id": "example", "sender": "alerts@example.com", "to": ["alerts@example.com"], "client_secret_env": "EXAMPLE_SECRET"},
        **{kind: {"type": kind, "webhook_url_env": "EXAMPLE_WEBHOOK"} for kind in ("teams", "slack", "discord")},
        "telegram": {"type": "telegram", "bot_token_env": "EXAMPLE_SECRET", "chat_id": "1234"},
        "matrix": {"type": "matrix", "homeserver": "https://example.com", "room_id": "!room:example.com", "access_token_env": "EXAMPLE_SECRET"},
        "ntfy": {"type": "ntfy", "topic": "example"},
        "gotify": {"type": "gotify", "server": "https://example.com", "app_token_env": "EXAMPLE_SECRET"},
        "webhook": {"type": "webhook", "url_env": "EXAMPLE_WEBHOOK"},
        "teams_bot": {"type": "teams_bot", "tenant_id": "00000000-0000-0000-0000-000000000001",
                      "app_id": "00000000-0000-0000-0000-000000000002",
                      "client_secret_file": secret.name, "recipients": ["alerts@example.com"]},
    }



@pytest.mark.parametrize("kind", dc.TYPE_KEYS)
def test_channel_defaults_against_loader(tmp_path, kind, monkeypatch):
    monkeypatch.delenv("EXAMPLE_SECRET", raising=False)
    monkeypatch.delenv("EXAMPLE_WEBHOOK", raising=False)
    path = tmp_path / "config.toml"
    path.write_text(dc.dumps({"inventory": {"path": "inventory.csv"}, "watch": {"channels": {"example": channel_rows(tmp_path)[kind]}}}))
    channel = load_config(path).watch.channels[0]
    for key in dc.COMMON_KEYS | dc.TYPE_KEYS[kind]:
        spec = dc.FIELD_METADATA[f"watch.channels.{kind}.{key}"]
        assert spec.help and spec.example is not None
        if key == "url" and "url_env" in channel_rows(tmp_path)[kind]:
            assert spec.default is None  # Resolved references are not a direct URL default.
        elif key not in channel_rows(tmp_path)[kind]:
            actual = getattr(channel, key, channel.options.get(key))
            if isinstance(actual, tuple):
                actual = list(actual)
            assert actual == spec.default, f"{kind}.{key}"



def test_rule_defaults_against_loader(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(dc.dumps({"inventory": {"path": "inventory.csv"}, "watch": {
        "channels": {"email": email_channel()},
        "rules": [{"name": "example", "channels": ["email"], "condition": {"cvss_min": 9.0}}],
    }}))
    rule = load_config(path).watch.rules[0]
    for key in ("enabled", "old_cves", "events", "cvss_providers"):
        actual = getattr(rule, key)
        assert dc.FIELD_METADATA["watch.rules." + key].default == (list(actual) if isinstance(actual, tuple) else actual)



@pytest.mark.parametrize("kind,key", [(kind, key) for kind, keys in dc.TYPE_KEYS.items()
                                     for key in dc.NUMBER_FIELDS & (keys | dc.COMMON_KEYS)])
def test_channel_numeric_limits_against_loader(tmp_path, kind, key, monkeypatch):
    monkeypatch.delenv("EXAMPLE_SECRET", raising=False)
    monkeypatch.delenv("EXAMPLE_WEBHOOK", raising=False)
    spec = dc.FIELD_METADATA[f"watch.channels.{kind}.{key}"]
    lower = min(spec.choices) if spec.choices else spec.minimum
    upper = max(spec.choices) if spec.choices else spec.maximum
    assert lower is not None and upper is not None
    path = tmp_path / "config.toml"
    for number, accepted in ((lower - 1, False), (lower, True), (upper, True), (upper + 1, False)):
        row = {**channel_rows(tmp_path)[kind], key: number}
        path.write_text(dc.dumps({"inventory": {"path": "inventory.csv"}, "watch": {"channels": {"example": row}}}))
        if accepted:
            load_config(path)
        else:
            with pytest.raises(ConfigurationError):
                load_config(path)



def _future_enum_validator(value):
    from cvebeacon.config import WATCH_INITIAL_MODES
    if value not in WATCH_INITIAL_MODES:
        raise ConfigurationError("future.choice must be a known mode")



def test_new_validator_helpers_require_an_explicit_field_contract(monkeypatch):
    from cvebeacon import config
    from test_dashboard_config_ux import test_enum_metadata_covers_validator_enums
    monkeypatch.setattr(_future_enum_validator, "__module__", config.__name__)
    monkeypatch.setattr(config, "_future_enum_validator", _future_enum_validator, raising=False)
    with pytest.raises(AssertionError, match="Bind enum validation to field identities"):
        test_enum_metadata_covers_validator_enums()


def _future_literal_validator(value):
    if value not in ("first", "second"):
        raise ConfigurationError("future.choice must be first or second")


def test_new_inline_enum_validators_require_shared_choices(monkeypatch):
    from cvebeacon import config
    from test_dashboard_config_ux import test_enum_metadata_covers_validator_enums
    monkeypatch.setattr(_future_literal_validator, "__module__", config.__name__)
    monkeypatch.setattr(config, "_future_literal_validator", _future_literal_validator, raising=False)
    with pytest.raises(AssertionError, match="Export enum choices as a shared constant"):
        test_enum_metadata_covers_validator_enums()
