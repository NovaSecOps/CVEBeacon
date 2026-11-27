"""Independent field identities for checking the editor against its validators."""

import ast
import inspect

from cvebeacon import config, dashboard_config as dc
from cvebeacon.watch import catalog, channels, reported, rules


def enum_contracts():
    contracts = {
        "watch.initial": ("enum", config.WATCH_INITIAL_MODES),
        "watch.language": ("enum", catalog.SUPPORTED_LANGUAGES),
        "watch.reporting.identity": ("enum", reported.IDENTITY_MODES),
        "inventory.format": ("enum", config.INVENTORY_FORMATS),
        "web.inventory_sync": ("enum", config.WEB_SYNC_MODES),
        "watch.rules.old_cves": ("enum", rules.OLD_CVES_MODES),
        "watch.sources": ("toml", config.WATCH_SOURCES),
        "watch.rules.events": ("toml", rules.EVENT_KINDS),
        "watch.rules.cvss_providers": ("toml", rules.CVSS_PROVIDERS),
    }
    common = {"type": channels.CHANNEL_TYPES, "grouping": channels.GROUPING_MODES,
              "language": catalog.SUPPORTED_LANGUAGES}
    for kind, keys in channels.TYPE_KEYS.items():
        for key, choices in common.items():
            contracts[f"watch.channels.{kind}.{key}"] = ("enum", choices)
        if "format" in keys:
            choices = channels.TEAMS_BOT_FORMATS if kind == "teams_bot" else channels.MESSAGE_FORMATS
            contracts[f"watch.channels.{kind}.format"] = ("enum", choices)
        if "security" in keys:
            contracts[f"watch.channels.{kind}.security"] = ("enum", channels.SMTP_SECURITY)
        if "priority" in keys:
            contracts[f"watch.channels.{kind}.priority"] = ("enum", tuple(range(1, 6) if kind == "ntfy" else range(-2, 11)))
    return contracts


def assert_enum_metadata():
    for identity, (kind, choices) in enum_contracts().items():
        spec = dc.FIELD_METADATA[identity]
        assert spec.kind == kind, identity
        assert (spec.choices if kind == "enum" else spec.item_choices) == choices, identity


def test_discovered_enum_sites_have_field_contracts():
    """Scan every module function, including future parser/validator helpers."""
    bindings = {
        ("config", "load_config", "WATCH_INITIAL_MODES"): ["watch.initial"],
        ("config", "load_config", "IDENTITY_MODES"): ["watch.reporting.identity"],
        ("config", "load_config", "INVENTORY_FORMATS"): ["inventory.format"],
        ("config", "load_config", "WEB_SYNC_MODES"): ["web.inventory_sync"],
        ("channels", "_common", "GROUPING_MODES"): [f"watch.channels.{kind}.grouping" for kind in channels.CHANNEL_TYPES],
        ("channels", "_common", "MESSAGE_FORMATS"): [f"watch.channels.{kind}.format" for kind, keys in channels.TYPE_KEYS.items() if "format" in keys and kind != "teams_bot"],
        ("channels", "_common", "TEAMS_BOT_FORMATS"): ["watch.channels.teams_bot.format"],
        ("channels", "_parse_smtp", "SMTP_SECURITY"): ["watch.channels.smtp.security"],
        ("channels", "parse_channels", "CHANNEL_TYPES"): [f"watch.channels.{kind}.type" for kind in channels.CHANNEL_TYPES],
        ("catalog", "canonical_language", "SUPPORTED_LANGUAGES"): ["watch.language", *[f"watch.channels.{kind}.language" for kind in channels.CHANNEL_TYPES]],
        ("rules", "_rule_old_cves", "OLD_CVES_MODES"): ["watch.rules.old_cves"],
        ("rules", "_rule_events", "EVENT_KINDS"): ["watch.rules.events"],
        ("rules", "_rule_providers", "CVSS_PROVIDERS"): ["watch.rules.cvss_providers"],
    }
    contracts = enum_contracts()
    discovered = set()
    for module in (config, channels, catalog, rules):
        for name, function in inspect.getmembers(module, inspect.isfunction):
            if function.__module__ != module.__name__:
                continue
            for node in ast.walk(ast.parse(inspect.getsource(function))):
                allowed = None
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_enum":
                    allowed = node.args[2]
                    assert (isinstance(allowed, ast.Name) or module is rules and name == "_leaf_value"), "Export enum choices as a shared constant"
                elif isinstance(node, ast.Compare) and any(isinstance(op, ast.NotIn) for op in node.ops):
                    allowed = node.comparators[-1]
                    if isinstance(allowed, (ast.List, ast.Tuple, ast.Set)):
                        # These constrain URL components, not enumerated fields.
                        component_constraints = {
                            ("channels", "_matrix_homeserver", "parts.path"): {"", "/"},
                            ("channels", "_validate_webhook_host", "parts.hostname"): {"discord.com", "discordapp.com"},
                            ("channels", "teams_service_url", "port"): {None, 443},
                        }
                        site = (module.__name__.rsplit(".", 1)[-1], name, ast.unparse(node.left))
                        assert site in component_constraints, "Export enum choices as a shared constant"
                        assert set(ast.literal_eval(allowed)) == component_constraints[site]
                elif isinstance(node, ast.For):
                    allowed = node.iter
                if not isinstance(allowed, ast.Name):
                    continue
                choices = getattr(module, allowed.id, None)
                if not isinstance(choices, tuple) or not choices or not all(isinstance(item, str) for item in choices):
                    continue
                if allowed.id == "LEAF_KEYS":
                    assert dc.FIELD_METADATA["watch.rules.condition"].kind == "toml"
                    assert set(choices) == set(rules.CONDITION_SCHEMA)
                    continue
                site = (module.__name__.rsplit(".", 1)[-1], name, allowed.id)
                assert site in bindings, f"Bind enum validation to field identities: {site}"
                discovered.add(site)
                for identity in bindings[site]:
                    assert contracts[identity][1] == choices, (site, identity)
    assert discovered == set(bindings)
    assert_enum_metadata()
