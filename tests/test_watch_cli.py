from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest
from watch_support import NOW, mock_client, nvd_cve, nvd_page, write_config

from cvebeacon import cli, dashboard
from cvebeacon.errors import CVEBeaconError
from cvebeacon.models import (
    Applicability,
    Asset,
    Finding,
    QueryResult,
    Vulnerability,
)
from cvebeacon.state import StateStore
from cvebeacon.watch import store as watch_store, sync as watch_sync
from cvebeacon.watch.records import CVSSEntry, WatchRecord
from cvebeacon.watch.rules import parse_rules
from cvebeacon.watch.store import WatchStore

RULES = """
[[watch.rules]]
name = "critical-or-likely"
condition = { any = [ { cvss_min = 9.0 }, { epss_min = 0.5 } ] }
channels = ["soc-email"]

[[watch.rules]]
name = "kev-watch"
condition = { kev = "any" }
channels = ["teams"]
events = ["match", "kev_added"]
"""

# CVSS-only variant for tests that run `watch run` or `watch sync`: their mock
# server answers every URL with NVD JSON, so no EPSS feed is available there.
RULES_CVSS_ONLY = """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9.0 }
channels = ["soc-email"]

[[watch.rules]]
name = "kev-watch"
condition = { kev = "any" }
channels = ["teams"]
events = ["match", "kev_added"]
"""


def record(identifier: str = "CVE-2026-0001", **overrides) -> WatchRecord:
    values = {
        "cve_id": identifier,
        "status": "published",
        "published": "2026-10-30T00:00:00.000",
        "description": "Example vulnerability",
        "cvss": (CVSSEntry("cna", "security@example.com", "3.1", 9.8),),
    }
    values.update(overrides)
    return WatchRecord(**values)


def test_watch_rules_check_prints_readable_conditions(tmp_path, capsys):
    config = write_config(tmp_path, sources=("nvd", "epss"), extra=RULES)
    assert cli.main(["--config", str(config.config_path), "watch", "rules", "check"]) == 0
    output = capsys.readouterr().out
    assert "critical-or-likely: (cvss >= 9.0 OR epss >= 0.5)" in output
    assert "kev-watch: kev any" in output


def test_watch_rules_check_works_for_a_watch_only_config(tmp_path, capsys):
    config = write_config(tmp_path, inventory=False, sources=("nvd", "epss"), extra=RULES)
    assert config.inventory is None
    assert cli.main(["--config", str(config.config_path), "watch", "rules", "check"]) == 0
    assert "critical-or-likely" in capsys.readouterr().out


def test_watch_events_lists_concise_lines_and_filters(tmp_path, capsys):
    config = write_config(tmp_path, sources=("nvd", "epss"), extra=RULES)
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd(
        [
            record(),
            record("CVE-2026-0002", cisa_kev_added="2026-11-03"),
            record("CVE-2026-0003", published=None),
        ]
    )
    store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources)
    assert cli.main(["--config", str(config.config_path), "watch", "events"]) == 0
    output = capsys.readouterr().out
    assert (
        "2026-11-03 12:00Z  critical-or-likely  CVE-2026-0001  match  "
        "cvss 9.8 v3.1 (cna)  "
        "Published 2026-10-30 · first seen 2026-11-03"
    ) in output
    assert (
        "2026-11-03 12:00Z  kev-watch  CVE-2026-0002  match  kev cisa  "
        "Published 2026-10-30 · first seen 2026-11-03"
    ) in output
    assert (
        "2026-11-03 12:00Z  critical-or-likely  CVE-2026-0002  match  "
        "cvss 9.8 v3.1 (cna)  "
        "Published 2026-10-30 · first seen 2026-11-03"
    ) in output
    assert (
        "2026-11-03 12:00Z  critical-or-likely  CVE-2026-0003  match  "
        "cvss 9.8 v3.1 (cna)  "
        "Published unknown · first seen 2026-11-03"
    ) in output
    assert cli.main(
        ["--config", str(config.config_path), "watch", "events", "--rule", "kev-watch"]
    ) == 0
    output = capsys.readouterr().out
    assert "critical-or-likely" not in output
    assert output.count("kev-watch") == 1


def test_watch_events_shows_affected_clients(tmp_path, capsys):
    config = write_config(tmp_path, sources=("nvd", "epss"), extra=RULES)
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources)
    state = StateStore(config.database_path)
    acme = Asset("a1", "Acme", "Widget", "1", client="Acme")
    globex = Asset("a2", "Acme", "Widget", "2", client="Globex")
    state.record_scan(
        [
            QueryResult(
                acme,
                (
                    Finding(
                        acme,
                        Vulnerability("CVE-2026-0001"),
                        Applicability.AFFECTED,
                        "high",
                        "test",
                    ),
                ),
                (),
            ),
            QueryResult(
                globex,
                (
                    Finding(
                        globex,
                        Vulnerability("CVE-2026-0001"),
                        Applicability.NEEDS_REVIEW,
                        "limited",
                        "test",
                    ),
                ),
                (),
            ),
        ]
    )
    assert cli.main(["--config", str(config.config_path), "watch", "events"]) == 0
    output = capsys.readouterr().out
    assert "Affected clients: Acme, Globex (review)" in output


def test_watch_events_pending_filter(tmp_path, capsys):
    config = write_config(tmp_path, sources=("nvd", "epss"), extra=RULES)
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd([record(cisa_kev_added="2026-11-03")])
    store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_delivery SET status='sent' WHERE event_id IN "
            "(SELECT id FROM watch_event WHERE rule='critical-or-likely')"
        )
    assert cli.main(["--config", str(config.config_path), "watch", "events", "--pending"]) == 0
    output = capsys.readouterr().out
    assert "critical-or-likely" not in output
    assert "kev-watch" in output


def test_watch_evaluate_all_requires_confirmation_and_marks_initial(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, sources=("nvd", "epss"), extra=RULES)
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd([record(cisa_kev_added="2026-11-03")])
    store.acknowledge(store.pending_evaluations(100))

    monkeypatch.setattr("builtins.input", lambda message: "n")
    assert cli.main(["--config", str(config.config_path), "watch", "evaluate", "--all"]) == 1
    assert "cancelled" in capsys.readouterr().out
    assert store.events() == ()

    monkeypatch.setattr("builtins.input", lambda message: "y")
    assert cli.main(["--config", str(config.config_path), "watch", "evaluate", "--all"]) == 0
    output = capsys.readouterr().out
    assert "evaluated: 1 CVE(s)" in output
    assert "events: 2 new (match 2)" in output
    assert all(event.initial for event in store.events())


def test_watch_run_syncs_and_evaluates_with_initial_events(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, initial="backfill", extra=RULES_CVSS_ONLY)

    def handler(request):
        return httpx.Response(200, json=nvd_page([nvd_cve(cisaExploitAdd="2026-11-03")]))

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 0
    output = capsys.readouterr().out
    assert "nvd:" in output
    assert "events: 2 new (match 2)" in output
    events = WatchStore(config.watch.database).events()
    assert len(events) == 2 and all(event.initial for event in events)


def test_watch_sync_leaves_evaluation_for_watch_run(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, initial="backfill", extra=RULES_CVSS_ONLY)

    def handler(request):
        return httpx.Response(200, json=nvd_page([nvd_cve(cisaExploitAdd="2026-11-03")]))

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 0
    store = WatchStore(config.watch.database)
    assert store.events() == ()
    assert store.pending_evaluations(10) == ("CVE-2026-0001",)
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 0
    output = capsys.readouterr().out
    assert "events: 2 new (match 2)" in output


def test_watch_evaluate_all_closes_a_completed_initial_backfill(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    )
    config = write_config(
        tmp_path,
        initial="backfill",
        channels="""
[watch.channels.slack]
type = "slack"
webhook_url_env = "SLACK_URL"
""",
        extra="""
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["slack"]
""",
    )
    clock = [NOW]
    real_sync = watch_sync.sync_watch

    def fixed_sync(config, http, **kwargs):
        return real_sync(config, http, clock=lambda: clock[0], **kwargs)

    def fixed_store(path, **kwargs):
        return WatchStore(path, clock=lambda: clock[0])

    monkeypatch.setattr(watch_sync, "sync_watch", fixed_sync)
    monkeypatch.setattr(watch_store, "WatchStore", fixed_store)

    changes = [
        nvd_cve("CVE-2026-0001", published="2026-11-01T00:00:00.000"),
    ]
    seen = []

    def handler(request):
        if "hooks.slack.com" in str(request.url):
            seen.append(json.loads(request.content)["text"])
            return httpx.Response(200, content=b"ok")
        return httpx.Response(200, json=nvd_page(changes))

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    commands = (
        ["watch", "sync"],
        ["watch", "evaluate", "--all", "--yes"],
        ["watch", "notify"],
    )
    for command in commands:
        assert cli.main(["--config", str(config.config_path), *command]) == 0

    store = WatchStore(config.watch.database)
    metadata = store.metadata()
    assert metadata["initial_sync_completed_at"] == NOW.isoformat()
    assert metadata["initial_evaluated_at"] == NOW.isoformat()
    assert store.pending_evaluations(10) == ()
    assert len(seen) == 1
    assert "CVEBeacon initial summary: 1 CVE across 1 rule" in seen[0]

    changes.append(
        nvd_cve(
            "CVE-2026-0002",
            published="2026-11-03T13:00:00.000",
            lastModified="2026-11-03T13:00:00.000",
        )
    )
    clock[0] = NOW + timedelta(hours=1)
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 0

    assert len(seen) == 2
    assert "initial summary" not in seen[1]
    assert "CVE-2026-0002" in seen[1]
    events = [(event.cve_id, event.initial) for event in store.events()]
    assert events == [("CVE-2026-0002", False), ("CVE-2026-0001", True)]


def test_watch_evaluate_all_keeps_an_interrupted_initial_sync_open(tmp_path, monkeypatch, capsys):
    config = write_config(
        tmp_path,
        initial="full",
        extra="""
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["soc-email"]
""",
    )
    requests = {"nvd": 0}

    def handler(request):
        requests["nvd"] += 1
        if requests["nvd"] == 1:
            return httpx.Response(200, json=nvd_page([nvd_cve()]))
        return httpx.Response(500)

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "sync", "--yes"]) == 2

    store = WatchStore(config.watch.database)
    metadata = store.metadata()
    assert metadata["initial_mode"] == "full"
    assert "initialized_at" not in metadata
    capsys.readouterr()

    assert (
        cli.main(
            ["--config", str(config.config_path), "watch", "evaluate", "--all", "--yes"]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "initialization stays open until the initial sync completes" in output
    assert "initial_evaluated_at" not in store.metadata()
    assert store.pending_evaluations(10) == ("CVE-2026-0001",)


def test_watch_evaluate_all_eof_is_cancelled(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, sources=("nvd", "epss"), extra=RULES)

    def eof(message):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert cli.main(["--config", str(config.config_path), "watch", "evaluate", "--all"]) == 1
    assert "cancelled" in capsys.readouterr().out


def test_watch_run_works_without_an_inventory(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, inventory=False, initial="backfill", extra=RULES_CVSS_ONLY)

    def handler(request):
        return httpx.Response(
            200, json=nvd_page([nvd_cve(cisaExploitAdd="2026-11-03")])
        )

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "run"]) == 0
    assert "events: 2 new (match 2)" in capsys.readouterr().out


def test_inventory_commands_fail_clearly_without_inventory(tmp_path, capsys):
    config = write_config(tmp_path, inventory=False, sources=("nvd", "epss"), extra=RULES)
    for command in (
        ["scan"],
        ["asset", "example"],
        ["export"],
        ["inventory", "validate"],
        ["inventory", "inspect"],
    ):
        assert cli.main(["--config", str(config.config_path), *command]) == 2
        error = capsys.readouterr().err
        assert "requires an inventory" in error
        assert "[inventory] path" in error
        assert "add or restore an inventory from the Inventory page" in error
        assert "client inventory" not in error.casefold()
        assert "Clients page" not in error


def test_doctor_without_inventory_points_to_the_inventory_page(tmp_path, capsys):
    config = write_config(
        tmp_path, inventory=False, enabled=False,
        extra="[inventory]\nmanaged = true\n",
    )
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 0
    checks = json.loads(capsys.readouterr().out)
    assert checks["inventory"] == "skipped (add or restore an inventory from the Inventory page)"


def test_inventory_validate_accepts_an_explicit_path_without_inventory(tmp_path, capsys):
    config = write_config(tmp_path, inventory=False)
    inventory = tmp_path / "inventory.csv"
    inventory.write_text(
        "asset_id,vendor,product,version\nserver-1,Acme,Widget,1.0\n",
        encoding="utf-8",
    )
    assert cli.main(
        ["--config", str(config.config_path), "inventory", "validate", str(inventory)]
    ) == 0
    assert "valid: 1 asset(s)" in capsys.readouterr().out


def test_dashboard_accepts_watch_only_config_without_inventory(tmp_path):
    config = write_config(tmp_path, inventory=False)
    dashboard.create_app(config)


def test_dashboard_refuses_configuration_without_watch_or_inventory(tmp_path):
    config = write_config(tmp_path, inventory=False)
    config = replace(config, watch=replace(config.watch, enabled=False))
    try:
        dashboard.create_app(config)
    except CVEBeaconError as exc:
        assert "[inventory] path" in str(exc)
        assert "[watch] enabled = true" in str(exc)
    else:
        raise AssertionError("the dashboard must refuse an empty configuration")


def test_known_rules_still_load_from_the_old_config_shape(tmp_path):
    config = write_config(tmp_path)
    assert config.watch.rules == ()
    assert config.inventory is not None


def test_watch_events_rule_filter_and_display_are_case_insensitive(tmp_path, capsys):
    config = write_config(
        tmp_path,
        extra="""
[[watch.rules]]
name = "Critical"
condition = { cvss_min = 9 }
channels = ["soc-email"]
""",
    )
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources)
    assert cli.main(
        ["--config", str(config.config_path), "watch", "events", "--rule", "CRITICAL"]
    ) == 0
    output = capsys.readouterr().out
    assert "  Critical  CVE-2026-0001  match" in output


def test_watch_output_is_ascii_under_cp1252(tmp_path, monkeypatch):
    import io
    import sys

    config = write_config(tmp_path, sources=("nvd", "epss"), extra=RULES)
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.evaluate_touched(config.watch.rules, catalogs=config.watch.sources)

    for command, expected in (
        (["watch", "rules", "check"], "cvss >= 9.0"),
        (["watch", "events"], "cvss 9.8 v3.1 (cna)"),
    ):
        buffer = io.BytesIO()
        wrapper = io.TextIOWrapper(buffer, encoding="cp1252")
        monkeypatch.setattr(sys, "stdout", wrapper)
        assert cli.main(["--config", str(config.config_path), *command]) == 0
        wrapper.flush()
        assert expected in buffer.getvalue().decode("cp1252")


def test_watch_only_config_can_schedule_watch_run(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, inventory=False)
    installed = []
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    monkeypatch.setattr(cli, "install", lambda plan: installed.append(plan))
    assert cli.main(
        [
            "--config",
            str(config.config_path),
            "schedule",
            "install",
            "--times",
            "07:00",
            "--yes",
        ]
    ) == 0
    assert installed[0].schedule_command == "watch"
    output = capsys.readouterr().out
    assert "watch run" in output
    assert "Schedule: daily at 07:00" in output


def test_watch_only_config_doctor_checks_watch_deployment(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False, sources=("nvd", "epss"))
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 0
    output = capsys.readouterr().out
    checks = json.loads(output)
    assert checks["configuration"] == "ok"
    assert checks["inventory"].startswith("skipped (watch-only deployment")
    assert checks["data_directory"].startswith("ok (")
    assert checks["state_directory"].startswith("ok (")
    assert checks["watch_database"] == "not created yet"
    assert checks["watch_channels"] == "ok (no enabled channels)"
    assert checks["watch_sources"] == "ok (nvd, epss; NVD API key not set (optional))"
    assert checks["schedule"] == "not installed"
    assert not (tmp_path / "watch.db").exists()


def test_watch_only_doctor_checks_an_existing_watch_database(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 0
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == "ok (0 CVEs, schema 10)"


@pytest.mark.parametrize("version", ["11", "999", "not-a-version"])
def test_watch_only_doctor_rejects_an_unsupported_watch_schema(
    tmp_path, monkeypatch, capsys, version
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute(
            "UPDATE watch_meta SET value=? WHERE key='schema_version'", (version,)
        )
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        f"unreadable (unsupported watch schema version {version}; expected 10 or "
        "an older supported schema)"
    )


@pytest.mark.parametrize("version", ["1", "6", "8", "9"])
def test_watch_only_doctor_accepts_an_older_supported_watch_schema(
    tmp_path, monkeypatch, capsys, version
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute(
            "UPDATE watch_meta SET value=? WHERE key='schema_version'", (version,)
        )
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 0
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        f"ok (0 CVEs, schema {version}; will migrate to 10 on the next write)"
    )


@pytest.mark.parametrize("row_count", [2, 50])
def test_watch_only_doctor_rejects_ambiguous_watch_schema_metadata(
    tmp_path, monkeypatch, capsys, row_count
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("DROP TABLE watch_meta")
        db.execute("CREATE TABLE watch_meta (key TEXT, value TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO watch_meta VALUES (?, ?)",
            [("schema_version", "7")] * row_count,
        )
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        "unreadable (ambiguous watch schema metadata; expected one version row)"
    )


def test_watch_only_doctor_rejects_an_incompatible_older_watch_schema(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("ALTER TABLE watch_report DROP COLUMN chain")
        db.execute("UPDATE watch_meta SET value='6' WHERE key='schema_version'")
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        "unreadable (watch database cannot be migrated from schema 6: "
        "watch_report has no chain column)"
    )


def test_watch_only_doctor_rejects_chain_version_without_chain(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("ALTER TABLE watch_report DROP COLUMN chain")
        db.execute("UPDATE watch_meta SET value='5' WHERE key='schema_version'")
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        "unreadable (watch database cannot be migrated from schema 5: "
        "watch_report has chain_version without chain)"
    )


def test_watch_only_doctor_rejects_version_floor_damage(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("ALTER TABLE watch_event DROP COLUMN details_json")
        db.execute("UPDATE watch_meta SET value='6' WHERE key='schema_version'")
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        "unreadable (watch database cannot be migrated from schema 6: "
        "missing watch_event.details_json)"
    )


def test_watch_only_doctor_reports_a_pre_release_watch_schema(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("ALTER TABLE watch_alert_state DROP COLUMN providers_hash")
        db.execute("UPDATE watch_meta SET value='2' WHERE key='schema_version'")
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        "unreadable (watch database was created by a pre-release build; delete "
        "it and run `watch sync` again)"
    )


def test_watch_only_doctor_rejects_an_incomplete_watch_schema(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("DROP TABLE watch_event")
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        "unreadable (watch database is missing required tables)"
    )


def test_watch_only_doctor_rejects_a_missing_watch_schema_column(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    with sqlite3.connect(config.watch.database) as db:
        db.execute("ALTER TABLE watch_report DROP COLUMN chain_version")
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_database"] == (
        "unreadable (watch database is missing required columns in watch_report)"
    )


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="POSIX file modes for a non-root account",
)
def test_watch_only_doctor_unwritable_database_has_no_traceback(tmp_path):
    config = write_config(tmp_path, inventory=False)
    WatchStore(config.watch.database).initialize()
    config.watch.database.chmod(0o400)
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "cvebeacon",
                "--config",
                str(config.config_path),
                "doctor",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        config.watch.database.chmod(0o600)
    assert result.returncode == 2, result.stderr
    assert "not writable" in result.stdout
    assert "Traceback" not in result.stderr


def test_watch_channel_check_derives_env_only_credential_names(
    tmp_path, monkeypatch
):
    from cvebeacon.watch import channels as watch_channels

    config = write_config(tmp_path, inventory=False, channels=MISSING_WEBHOOK_URL)
    monkeypatch.delenv("CVEBEACON_TEST_MISSING_HOOK", raising=False)
    monkeypatch.setitem(watch_channels.CREDENTIAL_FIELDS, "webhook", ("url_env",))
    assert cli._watch_channel_check(config).startswith("missing: hook (url)")


MISSING_WEBHOOK_URL = """
[watch.channels.hook]
type = "webhook"
url_env = "CVEBEACON_TEST_MISSING_HOOK"
"""
MISSING_SMTP_PASSWORD = """
[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
username = "alerts@example.invalid"
from = "alerts@example.invalid"
to = ["soc@example.invalid"]
"""
MISSING_WEBHOOK_HEADER = """
[watch.channels.hook]
type = "webhook"
url = "https://example.invalid/cvebeacon"
header_name = "X-Auth"
header_value_env = "CVEBEACON_TEST_MISSING_HEADER"
"""
MISSING_NTFY_TOKEN = """
[watch.channels.alerts]
type = "ntfy"
topic = "cvebeacon-test"
token_env = "CVEBEACON_TEST_MISSING_NTFY_TOKEN"
"""


@pytest.mark.parametrize(
    "channels, expected",
    [
        (MISSING_WEBHOOK_URL, "hook (url)"),
        (MISSING_SMTP_PASSWORD, "mail (password)"),
        (MISSING_WEBHOOK_HEADER, "hook (header value)"),
        (MISSING_NTFY_TOKEN, "alerts (token)"),
    ],
)
def test_watch_only_doctor_fails_for_missing_channel_secrets(
    tmp_path, monkeypatch, capsys, channels, expected
):
    config = write_config(tmp_path, inventory=False, channels=channels)
    for name in (
        "CVEBEACON_TEST_MISSING_HOOK",
        "CVEBEACON_TEST_MISSING_HEADER",
        "CVEBEACON_TEST_MISSING_NTFY_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_channels"].startswith("missing:")
    assert expected in checks["watch_channels"]


ANONYMOUS_SMTP = """
[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
from = "alerts@example.invalid"
to = ["soc@example.invalid"]
"""
UNUSED_SMTP_PASSWORD = """
[watch.channels.mail]
type = "smtp"
host = "smtp.example.invalid"
password_env = "CVEBEACON_TEST_UNUSED_SMTP_PASSWORD"
from = "alerts@example.invalid"
to = ["soc@example.invalid"]
"""
PLAIN_NTFY = """
[watch.channels.alerts]
type = "ntfy"
topic = "cvebeacon-test"
"""
DIRECT_WEBHOOK = """
[watch.channels.hook]
type = "webhook"
url = "https://example.invalid/cvebeacon"
"""


@pytest.mark.parametrize(
    "channels", [ANONYMOUS_SMTP, UNUSED_SMTP_PASSWORD, PLAIN_NTFY, DIRECT_WEBHOOK]
)
def test_watch_only_doctor_accepts_channels_without_optional_auth(
    tmp_path, monkeypatch, capsys, channels
):
    config = write_config(tmp_path, inventory=False, channels=channels)
    monkeypatch.delenv("CVEBEACON_TEST_UNUSED_SMTP_PASSWORD", raising=False)
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 0
    checks = json.loads(capsys.readouterr().out)
    assert checks["watch_channels"].startswith("ok (1 enabled:")


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes")
def test_watch_only_doctor_reports_unsafe_data_directory(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    tmp_path.chmod(0o777)
    try:
        assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    finally:
        tmp_path.chmod(0o700)
    output = capsys.readouterr().out
    assert '"data_directory": "unsafe (group or other writable:' in output


def test_watch_only_doctor_does_not_create_missing_watch_paths(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    target = tmp_path / "new-data"
    config = replace(
        config, watch=replace(config.watch, database=target / "watch.db")
    )
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 0
    checks = json.loads(capsys.readouterr().out)
    assert checks["data_directory"].endswith("not created yet)")
    assert checks["watch_database"] == "not created yet"
    assert not target.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes")
def test_watch_only_doctor_reports_unwritable_new_watch_directory(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0o500)
    config = replace(
        config, watch=replace(config.watch, database=blocked / "new" / "watch.db")
    )
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    try:
        assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    finally:
        blocked.chmod(0o700)
    captured = capsys.readouterr()
    checks = json.loads(captured.out)
    assert checks["data_directory"].startswith("not writable")
    assert checks["watch_database"].startswith("skipped")
    assert not (blocked / "new").exists()
    assert "Traceback" not in captured.err


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes")
def test_watch_only_doctor_unwritable_directory_has_no_traceback(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0o500)
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[state]
database = "state.db"

[output]
directory = "reports"

[watch]
enabled = true
database = "blocked/new/watch.db"
sources = ["nvd"]
initial = "baseline"
""",
        encoding="utf-8",
    )
    try:
        result = subprocess.run(
            [sys.executable, "-m", "cvebeacon", "--config", str(config_path), "doctor"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        blocked.chmod(0o700)
    assert result.returncode == 2, result.stderr
    assert "Traceback" not in result.stderr
    assert "not writable" in result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes")
def test_watch_only_doctor_reports_unwritable_state_directory(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    state_directory = tmp_path / "state"
    state_directory.mkdir()
    state_directory.chmod(0o500)
    config = replace(config, database_path=state_directory / "state.db")
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    try:
        assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    finally:
        state_directory.chmod(0o700)
    checks = json.loads(capsys.readouterr().out)
    assert checks["state_directory"].startswith("not writable")


@pytest.mark.skipif(os.name != "posix", reason="POSIX crontab parsing")
def test_watch_only_doctor_fails_for_a_malformed_managed_schedule(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)
    monkeypatch.setattr(
        "cvebeacon.scheduling._read_crontab",
        lambda run=None: "# BEGIN CVEBEACON MANAGED\n0 7 * * * /bin/true\n",
    )
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)
    assert checks["schedule"] == "invalid (managed schedule is malformed)"


def test_watch_only_doctor_tolerates_an_unavailable_schedule(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False)

    def unavailable(**kwargs):
        raise OSError("crontab is not installed")

    monkeypatch.setattr(cli, "status", unavailable)
    assert cli.main(["--config", str(config.config_path), "doctor"]) == 0
    checks = json.loads(capsys.readouterr().out)
    assert checks["schedule"].startswith("not checked")


def test_watch_only_doctor_live_checks_only_watch_sources(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, inventory=False, sources=("nvd", "epss"))
    monkeypatch.setattr(cli, "status", lambda **kwargs: "not installed")
    calls = []

    def live_checks(app_config, *, only=None):
        calls.append(only)
        return {name: "ok" for name in only}

    monkeypatch.setattr(cli, "_live_source_checks", live_checks)
    assert cli.main(["--config", str(config.config_path), "doctor", "--live"]) == 0
    checks = json.loads(capsys.readouterr().out)
    assert calls == [("nvd", "epss")]
    assert checks["live_sources"] == {"nvd": "ok", "epss": "ok"}


def test_live_source_checks_filter_to_the_requested_sources(
    tmp_path, monkeypatch
):
    config = write_config(tmp_path, inventory=False, sources=("nvd", "epss"))
    calls = []

    class FakeHttp:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get_json(self, *args, **kwargs):
            calls.append("nvd")
            return {"vulnerabilities": []}

    class FakeEPSS:
        def __init__(self, http):
            pass

        def scores(self, identifiers):
            calls.append("epss")
            return {}

    monkeypatch.setattr(cli, "HttpClient", FakeHttp)
    monkeypatch.setattr(cli, "EPSSSource", FakeEPSS)
    checks = cli._live_source_checks(config, only=("nvd", "epss"))
    assert checks == {"nvd": "ok", "epss": "ok"}
    assert calls == ["nvd", "epss"]


def test_watch_only_config_serves_dashboard(tmp_path, monkeypatch):
    config = write_config(tmp_path, inventory=False)
    calls = []
    monkeypatch.setattr(
        dashboard, "serve", lambda value, **kwargs: calls.append(kwargs)
    )
    assert cli.main(["--config", str(config.config_path), "serve"]) == 0
    assert calls == [
        {
            "host": "127.0.0.1",
            "port": 8787,
            "allow_unauthenticated_remote": False,
        }
    ]
