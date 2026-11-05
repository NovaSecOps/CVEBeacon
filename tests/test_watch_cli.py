from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

import httpx
from watch_support import NOW, mock_client, nvd_cve, nvd_page, write_config

from cvebeacon import cli
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
        ["doctor"],
    ):
        assert cli.main(["--config", str(config.config_path), *command]) == 2
        error = capsys.readouterr().err
        assert "requires an inventory" in error
        assert "[inventory] path" in error


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


def test_dashboard_requires_inventory_when_it_is_missing(tmp_path):
    from cvebeacon.dashboard import create_app
    from cvebeacon.errors import CVEBeaconError

    config = write_config(tmp_path, inventory=False)
    try:
        create_app(config)
    except CVEBeaconError as exc:
        assert "inventory" in str(exc)
    else:
        raise AssertionError("the dashboard must refuse a watch-only configuration")


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


def test_watch_only_config_refuses_doctor_and_serve(tmp_path, capsys):
    config = write_config(tmp_path, inventory=False)
    for command in ("doctor", "serve"):
        assert cli.main(["--config", str(config.config_path), command]) == 2
        error = capsys.readouterr().err
        assert "requires an inventory" in error
        assert "watch run" in error
