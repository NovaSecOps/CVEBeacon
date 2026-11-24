"""Home getting-started checklist: detectors, copy, permissions and rendering."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sqlite3

import pytest
from flask import g

from cvebeacon import backup, dashboard, dashboard_setup
from cvebeacon.config import AppConfig, WatchConfig
from cvebeacon.dashboard_jobs import Job, MAX_HISTORY, build_command
from cvebeacon.dashboard_setup import (
    STALE_BACKUP_DAYS,
    STALE_SYNC_DAYS,
    WATCH_UNREADABLE,
    ClientInfo,
    Setup,
    Viewer,
    build_setup,
    gather,
)
from cvebeacon.errors import StateError
from cvebeacon.state import StateStore
from cvebeacon.watch.channels import ChannelConfig
from cvebeacon.watch.rules import Condition, Rule
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from watch_support import write_config

PASSWORD = "Synthetic setup checklist password"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
STAMP = "2026-11-23 09:30 UTC"
BANNED = re.compile(r"\b(safe|protected|working|healthy|all set|not affected)\b", re.IGNORECASE)
FULL_PERMISSIONS = frozenset({
    "view", "run", "test_channel", "edit_watch", "edit_channels", "edit_rules",
    "edit_inventory", "manage_inventory", "manage_schedule", "manage_secrets",
})
BASE_ENDPOINTS = frozenset({
    "backups.index",
    "client_inventory.add",
    "config_editor.channels",
    "config_editor.inventory",
    "config_editor.rules",
    "config_editor.watch",
    "operations.index",
    "operations.job_detail",
    "operations.schedule",
    "watch.clients",
    "watch.overview",
})
CHANNELS = """
[watch.channels.email]
type = "webhook"
url = "http://127.0.0.1:9/sink"
allow_insecure = true
"""


def fake_link(endpoint, values):
    query = "&".join(f"{key}={value}" for key, value in sorted(values.items()))
    return f"/{endpoint}" + (f"?{query}" if query else "")


def make_viewer(
    permissions=FULL_PERMISSIONS,
    *,
    endpoints=BASE_ENDPOINTS,
    accounts=True,
    is_admin=True,
):
    return Viewer(
        accounts=accounts,
        permissions=frozenset(permissions),
        endpoints=frozenset(endpoints),
        is_admin=is_admin,
        link=fake_link,
    )


def make_channel(name="email", *, enabled=True):
    return ChannelConfig(name=name, type="webhook", enabled=enabled)


def make_rule(name="alerts", *, channels=("email",), enabled=True):
    return Rule(name=name, condition=Condition("leaf"), channels=tuple(channels),
                enabled=enabled)


def unit_config(*, enabled=True, sources=("nvd",), channels=(), rules=(), managed=True):
    return AppConfig(
        config_path=Path("config.toml"),
        inventory=None,
        database_path=Path("state.db"),
        output_dir=Path("reports"),
        watch=WatchConfig(
            enabled=enabled,
            database=Path("watch.db"),
            sources=tuple(sources),
            channels=tuple(channels),
            rules=tuple(rules),
        ),
        managed_inventory=managed,
    )


def steps_for(config, **values):
    options = {
        "meta": {},
        "jobs": (),
        "schedule_state": "none",
        "backup_info": {"count": 0, "last": None, "last_id": None},
        "client_info": ClientInfo(managed=False, scanned=0),
        "now": NOW,
        "viewer": make_viewer(),
    }
    options.update(values)
    return build_setup(config, **options)


def step(steps, step_id):
    return next(item for item in steps if item.id == step_id)


def make_job(
    job_id=1,
    name="email",
    *,
    status="succeeded",
    exit_code=0,
    ended_at="2026-11-23T09:30:00+00:00",
    argv=None,
    operation="notify-test",
):
    return Job(
        job_id,
        operation,
        status,
        "admin",
        "2026-11-23T09:29:00+00:00",
        "2026-11-23T09:29:00+00:00",
        ended_at,
        exit_code,
        False,
        "job.log",
        None,
        tuple(argv) if argv is not None else
        ("cvebeacon", "--config", "config.toml", "watch", "notify", "test", name),
    )


def test_sources_step_reports_watch_off():
    item = step(steps_for(unit_config(enabled=False)), "sources")
    assert item.state == "todo"
    assert item.title == "Turn on watching and get the first data"
    assert item.detail == "Watch mode is off, so CVEBeacon is not collecting vulnerability data."
    assert item.action_label == "Turn on watch mode"
    assert item.action_url == "/config_editor.watch"
    assert item.hint is None


def test_sources_step_reports_no_download_yet():
    item = step(steps_for(unit_config()), "sources")
    assert item.state == "todo"
    assert item.detail == "Watch mode is on, but no data has been downloaded yet."
    assert item.action_label == "Run the first sync"
    assert item.action_url == "/operations.index"
    assert item.hint is None


def test_sources_step_reports_initial_sync_pending():
    item = step(steps_for(unit_config(), meta={"initial_mode": "baseline"}), "sources")
    assert item.state == "todo"
    assert item.detail == "The first sync has not finished. Run it again if it stopped."
    assert item.action_label == "Open Operations"
    assert item.action_url == "/operations.index"


def test_sources_step_reports_failed_sources():
    item = step(steps_for(unit_config(), meta={
        "last_sync_at": "2026-11-23T09:30:00+00:00",
        "last_sync_failures": "nvd,epss",
    }), "sources")
    assert item.state == "attention"
    assert item.detail == "The last sync failed for: nvd, epss. Data may be out of date."
    assert item.action_label == "See sync details"
    assert item.action_url == "/watch.overview"
    assert item.hint is None


def test_sources_step_reports_stale_sync():
    item = step(steps_for(unit_config(), meta={
        "last_sync_at": (NOW - timedelta(days=4)).isoformat(),
    }), "sources")
    assert item.state == "attention"
    assert item.detail == "The last sync started 4 days ago. Data may be out of date."
    assert item.action_label == "See sync details"
    assert item.action_url == "/watch.overview"


def test_sources_step_staleness_boundary_is_three_days():
    fresh = step(steps_for(unit_config(), meta={
        "last_sync_at": (NOW - timedelta(days=STALE_SYNC_DAYS)).isoformat(),
    }), "sources")
    assert fresh.state == "done"
    stale = step(steps_for(unit_config(), meta={
        "last_sync_at": (NOW - timedelta(days=STALE_SYNC_DAYS, seconds=1)).isoformat(),
    }), "sources")
    assert stale.state == "attention"


def test_sources_step_reports_done_with_source_count_and_stamp():
    item = step(steps_for(unit_config(sources=("nvd", "cve")), meta={
        "last_sync_at": "2026-11-23T09:30:00+00:00",
    }), "sources")
    assert item.state == "done"
    assert item.detail == "Watching 2 sources. Last sync 2026-11-23 09:30 UTC."
    assert item.action_url is None
    assert item.action_label is None
    assert item.hint is None


@pytest.mark.parametrize("meta", [None, {"last_sync_at": "not-a-date"},
                                  {"last_sync_at": (NOW + timedelta(days=1)).isoformat()},
                                  {"last_sync_at": 42}])
def test_sources_step_reports_unreadable_data(meta):
    item = step(steps_for(unit_config(), meta=meta), "sources")
    assert item.state == "unknown"
    assert item.detail == WATCH_UNREADABLE
    assert item.action_label == "Open Watch overview"
    assert item.action_url == "/watch.overview"


def test_sources_step_without_sources_asks_to_choose_sources():
    item = step(steps_for(unit_config(sources=())), "sources")
    assert item.state == "todo"
    assert item.detail == "Watch mode is on, but no data source is selected."
    assert item.action_label == "Choose sources"
    assert item.action_url == "/config_editor.watch"
    assert item.hint is None


def test_channel_step_reports_no_enabled_channel():
    item = step(steps_for(unit_config(channels=(make_channel(enabled=False),))), "channel")
    assert item.state == "todo"
    assert item.title == "Set up and test a way to receive alerts"
    assert item.detail == "No alert channel is set up yet."
    assert item.action_label == "Add a channel"
    assert item.action_url == "/config_editor.channels"
    assert item.hint is None


def test_channel_step_uses_the_guided_setup_when_it_exists():
    endpoints = BASE_ENDPOINTS | {"config_editor.channel_wizard"}
    item = step(steps_for(unit_config(),
                          viewer=make_viewer(endpoints=endpoints)), "channel")
    assert item.state == "todo"
    assert item.action_url == "/config_editor.channel_wizard"


def test_channel_step_reports_untested_channel():
    item = step(steps_for(unit_config(channels=(make_channel(),))), "channel")
    assert item.state == "todo"
    assert item.detail == ('Channel "email" is set up, but there is no recent test on record.')
    assert item.action_label == "Send a test"
    assert item.action_url == "/operations.index"
    assert item.hint is None


def test_channel_step_uses_the_test_page_when_it_exists():
    endpoints = BASE_ENDPOINTS | {"operations.channel_test_form"}
    item = step(steps_for(unit_config(channels=(make_channel(),)),
                          viewer=make_viewer(endpoints=endpoints)), "channel")
    assert item.action_url == "/operations.channel_test_form?name=email"


def test_channel_step_reports_failed_test():
    item = step(steps_for(unit_config(channels=(make_channel(),)),
                          jobs=(make_job(status="failed", exit_code=3),)), "channel")
    assert item.state == "attention"
    assert item.detail == 'The last test to "email" failed. Alerts may not reach anyone.'
    assert item.action_label == "Review the test"
    assert item.action_url == "/operations.job_detail?job_id=1"


def test_channel_step_uses_the_result_page_when_it_exists():
    endpoints = BASE_ENDPOINTS | {"operations.channel_test_result"}
    item = step(steps_for(unit_config(channels=(make_channel(),)),
                          jobs=(make_job(status="failed", exit_code=3),),
                          viewer=make_viewer(endpoints=endpoints)), "channel")
    assert item.action_url == "/operations.channel_test_result?job_id=1&name=email"


def test_channel_step_reports_an_accepted_test():
    item = step(steps_for(unit_config(channels=(make_channel(),)),
                          jobs=(make_job(),)), "channel")
    assert item.state == "done"
    assert item.detail == (
        f'"email" accepted a test message on {STAMP}. '
        "Accepted means the service took it; check that it arrived."
    )
    assert item.action_url is None


def test_channel_step_counts_tested_channels():
    config = unit_config(channels=(make_channel("email"), make_channel("slack")))
    item = step(steps_for(config, jobs=(make_job(name="email"),)), "channel")
    assert item.state == "done"
    assert item.detail.endswith(" 1 of 2 channels tested.")


def test_channel_step_uses_the_latest_job_per_channel():
    older_success = make_job(1, status="succeeded", exit_code=0)
    newer_failure = make_job(2, status="failed", exit_code=3)
    item = step(steps_for(unit_config(channels=(make_channel(),)),
                          jobs=(newer_failure, older_success)), "channel")
    assert item.state == "attention"
    newer_success = make_job(3, status="succeeded", exit_code=0)
    item = step(steps_for(unit_config(channels=(make_channel(),)),
                          jobs=(newer_success, older_success)), "channel")
    assert item.state == "done"


def test_channel_step_reports_a_failure_beside_an_accepted_test():
    config = unit_config(channels=(make_channel("email"), make_channel("slack")))
    item = step(steps_for(config, jobs=(
        make_job(1, name="email"),
        make_job(2, name="slack", status="failed", exit_code=3),
    )), "channel")
    assert item.state == "attention"
    assert item.detail == (
        f'"email" accepted a test message on {STAMP}. '
        "Accepted means the service took it; check that it arrived. "
        "1 of 2 channels tested. "
        'The last test to "slack" failed.'
    )
    assert item.action_label == "Review the test"
    assert item.action_url == "/operations.job_detail?job_id=2"


def test_channel_step_names_at_most_three_failed_channels():
    names = ("email", "alpha", "bravo", "charlie", "delta", "echo")
    config = unit_config(channels=tuple(make_channel(name) for name in names))
    jobs = [make_job(1, name="email")]
    jobs.extend(make_job(index, name=name, status="failed", exit_code=3)
                for index, name in enumerate(names[1:], start=2))
    item = step(steps_for(config, jobs=tuple(jobs)), "channel")
    assert item.state == "attention"
    assert item.detail.endswith(
        'The last test to "alpha", "bravo", "charlie" and 2 more failed.'
    )
    assert item.action_url == "/operations.job_detail?job_id=2"


def test_channel_step_names_several_failed_channels():
    config = unit_config(channels=(make_channel("email"), make_channel("alpha"),
                                   make_channel("bravo")))
    item = step(steps_for(config, jobs=(
        make_job(1, name="email"),
        make_job(2, name="alpha", status="failed", exit_code=3),
        make_job(3, name="bravo", status="failed", exit_code=3),
    )), "channel")
    assert item.state == "attention"
    assert item.detail.endswith('The last test to "alpha" and "bravo" failed.')
    assert item.action_url == "/operations.job_detail?job_id=2"


def test_channel_step_ignores_disabled_channels_and_other_jobs():
    config = unit_config(channels=(make_channel("email"), make_channel("old", enabled=False)))
    jobs = (
        make_job(1, name="old", status="succeeded", exit_code=0),
        make_job(2, name="email", operation="scan", status="succeeded", exit_code=0),
    )
    item = step(steps_for(config, jobs=jobs), "channel")
    assert item.state == "todo"
    assert item.detail == 'Channel "email" is set up, but there is no recent test on record.'


def test_channel_step_reports_unreadable_history():
    item = step(steps_for(unit_config(channels=(make_channel(),)), jobs=None), "channel")
    assert item.state == "unknown"
    assert item.detail == "Test history could not be read."
    assert item.action_label == "Open Operations"
    assert item.action_url == "/operations.index"


def test_channel_test_job_argv_matches_build_command():
    config = unit_config(channels=(make_channel(),))
    argv = build_command(config, "notify-test", channel="email")
    assert argv[-1] == "email"
    item = step(steps_for(config, jobs=(make_job(argv=argv),)), "channel")
    assert item.state == "done"


@pytest.mark.parametrize("rules", [
    (),
    (make_rule(enabled=False),),
    (make_rule(channels=("sms",)),),
    (make_rule(channels=("disabled",)),),
])
def test_rule_step_requires_an_enabled_rule_and_enabled_channel(rules):
    config = unit_config(channels=(make_channel(), make_channel("disabled", enabled=False)),
                         rules=rules)
    item = step(steps_for(config), "rule")
    assert item.state == "todo"
    assert item.title == "Choose what should trigger an alert"
    assert item.detail == (
        "No enabled rule sends alerts to an enabled channel, so no alert will be delivered."
    )
    assert item.action_label == "Create a rule"
    assert item.action_url == "/config_editor.rules"
    assert item.hint is None


def test_rule_step_reports_done_and_counts_rules():
    config = unit_config(channels=(make_channel(),), rules=(make_rule(),))
    item = step(steps_for(config), "rule")
    assert item.state == "done"
    assert item.detail == "1 rule sends alerts to an enabled channel."
    config = unit_config(channels=(make_channel(),),
                         rules=(make_rule("first"), make_rule("second")))
    item = step(steps_for(config), "rule")
    assert item.detail == "2 rules send alerts to an enabled channel."


def test_client_step_reports_no_client_list():
    item = step(steps_for(unit_config()), "client")
    assert item.state == "todo"
    assert item.title == "Add a client and their software list"
    assert item.detail == (
        "No client has a software list yet. Until one does, CVEBeacon cannot say "
        "which clients are affected."
    )
    assert item.action_label == "Add a client"
    assert item.action_url == "/client_inventory.add"
    assert item.hint is None


def test_client_step_reports_disabled_managed_lists():
    item = step(steps_for(unit_config(managed=False)), "client")
    assert item.state == "na"
    assert item.detail == "Client software lists added in the dashboard are turned off."
    assert item.action_label == "Open inventory settings"
    assert item.action_url == "/config_editor.inventory"
    assert item.hint is None


@pytest.mark.parametrize("client_info", [ClientInfo(managed=True, scanned=0),
                                         ClientInfo(managed=False, scanned=3)])
def test_client_step_reports_done(client_info):
    item = step(steps_for(unit_config(), client_info=client_info), "client")
    assert item.state == "done"
    assert item.detail == "At least one client has a software list."


def test_client_step_reports_unreadable_information():
    item = step(steps_for(unit_config(), client_info=None), "client")
    assert item.state == "unknown"
    assert item.detail == "Client information could not be read. Open Clients for details."
    assert item.action_label == "Open Clients"
    assert item.action_url == "/watch.clients"


@pytest.mark.parametrize("state,expected,detail,label,url", [
    ("none", "todo", "Nothing is scheduled. CVEBeacon only runs when someone starts it.",
     "Set a schedule", "/operations.schedule"),
    ("unknown", "unknown", "The schedule could not be checked on this server.",
     "Open Schedule", "/operations.schedule"),
    ("unexpected", "unknown", "The schedule could not be checked on this server.",
     "Open Schedule", "/operations.schedule"),
    ("scan", "done",
     "A schedule is installed for this configuration. Open Schedule for the times.",
     None, None),
    ("watch", "done",
     "A schedule is installed for this configuration. Open Schedule for the times.",
     None, None),
])
def test_schedule_step_states(state, expected, detail, label, url):
    item = step(steps_for(unit_config(), schedule_state=state), "schedule")
    assert item.state == expected
    assert item.title == "Run CVEBeacon automatically"
    assert item.detail == detail
    assert item.action_label == label
    assert item.action_url == url


@pytest.mark.parametrize("info,state,detail", [
    ({"count": 0, "last": None, "last_id": None}, "todo", "No backup exists yet."),
    ({"count": 2, "last": None, "last_id": None}, "todo", "No valid backup exists yet."),
    ({"count": 1, "last": (NOW - timedelta(days=STALE_BACKUP_DAYS + 1)).isoformat(),
      "last_id": "b"}, "attention", "The newest backup is 8 days old."),
    ({"count": 1, "last": "2026-11-23T09:30:00+00:00", "last_id": "b"}, "done",
     "Last backup 2026-11-23 09:30 UTC. Use Verify on the Backups page before you rely on it."),
    (None, "unknown", "Backups could not be read."),
    ({"count": 1, "last": "not-a-date", "last_id": "b"}, "unknown",
     "Backups could not be read."),
    ({"count": 1, "last": (NOW + timedelta(days=1)).isoformat(), "last_id": "b"},
     "unknown", "Backups could not be read."),
])
def test_backup_step_states(info, state, detail):
    item = step(steps_for(unit_config(), backup_info=info), "backup")
    assert item.state == state
    assert item.title == "Make a backup"
    assert item.detail == detail
    if state == "done":
        assert item.action_url is None
        assert item.action_label is None
    else:
        assert item.action_url == "/backups.index"
        assert item.action_label == "Open Backups"


def test_backup_step_is_omitted_without_the_backups_page():
    endpoints = BASE_ENDPOINTS - {"backups.index"}
    steps = steps_for(unit_config(), viewer=make_viewer(endpoints=endpoints))
    assert [item.id for item in steps] == ["sources", "channel", "rule", "client", "schedule"]
    assert Setup.from_steps(steps).total == 5


def test_steps_are_in_the_documented_order():
    assert [item.id for item in steps_for(unit_config())] == [
        "sources", "channel", "rule", "client", "schedule", "backup",
    ]


def test_actions_without_an_endpoint_get_no_link():
    endpoints = BASE_ENDPOINTS - {"operations.schedule"}
    item = step(steps_for(unit_config(), viewer=make_viewer(endpoints=endpoints)),
                "schedule")
    assert item.action_url is None
    assert item.action_label is None
    assert item.hint is None


def test_watch_metadata_read_does_not_create_the_database(tmp_path):
    path = tmp_path / "watch.db"
    store = WatchStore(path)
    metadata = store.metadata()
    assert "last_sync_at" not in metadata
    assert not path.exists()


def test_view_only_actions_are_limited_to_read_pages():
    config = unit_config(enabled=False, channels=(make_channel(),))
    item = step(steps_for(config, viewer=make_viewer({"view"}, is_admin=False)), "sources")
    assert item.action_url is None
    assert item.hint == "Ask an administrator to turn on watch mode."

    item = step(steps_for(unit_config(sources=()),
                          viewer=make_viewer({"view"}, is_admin=False)), "sources")
    assert item.action_url is None
    assert item.hint == "Ask an administrator to choose data sources."

    item = step(steps_for(unit_config(channels=(make_channel(),)),
                          viewer=make_viewer({"view"}, is_admin=False)), "channel")
    assert item.action_url is None
    assert item.hint == "Ask someone who may send tests."

    item = step(steps_for(unit_config(), viewer=make_viewer({"view"}, is_admin=False)), "rule")
    assert item.action_url is None
    assert item.hint == "Ask someone who may edit alert rules."

    item = step(steps_for(unit_config(), viewer=make_viewer({"view"}, is_admin=False)), "client")
    assert item.action_url is None
    assert item.hint == "Ask someone who may manage client lists."

    item = step(steps_for(unit_config(), viewer=make_viewer({"view"}, is_admin=False)),
                "schedule")
    assert item.action_url is None
    assert item.hint == "Ask an administrator to set a schedule."

    item = step(steps_for(unit_config(), viewer=make_viewer({"view"}, is_admin=False)), "backup")
    assert item.action_url is None
    assert item.hint == "Ask an administrator to create a backup."


def test_operator_can_run_a_sync_and_send_a_test_from_home():
    permissions = {"view", "run", "test_channel"}
    config = unit_config(channels=(make_channel(),))
    viewer = make_viewer(permissions, is_admin=False)
    sources = step(steps_for(config, viewer=viewer), "sources")
    assert sources.action_label == "Run the first sync"
    channel = step(steps_for(config, viewer=viewer), "channel")
    assert channel.action_label == "Send a test"
    rule = step(steps_for(config, viewer=viewer), "rule")
    assert rule.action_url is None and rule.hint == "Ask someone who may edit alert rules."


def test_account_less_mode_has_no_actions_or_hints():
    config = unit_config(enabled=False, channels=(make_channel(),))
    steps = steps_for(config, viewer=make_viewer(accounts=False, is_admin=False))
    assert all(item.action_url is None for item in steps)
    assert all(item.action_label is None for item in steps)
    assert all(item.hint is None for item in steps)


def test_setup_summary_collapses_when_nothing_needs_attention():
    config = unit_config(
        sources=("nvd",),
        channels=(make_channel(),),
        rules=(make_rule(),),
    )
    steps = steps_for(
        config,
        meta={"last_sync_at": "2026-11-23T09:30:00+00:00"},
        jobs=(make_job(),),
        schedule_state="scan",
        backup_info={"count": 1, "last": "2026-11-23T09:30:00+00:00", "last_id": "b"},
        client_info=ClientInfo(managed=True, scanned=0),
    )
    summary = Setup.from_steps(steps)
    assert summary.done == 6
    assert summary.total == 6
    assert summary.unknown == 0
    assert summary.open is False


def test_setup_summary_opens_for_todo_and_attention_only():
    done = [dashboard_setup.Step(str(index), "Title", "done", "Detail")
            for index in range(3)]
    unknown = dashboard_setup.Step("unknown", "Title", "unknown", "Detail")
    summary = Setup.from_steps([*done, unknown])
    assert summary.open is False
    assert summary.unknown == 1
    assert summary.done == 3
    assert Setup.from_steps([*done, replace(done[0], state="todo")]).open is True
    assert Setup.from_steps([*done, replace(done[0], state="attention")]).open is True
    assert Setup.from_steps([*done, replace(done[0], state="na")]).open is False
    assert Setup.from_steps([*done, replace(done[0], state="na")]).done == 3


def test_all_setup_copy_avoids_banned_words():
    config = unit_config(
        channels=(make_channel(),),
        rules=(make_rule(),),
    )
    collected = []
    collected.extend(steps_for(unit_config(enabled=False)))
    collected.extend(steps_for(unit_config(sources=())))
    collected.extend(steps_for(config))
    collected.extend(steps_for(config, meta={"initial_mode": "baseline"}))
    collected.extend(steps_for(config, meta={
        "last_sync_at": "2026-11-23T09:30:00+00:00",
        "last_sync_failures": "nvd",
    }))
    collected.extend(steps_for(config, meta={
        "last_sync_at": (NOW - timedelta(days=9)).isoformat(),
    }))
    collected.extend(steps_for(config, meta=None))
    collected.extend(steps_for(config, jobs=None))
    collected.extend(steps_for(config, jobs=(make_job(status="failed", exit_code=3),)))
    collected.extend(steps_for(config, jobs=(make_job(),)))
    mixed = unit_config(channels=(make_channel("email"), make_channel("slack")),
                        rules=(make_rule(),))
    collected.extend(steps_for(mixed, jobs=(
        make_job(1, name="email"),
        make_job(2, name="slack", status="failed", exit_code=3),
    )))
    collected.extend(steps_for(config, backup_info={"count": 2, "last": None, "last_id": None}))
    collected.extend(steps_for(unit_config(managed=False)))
    collected.extend(steps_for(config, schedule_state="unknown"))
    collected.extend(steps_for(config, backup_info=None))
    for item in collected:
        for text in (item.title, item.detail, item.action_label, item.hint):
            if text is None:
                continue
            assert BANNED.search(text) is None, text


class _Result:
    returncode = 0
    stdout = b""
    stderr = b""


def no_schedule(*args, **kwargs):
    return _Result()


def add_admin(config):
    UserStore(config.watch.users_database).add(
        "admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP,
    )


def make_app(tmp_path, *, inventory=False, enabled=True, channels="", rules=(), admin=False):
    config = write_config(tmp_path, inventory=inventory, enabled=enabled, channels=channels)
    if rules:
        config = replace(config, watch=replace(config.watch, rules=tuple(rules)))
    if admin:
        add_admin(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = no_schedule
    return config, app


def login(client):
    page = client.get("/login")
    assert page.status_code == 200
    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    response = client.post("/login", data={
        "csrf": token, "username": "admin", "password": PASSWORD,
    })
    assert response.status_code == 303


def checklist_text(page):
    start = page.index('id="getting-started"')
    end = page.index("</details>", start)
    return page[start:end]


def test_fresh_watch_install_renders_every_step_to_do(tmp_path):
    config, app = make_app(tmp_path, inventory=False)
    page = app.test_client().get("/")
    assert page.status_code == 200
    assert "0 of 6 steps done" in page.text
    assert 'id="getting-started" open' in page.text
    for title in (
        "Turn on watching and get the first data",
        "Set up and test a way to receive alerts",
        "Choose what should trigger an alert",
        "Add a client and their software list",
        "Run CVEBeacon automatically",
        "Make a backup",
    ):
        assert title in page.text
    assert "setup-unknown" not in page.text
    # Reading the checklist must not create a missing watch database.
    assert not config.watch.database.exists()


def test_home_get_does_not_create_scan_database_sidecars(tmp_path):
    config, app = make_app(tmp_path, inventory=False)
    assert not config.database_path.exists()
    client = app.test_client()
    for _ in range(2):
        page = client.get("/")
        assert page.status_code == 200
        for suffix in ("-wal", "-shm"):
            sidecar = config.database_path.with_name(config.database_path.name + suffix)
            assert not sidecar.exists(), sidecar


def test_fresh_scan_install_renders_every_step_to_do(tmp_path):
    (tmp_path / "missing-inventory.csv").write_text(
        "asset_id,vendor,product,version\na,Acme,Widget,1\n", encoding="utf-8")
    _, app = make_app(tmp_path, inventory=True, enabled=False)
    page = app.test_client().get("/")
    assert page.status_code == 200
    assert "0 of 6 steps done" in page.text
    assert "Turn on watching and get the first data" in page.text
    assert "Watch mode is off" in page.text


def test_home_counts_a_successful_channel_test_and_matching_rule(tmp_path):
    config, app = make_app(tmp_path, inventory=False, channels=CHANNELS,
                           rules=(make_rule(),), admin=True)
    client = app.test_client()
    login(client)
    manager = app.extensions["dashboard_jobs"]
    job = manager.store.create(
        "notify-test", "admin", build_command(config, "notify-test", channel="email"))
    manager.store.finish(job.id, "succeeded", exit_code=0)
    page = client.get("/")
    assert page.status_code == 200
    assert "2 of 6 steps done" in page.text
    assert "accepted a test message on" in page.text
    assert "1 rule sends alerts to an enabled channel." in page.text


def test_home_offers_one_account_callout_instead_of_links(tmp_path):
    _, app = make_app(tmp_path, inventory=False)
    page = app.test_client().get("/")
    assert page.status_code == 200
    assert "Changing settings from the dashboard needs user accounts." in page.text
    assert 'href="/bootstrap"' in page.text
    checklist = checklist_text(page.text)
    assert "Run the first sync" not in checklist
    assert "Turn on watch mode" not in checklist
    assert "Add a channel" not in checklist
    assert "Ask an administrator" not in checklist


def make_home(tmp_path):
    config, app = make_app(tmp_path, inventory=False)
    return config, app, app.test_client()


def test_home_reports_unreadable_watch_metadata(tmp_path, monkeypatch):
    config, app, client = make_home(tmp_path)
    WatchStore(config.watch.database).initialize()
    store = app.extensions["dashboard_watch"]["store"]

    def explode():
        raise StateError("metadata secret detail")

    monkeypatch.setattr(store, "metadata", explode)
    page = client.get("/")
    assert page.status_code == 200
    assert WATCH_UNREADABLE in page.text
    assert "metadata secret detail" not in page.text


def test_home_reports_unreadable_job_history(tmp_path, monkeypatch):
    _, app = make_app(tmp_path, inventory=False, channels=CHANNELS)
    client = app.test_client()
    manager = app.extensions["dashboard_jobs"]

    def explode(limit):
        raise StateError("job secret detail")

    monkeypatch.setattr(manager.store, "recent", explode)
    page = client.get("/")
    assert page.status_code == 200
    assert "Test history could not be read." in page.text
    assert "job secret detail" not in page.text


def test_home_reports_unreadable_schedule(tmp_path, monkeypatch):
    _, _, client = make_home(tmp_path)

    def explode(config):
        raise OSError("schedule secret detail")

    monkeypatch.setattr(dashboard_setup, "schedule_scan_state", explode)
    page = client.get("/")
    assert page.status_code == 200
    assert "The schedule could not be checked on this server." in page.text
    assert "schedule secret detail" not in page.text


def test_home_reports_unreadable_backups(tmp_path, monkeypatch):
    _, _, client = make_home(tmp_path)

    def explode(config):
        raise StateError("backup secret detail")

    monkeypatch.setattr(backup, "summary", explode)
    page = client.get("/")
    assert page.status_code == 200
    assert "Backups could not be read." in page.text
    assert "0 of 6 steps done; 1 could not be checked" in page.text
    assert "backup secret detail" not in page.text


def test_home_reports_unreadable_client_information(tmp_path, monkeypatch):
    config, app, client = make_home(tmp_path)
    StateStore(config.database_path).record_scan([])

    def explode(path, *, limit=1):
        raise sqlite3.Error("client secret detail")

    monkeypatch.setattr(dashboard_setup, "client_page", explode)
    page = client.get("/")
    assert page.status_code == 200
    assert "Client information could not be read." in page.text
    assert "client secret detail" not in page.text


def test_rendered_checklist_avoids_banned_words(tmp_path):
    config, app = make_app(tmp_path, inventory=False, channels=CHANNELS,
                           rules=(make_rule(),), admin=True)
    client = app.test_client()
    login(client)
    checklist = checklist_text(client.get("/").text)
    assert BANNED.search(checklist) is None


def test_can_helper_requires_accounts_and_permission(tmp_path):
    _, app = make_app(tmp_path, inventory=False)
    with app.test_request_context("/"):
        g.accounts = True
        g.permissions = frozenset({"view", "run"})
        can = app.jinja_env.globals["can"]
        assert can("view") is True
        assert can("run") is True
        assert can("edit_rules") is False
    with app.test_request_context("/"):
        g.accounts = False
        g.permissions = frozenset({"view"})
        assert app.jinja_env.globals["can"]("view") is False


def test_gather_uses_the_recent_job_limit(tmp_path):
    config, app = make_app(tmp_path, inventory=False, channels=CHANNELS,
                           rules=(make_rule(),))
    with app.test_request_context("/"):
        calls = []
        manager = app.extensions["dashboard_jobs"]
        original = manager.store.recent

        def recent(limit=MAX_HISTORY):
            calls.append(limit)
            return original(limit)

        manager.store.recent = recent
        gather(config, viewer=make_viewer())
        assert calls == [MAX_HISTORY]
