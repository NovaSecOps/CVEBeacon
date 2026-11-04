from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone

import pytest

from cvebeacon.errors import SourceError, StateError
from cvebeacon.watch.records import (
    CVSSEntry,
    EUVDUpdate,
    KEVFields,
    Product,
    Reference,
    WatchRecord,
    build_view,
    epss_band,
)
from cvebeacon.watch.rules import parse_rules
from cvebeacon.watch.store import WatchStore

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def record(identifier: str = "CVE-2026-0001", **overrides) -> WatchRecord:
    value = {
        "cve_id": identifier,
        "status": "published",
        "published": "2026-11-01T00:00:00.000",
        "last_modified": "2026-11-02T00:00:00.000",
        "description": "Example",
        "source_identifier": "security@example.com",
        "cvss": (CVSSEntry("nvd", "nvd@nist.gov", "3.1", 9.8, "CVSS:3.1/X", "CRITICAL"),),
        "cwes": ("CWE-79",),
        "products": (Product("acme", "widget"),),
        "references": (Reference("https://example.test/a", ("Patch",)),),
    }
    value.update(overrides)
    return WatchRecord(**value)


def fetch_row(store: WatchStore, identifier: str) -> sqlite3.Row:
    with sqlite3.connect(store.path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM watch_cve WHERE cve_id=?", (identifier,)).fetchone()
    assert row is not None
    return row


def euvd(
    euvd_id: str,
    cve_ids: tuple[str, ...],
    *,
    exploited: str | None = None,
    score: float | None = None,
    updated: str | None = None,
) -> EUVDUpdate:
    return EUVDUpdate(
        cve_ids,
        euvd_id,
        exploited,
        CVSSEntry("euvd", "euvd", "3.1", score) if score is not None else None,
        updated,
    )


def test_upsert_is_idempotent_and_updates_only_on_change(tmp_path):
    now = [NOW]
    store = WatchStore(tmp_path / "watch.db", clock=lambda: now[0])
    assert store.upsert_nvd([record()]).new == 1
    first = fetch_row(store, "CVE-2026-0001")

    now[0] += timedelta(hours=1)
    counts = store.upsert_nvd([record()])
    assert (counts.new, counts.changed, counts.unchanged) == (0, 0, 1)
    assert fetch_row(store, "CVE-2026-0001")["updated_at"] == first["updated_at"]

    now[0] += timedelta(hours=1)
    counts = store.upsert_nvd([record(description="Changed")])
    assert (counts.new, counts.changed, counts.unchanged) == (0, 0, 0)
    assert counts.touched_ids == ("CVE-2026-0001",)
    updated = fetch_row(store, "CVE-2026-0001")
    assert updated["updated_at"] != first["updated_at"]
    assert updated["first_seen"] == first["first_seen"]


@pytest.mark.parametrize("changed_index", [0, 1])
def test_touched_ids_follow_each_records_own_outcome(tmp_path, changed_index):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    first = record("CVE-2026-0001")
    second = record("CVE-2026-0002")
    store.upsert_nvd([first, second])
    store.acknowledge(store.pending_evaluations(10))

    updates = [first, second]
    updates[changed_index] = record(
        f"CVE-2026-{changed_index + 1:04d}",
        description="Changed",
    )
    counts = store.upsert_nvd(updates)
    assert counts.touched_ids == (
        f"CVE-2026-{changed_index + 1:04d}",
    )
    assert store.pending_evaluations(10) == counts.touched_ids


def test_pending_evaluations_only_include_known_cves_and_can_be_acknowledged(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.replace_euvd_items(
        [euvd("EUVD-2026-9", ("CVE-2026-9999",), exploited="2026-11-01")],
        catalogs=("nvd", "euvd"),
    )
    assert store.pending_evaluations(10) == ()

    store.upsert_nvd([record("CVE-2026-0001"), record("CVE-2026-9999")])
    assert set(store.pending_evaluations(10)) == {
        "CVE-2026-0001",
        "CVE-2026-9999",
    }
    store.acknowledge(["CVE-2026-0001"])
    assert store.pending_evaluations(10) == ("CVE-2026-9999",)
    store.acknowledge(["CVE-2026-9999"])
    assert store.pending_evaluations(10) == ()


def test_view_combines_euvd_kev_and_epss(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()], catalogs=("nvd",))
    store.replace_euvd_items(
        [euvd("EUVD-2026-1", ("CVE-2026-0001",), exploited="2026-11-01", score=7.5)],
        catalogs=("nvd", "euvd"),
    )
    store.replace_kev(
        "cisa",
        {"CVE-2026-0001": KEVFields("2026-11-03", "2026-11-20", "Apply updates", "Known")},
        catalogs=("nvd", "cisa_kev"),
    )
    store.replace_epss([("CVE-2026-0001", 0.5, 0.9, date(2026, 11, 3))])
    view = store.view("CVE-2026-0001", catalogs=("nvd", "euvd", "cisa_kev", "epss"))
    assert view is not None
    assert view.published == "2026-11-01T00:00:00.000"
    assert view.first_seen == NOW.isoformat()
    assert {entry.provider for entry in view.cvss} == {"nvd", "euvd"}
    assert view.euvd_id == "EUVD-2026-1"
    assert view.euvd_exploited_since == "2026-11-01"
    assert view.cisa_kev_added == "2026-11-03"
    assert (view.epss, view.epss_percentile, view.epss_date) == (0.5, 0.9, "2026-11-03")
    assert view.epss_band == 2


def test_euvd_before_nvd_is_applied_immediately_by_the_view(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.replace_euvd_items(
        [euvd("EUVD-2026-9", ("CVE-2026-9999",), exploited="2026-11-01", score=8.8)],
        catalogs=("nvd", "euvd"),
    )
    assert store.view("CVE-2026-9999", catalogs=("nvd", "euvd")) is None
    counts = store.upsert_nvd([record("CVE-2026-9999")], catalogs=("nvd", "euvd"))
    assert counts.new == 1
    view = store.view("CVE-2026-9999", catalogs=("nvd", "euvd"))
    assert view is not None
    assert view.euvd_id == "EUVD-2026-9"
    assert view.euvd_exploited_since == "2026-11-01"
    assert any(entry.provider == "euvd" and entry.score == 8.8 for entry in view.cvss)


def test_euvd_winner_survives_a_narrower_later_window(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()], catalogs=("nvd", "euvd"))
    winner = euvd(
        "EUVD-2026-1",
        ("CVE-2026-0001",),
        exploited="2026-11-01",
        score=9.8,
        updated="2026-11-01T00:00:00",
    )
    later = euvd(
        "EUVD-2026-2",
        ("CVE-2026-0001",),
        score=5.0,
        updated="2026-11-03T00:00:00",
    )
    store.replace_euvd_items([winner, later], catalogs=("nvd", "euvd"))
    first = store.view("CVE-2026-0001", catalogs=("nvd", "euvd"))
    assert first.euvd_id == "EUVD-2026-1"

    # The next window only returns the lower-priority item. The earlier item
    # stays stored, so the winner and its exploitation evidence must survive.
    counts = store.replace_euvd_items([later], catalogs=("nvd", "euvd"))
    assert counts.changed == 0
    second = store.view("CVE-2026-0001", catalogs=("nvd", "euvd"))
    assert second.euvd_id == "EUVD-2026-1"
    assert second.euvd_exploited_since == "2026-11-01"

    # A correction on the winner itself replaces its old evidence.
    corrected = euvd("EUVD-2026-1", ("CVE-2026-0001",), score=1.0, updated="2026-10-31T00:00:00")
    assert store.replace_euvd_items([corrected], catalogs=("nvd", "euvd")).changed == 1
    third = store.view("CVE-2026-0001", catalogs=("nvd", "euvd"))
    assert third.euvd_id == "EUVD-2026-2"
    assert third.euvd_exploited_since is None


def test_euvd_alias_changes_touch_old_and_new_cves(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record("CVE-2026-0001"), record("CVE-2026-0002")])
    store.replace_euvd_items(
        [euvd("EUVD-1", ("CVE-2026-0001",), exploited="2026-11-01")],
        catalogs=("nvd", "euvd"),
    )
    counts = store.replace_euvd_items(
        [euvd("EUVD-1", ("CVE-2026-0002",), exploited="2026-11-01")],
        catalogs=("nvd", "euvd"),
    )
    assert set(counts.touched_ids) == {"CVE-2026-0001", "CVE-2026-0002"}
    assert store.view("CVE-2026-0001", catalogs=("nvd", "euvd")).euvd_id is None
    assert store.view("CVE-2026-0002", catalogs=("nvd", "euvd")).euvd_id == "EUVD-1"


def test_kev_catalog_replacement_adds_changes_and_removes(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record("CVE-2026-0001"), record("CVE-2026-0002")])
    first = store.replace_kev(
        "cisa",
        {
            "CVE-2026-0001": KEVFields("2026-11-03", "2026-11-20", "Old", "Known"),
            "CVE-2026-0002": KEVFields("2026-11-03"),
        },
        catalogs=("nvd", "cisa_kev"),
    )
    assert first.new == 2
    assert first.changed == 2
    second = store.replace_kev(
        "cisa",
        {
            "CVE-2026-0001": KEVFields("2026-11-03", "2026-11-30", "New", "Known"),
            "CVE-2026-0003": KEVFields("2026-11-04"),
        },
        catalogs=("nvd", "cisa_kev"),
    )
    assert set(second.touched_ids) == {"CVE-2026-0001", "CVE-2026-0002"}
    assert second.new == 1
    assert second.changed == 2
    view = store.view("CVE-2026-0001", catalogs=("nvd", "cisa_kev"))
    assert view.cisa_kev_due == "2026-11-30"
    assert view.cisa_required_action == "New"
    assert store.view("CVE-2026-0002", catalogs=("nvd", "cisa_kev")).cisa_kev_added is None
    again = store.replace_kev(
        "cisa",
        {
            "CVE-2026-0001": KEVFields("2026-11-03", "2026-11-30", "New", "Known"),
            "CVE-2026-0003": KEVFields("2026-11-04"),
        },
        catalogs=("nvd", "cisa_kev"),
    )
    assert again.changed == 0
    assert again.touched_ids == ()


def test_view_uses_nvd_cisa_fields_only_when_no_catalog_is_configured(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd(
        [
            record(
                cisa_kev_added="2026-11-01",
                cisa_kev_due="2026-11-20",
                cisa_required_action="Apply",
                cisa_ransomware="Known",
            )
        ]
    )
    view = store.view("CVE-2026-0001")
    assert view.cisa_kev_added == "2026-11-01"
    catalog_view = store.view("CVE-2026-0001", catalogs=("nvd", "cisa_kev"))
    assert catalog_view.cisa_kev_added is None


def test_view_policy_change_recomputes_in_batches(tmp_path, monkeypatch):
    import cvebeacon.watch.store as store_module

    monkeypatch.setattr(store_module, "VIEW_POLICY_BATCH", 2)
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    identifiers = [f"CVE-2026-{index:04d}" for index in range(5)]
    store.upsert_nvd(
        [record(identifier, cisa_kev_added="2026-11-01") for identifier in identifiers]
    )
    store.acknowledge(store.pending_evaluations(10))

    changed = store.apply_view_policy(("cisa_kev",))
    assert changed == tuple(identifiers)
    assert sorted(store.pending_evaluations(10)) == identifiers
    assert store.apply_view_policy(("cisa_kev",)) == ()


def test_epss_load_is_idempotent_and_reports_band_changes(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record("CVE-2026-0001"), record("CVE-2026-0002")])
    first = store.replace_epss(
        [
            ("CVE-2026-0001", 0.8, 0.99, date(2026, 11, 1)),
            ("CVE-2026-0002", 0.2, 0.5, date(2026, 11, 1)),
        ]
    )
    assert (first.rows, first.batches) == (2, 1)
    assert first.changed_ids == ("CVE-2026-0001", "CVE-2026-0002")
    same = store.replace_epss(
        [
            ("CVE-2026-0001", 0.8, 0.99, date(2026, 11, 2)),
            ("CVE-2026-0002", 0.2, 0.5, date(2026, 11, 2)),
        ]
    )
    assert same.changed_ids == ()
    down = store.replace_epss(
        [
            ("CVE-2026-0001", 0.05, 0.2, date(2026, 11, 3)),
            ("CVE-2026-0002", 0.2, 0.5, date(2026, 11, 3)),
        ]
    )
    assert down.changed_ids == ("CVE-2026-0001",)
    missing = store.replace_epss(
        [("CVE-2026-0001", 0.05, 0.2, date(2026, 11, 4))]
    )
    assert missing.changed_ids == ("CVE-2026-0002",)
    assert store.view("CVE-2026-0002").epss is None


@pytest.mark.parametrize(
    "thresholds,expected",
    [
        ((0.1, 0.5, 0.9), ()),
        ((0.3,), ("CVE-2026-0001",)),
    ],
)
def test_epss_threshold_crossing_uses_the_configured_thresholds(
    tmp_path, thresholds, expected
):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.acknowledge(store.pending_evaluations(10))
    store.replace_epss(
        [("CVE-2026-0001", 0.20, 0.8, date(2026, 11, 2))],
        thresholds=thresholds,
    )
    store.acknowledge(store.pending_evaluations(10))
    result = store.replace_epss(
        [("CVE-2026-0001", 0.40, 0.9, date(2026, 11, 3))],
        thresholds=thresholds,
    )
    assert result.changed_ids == expected


def test_epss_rejects_a_file_below_half_the_current_table(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    store.replace_epss(
        [
            ("CVE-2026-0001", 0.8, 0.99, date(2026, 11, 2)),
            ("CVE-2026-0002", 0.7, 0.9, date(2026, 11, 2)),
            ("CVE-2026-0003", 0.6, 0.8, date(2026, 11, 2)),
            ("CVE-2026-0004", 0.5, 0.7, date(2026, 11, 2)),
        ]
    )
    with pytest.raises(SourceError, match="too few EPSS scores"):
        store.replace_epss(
            [("CVE-2026-0001", 0.1, 0.2, date(2026, 11, 3))]
        )
    assert store.status()["epss_rows"] == 4
    assert store.view("CVE-2026-0001", catalogs=("epss",)).epss == 0.8


def test_epss_write_batches_interleave_with_reading(tmp_path, monkeypatch):
    import cvebeacon.watch.store as store_module

    produced = [0]
    writes: list[tuple[int, int]] = []
    original = sqlite3.connect

    class Connection(sqlite3.Connection):
        def executemany(self, sql, parameters):
            if sql.startswith("INSERT OR REPLACE INTO watch_epss_load"):
                writes.append((produced[0], len(parameters)))
            return super().executemany(sql, parameters)

    def connect(*args, **kwargs):
        return original(*args, **kwargs, factory=Connection)

    monkeypatch.setattr(sqlite3, "connect", connect)

    def rows():
        for index in range(store_module.EPSS_WRITE_BATCH + 1):
            if index == store_module.EPSS_WRITE_BATCH:
                assert writes == [(store_module.EPSS_WRITE_BATCH, store_module.EPSS_WRITE_BATCH)]
            produced[0] += 1
            yield f"CVE-2026-{1000 + index}", 0.5, 0.9, date(2026, 11, 3)

    result = WatchStore(tmp_path / "watch.db").replace_epss(rows())
    assert (result.rows, result.batches) == (store_module.EPSS_WRITE_BATCH + 1, 2)
    assert writes == [
        (store_module.EPSS_WRITE_BATCH, store_module.EPSS_WRITE_BATCH),
        (store_module.EPSS_WRITE_BATCH + 1, 1),
    ]


def test_lookup_backoff_never_resets_or_deletes_while_the_trigger_exists(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.replace_kev(
        "cisa",
        {"CVE-2026-0002": KEVFields("2026-11-03")},
        catalogs=("nvd", "cisa_kev"),
    )
    store.sync_lookups(
        ["cisa_kev"], initial_window_start="2026-10-27", now=NOW
    )
    assert [row.cve_id for row in store.due_lookups(now=NOW)] == ["CVE-2026-0002"]

    current = NOW
    delays: list[float] = []
    for attempt in range(1, 13):
        store.lookup_failed("CVE-2026-0002", error=f"fail {attempt}", now=current)
        row = store.due_lookups(now=current + timedelta(days=30))[0]
        assert row.attempts == attempt
        remaining = datetime.fromisoformat(row.next_attempt_at) - current
        delays.append(remaining.total_seconds() / 3600)
        # Re-downloading and re-syncing the unchanged catalog must not reset it.
        store.replace_kev(
            "cisa",
            {"CVE-2026-0002": KEVFields("2026-11-03")},
            catalogs=("nvd", "cisa_kev"),
        )
        store.sync_lookups(
            ["cisa_kev"], initial_window_start="2026-10-27", now=current
        )
        current = datetime.fromisoformat(row.next_attempt_at)
    assert delays[:3] == [1.0, 2.0, 4.0]
    assert delays[-1] == 168.0
    assert store.status()["lookups"] == 1


def test_lookups_cover_kev_window_and_exploited_euvd_and_delete_on_insert(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.replace_kev(
        "cisa",
        {
            "CVE-2026-0001": KEVFields("2026-10-01"),
            "CVE-2026-0002": KEVFields("2026-11-03"),
        },
        catalogs=("nvd", "cisa_kev"),
    )
    store.replace_euvd_items(
        [
            euvd("EUVD-1", ("CVE-2026-0003",), exploited="2026-11-01"),
            euvd("EUVD-2", ("CVE-2026-0004",), score=5.0),
        ],
        catalogs=("nvd", "euvd"),
    )
    assert store.sync_lookups(
        ["cisa_kev"], initial_window_start="2026-10-27", now=NOW
    ) == 2
    assert {row.cve_id for row in store.due_lookups(now=NOW, limit=10)} == {
        "CVE-2026-0002",
        "CVE-2026-0003",
    }
    store.upsert_nvd([record("CVE-2026-0002")])
    assert {row.cve_id for row in store.due_lookups(now=NOW, limit=10)} == {"CVE-2026-0003"}

    # Removing the trigger deletes the lookup row.
    store.replace_euvd_items(
        [euvd("EUVD-1", ("CVE-2026-0003",), score=1.0)],
        catalogs=("nvd", "euvd"),
    )
    store.sync_lookups(["cisa_kev"], initial_window_start="2026-10-27", now=NOW)
    assert store.due_lookups(now=NOW, limit=10) == ()
    assert store.sync_lookups(
        ["cisa_kev"], initial_window_start=None, now=NOW
    ) == 0


def test_identical_euvd_reobservation_refreshes_seen_at_without_a_change(tmp_path):
    now = [NOW - timedelta(days=31)]
    store = WatchStore(tmp_path / "watch.db", clock=lambda: now[0])
    item = euvd("EUVD-2026-1", ("CVE-2026-9999",), score=9.8)
    store.replace_euvd_items([item])
    store.acknowledge(store.pending_evaluations(10))
    now[0] = NOW
    counts = store.replace_euvd_items([item])
    assert (counts.new, counts.changed, counts.unchanged) == (0, 0, 1)
    assert counts.touched_ids == ()
    assert store.prune_euvd(now=NOW) == 0
    with sqlite3.connect(store.path) as db:
        seen_at = db.execute(
            "SELECT seen_at FROM watch_euvd_item WHERE euvd_id='EUVD-2026-1'"
        ).fetchone()[0]
    assert seen_at == NOW.isoformat()


def test_prune_euvd_removes_only_old_unexploited_unreferenced_items(tmp_path):
    now = [NOW - timedelta(days=31)]
    store = WatchStore(tmp_path / "watch.db", clock=lambda: now[0])
    store.upsert_nvd([record()])
    store.replace_euvd_items(
        [
            euvd("EUVD-old-missing", ("CVE-2026-9999",), score=5.0),
            euvd("EUVD-old-exploited", ("CVE-2026-9998",), exploited="2026-01-01"),
            euvd("EUVD-old-known", ("CVE-2026-0001",), score=5.0),
        ]
    )
    now[0] = NOW
    store.replace_euvd_items([euvd("EUVD-new-missing", ("CVE-2026-9997",), score=5.0)])
    pruned = store.prune_euvd(now=NOW)
    assert pruned == 1
    assert store.prune_euvd(now=NOW) is None
    with sqlite3.connect(store.path) as db:
        identifiers = {
            row[0] for row in db.execute("SELECT euvd_id FROM watch_euvd_item")
        }
        aliases = {row[0] for row in db.execute("SELECT euvd_id FROM watch_euvd_alias")}
    assert identifiers == {
        "EUVD-old-exploited",
        "EUVD-old-known",
        "EUVD-new-missing",
    }
    assert aliases == {"EUVD-old-exploited", "EUVD-old-known", "EUVD-new-missing"}


def test_schema_version_guard_and_ambiguous_metadata_fail_closed(tmp_path):
    store = WatchStore(tmp_path / "watch.db")
    store.initialize()
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_meta SET value='9' WHERE key='schema_version'")
    with pytest.raises(StateError, match="unsupported watch schema version 9"):
        store.initialize()

    path = tmp_path / "ambiguous.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE watch_meta(key TEXT, value TEXT)")
        db.execute("INSERT INTO watch_meta VALUES ('schema_version','1')")
        db.execute("INSERT INTO watch_meta VALUES ('schema_version','1')")
    with pytest.raises(StateError, match="ambiguous watch schema"):
        WatchStore(path).initialize()


def test_euvd_score_removal_drops_the_entry(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()], catalogs=("nvd", "euvd"))
    store.replace_euvd_items(
        [euvd("EUVD-2026-1", ("CVE-2026-0001",), exploited="2026-11-01", score=9.8)],
        catalogs=("nvd", "euvd"),
    )
    assert any(
        entry.provider == "euvd"
        for entry in store.view("CVE-2026-0001", catalogs=("nvd", "euvd")).cvss
    )
    assert store.replace_euvd_items(
        [euvd("EUVD-2026-1", ("CVE-2026-0001",), exploited="2026-11-01")],
        catalogs=("nvd", "euvd"),
    ).changed == 1
    view = store.view("CVE-2026-0001", catalogs=("nvd", "euvd"))
    assert not any(entry.provider == "euvd" for entry in view.cvss)
    assert view.euvd_id == "EUVD-2026-1"


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "rejected"),
        ("cvss", (CVSSEntry("cna", "security@example.com", "3.1", 8.0),)),
        ("ssvc_exploitation", "active"),
        ("cisa_kev_added", "2026-11-03"),
        ("cisa_kev_due", "2026-11-20"),
        ("cisa_required_action", "Apply updates"),
        ("cisa_ransomware", "Known"),
    ],
)
def test_view_fingerprint_tracks_nvd_alert_fields(field, value):
    original = build_view(record())
    changed = build_view(replace(record(), **{field: value}))
    assert changed.fingerprint() != original.fingerprint()


def test_view_fingerprint_tracks_euvd_and_kev_fields():
    original = build_view(record())
    euvd_view = build_view(
        record(),
        euvd=euvd("EUVD-1", ("CVE-2026-0001",), exploited="2026-11-01"),
        eu_kev=KEVFields("2026-11-04"),
        eu_catalog=True,
        cisa_kev=KEVFields("2026-11-03"),
        cisa_catalog=True,
    )
    assert euvd_view.fingerprint() != original.fingerprint()
    assert build_view(
        record(),
        cisa_kev=KEVFields("2026-11-03"),
        cisa_catalog=True,
    ).fingerprint() != original.fingerprint()


def test_view_fingerprint_ignores_identifiers_epss_and_timestamps():
    first = build_view(
        record(),
        euvd=euvd("EUVD-1", ("CVE-2026-0001",), exploited="2026-11-01", score=7.5),
        epss=(0.1, 0.1, "2026-11-01"),
    )
    second = build_view(
        record(published="2020-01-01", last_modified="2020-01-01"),
        euvd=euvd("EUVD-999", ("CVE-2026-0001",), exploited="2026-11-01", score=7.5),
        epss=(0.9, 0.9, "2026-11-02"),
    )
    assert first.fingerprint() == second.fingerprint()


def test_baseline_and_status_counts(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.record_baseline(
        nvd_cursor=NOW.isoformat(),
        initialized_at=NOW.isoformat(),
        euvd_cursor="2026-11-03",
    )
    metadata = store.metadata()
    assert metadata["nvd_cursor"] == NOW.isoformat()
    assert metadata["euvd_cursor"] == "2026-11-03"
    assert "initial_complete" not in metadata

    store.upsert_nvd(
        [
            record("CVE-2026-0001", ssvc_exploitation="active"),
            record("CVE-2026-0002"),
            record("CVE-2026-0003"),
        ]
    )
    store.replace_kev(
        "cisa",
        {
            "CVE-2026-0001": KEVFields("2026-11-03"),
            "CVE-2026-9999": KEVFields("2026-11-04"),
        },
        catalogs=("nvd", "cisa_kev"),
    )
    store.replace_kev(
        "eu", {"CVE-2026-0002": KEVFields("2026-11-04")}, catalogs=("nvd", "eu_kev")
    )
    store.replace_epss(
        [
            ("CVE-2026-0001", 0.2, 0.9, date(2026, 11, 3)),
            ("CVE-2026-0002", 0.05, 0.5, date(2026, 11, 3)),
        ]
    )
    status = store.status(catalogs=("nvd", "cisa_kev", "eu_kev"))
    assert status["rows"] == 3
    assert status["euvd_items"] == 0
    assert status["cisa_kev"] == 2
    assert status["eu_kev"] == 1
    assert status["any_kev"] == 3
    assert status["cisa_watched"] == 1
    assert status["eu_watched"] == 1
    assert status["any_watched"] == 2
    assert status["active_ssvc"] == 1
    assert status["epss_rows"] == 2
    assert status["epss_date"] == "2026-11-03"
    assert status["lookups"] == 0


def test_record_normalizes_limits():
    with pytest.raises(ValueError):
        record(status="withdrawn")
    value = record(
        description="x" * 1500,
        products=tuple(Product(f"v{index}", f"p{index}") for index in range(60)),
        references=tuple(Reference(f"https://example.test/{index}") for index in range(40)),
    )
    assert value.description is not None and len(value.description) == 1000
    assert len(value.products) == 60
    assert len(value.references) == 30


def test_view_fingerprint_ignores_epss_and_timestamps():
    first = build_view(record(), epss=(0.1, 0.1, "2026-11-01"))
    second = build_view(
        record(published="2020-01-01", last_modified="2020-01-01"),
        epss=(0.9, 0.9, "2026-11-02"),
    )
    assert first.fingerprint() == second.fingerprint()
    assert epss_band(None) == -1
    assert [epss_band(value) for value in (0.0, 0.1, 0.5, 0.9)] == [0, 1, 2, 3]


def test_view_policy_change_queues_every_cve_even_without_a_fingerprint_change(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    identifiers = [f"CVE-2026-{index:04d}" for index in range(3)]
    store.upsert_nvd([record(identifier) for identifier in identifiers])
    store.acknowledge(store.pending_evaluations(10))
    assert store.apply_view_policy(("cisa_kev",)) == tuple(identifiers)
    store.acknowledge(store.pending_evaluations(10))
    assert store.apply_view_policy(("nvd",)) == tuple(identifiers)
    assert store.pending_evaluations(10) == tuple(identifiers)


def test_euvd_is_ignored_when_the_source_is_not_configured(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()], catalogs=("nvd", "euvd"))
    store.replace_euvd_items(
        [
            euvd(
                "EUVD-1",
                ("CVE-2026-0001",),
                exploited="2026-11-01",
                score=10.0,
            )
        ],
        catalogs=("nvd", "euvd"),
    )
    excluded = store.view("CVE-2026-0001", catalogs=("nvd",))
    assert excluded.euvd_id is None
    assert excluded.euvd_exploited_since is None
    assert not any(entry.provider == "euvd" for entry in excluded.cvss)
    assert excluded.vendors == ("acme",)
    included = store.view("CVE-2026-0001", catalogs=("nvd", "euvd"))
    assert included.euvd_id == "EUVD-1"
    assert any(entry.provider == "euvd" for entry in included.cvss)


def test_backlog_window_falls_back_to_the_initialization_time(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.record_baseline(nvd_cursor=NOW.isoformat(), initialized_at=NOW.isoformat())
    store.upsert_nvd([record(published="2015-01-01T00:00:00.000")])
    configured = parse_rules(
        [{"name": "old", "condition": {"cvss_min": 1}, "channels": ["c"]}]
    )[0]
    store.evaluate_touched((configured,), catalogs=("nvd",))
    assert store.events()[0].initial is True


def test_baseline_backlog_uses_initialized_at_over_window_start(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.record_baseline(
        nvd_cursor=NOW.isoformat(),
        initialized_at=NOW.isoformat(),
        initial_window_start="2026-01-01",
    )
    store.upsert_nvd([record(published="2026-06-01T00:00:00.000")])
    configured = parse_rules(
        [{"name": "old", "condition": {"cvss_min": 1}, "channels": ["c"]}]
    )[0]
    store.evaluate_touched((configured,), catalogs=("nvd",))
    assert store.events()[0].initial is True


def test_products_and_names_are_capped_at_the_new_limits(tmp_path):
    products = tuple(Product(f"v{index:04d}", f"p{index:04d}") for index in range(1100))
    value = record(products=products)
    assert len(value.products) == 1000
    view = build_view(value)
    assert len(view.vendors) == 500
    assert len(view.products) == 500
    assert view.vendors[-1] == "v0499"
    assert view.products[-1] == "p0499"


def test_epss_is_ignored_when_the_source_is_not_configured(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()], catalogs=("nvd",))
    store.replace_epss([("CVE-2026-0001", 0.5, 0.9, date(2026, 11, 3))])
    assert store.view("CVE-2026-0001", catalogs=("nvd",)).epss is None
    assert store.view("CVE-2026-0001", catalogs=("nvd", "epss")).epss == 0.5


def test_adding_or_removing_the_epss_source_recomputes_views(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert_nvd([record()])
    assert store.apply_view_policy(("nvd",)) == ("CVE-2026-0001",)
    store.acknowledge(store.pending_evaluations(10))
    assert store.apply_view_policy(("nvd", "epss")) == ("CVE-2026-0001",)
    store.acknowledge(store.pending_evaluations(10))
    assert store.apply_view_policy(("nvd",)) == ("CVE-2026-0001",)
