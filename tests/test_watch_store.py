from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone

import pytest

from cvebeacon.errors import StateError
from cvebeacon.watch.records import (
    CVSSEntry,
    EUVDUpdate,
    KEVFields,
    Product,
    Reference,
    WatchRecord,
)
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


def test_upsert_is_idempotent_and_updates_only_on_change(tmp_path):
    now = [NOW]
    store = WatchStore(tmp_path / "watch.db", clock=lambda: now[0])
    assert store.upsert([record()]).new == 1
    first = fetch_row(store, "CVE-2026-0001")

    now[0] += timedelta(hours=1)
    counts = store.upsert([record()])
    assert (counts.new, counts.changed, counts.unchanged) == (0, 0, 1)
    assert fetch_row(store, "CVE-2026-0001")["updated_at"] == first["updated_at"]

    now[0] += timedelta(hours=1)
    counts = store.upsert([record(cisa_kev_added="2026-11-03")])
    assert (counts.new, counts.changed, counts.unchanged) == (0, 1, 0)
    updated = fetch_row(store, "CVE-2026-0001")
    assert updated["updated_at"] != first["updated_at"]
    assert updated["first_seen"] == first["first_seen"]


def test_epss_changes_the_row_but_not_the_fingerprint(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    original = record()
    store.upsert([original])
    assert replace(original, epss=0.9).fingerprint() == original.fingerprint()
    counts = store.apply_epss(
        {"CVE-2026-0001": (0.9, 0.95, date(2026, 11, 3))}
    )
    assert (counts.new, counts.changed, counts.unchanged) == (0, 0, 1)
    row = fetch_row(store, "CVE-2026-0001")
    assert (row["epss"], row["epss_percentile"], row["epss_date"]) == (0.9, 0.95, "2026-11-03")
    assert row["fingerprint"] == original.fingerprint()


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
        ("eu_kev_added", "2026-11-04"),
        ("euvd_exploited_since", "2026-11-01"),
    ],
)
def test_fingerprint_tracks_alert_relevant_fields(field, value):
    original = record()
    assert replace(original, **{field: value}).fingerprint() != original.fingerprint()


@pytest.mark.parametrize(
    "field,value",
    [
        ("published", "2020-01-01T00:00:00.000"),
        ("last_modified", "2026-10-01T00:00:00.000"),
        ("description", "A different description"),
        ("source_identifier", "other@example.com"),
        ("cwes", ("CWE-20",)),
        ("products", (Product("other", "thing"),)),
        ("references", (Reference("https://example.test/b"),)),
        ("euvd_id", "EUVD-2026-1"),
        ("epss", 0.9),
        ("epss_percentile", 0.99),
        ("epss_date", "2026-11-03"),
    ],
)
def test_fingerprint_ignores_non_alert_fields(field, value):
    original = record()
    assert replace(original, **{field: value}).fingerprint() == original.fingerprint()


def test_euvd_updates_existing_rows_only_and_replaces_its_score(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert([record()])
    update = EUVDUpdate(
        ("CVE-2026-0001", "CVE-2026-9999"),
        "EUVD-2026-1",
        "Oct 30, 2026, 12:00:00 AM",
        CVSSEntry("euvd", "euvd", "3.1", 7.5, "CVSS:3.1/X"),
    )
    counts = store.apply_euvd([update])
    assert counts.new == 0
    assert store.status(epss_floor=0.1)["rows"] == 1
    row = fetch_row(store, "CVE-2026-0001")
    assert row["euvd_id"] == "EUVD-2026-1"
    assert row["euvd_exploited_since"] == "Oct 30, 2026, 12:00:00 AM"
    assert row["epss"] is None
    assert row["cvss_json"].count('"provider":"euvd"') == 1

    store.apply_euvd(
        [
            EUVDUpdate(
                ("CVE-2026-0001",),
                "EUVD-2026-1",
                None,
                CVSSEntry("euvd", "euvd", "3.1", 8.5, "CVSS:3.1/Y"),
            )
        ]
    )
    row = fetch_row(store, "CVE-2026-0001")
    assert '"provider":"euvd"' in row["cvss_json"]
    assert '"score":8.5' in row["cvss_json"]
    assert '"score":7.5' not in row["cvss_json"]


def test_kev_updates_only_existing_rows(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert([record()])
    counts = store.apply_kev(
        {
            "CVE-2026-0001": KEVFields("2026-11-03", "2026-11-20", "Apply updates", "Known"),
            "CVE-2026-9999": KEVFields("2026-11-03"),
        },
        {"CVE-2026-0001": KEVFields("2026-11-04")},
    )
    assert counts.new == 0
    assert store.status(epss_floor=0.1)["rows"] == 1
    with sqlite3.connect(store.path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM watch_cve WHERE cve_id='CVE-2026-9999'"
        ).fetchone()[0] == 0
    row = fetch_row(store, "CVE-2026-0001")
    assert (row["cisa_kev_added"], row["cisa_kev_due"]) == ("2026-11-03", "2026-11-20")
    assert row["cisa_required_action"] == "Apply updates"
    assert row["cisa_ransomware"] == "Known"
    assert row["eu_kev_added"] == "2026-11-04"


def test_schema_version_guard_fails_closed(tmp_path):
    store = WatchStore(tmp_path / "watch.db")
    store.initialize()
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_meta SET value='9' WHERE key='schema_version'")
    with pytest.raises(StateError, match="unsupported watch schema version 9"):
        store.initialize()


def test_ambiguous_schema_metadata_fails_closed(tmp_path):
    path = tmp_path / "watch.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE watch_meta(key TEXT, value TEXT)")
        db.execute("INSERT INTO watch_meta VALUES ('schema_version','1')")
        db.execute("INSERT INTO watch_meta VALUES ('schema_version','1')")
    with pytest.raises(StateError, match="ambiguous watch schema"):
        WatchStore(path).initialize()


def test_baseline_records_cursors_without_rows(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.record_baseline(
        nvd_cursor=NOW.isoformat(),
        initialized_at=NOW.isoformat(),
        euvd_cursor="2026-11-03",
    )
    metadata = store.metadata()
    assert metadata["nvd_cursor"] == NOW.isoformat()
    assert metadata["euvd_cursor"] == "2026-11-03"
    assert store.status(epss_floor=0.1)["rows"] == 0


def test_status_counts_kev_ssvc_and_epss(tmp_path):
    store = WatchStore(tmp_path / "watch.db", clock=lambda: NOW)
    store.upsert(
        [
            record("CVE-2026-0001", cisa_kev_added="2026-11-03", ssvc_exploitation="active"),
            record("CVE-2026-0002", eu_kev_added="2026-11-03"),
            record("CVE-2026-0003"),
        ]
    )
    store.apply_epss(
        {
            "CVE-2026-0001": (0.2, 0.9, date(2026, 11, 3)),
            "CVE-2026-0002": (0.05, 0.5, date(2026, 11, 3)),
        }
    )
    status = store.status(epss_floor=0.1)
    assert status["rows"] == 3
    assert status["cisa_kev"] == 1
    assert status["eu_kev"] == 1
    assert status["any_kev"] == 2
    assert status["active_ssvc"] == 1
    assert status["epss_above"] == 1


def test_record_rejects_unknown_status_and_normalizes_limits(tmp_path):
    with pytest.raises(ValueError):
        record(status="withdrawn")
    value = record(
        description="x" * 1500,
        products=tuple(Product(f"v{index}", f"p{index}") for index in range(60)),
        references=tuple(Reference(f"https://example.test/{index}") for index in range(40)),
    )
    assert value.description is not None and len(value.description) == 1000
    assert len(value.products) == 50
    assert len(value.references) == 30
