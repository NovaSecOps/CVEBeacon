from __future__ import annotations

import copy
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cvebeacon import cli
from cvebeacon.errors import StateError
from cvebeacon.models import (
    Applicability,
    Asset,
    Evidence,
    Finding,
    QueryResult,
    Vulnerability,
)
from cvebeacon.state import StateStore
from cvebeacon.stix import (
    build_bundle,
    export_stix,
    read_latest_successful_scan,
    select_findings,
)

from stix_support import validate_bundle

FIXED = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
FIXTURE = Path(__file__).parent / "fixtures" / "stix_bundle.json"


def _evidence(source: str, role: str = "cve_enrichment") -> Evidence:
    return Evidence(
        source=source,
        role=role,
        statement="synthetic evidence for the STIX fixture",
    )


def _finding(
    asset: Asset,
    *,
    cve_id: str = "",
    advisory_id: str = "",
    aliases: tuple[str, ...] = (),
    state: Applicability,
    summary: str | None = None,
    confidence: str = "high",
    sources: tuple[str, ...] = ("nvd",),
) -> Finding:
    return Finding(
        asset,
        Vulnerability(
            cve_id=cve_id or None,
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary,
        ),
        state,
        confidence,
        "synthetic fixture reason",
        tuple(_evidence(source) for source in sources),
    )


def _record(
    store: StateStore,
    findings: list[Finding],
    times: dict[tuple[str, str], tuple[str, str]],
) -> str:
    by_asset: dict[str, list[Finding]] = {}
    for item in findings:
        by_asset.setdefault(item.asset.asset_id, []).append(item)
    results = [
        QueryResult(item[0].asset, tuple(item), ())
        for item in by_asset.values()
    ]
    run_id, _ = store.record_scan(results)
    by_key = {
        (item.asset.asset_id, item.vulnerability.primary_id.casefold()): item
        for item in findings
    }
    with store.transaction() as db:
        for index, (
            (asset_id, advisory_id),
            (first_seen, last_seen),
        ) in enumerate(times.items()):
            db.execute(
                "UPDATE scan_finding_details SET first_seen=?,last_seen=? "
                "WHERE run_id=? AND asset_id=? AND advisory_id=?",
                (first_seen, last_seen, run_id, asset_id, advisory_id),
            )
            db.execute(
                "UPDATE current_findings SET first_seen=?,last_seen=? "
                "WHERE asset_id=? AND cve_id=? COLLATE NOCASE",
                (first_seen, last_seen, asset_id, advisory_id),
            )
            finding = by_key[(asset_id, advisory_id.casefold())]
            history_run = f"history-{run_id}-{index}"
            db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?,?)",
                (
                    history_run,
                    first_seen,
                    first_seen,
                    "completed",
                    1,
                    1,
                    0,
                ),
            )
            db.execute(
                "INSERT INTO scan_assets VALUES (?,?,?)",
                (
                    history_run,
                    asset_id,
                    json.dumps(
                        {
                            "asset": asdict(finding.asset),
                            "coverage": None,
                            "coverage_reason": None,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
            db.execute(
                "INSERT INTO scan_asset_clients VALUES (?,?,?,?)",
                (
                    history_run,
                    asset_id,
                    finding.asset.client,
                    finding.asset.client.casefold(),
                ),
            )
            for identifier in finding.vulnerability.identifiers:
                db.execute(
                    "INSERT INTO scan_findings VALUES (?,?,?,?,?)",
                    (
                        history_run,
                        asset_id,
                        identifier.upper(),
                        finding.vulnerability.primary_id.upper(),
                        finding.applicability.value,
                    ),
                )
    return run_id


def _fixture_findings() -> tuple[list[Finding], dict[tuple[str, str], tuple[str, str]]]:
    widget = Asset(
        "asset-widget-1",
        "Example",
        "Widget",
        "1.0",
        cpe="cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",
        category="appliance",
        system_id="internal-system-alpha",
        client="Acme",
    )
    widget_again = Asset(
        "asset-widget-2",
        "Example",
        "Widget",
        "1.0",
        cpe="cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",
        client="Acme",
    )
    gadget = Asset(
        "asset-gadget-1",
        "Example",
        "Gadget",
        "2.0",
        purl="pkg:pypi/example-gadget@2.0",
        ecosystem="PyPI",
        repository="https://example.invalid/private/repository",
        client="Globex",
    )
    gizmo = Asset(
        "asset-gizmo-1",
        "Example",
        "Gizmo",
        "3.0",
        client="Initech",
    )
    findings = [
        _finding(
            widget,
            cve_id="CVE-2026-0001",
            state=Applicability.AFFECTED,
            summary="Widget issue",
            confidence="high",
            sources=("nvd",),
        ),
        _finding(
            widget_again,
            cve_id="CVE-2026-0001",
            state=Applicability.NEEDS_REVIEW,
            summary="Widget issue",
            confidence="limited",
            sources=("euvd",),
        ),
        _finding(
            gadget,
            cve_id="CVE-2026-0002",
            state=Applicability.NEEDS_REVIEW,
            summary="Gadget issue",
            confidence="limited",
            sources=("osv",),
        ),
        _finding(
            gizmo,
            cve_id="CVE-2026-0003",
            state=Applicability.NOT_AFFECTED,
            sources=("nvd",),
        ),
        _finding(
            gizmo,
            cve_id="CVE-2026-0004",
            state=Applicability.COVERAGE_UNKNOWN,
            sources=("nvd",),
        ),
    ]
    times = {
        ("asset-widget-1", "CVE-2026-0001"): (
            "2026-11-01T00:00:00+00:00",
            "2026-11-10T00:00:00+00:00",
        ),
        ("asset-widget-2", "CVE-2026-0001"): (
            "2026-11-02T00:00:00+00:00",
            "2026-11-11T00:00:00+00:00",
        ),
        ("asset-gadget-1", "CVE-2026-0002"): (
            "2026-11-03T00:00:00+00:00",
            "2026-11-12T00:00:00+00:00",
        ),
        ("asset-gizmo-1", "CVE-2026-0003"): (
            "2026-11-04T00:00:00+00:00",
            "2026-11-13T00:00:00+00:00",
        ),
        ("asset-gizmo-1", "CVE-2026-0004"): (
            "2026-11-05T00:00:00+00:00",
            "2026-11-14T00:00:00+00:00",
        ),
    }
    return findings, times


def build_fixture_database(path: str | Path) -> None:
    findings, times = _fixture_findings()
    _record(StateStore(path), findings, times)


def _config(tmp_path: Path) -> Path:
    (tmp_path / "inventory.csv").write_text(
        "asset_id,vendor,product,version\nfixture,Example,Widget,1.0\n",
        encoding="utf-8",
    )
    config = tmp_path / "config.toml"
    config.write_text(
        "[inventory]\n"
        "path='inventory.csv'\n"
        "[state]\n"
        "database='state.db'\n"
        "[output]\n"
        "directory='reports'\n",
        encoding="utf-8",
    )
    return config


def _export(
    tmp_path: Path,
    *extra: str,
    output: str = "bundle.json",
) -> dict:
    config = _config(tmp_path)
    destination = tmp_path / output
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "export",
                "stix",
                "--output",
                str(destination),
                *extra,
            ]
        )
        == 0
    )
    return json.loads(destination.read_text(encoding="utf-8"))


def test_record_scan_stores_run_scoped_finding_details(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    with closing(sqlite3.connect(tmp_path / "state.db")) as db:
        rows = db.execute(
            "SELECT asset_id,advisory_id,first_seen,last_seen,payload_json "
            "FROM scan_finding_details ORDER BY asset_id,advisory_id"
        ).fetchall()
    assert len(rows) == 5
    assert rows[0][0] == "asset-gadget-1"
    assert json.loads(rows[0][4])["applicability"] == "needs_review"


def test_old_details_are_pruned_but_latest_successful_is_kept(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.initialize()
    payload = json.dumps(
        {
            "asset": {"asset_id": "legacy", "vendor": "Example",
                      "product": "Widget", "version": "1.0"},
            "applicability": "affected",
            "confidence": "high",
            "vulnerability": {"cve_id": "CVE-2026-0015"},
            "evidence": [],
        }
    )
    with store.transaction() as db:
        db.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?)",
            (
                "old-success",
                "2000-01-01T00:00:00+00:00",
                "2000-01-01T00:00:00+00:00",
                "completed",
                1,
                1,
                0,
            ),
        )
        db.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?)",
            (
                "old-failed",
                "2001-01-01T00:00:00+00:00",
                "2001-01-01T00:00:00+00:00",
                "failed",
                1,
                1,
                1,
            ),
        )
        for run_id in ("old-success", "old-failed"):
            db.execute(
                "INSERT INTO scan_finding_details("
                "run_id,asset_id,advisory_id,first_seen,last_seen,payload_json"
                ") VALUES (?,?,?,?,?,?)",
                (
                    run_id,
                    "legacy",
                    "CVE-2026-0015",
                    "2000-01-01T00:00:00+00:00",
                    "2000-01-01T00:00:00+00:00",
                    payload,
                ),
            )
    asset = Asset("asset-new", "Example", "Widget", "1.0")
    finding = _finding(
        asset,
        cve_id="CVE-2026-0016",
        state=Applicability.AFFECTED,
    )
    store.record_scan(
        [
            QueryResult(
                asset,
                (finding,),
                (),
                Applicability.COVERAGE_UNKNOWN,
                "synthetic incomplete coverage",
            )
        ]
    )
    with closing(sqlite3.connect(tmp_path / "state.db")) as db:
        remaining = {
            row[0]
            for row in db.execute(
                "SELECT run_id FROM scan_finding_details"
            )
        }
    assert "old-success" in remaining
    assert "old-failed" not in remaining


def test_new_successful_run_replaces_previous_details(tmp_path):
    store = StateStore(tmp_path / "state.db")
    first = Asset("asset-1", "Example", "Widget", "1.0")
    first_finding = _finding(
        first,
        cve_id="CVE-2026-0020",
        state=Applicability.AFFECTED,
    )
    old_run, _ = store.record_scan(
        [QueryResult(first, (first_finding,), ())]
    )
    second = Asset("asset-2", "Example", "Widget", "1.0")
    second_finding = _finding(
        second,
        cve_id="CVE-2026-0021",
        state=Applicability.AFFECTED,
    )
    new_run, _ = store.record_scan(
        [QueryResult(second, (second_finding,), ())]
    )
    with closing(sqlite3.connect(tmp_path / "state.db")) as db:
        remaining = {
            row[0]
            for row in db.execute(
                "SELECT DISTINCT run_id FROM scan_finding_details"
            )
        }
    assert remaining == {new_run}
    assert old_run != new_run


def test_golden_bundle_from_fixture_state(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    selected = select_findings(snapshot.findings)
    bundle = build_bundle(
        selected,
        generated_at=FIXED,
        history=snapshot.history,
        run_history=snapshot.run_history,
    )
    validate_bundle(bundle)
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert bundle == expected


def test_needs_review_observation_remains_visible(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    bundle = build_bundle(
        select_findings(snapshot.findings), generated_at=FIXED
    )
    vulnerability = next(
        value
        for value in bundle["objects"]
        if value["type"] == "vulnerability"
        and value["name"] == "CVE-2026-0001"
    )
    assert vulnerability["x_cvebeacon_applicability"] == "affected"
    assert vulnerability["x_cvebeacon_states"] == [
        "affected",
        "needs_review",
    ]
    edges = [
        value
        for value in bundle["objects"]
        if value["type"] == "relationship"
        and value["target_ref"] == vulnerability["id"]
    ]
    by_state = {
        value["x_cvebeacon_applicability"]: value for value in edges
    }
    assert set(by_state) == {"affected", "needs_review"}
    assert by_state["affected"]["x_cvebeacon_sources"] == ["nvd"]
    assert by_state["affected"]["x_cvebeacon_confidence"] == "high"
    assert by_state["needs_review"]["x_cvebeacon_sources"] == ["euvd"]
    assert by_state["needs_review"]["x_cvebeacon_confidence"] == "limited"


def test_finding_without_evidence_omits_empty_sources(tmp_path):
    store = StateStore(tmp_path / "state.db")
    asset = Asset("asset-1", "Example", "Widget", "1.0")
    finding = Finding(
        asset,
        Vulnerability(cve_id="CVE-2026-0012"),
        Applicability.AFFECTED,
        "high",
        "synthetic fixture reason",
        (),
    )
    store.record_scan([QueryResult(asset, (finding,), ())])
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    bundle = build_bundle(
        select_findings(snapshot.findings), generated_at=FIXED
    )
    validate_bundle(bundle)
    for value in bundle["objects"]:
        if value["type"] in {"vulnerability", "relationship"}:
            assert "x_cvebeacon_sources" not in value


def test_deterministic_ids_across_runs_and_timestamps(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    selected = select_findings(snapshot.findings)
    first = build_bundle(
        selected, generated_at=FIXED, include_clients=True
    )
    second = build_bundle(
        selected,
        generated_at=datetime(2027, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        include_clients=True,
    )
    assert [value["id"] for value in first["objects"]] == [
        value["id"] for value in second["objects"]
    ]
    assert first["id"] == second["id"]
    assert {
        value["id"]: value.get("created")
        for value in first["objects"]
        if "created" in value
    } == {
        value["id"]: value.get("created")
        for value in second["objects"]
        if "created" in value
    }


def test_created_uses_full_history_when_earliest_observation_disappears(tmp_path):
    store = StateStore(tmp_path / "state.db")
    first = Asset(
        "asset-1", "Example", "Widget", "1.0", client="Acme"
    )
    second = Asset(
        "asset-2", "Example", "Widget", "1.0", client="Acme"
    )
    findings = [
        _finding(
            asset,
            cve_id="CVE-2026-0019",
            state=Applicability.AFFECTED,
        )
        for asset in (first, second)
    ]
    _record(
        store,
        findings,
        {
            ("asset-1", "CVE-2026-0019"): (
                "2026-11-01T00:00:00+00:00",
                "2026-11-01T00:00:00+00:00",
            ),
            ("asset-2", "CVE-2026-0019"): (
                "2026-11-02T00:00:00+00:00",
                "2026-11-02T00:00:00+00:00",
            ),
        },
    )
    first_output = tmp_path / "before.json"
    export_stix(
        tmp_path / "state.db",
        first_output,
        generated_at=FIXED,
        include_clients=True,
    )
    before = json.loads(first_output.read_text(encoding="utf-8"))
    before_created = {
        value["id"]: value.get("created")
        for value in before["objects"]
        if "created" in value
    }
    vulnerability = next(
        value
        for value in before["objects"]
        if value["type"] == "vulnerability"
    )
    assert vulnerability["created"] == "2026-11-01T00:00:00.000Z"

    # Prove the history fallback, not the ledger, keeps the timestamp.
    _drop_tables(tmp_path / "state.db", "stix_object_created")
    store.record_scan([QueryResult(second, (findings[1],), ())])
    second_output = tmp_path / "after.json"
    export_stix(
        tmp_path / "state.db",
        second_output,
        generated_at=FIXED,
        include_clients=True,
    )
    after = json.loads(second_output.read_text(encoding="utf-8"))
    validate_bundle(after)
    assert [value["id"] for value in before["objects"]] == [
        value["id"] for value in after["objects"]
    ]
    assert before_created == {
        value["id"]: value.get("created")
        for value in after["objects"]
        if "created" in value
    }


def test_created_ledger_freezes_existing_ids_across_asset_changes(tmp_path):
    database = tmp_path / "state.db"
    store = StateStore(database)
    widget = Asset("asset-1", "Example", "Widget", "1.0", client="Acme")
    finding = _finding(
        widget,
        cve_id="CVE-2026-0022",
        state=Applicability.AFFECTED,
    )
    store.record_scan([QueryResult(widget, (finding,), ())])
    with store.transaction() as db:
        db.execute(
            "UPDATE current_findings SET first_seen=? WHERE asset_id=?",
            ("2026-11-01T00:00:00+00:00", "asset-1"),
        )
    first_output = tmp_path / "first.json"
    export_stix(
        database,
        first_output,
        generated_at=FIXED,
        include_clients=True,
    )
    first = json.loads(first_output.read_text(encoding="utf-8"))
    first_software = {
        value["id"]: value["name"]
        for value in first["objects"]
        if value["type"] == "software"
    }
    widget_relationship = next(
        value
        for value in first["objects"]
        if value["type"] == "relationship"
        and first_software[value["source_ref"]] == "Widget"
    )
    first_created = widget_relationship["created"]
    with closing(sqlite3.connect(database)) as db:
        ledger = dict(
            db.execute("SELECT object_id,created FROM stix_object_created")
        )
    assert ledger[widget_relationship["id"]] == first_created

    gadget = Asset("asset-1", "Example", "Gadget", "2.0", client="Acme")
    second_widget = Asset(
        "asset-2", "Example", "Widget", "1.0", client="Acme"
    )
    store.record_scan(
        [
            QueryResult(
                gadget,
                (
                    _finding(
                        gadget,
                        cve_id="CVE-2026-0022",
                        state=Applicability.AFFECTED,
                    ),
                ),
                (),
            ),
            QueryResult(
                second_widget,
                (
                    _finding(
                        second_widget,
                        cve_id="CVE-2026-0022",
                        state=Applicability.AFFECTED,
                    ),
                ),
                (),
            ),
        ]
    )
    with store.transaction() as db:
        db.execute(
            "UPDATE current_findings SET first_seen=? WHERE asset_id=?",
            ("2026-11-05T00:00:00+00:00", "asset-2"),
        )
    second_output = tmp_path / "second.json"
    export_stix(
        database,
        second_output,
        generated_at=FIXED,
        include_clients=True,
    )
    second = json.loads(second_output.read_text(encoding="utf-8"))
    validate_bundle(second)
    repeated = next(
        value
        for value in second["objects"]
        if value["id"] == widget_relationship["id"]
    )
    assert repeated["created"] == first_created
    second_software = {
        value["id"]: value["name"]
        for value in second["objects"]
        if value["type"] == "software"
    }
    gadget_relationship = next(
        value
        for value in second["objects"]
        if value["type"] == "relationship"
        and second_software[value["source_ref"]] == "Gadget"
    )
    assert gadget_relationship["created"] != first_created
    assert (
        gadget_relationship["created"]
        == gadget_relationship["x_cvebeacon_first_seen"]
    )
    with closing(sqlite3.connect(database)) as db:
        ledger_after = dict(
            db.execute("SELECT object_id,created FROM stix_object_created")
        )
    assert ledger_after[widget_relationship["id"]] == first_created
    assert ledger_after[gadget_relationship["id"]] == (
        gadget_relationship["created"]
    )


def test_report_created_is_recomputed_after_ledger_is_applied(tmp_path):
    database = tmp_path / "state.db"
    store = StateStore(database)
    widget = Asset("asset-1", "Example", "Widget", "1.0", client="Acme")
    widget_finding = _finding(
        widget,
        cve_id="CVE-2026-0023",
        state=Applicability.AFFECTED,
    )
    store.record_scan([QueryResult(widget, (widget_finding,), ())])
    with store.transaction() as db:
        db.execute(
            "UPDATE current_findings SET first_seen=? WHERE asset_id=?",
            ("2026-11-01T00:00:00+00:00", "asset-1"),
        )
    first_output = tmp_path / "first.json"
    export_stix(
        database,
        first_output,
        generated_at=FIXED,
        client="Acme",
        include_clients=True,
    )
    first = json.loads(first_output.read_text(encoding="utf-8"))
    identity = next(
        value for value in first["objects"] if value["type"] == "identity"
    )
    with closing(sqlite3.connect(database)) as db:
        db.execute(
            "UPDATE stix_object_created SET created=? WHERE object_id=?",
            ("2025-01-01T00:00:00.000Z", identity["id"]),
        )
        db.commit()

    gadget = Asset("asset-2", "Example", "Gadget", "2.0", client="Acme")
    gadget_finding = _finding(
        gadget,
        cve_id="CVE-2026-0023",
        state=Applicability.AFFECTED,
    )
    store.record_scan(
        [
            QueryResult(widget, (widget_finding,), ()),
            QueryResult(gadget, (gadget_finding,), ()),
        ]
    )
    second_output = tmp_path / "second.json"
    export_stix(
        database,
        second_output,
        generated_at=FIXED,
        client="Acme",
        include_clients=True,
    )
    second = json.loads(second_output.read_text(encoding="utf-8"))
    report = next(
        value for value in second["objects"] if value["type"] == "report"
    )
    assert report["created"] == "2025-01-01T00:00:00.000Z"
    with closing(sqlite3.connect(database)) as db:
        stored = db.execute(
            "SELECT created FROM stix_object_created WHERE object_id=?",
            (report["id"],),
        ).fetchone()
    assert stored is not None and stored[0] == report["created"]


def test_created_ledger_write_failure_warns_and_still_exports(tmp_path, monkeypatch):
    build_fixture_database(tmp_path / "state.db")
    messages: list[str] = []
    monkeypatch.setattr(
        "cvebeacon.stix._write_created_ledger",
        lambda database, pending: False,
    )
    destination = tmp_path / "bundle.json"
    export_stix(
        tmp_path / "state.db",
        destination,
        generated_at=FIXED,
        warning=messages.append,
    )
    bundle = json.loads(destination.read_text(encoding="utf-8"))
    validate_bundle(bundle)
    assert any("ledger" in message for message in messages)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_read_only_database_file_falls_back_with_warning(
    tmp_path, capsys
):
    if os.geteuid() == 0:
        pytest.skip("root can write a mode-0444 file")
    database = tmp_path / "state.db"
    build_fixture_database(database)
    with closing(sqlite3.connect(database)) as db:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for suffix in ("-wal", "-shm"):
        Path(str(database) + suffix).unlink(missing_ok=True)
    before = database.read_bytes()
    os.chmod(database, 0o444)
    try:
        code = cli.main(
            [
                "--config",
                str(_config(tmp_path)),
                "export",
                "stix",
                "--output",
                str(tmp_path / "bundle.json"),
            ]
        )
        captured = capsys.readouterr()
    finally:
        os.chmod(database, 0o644)
    assert code == 0
    assert "warning:" in captured.err
    assert "ledger" in captured.err
    assert database.read_bytes() == before
    with closing(sqlite3.connect(database)) as db:
        table = db.execute(
            "SELECT name FROM sqlite_master WHERE name='stix_object_created'"
        ).fetchone()
    assert table is None


def test_created_ledger_is_insert_only(tmp_path, monkeypatch):
    database = tmp_path / "state.db"
    store = StateStore(database)
    asset = Asset("asset-1", "Example", "Widget", "1.0")
    finding = _finding(
        asset,
        cve_id="CVE-2026-0024",
        state=Applicability.AFFECTED,
    )
    run_id, _ = store.record_scan([QueryResult(asset, (finding,), ())])
    first_output = tmp_path / "first.json"
    export_stix(database, first_output, generated_at=FIXED)
    with closing(sqlite3.connect(database)) as db:
        before = dict(
            db.execute("SELECT object_id,created FROM stix_object_created")
        )
    assert before

    with store.transaction() as db:
        db.execute(
            "UPDATE runs SET completed_at=? WHERE run_id=?",
            ("2026-12-01T00:00:00+00:00", run_id),
        )
        db.execute(
            "UPDATE current_findings SET first_seen=? WHERE asset_id=?",
            ("2026-12-01T00:00:00+00:00", "asset-1"),
        )
    monkeypatch.setattr(
        "cvebeacon.stix._read_created_ledger", lambda database: {}
    )
    second_output = tmp_path / "second.json"
    export_stix(database, second_output, generated_at=FIXED)
    with closing(sqlite3.connect(database)) as db:
        after = dict(
            db.execute("SELECT object_id,created FROM stix_object_created")
        )
    assert after == before


def test_created_ledger_read_failure_does_not_overwrite_rows(
    tmp_path, monkeypatch
):
    database = tmp_path / "state.db"
    build_fixture_database(database)
    first_output = tmp_path / "first.json"
    export_stix(database, first_output, generated_at=FIXED)
    with closing(sqlite3.connect(database)) as db:
        before = dict(
            db.execute("SELECT object_id,created FROM stix_object_created")
        )
    assert before

    def fail(_database):
        raise StateError("transient ledger read failure")

    messages: list[str] = []
    monkeypatch.setattr("cvebeacon.stix._read_created_ledger", fail)
    second_output = tmp_path / "second.json"
    export_stix(
        database,
        second_output,
        generated_at=FIXED,
        warning=messages.append,
    )
    with closing(sqlite3.connect(database)) as db:
        after = dict(
            db.execute("SELECT object_id,created FROM stix_object_created")
        )
    assert after == before
    assert any("could not be read" in message for message in messages)


def test_invalid_unrelated_history_row_is_skipped_and_counted(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    payload = json.dumps(
        {
            "asset": {
                "asset_id": "stale",
                "vendor": "Example",
                "product": "Stale",
                "version": "1.0",
            },
            "applicability": "affected",
            "confidence": "high",
            "vulnerability": {"cve_id": "CVE-2026-0099"},
            "evidence": [],
        }
    )
    with closing(sqlite3.connect(tmp_path / "state.db")) as db:
        db.execute(
            "INSERT INTO current_findings("
            "asset_id,cve_id,first_seen,last_seen,fingerprint,payload_json"
            ") VALUES (?,?,?,?,?,?)",
            (
                "stale",
                "CVE-2026-0099",
                "not-a-timestamp",
                "not-a-timestamp",
                "stale",
                payload,
            ),
        )
        db.commit()
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    assert snapshot.history_skipped == 1
    messages: list[str] = []
    destination = tmp_path / "bundle.json"
    export_stix(
        tmp_path / "state.db",
        destination,
        generated_at=FIXED,
        warning=messages.append,
    )
    bundle = json.loads(destination.read_text(encoding="utf-8"))
    validate_bundle(bundle)
    assert any("skipped 1" in message for message in messages)


def test_export_uses_latest_successful_scan(tmp_path):
    store = StateStore(tmp_path / "state.db")
    asset = Asset("asset-1", "Example", "Widget", "1.0")
    successful = _finding(asset, cve_id="CVE-2026-0001", state=Applicability.AFFECTED)
    successful_run, _ = store.record_scan(
        [QueryResult(asset, (successful,), ())]
    )
    failed = _finding(asset, cve_id="CVE-2026-0002", state=Applicability.AFFECTED)
    store.record_scan(
        [
            QueryResult(
                asset,
                (failed,),
                (),
                Applicability.COVERAGE_UNKNOWN,
                "synthetic incomplete coverage",
            )
        ]
    )
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    assert snapshot.run_id == successful_run
    bundle = build_bundle(
        select_findings(snapshot.findings), generated_at=FIXED
    )
    names = {
        value["name"]
        for value in bundle["objects"]
        if value["type"] == "vulnerability"
    }
    assert names == {"CVE-2026-0001"}


def _drop_tables(path: Path, *tables: str) -> None:
    with closing(sqlite3.connect(path)) as db:
        for table in tables:
            db.execute(f"DROP TABLE IF EXISTS {table}")
        db.commit()


def test_old_state_fallback_matches_primary_and_keeps_lowercase_advisory(tmp_path):
    store = StateStore(tmp_path / "state.db")
    advisory = Asset(
        "asset-advisory",
        "Example",
        "Widget",
        "1.0",
        client="Acme",
    )
    cve = Asset(
        "asset-cve",
        "Example",
        "Gadget",
        "2.0",
        client="Globex",
    )
    findings = [
        _finding(
            advisory,
            advisory_id="ghsa-lower-case",
            state=Applicability.AFFECTED,
        ),
        _finding(
            cve,
            cve_id="CVE-2026-0014",
            state=Applicability.NEEDS_REVIEW,
        ),
    ]
    store.record_scan(
        [
            QueryResult(advisory, (findings[0],), ()),
            QueryResult(cve, (findings[1],), ()),
        ]
    )
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    primary = build_bundle(
        select_findings(snapshot.findings),
        generated_at=FIXED,
        include_clients=True,
    )
    assert {
        value["name"]
        for value in primary["objects"]
        if value["type"] == "vulnerability"
    } == {"ghsa-lower-case", "CVE-2026-0014"}

    _drop_tables(tmp_path / "state.db", "scan_finding_details")
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    scan_fallback = build_bundle(
        select_findings(snapshot.findings),
        generated_at=FIXED,
        include_clients=True,
    )
    validate_bundle(scan_fallback)
    assert scan_fallback == primary

    _drop_tables(
        tmp_path / "state.db",
        "scan_findings",
        "scan_asset_clients",
    )
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    current_fallback = build_bundle(
        select_findings(snapshot.findings),
        generated_at=FIXED,
        include_clients=True,
    )
    validate_bundle(current_fallback)
    assert current_fallback == primary


def test_client_labels_are_excluded_by_default(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    bundle = _export(tmp_path)
    text = json.dumps(bundle)
    validate_bundle(bundle)
    assert "identity" not in {value["type"] for value in bundle["objects"]}
    for label in ("Acme", "Globex", "Initech"):
        assert label not in text
    for hidden in (
        "asset-widget-1",
        "internal-system-alpha",
        "example.invalid/private/repository",
    ):
        assert hidden not in text


def test_client_filter_and_opt_in_identities(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    filtered = _export(tmp_path, "--client", "globex")
    validate_bundle(filtered)
    names = {
        value["name"]
        for value in filtered["objects"]
        if value["type"] == "vulnerability"
    }
    assert names == {"CVE-2026-0002"}
    software_names = {
        value["name"]
        for value in filtered["objects"]
        if value["type"] == "software"
    }
    assert software_names == {"Gadget"}
    assert "Globex" not in json.dumps(filtered)
    assert "Widget" not in json.dumps(filtered)

    included = _export(
        tmp_path,
        "--client",
        "Globex",
        "--include-clients",
        output="included.json",
    )
    validate_bundle(included)
    identities = [
        value["name"]
        for value in included["objects"]
        if value["type"] == "identity"
    ]
    assert identities == ["Globex"]
    relationships = [
        value
        for value in included["objects"]
        if value["type"] == "relationship"
    ]
    identity_ids = [
        value["id"]
        for value in included["objects"]
        if value["type"] == "identity"
    ]
    assert relationships[0]["x_cvebeacon_clients"] == ["Globex"]
    assert relationships[0]["x_cvebeacon_client_refs"] == identity_ids
    assert "Acme" not in json.dumps(included)


def test_client_identities_include_only_exported_clients(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    bundle = _export(tmp_path, "--include-clients", output="clients.json")
    validate_bundle(bundle)
    identities = {
        value["name"]
        for value in bundle["objects"]
        if value["type"] == "identity"
    }
    assert identities == {"Acme", "Globex"}


def test_client_label_case_variants_collapse_to_one_identity(tmp_path):
    store = StateStore(tmp_path / "state.db")
    assets = [
        Asset("asset-1", "Example", "Widget", "1.0", client="Acme"),
        Asset("asset-2", "Example", "Widget", "1.0", client="acme"),
    ]
    findings = [
        _finding(
            asset,
            cve_id="CVE-2026-0017",
            state=Applicability.AFFECTED,
        )
        for asset in assets
    ]
    store.record_scan(
        [
            QueryResult(asset, (finding,), ())
            for asset, finding in zip(assets, findings)
        ]
    )
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    bundle = build_bundle(
        select_findings(snapshot.findings),
        generated_at=FIXED,
        include_clients=True,
    )
    validate_bundle(bundle)
    identities = [
        value for value in bundle["objects"] if value["type"] == "identity"
    ]
    relationships = [
        value
        for value in bundle["objects"]
        if value["type"] == "relationship"
    ]
    assert len(identities) == 1
    assert len(relationships) == 1
    assert relationships[0]["x_cvebeacon_clients"] == ["Acme"]
    assert relationships[0]["x_cvebeacon_client_refs"] == [
        identities[0]["id"]
    ]


def test_since_filters_by_first_seen_date(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    bundle = _export(tmp_path, "--since", "2026-11-03")
    validate_bundle(bundle)
    names = {
        value["name"]
        for value in bundle["objects"]
        if value["type"] == "vulnerability"
    }
    assert names == {"CVE-2026-0002"}
    assert all(
        value["type"] != "identity" for value in bundle["objects"]
    )


def test_invalid_since_fails_without_writing_output(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    config = _config(tmp_path)
    destination = tmp_path / "bundle.json"
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "export",
                "stix",
                "--output",
                str(destination),
                "--since",
                "not-a-date",
            ]
        )
        == 2
    )
    assert not destination.exists()


def test_state_only_configuration_can_export(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    config = tmp_path / "state-only.toml"
    config.write_text(
        "[state]\ndatabase='state.db'\n[output]\ndirectory='reports'\n",
        encoding="utf-8",
    )
    destination = tmp_path / "bundle.json"
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "export",
                "stix",
                "--output",
                str(destination),
            ]
        )
        == 0
    )
    bundle = json.loads(destination.read_text(encoding="utf-8"))
    validate_bundle(bundle)
    assert len(bundle["objects"]) == 8


def test_empty_result_is_a_valid_bundle(tmp_path):
    StateStore(tmp_path / "state.db").initialize()
    bundle = _export(tmp_path)
    validate_bundle(bundle)
    assert set(bundle) == {"type", "id"}


def test_missing_state_database_is_not_created(tmp_path):
    config = _config(tmp_path)
    destination = tmp_path / "bundle.json"
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "export",
                "stix",
                "--output",
                str(destination),
            ]
        )
        == 2
    )
    assert not (tmp_path / "state.db").exists()
    assert not destination.exists()


@pytest.mark.parametrize(
    "target",
    [
        "config.toml",
        "inventory.csv",
        "state.db",
        "state.db-wal",
        "state.db-shm",
        "state.db-journal",
        "cvebeacon-watch.db",
        "cvebeacon-users.db",
        "cvebeacon-users.db-wal",
        "cvebeacon-users.db-shm",
        "cvebeacon-users.db-journal",
    ],
)
def test_stix_export_cannot_overwrite_operational_files(
    tmp_path, target, capsys
):
    build_fixture_database(tmp_path / "state.db")
    config = _config(tmp_path)
    path = tmp_path / target
    if not path.exists():
        path.write_bytes(b"preserved")
    original = path.read_bytes()
    assert (
        cli.main(
            [
                "--config",
                str(config),
                "export",
                "stix",
                "--output",
                str(path),
            ]
        )
        == 2
    )
    assert "cannot overwrite" in capsys.readouterr().err
    assert path.read_bytes() == original


def test_export_does_not_change_findings_or_emit_config_paths(
    tmp_path, monkeypatch
):
    build_fixture_database(tmp_path / "state.db")
    database = tmp_path / "state.db"
    config = _config(tmp_path)
    secret = "https://example.invalid/hooks/private-token"
    monkeypatch.setenv("CVEBEACON_TEAMS_WEBHOOK_URL", secret)
    before_files = {path.name for path in tmp_path.iterdir()}
    tables = (
        "runs",
        "current_findings",
        "events",
        "deliveries",
        "source_health",
        "scan_attempts",
        "scan_assets",
        "scan_finding_details",
    )
    with closing(sqlite3.connect(database)) as db:
        before = {
            table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in tables
        }
    bundle = _export(tmp_path)
    text = json.dumps(bundle)
    validate_bundle(bundle)
    with closing(sqlite3.connect(database)) as db:
        after = {
            table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in tables
        }
        ledger = db.execute(
            "SELECT COUNT(*) FROM stix_object_created"
        ).fetchone()[0]
    assert after == before
    assert ledger > 0
    new_files = {path.name for path in tmp_path.iterdir()} - before_files
    # SQLite can create or refresh sidecars for a read-write ledger update.
    # No other directory effect is allowed.
    assert new_files <= {
        "bundle.json",
        "state.db-shm",
        "state.db-wal",
        "state.db-journal",
    }
    assert secret not in text
    assert str(tmp_path) not in text
    assert str(config) not in text
    assert "state.db" not in text


def test_non_cve_advisory_uses_a_known_cve_alias(tmp_path):
    store = StateStore(tmp_path / "state.db")
    asset = Asset("asset-1", "Example", "Widget", "1.0")
    cve_alias = _finding(
        asset,
        advisory_id="GHSA-aaaa-bbbb-cccc",
        cve_id="CVE-2026-0009",
        aliases=("GHSA-aaaa-bbbb-cccc",),
        state=Applicability.AFFECTED,
    )
    advisory_only = _finding(
        Asset("asset-2", "Example", "Widget", "1.0"),
        advisory_id="GHSA-dddd-eeee-ffff",
        state=Applicability.NEEDS_REVIEW,
    )
    store.record_scan(
        [
            QueryResult(asset, (cve_alias,), ()),
            QueryResult(
                advisory_only.asset, (advisory_only,), ()
            ),
        ]
    )
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    bundle = build_bundle(
        select_findings(snapshot.findings),
        generated_at=FIXED,
    )
    validate_bundle(bundle)
    vulnerabilities = {
        value["name"]: value
        for value in bundle["objects"]
        if value["type"] == "vulnerability"
    }
    assert set(vulnerabilities) == {
        "CVE-2026-0009",
        "GHSA-dddd-eeee-ffff",
    }
    assert vulnerabilities["CVE-2026-0009"]["external_references"][1][
        "source_name"
    ] == "cve"
    assert vulnerabilities["GHSA-dddd-eeee-ffff"]["external_references"] == [
        {
            "source_name": "advisory",
            "external_id": "GHSA-dddd-eeee-ffff",
        }
    ]


def test_software_uses_purl_package_identity(tmp_path):
    store = StateStore(tmp_path / "state.db")
    asset = Asset("asset-1", purl="pkg:pypi/example-gadget@2.0")
    finding = _finding(
        asset,
        cve_id="CVE-2026-0010",
        state=Applicability.AFFECTED,
    )
    store.record_scan([QueryResult(asset, (finding,), ())])
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    bundle = build_bundle(
        select_findings(snapshot.findings), generated_at=FIXED
    )
    validate_bundle(bundle)
    software = next(
        value for value in bundle["objects"] if value["type"] == "software"
    )
    assert software["name"] == "example-gadget"
    assert software["version"] == "2.0"
    assert software["x_cvebeacon_ecosystem"] == "PyPI"
    assert software["x_cvebeacon_purl"] == "pkg:pypi/example-gadget@2.0"


@pytest.mark.parametrize(
    ("purl", "name", "coordinate"),
    [
        ("pkg:pypi/requests", "requests", "pkg:pypi/requests"),
        (
            "pkg:deb/debian/openssl?arch=source&distro=bookworm",
            "debian/openssl",
            "pkg:deb/debian/openssl",
        ),
    ],
)
def test_versionless_purl_exports_without_a_version(
    tmp_path, purl, name, coordinate
):
    store = StateStore(tmp_path / "state.db")
    asset = Asset("asset-1", purl=purl)
    finding = _finding(
        asset,
        cve_id="CVE-2026-0018",
        state=Applicability.AFFECTED,
    )
    store.record_scan([QueryResult(asset, (finding,), ())])
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    bundle = build_bundle(
        select_findings(snapshot.findings), generated_at=FIXED
    )
    validate_bundle(bundle)
    software = next(
        value for value in bundle["objects"] if value["type"] == "software"
    )
    assert software["name"] == name
    assert "version" not in software
    assert software["x_cvebeacon_purl"] == coordinate


def test_purl_qualifiers_do_not_leak_urls_or_tokens(tmp_path):
    first = Asset(
        "asset-1",
        purl=(
            "pkg:maven/org.example/private-lib@1.0"
            "?repository_url=https://user:pass@internal.example/repo"
            "&download_url=https://example.invalid/private/package"
        ),
    )
    second = Asset(
        "asset-2",
        purl=(
            "pkg:maven/org.example/private-lib@1.0"
            "?token=private-token-value"
        ),
    )
    findings = [
        _finding(
            first,
            cve_id="CVE-2026-0011",
            state=Applicability.AFFECTED,
        ),
        _finding(
            second,
            cve_id="CVE-2026-0011",
            state=Applicability.AFFECTED,
        ),
    ]
    store = StateStore(tmp_path / "state.db")
    store.record_scan(
        [
            QueryResult(first, (findings[0],), ()),
            QueryResult(second, (findings[1],), ()),
        ]
    )
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    bundle = build_bundle(
        select_findings(snapshot.findings), generated_at=FIXED
    )
    validate_bundle(bundle)
    text = json.dumps(bundle)
    for leaked in (
        "repository_url",
        "download_url",
        "token",
        "private-token-value",
        "user:pass",
        "internal.example",
        "example.invalid/private",
    ):
        assert leaked not in text
    software = [
        value for value in bundle["objects"] if value["type"] == "software"
    ]
    assert len(software) == 1
    assert software[0]["x_cvebeacon_purl"] == (
        "pkg:maven/org.example/private-lib@1.0"
    )


def test_repeated_cli_export_reuses_ids_and_created(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    first = _export(
        tmp_path, "--include-clients", output="first.json"
    )
    second = _export(
        tmp_path, "--include-clients", output="second.json"
    )
    assert [value["id"] for value in first["objects"]] == [
        value["id"] for value in second["objects"]
    ]
    assert first["id"] == second["id"]
    assert {
        value["id"]: value.get("created")
        for value in first["objects"]
        if "created" in value
    } == {
        value["id"]: value.get("created")
        for value in second["objects"]
        if "created" in value
    }


def test_validator_rejects_a_missing_required_property(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    bundle = build_bundle(
        select_findings(snapshot.findings), generated_at=FIXED
    )
    broken = copy.deepcopy(bundle)
    next(
        value
        for value in broken["objects"]
        if value["type"] == "vulnerability"
    ).pop("name")
    with pytest.raises(AssertionError):
        validate_bundle(broken)
