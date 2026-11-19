from __future__ import annotations

import copy
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cvebeacon import cli
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
    with store.transaction() as db:
        for (asset_id, advisory_id), (first_seen, last_seen) in times.items():
            db.execute(
                "UPDATE scan_finding_details SET first_seen=?,last_seen=? "
                "WHERE run_id=? AND asset_id=? AND advisory_id=?",
                (first_seen, last_seen, run_id, asset_id, advisory_id),
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


def test_golden_bundle_from_fixture_state(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    selected = select_findings(snapshot.findings)
    bundle = build_bundle(selected, generated_at=FIXED)
    validate_bundle(bundle)
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert bundle == expected


def test_deterministic_ids_across_runs_and_timestamps(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    snapshot = read_latest_successful_scan(tmp_path / "state.db")
    selected = select_findings(snapshot.findings)
    first = build_bundle(selected, generated_at=FIXED)
    second = build_bundle(
        selected,
        generated_at=datetime(2027, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    assert [value["id"] for value in first["objects"]] == [
        value["id"] for value in second["objects"]
    ]
    assert first["id"] == second["id"]


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
    assert "Globex" not in json.dumps(filtered)

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
    assert relationships[0]["x_cvebeacon_clients"] == ["Globex"]
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
    assert len(bundle["objects"]) == 7


def test_empty_result_is_a_valid_bundle(tmp_path):
    StateStore(tmp_path / "state.db").initialize()
    bundle = _export(tmp_path)
    validate_bundle(bundle)
    assert bundle["objects"] == []


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


@pytest.mark.parametrize("target", ["config.toml", "inventory.csv", "state.db"])
def test_stix_export_cannot_overwrite_operational_files(tmp_path, target):
    build_fixture_database(tmp_path / "state.db")
    config = _config(tmp_path)
    path = tmp_path / target
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
    assert path.read_bytes() == original


def test_export_does_not_write_state_or_emit_config_paths(tmp_path, monkeypatch):
    build_fixture_database(tmp_path / "state.db")
    database = tmp_path / "state.db"
    config = _config(tmp_path)
    secret = "https://example.invalid/hooks/private-token"
    monkeypatch.setenv("CVEBEACON_TEAMS_WEBHOOK_URL", secret)
    before = database.read_bytes()
    bundle = _export(tmp_path)
    text = json.dumps(bundle)
    validate_bundle(bundle)
    assert database.read_bytes() == before
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


def test_repeated_cli_export_reuses_object_ids(tmp_path):
    build_fixture_database(tmp_path / "state.db")
    first = _export(tmp_path, output="first.json")
    second = _export(tmp_path, output="second.json")
    assert [value["id"] for value in first["objects"]] == [
        value["id"] for value in second["objects"]
    ]
    assert first["id"] == second["id"]


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
