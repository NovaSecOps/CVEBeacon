from __future__ import annotations

import json

from cvebeacon.clients import (
    ClientImpact,
    affected_clients,
    client_cves,
    client_summaries,
    format_affected_clients,
    latest_successful_scan,
)
from cvebeacon.models import (
    Applicability,
    Asset,
    Finding,
    QueryResult,
    Vulnerability,
)
from cvebeacon.state import StateStore


def finding(asset: Asset, cve_id: str, status: Applicability) -> Finding:
    return Finding(asset, Vulnerability(cve_id), status, "high", "test")


def scan(store: StateStore, results, *, failed: bool = False) -> str:
    if failed:
        results = [
            QueryResult(
                result.asset,
                result.findings,
                (),
                Applicability.COVERAGE_UNKNOWN,
                "offline coverage is unknown",
            )
            for result in results
        ]
    run_id, _ = store.record_scan(results)
    return run_id


def test_affected_and_review_clients_are_grouped(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    acme_one = Asset("a1", "Acme", "Widget", "1", client="Acme")
    acme_two = Asset("a2", "Acme", "Widget", "2", client="Acme")
    globex = Asset("g1", "Acme", "Widget", "3", client="Globex")
    initech = Asset("i1", "Acme", "Widget", "4", client="Initech")
    scan(
        store,
        [
            QueryResult(
                acme_one,
                (finding(acme_one, "CVE-2026-0001", Applicability.AFFECTED),),
                (),
            ),
            QueryResult(
                acme_two,
                (
                    finding(
                        acme_two, "CVE-2026-0001", Applicability.NEEDS_REVIEW
                    ),
                ),
                (),
            ),
            QueryResult(
                globex,
                (
                    finding(
                        globex, "CVE-2026-0001", Applicability.NEEDS_REVIEW
                    ),
                ),
                (),
            ),
            QueryResult(
                initech,
                (
                    finding(
                        initech, "CVE-2026-0001", Applicability.NOT_AFFECTED
                    ),
                ),
                (),
            ),
        ],
    )
    impacts = affected_clients(path, ("CVE-2026-0001",))
    assert impacts == {
        "CVE-2026-0001": (
            ClientImpact("Acme", 2, "affected"),
            ClientImpact("Globex", 1, "needs_review"),
        )
    }


def test_unaffected_cves_and_unassigned_assets_are_omitted(tmp_path):
    store = StateStore(tmp_path / "state.db")
    assigned = Asset("a1", "Acme", "Widget", "1", client="Acme")
    unassigned = Asset("a2", "Acme", "Widget", "2")
    scan(
        store,
        [
            QueryResult(
                assigned,
                (
                    finding(
                        assigned, "CVE-2026-0001", Applicability.NOT_AFFECTED
                    ),
                ),
                (),
            ),
            QueryResult(
                unassigned,
                (finding(unassigned, "CVE-2026-0002", Applicability.AFFECTED),),
                (),
            ),
        ],
    )
    assert affected_clients(
        tmp_path / "state.db", ("CVE-2026-0001", "CVE-2026-0002")
    ) == {}


def test_missing_state_database_is_omitted_and_not_created(tmp_path):
    path = tmp_path / "absent.db"
    assert latest_successful_scan(path) is None
    assert affected_clients(path, ("CVE-2026-0001",)) == {}
    assert client_summaries(path) == (None, ())
    assert not path.exists()


def test_database_without_a_successful_scan_is_omitted(tmp_path):
    path = tmp_path / "state.db"
    StateStore(path).initialize()
    assert latest_successful_scan(path) is None
    assert affected_clients(path, ("CVE-2026-0001",)) == {}


def test_latest_failed_scan_does_not_replace_the_last_successful_scan(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    acme = Asset("a1", "Acme", "Widget", "1", client="Acme")
    newco = Asset("n1", "Acme", "Widget", "1", client="Newco")
    scan(
        store,
        [
            QueryResult(
                acme,
                (finding(acme, "CVE-2026-0001", Applicability.AFFECTED),),
                (),
            )
        ],
    )
    scan(
        store,
        [
            QueryResult(
                newco,
                (finding(newco, "CVE-2026-0001", Applicability.AFFECTED),),
                (),
            )
        ],
        failed=True,
    )
    impacts = affected_clients(path, ("CVE-2026-0001",))
    assert impacts == {"CVE-2026-0001": (ClientImpact("Acme", 1, "affected"),)}


def test_alias_finding_matches_the_requested_cve(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    asset = Asset("a1", "Acme", "Widget", "1", client="Acme")
    advisory = Vulnerability(
        advisory_id="GHSA-aaaa-bbbb-cccc",
        aliases=("CVE-2026-0009",),
    )
    item = Finding(asset, advisory, Applicability.AFFECTED, "high", "test")
    store.record_scan([QueryResult(asset, (item,), ())])
    impacts = affected_clients(path, ("CVE-2026-0009",))
    assert impacts == {"CVE-2026-0009": (ClientImpact("Acme", 1, "affected"),)}


def test_client_summaries_count_assets_and_current_findings(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    first = Asset("a1", "Acme", "Widget", "1", client="Acme")
    second = Asset("a2", "Acme", "Widget", "2", client="Acme")
    other = Asset("b1", "Acme", "Widget", "3", client="Globex")
    unassigned = Asset("u1", "Acme", "Widget", "4")
    scan(
        store,
        [
            QueryResult(
                first,
                (finding(first, "CVE-2026-0002", Applicability.AFFECTED),),
                (),
            ),
            QueryResult(
                second,
                (finding(second, "CVE-2026-0001", Applicability.NEEDS_REVIEW),),
                (),
            ),
            QueryResult(other, (), ()),
            QueryResult(unassigned, (), ()),
        ],
    )
    info, clients = client_summaries(path)
    assert info is not None
    assert [(item.name, item.assets) for item in clients] == [
        ("Acme", 2),
        ("Globex", 1),
    ]
    assert [
        (finding.cve_id, finding.status) for finding in clients[0].findings
    ] == [("CVE-2026-0001", "needs_review"), ("CVE-2026-0002", "affected")]
    assert clients[1].findings == ()
    assert client_cves(path, "acme") == ("CVE-2026-0001", "CVE-2026-0002")
    assert client_cves(path, "Globex") == ()


def test_client_names_differing_only_by_case_are_one_client(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    first = Asset("a1", "Acme", "Widget", "1", client="Acme")
    second = Asset("a2", "Acme", "Widget", "2", client="acme")
    scan(
        store,
        [
            QueryResult(first, (), ()),
            QueryResult(second, (), ()),
        ],
    )
    _, clients = client_summaries(path)
    assert len(clients) == 1
    assert clients[0].name == "Acme"
    assert clients[0].assets == 2


def test_asset_client_is_stored_with_the_scan(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    asset = Asset("a1", "Acme", "Widget", "1", client="Acme")
    run_id = scan(store, [QueryResult(asset, (), ())])
    snapshot = store.dashboard_snapshot()
    assert snapshot["assets"][0]["asset"]["client"] == "Acme"
    import sqlite3

    with sqlite3.connect(path) as db:
        payload = db.execute(
            "SELECT payload_json FROM scan_assets WHERE run_id=?", (run_id,)
        ).fetchone()[0]
    assert json.loads(payload)["asset"]["client"] == "Acme"


def test_correlation_does_not_modify_the_state_database(tmp_path):
    path = tmp_path / "state.db"
    store = StateStore(path)
    asset = Asset("a1", "Acme", "Widget", "1", client="Acme")
    scan(
        store,
        [
            QueryResult(
                asset,
                (finding(asset, "CVE-2026-0001", Applicability.AFFECTED),),
                (),
            )
        ],
    )
    before = path.read_bytes()
    assert affected_clients(path, ("CVE-2026-0001",))
    assert client_summaries(path)
    assert path.read_bytes() == before


def test_affected_clients_line_is_localized_and_bounded():
    impacts = tuple(
        ClientImpact(f"Client {index}", 1, "affected") for index in range(1, 13)
    )
    english = format_affected_clients(impacts, limit=10)
    assert english.startswith("Affected clients: Client 1, Client 2,")
    assert english.endswith("and 2 more")
    assert "Client 11" not in english
    portuguese = format_affected_clients(impacts, language="pt-PT", limit=10)
    assert portuguese.startswith("Clientes afetados: Client 1,")
    assert portuguese.endswith("e mais 2")
