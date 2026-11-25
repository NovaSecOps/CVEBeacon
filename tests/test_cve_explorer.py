from __future__ import annotations

from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.records import WatchRecord


def official(identifier="CVE-2026-10001", state="PUBLISHED", description="Spring4Shell alias"):
    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": identifier, "state": state,
                        "datePublished": "2026-11-01T00:00:00Z",
                        "dateUpdated": "2026-11-02T00:00:00Z"},
        "containers": {"cna": {
            "providerMetadata": {"shortName": "Example CNA", "dateUpdated": "2026-11-02T00:00:00Z"},
            "descriptions": [{"lang": "en", "value": description}],
            "affected": [{"vendor": "Example", "product": "Widget"}],
            "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8}}],
            "references": [{"url": "https://example.com/advisory"}],
        }},
    }


def test_cve_list_only_record_enters_watch_database(tmp_path):
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_cve_list([official()], catalogs=("cve_list",))
    view = store.view("CVE-2026-10001", catalogs=("cve_list",))
    assert view.description == "Spring4Shell alias"
    assert view.cvss[0].provider == "cna"
    assert view.vendors == ("Example",)


def test_search_normalizes_id_and_finds_description_alias(tmp_path):
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([WatchRecord("CVE-2026-10001", "published", description="Spring4Shell alias")])
    for query in (" cve-2026-10001 ", "Spring4Shell"):
        result = store.search(query=query)
        assert result.total == 1
        assert result.records[0].cve_id == "CVE-2026-10001"


def test_search_bounds_fts_fallback_and_provider_descriptions(tmp_path, monkeypatch):
    import pytest
    from cvebeacon.errors import StateError
    store = WatchStore(tmp_path / 'watch.db')
    payload = official(description='A' * 1100 + ' LongAliasBeyondPreview')
    store.upsert_cve_list([payload])
    assert store.search(query='LongAliasBeyondPreview').total == 1
    assert store.search(query='LongAliasBeyondPreview', use_fts=False).total == 1
    with pytest.raises(StateError, match='256'):
        store.search(query='x' * 257)
    assert store.search(query='" OR * ( )').total == 0
    assert store.search(query='%', use_fts=False).total == 0
    # Simulate a stdlib build without the FTS5 module from database creation.
    monkeypatch.setattr(WatchStore, '_ensure_search', lambda db: None)
    fallback = WatchStore(tmp_path / 'fallback.db')
    fallback.upsert_cve_list([official()])
    result = fallback.search(query='Spring4Shell')
    assert result.total == 1
    assert not result.fts


def test_search_filter_sort_and_pagination(tmp_path):
    from datetime import date
    from cvebeacon.watch.records import KEVFields
    store = WatchStore(tmp_path / 'watch.db')
    store.upsert_cve_list([official(), official('CVE-2026-10002')])
    store.upsert_nvd([WatchRecord('CVE-2026-10003', 'published', published='2020-01-01')])
    store.replace_kev('cisa', {'CVE-2026-10001': KEVFields('2026-11-01')})
    assert store.search(source='cve_list').total == 2
    assert store.search(source='nvd').total == 1
    assert store.search(severity='critical').total == 2
    assert store.search(kev='yes').records[0].cve_id == 'CVE-2026-10001'
    assert store.search(kev='no').total == 2
    assert store.search(has_events='yes').total == 0
    assert store.search(since=date(2026, 1, 1)).total == 2
    assert store.search(until=date(2020, 12, 31)).total == 1
    assert store.search(client_ids=('CVE-2026-10001',)).total == 1
    first = store.search(sort='published', limit=1)
    assert first.total == 3 and len(first.records) == 1
    assert store.search(sort='published', limit=1, offset=1).records != first.records
    assert len(store.search(limit=1000).records) == 3


def test_schema_seven_upgrade_preserves_records_events_and_resume(tmp_path):
    import sqlite3
    from pathlib import Path
    path = tmp_path / 'watch.db'
    schema = Path(__file__).with_name('fixtures') / 'watch_schema_v7.sql'
    with sqlite3.connect(path) as db:
        db.executescript(schema.read_text())
        db.execute("INSERT INTO watch_cve(cve_id,status,description,cvss_json,cwes_json,products_json,references_json,first_seen,updated_at) VALUES ('CVE-2026-10001','published','Stored alias','[]','[]','[]','[]','2026-11-01','2026-11-02')")
        db.execute("INSERT INTO watch_event(rule,cve_id,kind,reasons_json,details_json,occurrence,initial,created_at) VALUES ('critical','CVE-2026-10001','match','[]','{}','match',0,'2026-11-02')")
        db.execute("INSERT INTO watch_delivery(event_id,channel,status,attempts,updated_at) VALUES (1,'sink','sent',1,'2026-11-02')")
        db.execute("INSERT INTO watch_meta VALUES ('euvd_page_cursor','unchanged cursor')")
    store = WatchStore(path)
    store.initialize()
    assert store.metadata()['schema_version'] == '10'
    assert store.metadata()['euvd_page_cursor'] == 'unchanged cursor'
    assert store.search(query='Stored').total == 1
    assert store.view('CVE-2026-10001').first_seen == '2026-11-01'
    assert len(store.events()) == 1
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT status,attempts FROM watch_delivery').fetchone() == ('sent', 1)
    assert store.source_presence('CVE-2026-10001')[0]['state'] == 'present'
    store.upsert_cve_list([official('CVE-2026-10002', state='RESERVED')])
    assert store.view('CVE-2026-10002').status == 'reserved'


def vulnrichment_record(identifier="CVE-2026-10001", exploitation="active"):
    payload = official(identifier)
    payload["containers"]["adp"] = [{
        "providerMetadata": {"shortName": "CISA-ADP"},
        "metrics": [
            {"other": {"type": "ssvc", "content": {"options": [
                {"Exploitation": exploitation}, {"Automatable": "no"},
            ]}}},
            {"cvssV4_0": {"baseScore": 7.5, "vectorString": "CVSS:4.0/AV:N"}},
        ],
    }]
    return payload


def test_vulnrichment_exploitation_and_scores_survive_nvd_precedence(tmp_path):
    from cvebeacon.watch.records import CVSSEntry
    from cvebeacon.watch.rules import evaluate_condition, parse_rules

    identifier = "CVE-2026-10001"
    catalogs = ("nvd", "cve_list")
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([WatchRecord(identifier, "published", cvss=(CVSSEntry("nvd", "nvd", "2.0", 6.0),))])
    store.upsert_cve_list([vulnrichment_record()], catalogs=catalogs)
    view = store.view(identifier, catalogs=catalogs)
    assert view.exploitation == ("active", ("CISA Vulnrichment (CVE List SSVC)",))
    assert [entry.version for entry in view.cvss_scores] == ["4.0", "3.1", "2.0"]
    base = {"name": "test", "channels": ["sink"]}
    for condition, expected in [
        ({"cvss_min": 9.0}, False),
        ({"cvss_min": {"score": 9.0, "versions": ["3.1"]}}, True),
    ]:
        rule = parse_rules([{**base, "condition": condition}])[0]
        assert evaluate_condition(view, rule.condition, rule)[0] is expected


def test_schema_eight_upgrade_backfills_vulnrichment_and_queues_only_changed_rows(tmp_path):
    from cvebeacon.watch.records import canonical_json

    store = WatchStore(tmp_path / "watch.db")
    store.upsert_cve_list([vulnrichment_record(), official("CVE-2026-10002")])
    with store.transaction() as db:
        db.execute("UPDATE watch_meta SET value='8' WHERE key='schema_version'")
        db.execute("UPDATE watch_provider SET record_json=json_set(record_json,'$.ssvc_exploitation',NULL)")
        db.execute("DELETE FROM watch_touched")
        db.execute("INSERT INTO watch_meta VALUES ('euvd_page_cursor',?)", (canonical_json(["cursor"]),))
    for _ in range(2):
        store.initialize()
    assert store.metadata()["schema_version"] == "10"
    assert store.metadata()["euvd_page_cursor"] == '["cursor"]'
    assert store.view("CVE-2026-10001").exploitation == ("active", ("CISA Vulnrichment (CVE List SSVC)",))
    with store.read() as db:
        assert [row[0] for row in db.execute("SELECT cve_id FROM watch_touched")] == ["CVE-2026-10001"]


def test_explorer_combines_filters_and_matches_score_and_selectors_on_same_entry(tmp_path):
    from datetime import date
    from cvebeacon.watch.records import CVSSEntry, KEVFields

    first, second, third = ("CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003")
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([WatchRecord(first, "published", cvss=(CVSSEntry("nvd", "nvd", "2.0", 10.0),))])
    store.upsert_cve_list([vulnrichment_record(first), vulnrichment_record(second, "none"), official(third)])
    store.replace_kev("eu", {first: KEVFields("2026-11-02")})
    with store.transaction() as db:
        db.execute("INSERT INTO watch_epss(cve_id,epss,percentile,score_date) VALUES (?,?,?,?)",
                   (first, .4, .9, "2026-11-02"))
        db.execute("INSERT INTO watch_event(rule,cve_id,kind,reasons_json,details_json,occurrence,initial,created_at) "
                   "VALUES ('rule',?,'match','[]','{}','match',0,'2026-11-02')", (first,))
    result = store.search(
        source=("cve_list", "euvd"), kev=("eu", "cisa"), exploitation=("active", "poc"),
        epss_min=.4, epss_max=.5, cvss_min=7.5, cvss_max=8,
        cvss_version=("4.0", "3.0"), cvss_provider=("cisa-adp", "other"),
        severity=("critical", "high"), since=date(2026, 11, 1), until=date(2026, 11, 1),
        modified_since=date(2026, 11, 2), modified_until=date(2026, 11, 2),
        has_events="yes", reported="no", client_ids=[first, third],
    )
    assert [item.cve_id for item in result.records] == [first]
    assert store.search(cvss_min=9, cvss_version="4.0", cvss_provider="nvd").total == 0
    assert store.search(cvss_max=8, cvss_version="4.0", cvss_provider="cisa-adp").total == 2
    assert store.search(exploitation="none", kev="neither").records[0].cve_id == second
    assert store.search(exploitation="unknown", kev="neither").records[0].cve_id == third
    assert store.search(source=("nvd", "cve_list")).total == 3


def test_explorer_rejects_invalid_filter_bounds_and_tokens(tmp_path):
    import pytest
    from cvebeacon.errors import StateError

    store = WatchStore(tmp_path / "watch.db")
    for filters in (
        {"epss_min": float("nan")}, {"epss_max": 1.1}, {"cvss_min": -1},
        {"cvss_min": 8, "cvss_max": 7}, {"cvss_version": "4.0') OR 1=1--"},
        {"cvss_provider": "nvd') OR 1=1--"}, {"source": ["nvd"] * 50},
        {"exploitation": "other"}, {"kev": "x"}, {"reported": ("yes", "no")},
        {"has_events": ("yes", "no")},
    ):
        with pytest.raises(StateError):
            store.search(**filters)


def test_vendor_and_product_filters_match_rule_leaves_across_nvd_and_euvd(tmp_path):
    from cvebeacon.watch.records import CVSSEntry, EUVDUpdate, Product
    from cvebeacon.watch.rules import evaluate_condition, parse_rules

    identifiers = tuple(f"CVE-2026-{number:05d}" for number in range(12001, 12006))
    first, second, no_data, euvd_only, underscored = identifiers
    store = WatchStore(tmp_path / "watch.db")
    catalogs = ("nvd", "euvd")
    store.upsert_nvd([
        WatchRecord(
            first, "published", cvss=(CVSSEntry("nvd", "nvd", "3.1", 9.5),),
            products=(Product("PHP Group", "PHP_Core"),), ssvc_exploitation="active",
        ),
        WatchRecord(second, "published", products=(Product("Other Vendor", "PHP_Core"),)),
        WatchRecord(no_data, "published"),
        WatchRecord(euvd_only, "published"),
        WatchRecord(underscored, "published", products=(Product("Big_Corp", "Widget_Server"),)),
    ], catalogs=catalogs)
    store.replace_euvd_items([
        EUVDUpdate((euvd_only,), "EUVD-2026-12004", "2026-11-01",
                   CVSSEntry("euvd", "euvd", "3.1", 8.0), "2026-11-02",
                   (Product("php group", "PHP_Core"),)),
        EUVDUpdate((euvd_only,), "EUVD-2026-12005", None,
                   CVSSEntry("euvd", "euvd", "4.0", 9.9), "2026-11-03",
                   (Product("Other Vendor", "Other_Product"),)),
    ], catalogs=catalogs)

    vendors = ("pHp GrOuP", "big_corp")
    products = ("php_core", "widget_server")
    vendor_results = {item.cve_id for item in store.search(
        catalogs=catalogs, vendor_names=("PHP GROUP",), limit=100,
    ).records}
    product_results = {item.cve_id for item in store.search(
        catalogs=catalogs, product_names=("PHP_core",), limit=100,
    ).records}
    both = store.search(catalogs=catalogs, vendor_names=vendors,
                        product_names=products, limit=100)
    assert vendor_results == {first, euvd_only}
    assert product_results == {first, second, euvd_only}
    assert {item.cve_id for item in both.records} == {first, euvd_only, underscored}
    assert store.search(catalogs=catalogs, product_names=("Widget Server",)).total == 0
    assert {item.cve_id for item in store.search(
        catalogs=catalogs, product_names=("widget_server",), limit=100,
    ).records} == {underscored}
    assert {item.cve_id for item in store.search(
        catalogs=catalogs,
        vendor_names=("php group",), product_names=("PHP_core",), cvss_min=9, cvss_max=9.7,
        exploitation="active", limit=100,
    ).records} == {first}

    for rule_filters, condition in (
        ({"vendor_names": ("PHP GROUP",)}, {"vendor": ["PHP GROUP"]}),
        ({"product_names": ("PHP_core",)}, {"product": ["PHP_core"]}),
        ({"vendor_names": vendors, "product_names": products},
         {"all": [{"vendor": list(vendors)}, {"product": list(products)}]}),
    ):
        rule = parse_rules([{
            "name": "vendor-and-product", "channels": ["sink"],
            "condition": condition,
        }])[0]
        rule_results = {
            identifier for identifier in identifiers
            if evaluate_condition(store.view(identifier, catalogs=catalogs),
                                 rule.condition, rule)[0]
        }
        explorer_results = {
            item.cve_id for item in store.search(
                catalogs=catalogs, **rule_filters, limit=100,
            ).records
        }
        assert explorer_results == rule_results
    baseline = store.search(limit=100)
    empty = store.search(vendor_names=(), product_names=(), limit=100)
    assert (empty.total, empty.records) == (baseline.total, baseline.records)


def test_vendor_product_filters_reject_out_of_bounds_and_control_format_names(tmp_path):
    import pytest
    from cvebeacon.errors import StateError

    store = WatchStore(tmp_path / "watch.db")
    for filters, message in (
        ({"vendor_names": ["php"] * 21}, "20 vendor names of at most 120 characters"),
        ({"product_names": ["x" * 121]}, "20 product names of at most 120 characters"),
        ({"vendor_names": ["php\x01group"]}, "20 vendor names of at most 120 characters"),
        ({"product_names": ["php\u200egroup"]}, "20 product names of at most 120 characters"),
    ):
        with pytest.raises(StateError, match=message):
            store.search(**filters)


def test_vendor_and_product_filters_each_match_exact_names(tmp_path):
    from cvebeacon.watch.records import Product

    first, second = "CVE-2026-13001", "CVE-2026-13002"
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([
        WatchRecord(first, "published", products=(Product("PHP Group", "PHP_Core"),)),
        WatchRecord(second, "published", products=(Product("Other Vendor", "PHP_Core"),)),
    ])
    cases = (
        ({"vendor_names": ("php group",)}, {first}),
        ({"product_names": ("PHP_core",)}, {first, second}),
    )
    for filters, expected in cases:
        assert {item.cve_id for item in store.search(**filters, limit=100).records} == expected


def test_empty_vendor_and_product_filters_preserve_search_results(tmp_path):
    from cvebeacon.watch.records import Product

    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([
        WatchRecord("CVE-2026-14001", "published", products=(Product("PHP", "Server"),)),
    ])
    baseline = store.search(limit=100)
    empty = store.search(vendor_names=(), product_names=(), limit=100)
    assert (empty.total, empty.records) == (baseline.total, baseline.records)


def test_name_filters_work_for_every_valid_catalog_combination(tmp_path):
    from itertools import combinations
    from cvebeacon.config import WATCH_SOURCES
    from cvebeacon.watch.records import Product

    store = WatchStore(tmp_path / "watch.db")
    identifier = "CVE-2026-14101"
    store.upsert_nvd([WatchRecord(
        identifier, "published", products=(Product("PHP Group", "PHP Core"),),
    )])
    optional = tuple(source for source in WATCH_SOURCES if source != "nvd")
    catalog_sets = tuple(
        ("nvd", *selected)
        for count in range(len(optional) + 1)
        for selected in combinations(optional, count)
    )
    for catalogs in catalog_sets:
        result = store.search(
            catalogs=catalogs, vendor_names=("php group",),
            product_names=("php core",), limit=100,
        )
        assert result.total == 1, catalogs
        assert result.records[0].cve_id == identifier, catalogs


def test_name_filter_results_match_watch_view_at_the_500_name_cap(tmp_path):
    from cvebeacon.watch.records import Product
    from cvebeacon.watch.rules import evaluate_condition, parse_rules

    identifier = "CVE-2026-14102"
    catalogs = ("nvd",)
    store = WatchStore(tmp_path / "watch.db")
    products = tuple(Product("Vendor", f"product-{index:03d}") for index in range(600))
    store.upsert_nvd([WatchRecord(identifier, "published", products=products)])
    view = store.view(identifier, catalogs=catalogs)
    cases = (("product-499", True), ("product-500", False))
    for product, expected in cases:
        rule = parse_rules([{
            "name": "product-cap", "channels": ["sink"],
            "condition": {"product": [product]},
        }])[0]
        rule_match = evaluate_condition(view, rule.condition, rule)[0]
        explorer_match = store.search(
            catalogs=catalogs, product_names=(product,), limit=100,
        ).total == 1
        assert rule_match is expected
        assert explorer_match is rule_match


def test_name_filter_search_skips_malformed_stored_json_rows(tmp_path):
    import sqlite3
    from cvebeacon.watch.records import EUVDUpdate, Product

    catalogs = ("nvd", "euvd")
    malformed_products, clean_nvd, malformed_euvd, clean_euvd = (
        f"CVE-2026-{number:05d}" for number in range(14103, 14107)
    )
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([
        WatchRecord(malformed_products, "published", products=(Product("Vendor", "Widget"),)),
        WatchRecord(clean_nvd, "published", products=(Product("Vendor", "Widget"),)),
        WatchRecord(malformed_euvd, "published"),
        WatchRecord(clean_euvd, "published"),
    ], catalogs=catalogs)
    store.replace_euvd_items([
        EUVDUpdate((malformed_euvd,), "EUVD-2026-14105", None,
                   vendors=(Product("Vendor", "Widget"),)),
        EUVDUpdate((clean_euvd,), "EUVD-2026-14106", None,
                   vendors=(Product("Vendor", "Widget"),)),
    ], catalogs=catalogs)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_cve SET products_json='{bad-json' WHERE cve_id=?",
                   (malformed_products,))
        db.execute("UPDATE watch_euvd_item SET vendors_json='{bad-json' WHERE euvd_id=?",
                   ("EUVD-2026-14105",))

    result = store.search(catalogs=catalogs, product_names=("Widget",), limit=100)
    assert result.total == 2
    assert {item.cve_id for item in result.records} == {clean_nvd, clean_euvd}


def test_name_filter_matches_maximum_size_nvd_row_exposed_by_watch_view(tmp_path):
    from cvebeacon.watch.records import Product
    from cvebeacon.watch.rules import evaluate_condition, parse_rules

    identifier = "CVE-2026-14107"
    store = WatchStore(tmp_path / "watch.db")
    products = tuple(
        Product("Vendor", f"product-{index:04d}-" + "x" * 2_480)
        for index in range(1_000)
    )
    store.upsert_nvd([WatchRecord(identifier, "published", products=products)])
    with store.read() as db:
        stored = db.execute(
            "SELECT products_json FROM watch_cve WHERE cve_id=?", (identifier,),
        ).fetchone()[0]
    assert len(stored.encode("utf-8")) > 2_500_000

    rule, = parse_rules([{
        "name": "long-product-row", "channels": ["sink"],
        "condition": {"vendor": ["Vendor"]},
    }])
    rule_match = evaluate_condition(
        store.view(identifier, catalogs=("nvd",)), rule.condition, rule,
    )[0]
    explorer_match = store.search(
        catalogs=("nvd",), vendor_names=("Vendor",), limit=100,
    ).total == 1
    assert rule_match is True
    assert explorer_match is rule_match


def test_name_filter_gate_preserves_rule_matches_for_bypass_cases(tmp_path, monkeypatch):
    import sqlite3
    from cvebeacon.watch import explorer
    from cvebeacon.watch.records import EUVDUpdate, Product
    from cvebeacon.watch.rules import evaluate_condition, parse_rules

    catalogs = ("nvd", "euvd", "cve_list")
    identifiers = tuple(f"CVE-2026-{number:05d}" for number in range(14108, 14117))
    (strasse, eszett, kelvin, quoted, slashed, escaped, provider_only,
     cve_list_record, euvd_only) = identifiers
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([
        WatchRecord(strasse, "published", products=(Product("Straße", "Widget"),)),
        WatchRecord(eszett, "published", products=(Product("Vendor", "ß"),)),
        WatchRecord(kelvin, "published", products=(Product("K", "Widget"),)),
        WatchRecord(quoted, "published", products=(Product('Acme "Tools"', "Widget"),)),
        WatchRecord(slashed, "published", products=(Product(r"Acme\Tools", "Widget"),)),
        WatchRecord(escaped, "published", products=(Product("placeholder", "Widget"),)),
        WatchRecord(cve_list_record, "published"),
        WatchRecord(euvd_only, "published"),
    ], catalogs=catalogs)
    fallback = official(cve_list_record, description="CVE List fallback")
    fallback["containers"]["cna"]["affected"][0]["vendor"] = "Official Vendor"
    store.upsert_cve_list([official(provider_only), fallback], catalogs=catalogs)
    store.replace_euvd_items([
        EUVDUpdate((euvd_only,), "EUVD-2026-14116", None,
                   vendors=(Product("EUVD Widget", "Widget"),)),
    ], catalogs=catalogs)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_cve SET products_json=? WHERE cve_id=?",
            ('[{"vendor":"\\u0050HP","product":"Widget"}]', escaped),
        )

    cases = (
        ({"vendor_names": ("STRASSE",)}, {"vendor": ["STRASSE"]}, {strasse}),
        ({"vendor_names": ("Straße",)}, {"vendor": ["Straße"]}, {strasse}),
        ({"product_names": ("ss",)}, {"product": ["ss"]}, {eszett}),
        ({"product_names": ("ß",)}, {"product": ["ß"]}, {eszett}),
        ({"vendor_names": ("k",)}, {"vendor": ["k"]}, {kelvin}),
        ({"vendor_names": ('Acme "Tools"',)}, {"vendor": ['Acme "Tools"']}, {quoted}),
        ({"vendor_names": (r"Acme\Tools",)}, {"vendor": [r"Acme\Tools"]}, {slashed}),
        ({"vendor_names": ("php",)}, {"vendor": ["php"]}, {escaped}),
        ({"vendor_names": ("Example",)}, {"vendor": ["Example"]}, {provider_only}),
        ({"vendor_names": ("Official Vendor",)}, {"vendor": ["Official Vendor"]},
         {cve_list_record}),
        ({"vendor_names": ("euvd widget",)}, {"vendor": ["euvd widget"]}, {euvd_only}),
    )
    gate_builder = explorer._name_filter_gate
    gated_results = []
    for filters, condition, expected in cases:
        field = "vendor_names" if "vendor_names" in filters else "product_names"
        gate, _ = gate_builder(filters[field], catalogs)
        if filters[field][0].isascii() and all(
            char not in filters[field][0] for char in ('"', "\\")
        ):
            assert gate is not None
        else:
            assert gate is None
        rule, = parse_rules([{
            "name": "gate-equivalence", "channels": ["sink"],
            "condition": condition,
        }])
        rule_matches = {
            identifier for identifier in identifiers
            if evaluate_condition(
                store.view(identifier, catalogs=catalogs), rule.condition, rule,
            )[0]
        }
        assert rule_matches == expected
        gated = {
            item.cve_id for item in store.search(
                catalogs=catalogs, limit=100, **filters,
            ).records
        }
        assert gated == rule_matches
        gated_results.append(gated)

    monkeypatch.setattr(explorer, "_name_filter_gate", lambda names, sources: (None, ()))
    for (filters, _, _), gated in zip(cases, gated_results):
        ungated = {
            item.cve_id for item in store.search(
                catalogs=catalogs, limit=100, **filters,
            ).records
        }
        assert ungated == gated


def test_randomized_name_filter_results_match_rule_leaves_with_gate(tmp_path):
    import random
    from cvebeacon.watch import explorer
    from cvebeacon.watch.records import EUVDUpdate, Product
    from cvebeacon.watch.rules import evaluate_condition, parse_rules

    rng = random.Random(20261125)
    catalogs = ("nvd", "euvd")
    vendors = ("php", "acme", "big_corp", "northstar", "widget labs")
    products = ("core", "server", "widget_server", "agent", "console")
    identifiers = tuple(f"CVE-2026-{number:05d}" for number in range(14200, 14296))
    records = []
    euvd_updates = []
    for index, identifier in enumerate(identifiers):
        pairs = tuple(Product(rng.choice(vendors), rng.choice(products))
                      for _ in range(rng.randrange(4)))
        records.append(WatchRecord(identifier, "published", products=pairs))
        if index % 9 == 0:
            euvd_updates.append(EUVDUpdate(
                (identifier,), f"EUVD-2026-{14200 + index}", None,
                vendors=(Product(rng.choice(vendors), rng.choice(products)),),
            ))
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd(records, catalogs=catalogs)
    store.replace_euvd_items(euvd_updates, catalogs=catalogs)
    views = {
        identifier: store.view(identifier, catalogs=catalogs)
        for identifier in identifiers
    }

    choices = (*vendors, "missing vendor")
    product_choices = (*products, "missing product")
    for _ in range(80):
        vendor_filter = tuple(rng.sample(choices, rng.randrange(1, 4)))
        product_filter = tuple(rng.sample(product_choices, rng.randrange(1, 4)))
        filters = {"vendor_names": vendor_filter, "product_names": product_filter}
        condition = {"all": [
            {"vendor": list(vendor_filter)}, {"product": list(product_filter)},
        ]}
        assert explorer._name_filter_gate(vendor_filter, catalogs)[0]
        assert explorer._name_filter_gate(product_filter, catalogs)[0]
        rule, = parse_rules([{
            "name": "random-gate-equivalence", "channels": ["sink"],
            "condition": condition,
        }])
        expected = {
            identifier for identifier in identifiers
            if evaluate_condition(
                views[identifier], rule.condition, rule,
            )[0]
        }
        actual = {
            item.cve_id for item in store.search(
                catalogs=catalogs, limit=100, **filters,
            ).records
        }
        assert actual == expected


def test_euvd_qualified_filters_include_all_effective_advisory_scores(tmp_path):
    from cvebeacon.watch.records import CVSSEntry, EUVDUpdate

    identifier = "CVE-2026-10001"
    catalogs = ("nvd", "euvd")
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([WatchRecord(identifier, "published")])
    active = EUVDUpdate((identifier,), "EUVD-2026-1", "2026-11-01",
                        CVSSEntry("euvd", "euvd", "3.1", 8.0))
    recent = EUVDUpdate((identifier,), "EUVD-2026-2", None,
                        CVSSEntry("euvd", "euvd", "4.0", 9.8), "2026-11-02")
    store.replace_euvd_items([active, recent], catalogs=catalogs)
    result = store.search(exploitation="active", cvss_version="4.0", cvss_provider="euvd", cvss_min=9)
    assert result.total == 1
    assert result.records[0].exploitation == ("active", ("EUVD",))
    assert [entry.version for entry in result.records[0].cvss_scores] == ["4.0", "3.1"]
    assert [entry.version for entry in result.records[0].cvss] == ["3.1"]

    store.upsert_euvd_cve(identifier, [recent], catalogs=catalogs)
    assert store.search(exploitation="active").total == 0
    assert store.search(exploitation="unknown", cvss_version="4.0", cvss_min=9).total == 1
    assert store.search(cvss_version="3.1").total == 0


def test_upgraded_ssvc_is_initial_without_an_alert_burst(tmp_path):
    from cvebeacon.watch.rules import parse_rules

    catalogs = ("nvd", "cve_list")
    store = WatchStore(tmp_path / "watch.db")
    recovered = [f"CVE-2026-{index:05d}" for index in range(10000, 10120)]
    no_exploitation, poc = "CVE-2026-11000", "CVE-2026-11001"
    store.upsert_cve_list([
        *(vulnrichment_record(identifier) for identifier in recovered),
        vulnrichment_record(no_exploitation, "none"), vulnrichment_record(poc, "poc"),
    ], catalogs=catalogs)

    def create_rule(name, condition, events, old_cves="digest"):
        return {"name": name, "condition": condition, "channels": ["sink"],
                "events": events, "old_cves": old_cves}

    rules = parse_rules([
        create_rule("tracked", {"status": "published"}, ["exploitation_active"]),
        *(create_rule(mode, {"exploitation": "active"}, ["match"], mode)
          for mode in ("digest", "alert", "ignore")),
    ])
    with store.transaction() as db:
        db.execute("UPDATE watch_provider SET record_json=json_set(record_json,'$.ssvc_exploitation',NULL)")
    assert store.evaluate_touched(rules, catalogs=catalogs).events == 0
    with store.transaction() as db:
        db.execute("UPDATE watch_meta SET value='8' WHERE key='schema_version'")
    store.initialize()
    assert store.view(no_exploitation, catalogs=catalogs).ssvc_exploitation == "none"
    with store.read() as db:
        assert db.execute("SELECT COUNT(*) FROM watch_touched").fetchone()[0] == len(recovered) + 1
    result = store.evaluate_touched(rules, catalogs=catalogs, limit=19)
    assert result.by_kind == (("match", 2 * len(recovered)),)
    assert not store.delivery_events("sink", catalogs=catalogs)
    events = store.events(limit=300)
    assert all(item.initial and item.rule in ("digest", "alert") for item in events)
    assert not store.evaluate_touched(rules, catalogs=catalogs).events

    store.upsert_cve_list([vulnrichment_record(poc, "active")], catalogs=catalogs)
    assert dict(store.evaluate_touched(rules, catalogs=catalogs).by_kind)["exploitation_active"] == 1
    assert any(event.kind == "exploitation_active" for event in store.delivery_events("sink", catalogs=catalogs))


def test_exploitation_sources_and_overview_include_vulnrichment_and_nvd(tmp_path):
    from cvebeacon.watch.records import EUVDUpdate
    from cvebeacon.watch.rules import evaluate_condition, parse_rules

    identifier = "CVE-2026-10001"
    catalogs = ("nvd", "euvd", "cve_list")
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_nvd([WatchRecord(identifier, "published", ssvc_exploitation="poc")])
    store.replace_euvd_items([EUVDUpdate((identifier,), "EUVD-2026-1", "2026-11-01")], catalogs=catalogs)
    view = store.view(identifier, catalogs=catalogs)
    assert view.exploitation == ("active", ("EUVD", "NVD SSVC"))
    rule, = parse_rules([{"name": "track", "condition": {"exploitation": "active"}, "channels": ["sink"]}])
    assert evaluate_condition(view, rule.condition, rule) == (True, ("exploitation active (NVD SSVC, euvd)",))
    store.upsert_cve_list([vulnrichment_record()], catalogs=catalogs)
    assert store.status(catalogs=catalogs)["active_ssvc"] == 1
    assert store.status(catalogs=("nvd", "euvd"))["active_ssvc"] == 0


def test_explorer_indexes_backfill_and_follow_source_updates(tmp_path):
    from cvebeacon.watch.records import CVSSEntry

    identifier = "CVE-2026-10001"
    catalogs = ("nvd", "cve_list")
    store = WatchStore(tmp_path / "watch.db")
    store.upsert_cve_list([vulnrichment_record()], catalogs=catalogs)
    nvd = WatchRecord(identifier, "published", cvss=(CVSSEntry("nvd", "nvd", "2.0", 8.0),))
    store.upsert_nvd([nvd], catalogs=catalogs)
    filters = {"exploitation": "active", "cvss_version": "4.0", "cvss_min": 7,
               "sort": "cvss", "severity": "critical"}
    with store.transaction() as db:
        db.execute("DELETE FROM watch_meta WHERE key='explorer_storage'")
        db.execute("DELETE FROM watch_explorer_metrics")
        db.execute("DELETE FROM watch_explorer_score")
        db.execute("UPDATE watch_meta SET value='8' WHERE key='schema_version'")
    legacy = store.search(catalogs=catalogs, **filters)
    assert legacy.total == 1
    store.initialize()
    assert store.search(catalogs=catalogs, **filters) == legacy
    assert store.search(catalogs=("nvd",), **filters).total == 0
    assert store.search(cvss_version="2.0", cvss_provider="nvd").total == 1

    updated = vulnrichment_record(exploitation="none")
    updated["containers"]["adp"][0]["metrics"][1]["cvssV4_0"]["baseScore"] = 5.0
    store.upsert_cve_list([updated], catalogs=catalogs)
    assert store.search(catalogs=catalogs, **filters).total == 0
    result = store.search(exploitation="none", cvss_version="4.0", cvss_max=5.0)
    assert result.total == 1
    assert store.search(cvss_version="2.0", cvss_provider="nvd").total == 1
