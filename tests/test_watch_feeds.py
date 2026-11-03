from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from watch_support import mock_client, nvd_cve, nvd_page

from cvebeacon.errors import SourceError
from cvebeacon.models import Evidence
from cvebeacon.sources.epss import EPSSSource, EPSS_URL
from cvebeacon.sources.kev import CISA_URL, EU_URL
from cvebeacon.sources.nvd import CVE_URL
from cvebeacon.watch import feeds
from cvebeacon.watch.feeds import (
    cisa_fields,
    eu_fields,
    euvd_chunks,
    fetch_epss_floor,
    fetch_epss_scores,
    fetch_euvd,
    fetch_nvd_cve,
    fetch_nvd_window,
    iso_timestamp,
    nvd_windows,
    parse_nvd_cve,
    parse_nvd_timestamp,
)
from cvebeacon.watch.records import CVSSEntry, Product

FIXTURES = Path(__file__).parent / "fixtures" / "watch"
CISA_ADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"


def test_recorded_nvd_sample_parses_ssvc_cvss_and_kev():
    payload = json.loads((FIXTURES / "nvd-ssvc-page.json").read_text(encoding="utf-8"))
    record = parse_nvd_cve(payload["vulnerabilities"][0]["cve"])
    assert record.cve_id == "CVE-2021-44228"
    assert record.ssvc_exploitation == "active"
    assert record.cisa_kev_added == "2021-12-10"
    assert record.cisa_kev_due == "2021-12-24"
    assert "updates exist" in record.cisa_required_action
    assert record.products == (Product("apache", "log4j"),)
    assert set(record.cwes) == {"CWE-20", "CWE-400", "CWE-502"}
    assert {(entry.provider, entry.version, entry.score) for entry in record.cvss} == {
        ("nvd", "3.1", 10.0),
        ("cna", "3.1", 10.0),
        ("nvd", "2.0", 9.3),
    }


def test_cvss_provider_mapping_covers_nvd_cna_cisa_adp_and_other():
    raw = nvd_cve(
        sourceIdentifier="security@example.com",
        metrics={
            "cvssMetricV40": [
                {"source": "nvd@nist.gov", "cvssData": {"version": "4.0", "baseScore": 8.0}}
            ],
            "cvssMetricV31": [
                {
                    "source": "security@example.com",
                    "cvssData": {"version": "3.1", "baseScore": 7.5},
                },
                {"source": CISA_ADP, "cvssData": {"version": "3.1", "baseScore": 5.0}},
                {
                    "source": "other@example.com",
                    "cvssData": {"version": "3.1", "baseScore": 4.0},
                },
            ],
            "cvssMetricV30": [
                {
                    "source": "nvd@nist.gov",
                    "cvssData": {"version": "3.0", "baseScore": 6.0},
                }
            ],
            "cvssMetricV2": [
                {
                    "source": "nvd@nist.gov",
                    "cvssData": {"version": "2.0", "baseScore": 5.0},
                    "baseSeverity": "MEDIUM",
                }
            ],
        },
    )
    record = parse_nvd_cve(raw)
    assert {(entry.source, entry.provider) for entry in record.cvss} == {
        ("nvd@nist.gov", "nvd"),
        ("security@example.com", "cna"),
        (CISA_ADP, "cisa-adp"),
        ("other@example.com", "other"),
    }
    assert {entry.version for entry in record.cvss} == {"2.0", "3.0", "3.1", "4.0"}
    v2 = next(entry for entry in record.cvss if entry.version == "2.0")
    assert v2.severity == "MEDIUM"


def test_cvss_scores_outside_zero_to_ten_are_ignored():
    raw = nvd_cve(
        metrics={
            "cvssMetricV31": [
                {"source": "nvd@nist.gov", "cvssData": {"version": "3.1", "baseScore": 10.5}},
                {"source": CISA_ADP, "cvssData": {"version": "3.1", "baseScore": -0.1}},
                {"source": "other@example.com", "cvssData": {"version": "3.1", "baseScore": "n/a"}},
                {"source": "security@example.com", "cvssData": {"version": "3.1", "baseScore": 10}},
                {"source": "nvd@nist.gov", "cvssData": {"version": "3.1", "baseScore": 0}},
            ]
        }
    )
    assert sorted(entry.score for entry in parse_nvd_cve(raw).cvss) == [0.0, 10.0]


@pytest.mark.parametrize(
    "options,expected",
    [
        ([{"exploitation": "active"}], "active"),
        ([{"Exploitation": "PoC"}], "poc"),
        ([{"exploitation": "none"}], "none"),
        ([{"exploitation": "unknown"}], None),
        ([{"automatable": "yes"}], None),
        ([], None),
    ],
)
def test_ssvc_exploitation_is_read_from_options(options, expected):
    metrics = {"ssvcV203": [{"source": CISA_ADP, "ssvcData": {"options": options}}]}
    assert parse_nvd_cve(nvd_cve(metrics=metrics)).ssvc_exploitation == expected


@pytest.mark.parametrize(
    "value", ["Rejected", "rejected", ["Rejected"], [{"status": "Rejected"}]]
)
def test_rejected_status_is_stored_as_rejected(value):
    assert parse_nvd_cve(nvd_cve(vulnStatus=value)).status == "rejected"
    assert parse_nvd_cve(nvd_cve(vulnStatus="Analyzed")).status == "published"


def test_description_is_truncated_and_products_and_references_are_bounded():
    cpes = [
        {"criteria": f"cpe:2.3:a:vendor{index}:product{index}:1:*:*:*:*:*:*:*"}
        for index in range(60)
    ]
    configurations = [{"nodes": [{"cpeMatch": cpes}]}]
    references = [{"url": f"https://example.test/{index}"} for index in range(40)]
    raw = nvd_cve(
        descriptions=[{"lang": "en", "value": "x" * 1200}],
        configurations=configurations,
        references=references,
    )
    record = parse_nvd_cve(raw)
    assert record.description is not None and len(record.description) == 1000
    assert len(record.products) == 50
    assert len(record.references) == 30


def test_products_include_nested_configuration_children():
    raw = nvd_cve(
        configurations=[
            {
                "nodes": [
                    {
                        "children": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    )
    assert parse_nvd_cve(raw).products == (Product("acme", "widget"),)


def test_nvd_paging_validation_rejects_bad_metadata():
    payloads = [
        {"unexpected": []},
        {"resultsPerPage": 1, "startIndex": 0, "vulnerabilities": []},
        {"resultsPerPage": 1, "startIndex": 1, "totalResults": 1, "vulnerabilities": [{"cve": nvd_cve()}]},
        {"resultsPerPage": 2, "startIndex": 0, "totalResults": 2, "vulnerabilities": [{"cve": nvd_cve()}]},
        {"resultsPerPage": 0, "startIndex": 0, "totalResults": 1, "vulnerabilities": []},
    ]
    for payload in payloads:
        client = mock_client(lambda request, payload=payload: httpx.Response(200, json=payload))
        with pytest.raises(SourceError):
            fetch_nvd_window(
                client,
                start=datetime(2026, 11, 1, tzinfo=timezone.utc),
                end=datetime(2026, 11, 2, tzinfo=timezone.utc),
            )


def test_nvd_paging_reads_every_reported_page():
    starts: list[int] = []

    def handler(request):
        start = int(dict(request.url.params)["startIndex"])
        starts.append(start)
        identifier = "CVE-2026-0001" if start == 0 else "CVE-2026-0002"
        return httpx.Response(200, json=nvd_page([nvd_cve(identifier)], start=start, total=2))

    feed = fetch_nvd_window(
        mock_client(handler),
        start=datetime(2026, 11, 1, tzinfo=timezone.utc),
        end=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    assert starts == [0, 1]
    assert [record.cve_id for record in feed.records] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert feed.requests == 2


def test_nvd_pagination_restarts_when_a_later_total_changes():
    calls: list[int] = []

    def handler(request):
        offset = int(dict(request.url.params)["startIndex"])
        calls.append(offset)
        if len(calls) == 1:
            return httpx.Response(200, json=nvd_page([nvd_cve("CVE-2026-0001")], total=2))
        if len(calls) == 2:
            return httpx.Response(
                200,
                json=nvd_page([nvd_cve("CVE-2026-0002")], start=1, total=3, count=1),
            )
        identifier = "CVE-2026-0001" if offset == 0 else "CVE-2026-0002"
        return httpx.Response(200, json=nvd_page([nvd_cve(identifier)], start=offset, total=2))

    feed = fetch_nvd_window(
        mock_client(handler),
        start=datetime(2026, 11, 1, tzinfo=timezone.utc),
        end=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    assert calls == [0, 1, 0, 1]
    assert [record.cve_id for record in feed.records] == ["CVE-2026-0001", "CVE-2026-0002"]


def test_nvd_repeated_identifier_restarts_the_window():
    calls: list[int] = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(
                200,
                json=nvd_page(
                    [nvd_cve("CVE-2026-0001"), nvd_cve("CVE-2026-0001")], total=2
                ),
            )
        return httpx.Response(
            200,
            json=nvd_page(
                [nvd_cve("CVE-2026-0001"), nvd_cve("CVE-2026-0002")], total=2
            ),
        )

    feed = fetch_nvd_window(
        mock_client(handler),
        start=datetime(2026, 11, 1, tzinfo=timezone.utc),
        end=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    assert len(calls) == 2
    assert [record.cve_id for record in feed.records] == ["CVE-2026-0001", "CVE-2026-0002"]


def test_nvd_unstable_pagination_fails_after_three_attempts():
    calls: list[int] = []

    def handler(request):
        offset = int(dict(request.url.params)["startIndex"])
        calls.append(offset)
        total = 2 if offset == 0 else 3
        return httpx.Response(
            200,
            json=nvd_page(
                [nvd_cve("CVE-2026-0001" if offset == 0 else "CVE-2026-0002")],
                start=offset,
                total=total,
                count=1,
            ),
        )

    with pytest.raises(SourceError, match="unstable pagination"):
        fetch_nvd_window(
            mock_client(handler),
            start=datetime(2026, 11, 1, tzinfo=timezone.utc),
            end=datetime(2026, 11, 2, tzinfo=timezone.utc),
        )
    assert calls == [0, 1] * 3


def test_nvd_window_requests_a_split_when_the_total_is_large(monkeypatch):
    monkeypatch.setattr(feeds, "NVD_WINDOW_RECORD_LIMIT", 3)

    def handler(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()], total=5))

    start = datetime(2026, 11, 1, tzinfo=timezone.utc)
    feed = fetch_nvd_window(
        mock_client(handler),
        start=start,
        end=start + timedelta(days=2),
    )
    assert feed.split is True
    assert feed.requests == 1
    assert feed.records == ()

    one_day = fetch_nvd_window(
        mock_client(lambda request: httpx.Response(200, json=nvd_page([nvd_cve()]))),
        start=start,
        end=start + timedelta(days=1),
    )
    assert one_day.split is False
    assert [record.cve_id for record in one_day.records] == ["CVE-2026-0001"]


def test_nvd_timestamp_is_parsed_strictly_and_missing_is_none():
    start = datetime(2026, 11, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    with_stamp = fetch_nvd_window(
        mock_client(
            lambda request: httpx.Response(
                200,
                json={**nvd_page([]), "timestamp": "2026-11-03T21:43:23.122"},
            )
        ),
        start=start,
        end=end,
    )
    assert with_stamp.timestamp == datetime(2026, 11, 3, 21, 43, 23, 122000, tzinfo=timezone.utc)

    without_stamp = fetch_nvd_window(
        mock_client(lambda request: httpx.Response(200, json=nvd_page([]))),
        start=start,
        end=end,
    )
    assert without_stamp.timestamp is None

    for value in ("2026-11-03T21:43:23Z", "2026-11-03T21:43:23+00:00", "yesterday"):
        with pytest.raises(SourceError, match="invalid response timestamp"):
            parse_nvd_timestamp(value)


def test_nvd_single_cve_lookup_requires_the_requested_identifier():
    result = fetch_nvd_cve(
        mock_client(lambda request: httpx.Response(200, json=nvd_page([nvd_cve()]))),
        "CVE-2026-0001",
    )
    assert result.record.cve_id == "CVE-2026-0001"
    assert result.requests == 1

    with pytest.raises(SourceError):
        fetch_nvd_cve(
            mock_client(lambda request: httpx.Response(200, json=nvd_page([]))),
            "CVE-2026-0001",
        )
    with pytest.raises(SourceError):
        fetch_nvd_cve(
            mock_client(
                lambda request: httpx.Response(200, json=nvd_page([nvd_cve("CVE-2026-9999")]))
            ),
            "CVE-2026-0001",
        )


def test_nvd_windows_are_consecutive_and_at_most_120_days():
    start = datetime(1999, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=300)
    windows = nvd_windows(start, end)
    assert len(windows) == 3
    assert windows[0][0] == start
    assert windows[-1][1] == end
    assert all(following[0] == previous[1] for previous, following in zip(windows, windows[1:]))
    assert all(second - first <= timedelta(days=120) for first, second in windows)


def test_nvd_fetch_uses_one_request_per_window_and_millisecond_timestamps():
    starts: list[str] = []

    def handler(request):
        params = dict(request.url.params)
        starts.append(params["lastModStartDate"])
        return httpx.Response(200, json=nvd_page([]))

    start = datetime(2026, 1, 1, 7, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=300)
    requests = 0
    for window_start, window_end in nvd_windows(start, end):
        feed = fetch_nvd_window(
            mock_client(handler), start=window_start, end=window_end
        )
        requests += feed.requests
        assert feed.records == ()
    assert requests == 3
    assert starts[0] == "2026-01-01T07:00:00.000Z"
    assert starts[1] == "2026-05-01T07:00:00.000Z"


def test_nvd_api_key_header_is_optional():
    def handler(request):
        assert request.headers.get("apiKey") == "secret"
        return httpx.Response(200, json=nvd_page([]))

    fetch_nvd_window(
        mock_client(handler),
        start=datetime(2026, 11, 1, tzinfo=timezone.utc),
        end=datetime(2026, 11, 2, tzinfo=timezone.utc),
        api_key="secret",
    )

    def anonymous(request):
        assert "apiKey" not in request.headers
        return httpx.Response(200, json=nvd_page([]))

    fetch_nvd_window(
        mock_client(anonymous),
        start=datetime(2026, 11, 1, tzinfo=timezone.utc),
        end=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )


def test_iso_timestamp_keeps_milliseconds():
    value = datetime(2026, 11, 3, 7, 0, 0, 123456, tzinfo=timezone.utc)
    assert iso_timestamp(value) == "2026-11-03T07:00:00.123Z"


def test_euvd_aliases_map_to_cves_and_epss_is_ignored():
    def handler(request):
        assert dict(request.url.params) == {
            "fromUpdatedDate": "2026-11-01",
            "toUpdatedDate": "2026-11-03",
            "page": "0",
            "size": "100",
        }
        return httpx.Response(
            200,
            json={
                "total": 1,
                "items": [
                    {
                        "id": "EUVD-2026-1",
                        "aliases": "CVE-2026-0001\nGHSA-aaaa\nCVE-2026-0002",
                        "baseScore": 7.5,
                        "baseScoreVersion": "3.1",
                        "baseScoreVector": "CVSS:3.1/AV:N",
                        "exploitedSince": "Oct 30, 2026, 12:00:00 AM",
                        "epss": 55.0,
                    }
                ],
            },
        )

    feed = fetch_euvd(
        mock_client(handler),
        start=date(2026, 11, 1),
        end=date(2026, 11, 3),
    )
    assert feed.requests == 1
    update = feed.updates[0]
    assert update.cve_ids == ("CVE-2026-0001", "CVE-2026-0002")
    assert update.euvd_id == "EUVD-2026-1"
    assert update.exploited_since == "Oct 30, 2026, 12:00:00 AM"
    assert update.cvss == CVSSEntry("euvd", "euvd", "3.1", 7.5, "CVSS:3.1/AV:N")
    assert update.date_updated is None
    # The EUVD epss field uses a 0-100 scale and must not become a CVSS score.
    assert update.cvss is not None and update.cvss.score == 7.5


def test_euvd_ranges_are_chunked_into_at_most_thirty_days():
    chunks = euvd_chunks(date(2026, 9, 4), date(2026, 11, 3))
    assert chunks == (
        (date(2026, 9, 4), date(2026, 10, 3)),
        (date(2026, 10, 4), date(2026, 11, 2)),
        (date(2026, 11, 3), date(2026, 11, 3)),
    )
    assert euvd_chunks(date(2026, 11, 1), date(2026, 11, 30)) == (
        (date(2026, 11, 1), date(2026, 11, 30)),
    )
    assert euvd_chunks(date(2026, 11, 3), date(2026, 11, 1)) == ()


def test_euvd_pagination_restarts_when_the_total_changes():
    calls: list[int] = []

    def handler(request):
        page = int(dict(request.url.params)["page"])
        calls.append(page)
        if len(calls) <= 2:
            if page == 0:
                return httpx.Response(
                    200,
                    json={
                        "total": 101,
                        "items": [{"id": f"EUVD-{index}", "aliases": f"CVE-2026-{1000 + index}"} for index in range(100)],
                    },
                )
            return httpx.Response(200, json={"total": 100, "items": []})
        return httpx.Response(
            200,
            json={"total": 1, "items": [{"id": "EUVD-1", "aliases": "CVE-2026-0001"}]},
        )

    feed = fetch_euvd(mock_client(handler), start=date(2026, 11, 1), end=date(2026, 11, 2))
    assert calls == [0, 1, 0]
    assert [update.euvd_id for update in feed.updates] == ["EUVD-1"]
    assert feed.requests == 3


def test_euvd_invalid_scores_and_versions_fail_the_chunk():
    def with_item(item):
        return mock_client(
            lambda request: httpx.Response(200, json={"total": 1, "items": [item]})
        )

    for item in (
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": 10.1, "baseScoreVersion": "3.1"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": -1, "baseScoreVersion": "3.1"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": True, "baseScoreVersion": "3.1"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": 5.0, "baseScoreVersion": "9.9"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": 5.0},
    ):
        with pytest.raises(SourceError):
            fetch_euvd(
                with_item(item), start=date(2026, 11, 1), end=date(2026, 11, 2)
            )

    feed = fetch_euvd(
        with_item({"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": None}),
        start=date(2026, 11, 1),
        end=date(2026, 11, 2),
    )
    assert feed.updates[0].cvss is None


def test_euvd_date_updated_is_normalized_for_ordering():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "total": 1,
                "items": [
                    {
                        "id": "EUVD-1",
                        "aliases": "CVE-2026-0001",
                        "dateUpdated": "Oct 21, 2025, 11:25:23 PM",
                    }
                ],
            },
        )

    feed = fetch_euvd(mock_client(handler), start=date(2026, 11, 1), end=date(2026, 11, 2))
    assert feed.updates[0].date_updated == "2025-10-21T23:25:23"


def test_euvd_paging_validation_and_second_page():
    responses = [
        {"total": 101, "items": [{"id": f"EUVD-{index}", "aliases": f"CVE-2026-{1000 + index}"} for index in range(100)]},
        {"total": 101, "items": [{"id": "EUVD-last", "aliases": "CVE-2026-9999"}]},
    ]
    pages: list[int] = []

    def handler(request):
        pages.append(int(dict(request.url.params)["page"]))
        return httpx.Response(200, json=responses.pop(0))

    feed = fetch_euvd(
        mock_client(handler), start=date(2026, 11, 1), end=date(2026, 11, 2)
    )
    assert pages == [0, 1]
    assert feed.requests == 2
    assert feed.updates[-1].cve_ids == ("CVE-2026-9999",)

    def short_page(request):
        return httpx.Response(200, json={"total": 2, "items": [{"aliases": "CVE-2026-0001"}]})

    with pytest.raises(SourceError):
        fetch_euvd(
            mock_client(short_page), start=date(2026, 11, 1), end=date(2026, 11, 2)
        )

    def bad_total(request):
        return httpx.Response(200, json={"total": "many", "items": []})

    with pytest.raises(SourceError):
        fetch_euvd(
            mock_client(bad_total), start=date(2026, 11, 1), end=date(2026, 11, 2)
        )


def test_epss_floor_queries_above_floor_and_validates_pagination(monkeypatch):
    offsets: list[int] = []
    monkeypatch.setattr(feeds, "EPSS_PAGE_SIZE", 2)

    def handler(request):
        params = dict(request.url.params)
        assert params["epss-gt"] == "0.1"
        offset = int(params["offset"])
        offsets.append(offset)
        rows = [
            {"cve": f"CVE-2026-{1000 + offset}", "epss": "0.5", "percentile": "0.9", "date": "2026-11-03"},
            {"cve": f"CVE-2026-{1001 + offset}", "epss": "0.2", "percentile": "0.8", "date": "2026-11-03"},
        ][: max(3 - offset, 0)]
        return httpx.Response(200, json={"total": 3, "offset": offset, "data": rows})

    scores, requests = fetch_epss_floor(mock_client(handler), floor=0.1)
    assert offsets == [0, 2]
    assert requests == 2
    assert len(scores) == 3

    def wrong_offset(request):
        return httpx.Response(200, json={"total": 1, "offset": 5, "data": []})

    with pytest.raises(SourceError):
        fetch_epss_floor(mock_client(wrong_offset), floor=0.1)

    def bad_score(request):
        return httpx.Response(
            200,
            json={
                "total": 1,
                "offset": 0,
                "data": [
                    {"cve": "CVE-2026-0001", "epss": "55", "percentile": "0.9", "date": "2026-11-03"}
                ],
            },
        )

    with pytest.raises(SourceError):
        fetch_epss_floor(mock_client(bad_score), floor=0.1)


def test_kev_field_conversion_reads_the_catalog_shape():
    cisa = Evidence(
        "cisa_kev",
        "known_exploitation",
        "x",
        details={
            "dateAdded": "2026-01-01",
            "dueDate": "2026-01-20",
            "requiredAction": "Apply updates",
            "knownRansomwareCampaignUse": "Known",
        },
    )
    eu = Evidence("eu_kev", "known_exploitation", "x", details={"dateAdded": "2026-01-02"})
    assert cisa_fields({"CVE-2026-0001": cisa})["CVE-2026-0001"].due == "2026-01-20"
    assert cisa_fields({"CVE-2026-0001": cisa})["CVE-2026-0001"].ransomware == "Known"
    assert eu_fields({"CVE-2026-0001": eu})["CVE-2026-0001"].added == "2026-01-02"


def test_kev_and_epss_urls_are_the_existing_public_endpoints():
    assert CISA_URL.startswith("https://www.cisa.gov/")
    assert EU_URL.startswith("https://euvdservices.enisa.europa.eu/")
    assert EPSS_URL == "https://api.first.org/data/v1/epss"
    assert CVE_URL == "https://services.nvd.nist.gov/rest/json/cves/2.0"


def test_epss_floor_restarts_when_a_later_total_changes(monkeypatch):
    monkeypatch.setattr(feeds, "EPSS_PAGE_SIZE", 2)
    calls: list[int] = []

    def handler(request):
        offset = int(dict(request.url.params)["offset"])
        calls.append(offset)
        if len(calls) <= 2:
            total = 3 if offset == 0 else 2
            rows = (
                [
                    {"cve": f"CVE-2026-{1000 + index}", "epss": "0.5", "percentile": "0.9", "date": "2026-11-03"}
                    for index in range(2)
                ]
                if offset == 0
                else []
            )
            return httpx.Response(200, json={"total": total, "offset": offset, "data": rows})
        rows = [
            {"cve": f"CVE-2026-{1000 + index + offset}", "epss": "0.5", "percentile": "0.9", "date": "2026-11-03"}
            for index in range(min(2, 3 - offset))
        ]
        return httpx.Response(200, json={"total": 3, "offset": offset, "data": rows})

    scores, requests = fetch_epss_floor(mock_client(handler), floor=0.1)
    assert calls == [0, 2, 0, 2]
    assert requests == 4
    assert len(scores) == 3


def test_batch_epss_adapter_rejects_json_booleans():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "total": 1,
                "data": [
                    {"cve": "CVE-2026-0001", "epss": True, "percentile": False, "date": "2026-11-03"}
                ],
            },
        )

    with pytest.raises(SourceError, match="invalid probability"):
        EPSSSource(mock_client(handler)).scores(["CVE-2026-0001"])
    with pytest.raises(SourceError, match="invalid probability"):
        fetch_epss_scores(mock_client(handler), ["CVE-2026-0001"])
