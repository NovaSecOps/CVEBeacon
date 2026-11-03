from __future__ import annotations

import io
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from watch_support import epss_gzip, mock_client, nvd_cve, nvd_page

from cvebeacon.errors import SourceError
from cvebeacon.models import Evidence
from cvebeacon.sources.common import as_float
from cvebeacon.sources.epss import EPSSSource, EPSS_URL
from cvebeacon.sources.kev import CISA_URL, EU_URL
from cvebeacon.sources.nvd import CVE_URL
from cvebeacon.watch import feeds
from cvebeacon.watch.feeds import (
    cisa_fields,
    eu_fields,
    euvd_chunks,
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
EPSS_FILE_PREFIX = "https://epss.empiricalsecurity.com/"


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
    references = [{"url": f"https://example.test/{index}"} for index in range(40)]
    raw = nvd_cve(
        descriptions=[{"lang": "en", "value": "x" * 1200}],
        configurations=[{"nodes": [{"cpeMatch": cpes}]}],
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
        with pytest.raises(SourceError):
            fetch_nvd_window(
                mock_client(lambda request, payload=payload: httpx.Response(200, json=payload)),
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


def test_nvd_one_page_window_is_a_single_request():
    calls: list[int] = []

    def handler(request):
        calling_start = int(dict(request.url.params)["startIndex"])
        calls.append(calling_start)
        return httpx.Response(200, json=nvd_page([nvd_cve()], total=1))

    feed = fetch_nvd_window(
        mock_client(handler),
        start=datetime(2026, 11, 1, tzinfo=timezone.utc),
        end=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    assert calls == [0]
    assert feed.split is False
    assert feed.requests == 1
    assert [record.cve_id for record in feed.records] == ["CVE-2026-0001"]


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

    with pytest.raises(SourceError, match="unstable pagination") as caught:
        fetch_nvd_window(
            mock_client(handler),
            start=datetime(2026, 11, 1, tzinfo=timezone.utc),
            end=datetime(2026, 11, 2, tzinfo=timezone.utc),
        )
    assert calls == [0, 1] * 3
    assert caught.value.requests == 6


def test_nvd_windows_split_above_one_page_until_one_hour_then_page(monkeypatch):
    monkeypatch.setattr(feeds, "NVD_PAGE_SIZE", 2)
    start = datetime(2026, 11, 1, tzinfo=timezone.utc)

    def split_handler(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()], total=3))

    split = fetch_nvd_window(
        mock_client(split_handler), start=start, end=start + timedelta(hours=2)
    )
    assert split.split is True
    assert split.records == ()
    assert split.requests == 1

    starts: list[int] = []

    def page_handler(request):
        offset = int(dict(request.url.params)["startIndex"])
        starts.append(offset)
        if offset == 0:
            return httpx.Response(
                200,
                json=nvd_page(
                    [nvd_cve("CVE-2026-0001"), nvd_cve("CVE-2026-0002")],
                    total=3,
                ),
            )
        return httpx.Response(
            200,
            json=nvd_page([nvd_cve("CVE-2026-0003")], start=2, total=3),
        )

    one_hour = fetch_nvd_window(
        mock_client(page_handler), start=start, end=start + timedelta(hours=1)
    )
    assert one_hour.split is False
    assert starts == [0, 2]
    assert [record.cve_id for record in one_hour.records] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    ]


def test_nvd_timestamp_accepts_utc_suffixes_and_rejects_others():
    start = datetime(2026, 11, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    for stamp in (
        "2026-11-03T21:43:23.122",
        "2026-11-03T21:43:23.122Z",
        "2026-11-03T21:43:23.122+00:00",
    ):
        feed = fetch_nvd_window(
            mock_client(
                lambda request, stamp=stamp: httpx.Response(
                    200, json={**nvd_page([]), "timestamp": stamp}
                )
            ),
            start=start,
            end=end,
        )
        assert feed.timestamp == datetime(
            2026, 11, 3, 21, 43, 23, 122000, tzinfo=timezone.utc
        )

    without_stamp = fetch_nvd_window(
        mock_client(lambda request: httpx.Response(200, json=nvd_page([]))),
        start=start,
        end=end,
    )
    assert without_stamp.timestamp is None

    for value in ("2026-11-03T21:43:23+01:00", "2026-11-03T21:43:23z", "yesterday"):
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
        starts.append(dict(request.url.params)["lastModStartDate"])
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
            "toUpdatedDate": "2026-11-04",
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
    assert update.cvss is not None and update.cvss.score == 7.5


def test_same_day_euvd_queries_are_widened_by_one_day():
    seen: list[dict[str, str]] = []

    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"total": 0, "items": []})

    fetch_euvd(mock_client(handler), start=date(2026, 11, 3), end=date(2026, 11, 3))
    assert seen[0]["fromUpdatedDate"] == "2026-11-03"
    assert seen[0]["toUpdatedDate"] == "2026-11-04"


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


def test_recorded_euvd_sample_handles_missing_and_unknown_versions():
    payload = json.loads((FIXTURES / "euvd-no-score-page.json").read_text(encoding="utf-8"))
    feed = fetch_euvd(
        mock_client(lambda request: httpx.Response(200, json=payload)),
        start=date(2026, 10, 31),
        end=date(2026, 11, 3),
    )
    assert feed.requests == 1
    assert len(feed.updates) == 7
    assert feed.ignored == 1
    by_id = {update.euvd_id: update for update in feed.updates}
    assert by_id["EUVD-2026-105471"].cvss == CVSSEntry(
        "euvd",
        "euvd",
        "3.1",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    assert by_id["EUVD-2026-105474"].cvss is None
    assert by_id["EUVD-2026-105477"].cvss is not None
    assert by_id["EUVD-2026-105477"].cvss.score == 0.0


def test_euvd_invalid_scores_with_a_known_version_fail_the_chunk():
    def with_item(item):
        return mock_client(
            lambda request: httpx.Response(200, json={"total": 1, "items": [item]})
        )

    for item in (
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": 10.1, "baseScoreVersion": "3.1"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": -1, "baseScoreVersion": "3.1"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": True, "baseScoreVersion": "3.1"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": "not-a-number", "baseScoreVersion": "3.1"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": "NaN", "baseScoreVersion": "3.1"},
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": 10 ** 1000, "baseScoreVersion": "3.1"},
    ):
        with pytest.raises(SourceError):
            fetch_euvd(with_item(item), start=date(2026, 11, 1), end=date(2026, 11, 2))

    feed = fetch_euvd(
        with_item(
            {
                "id": "EUVD-1",
                "aliases": "CVE-2026-0001",
                "baseScore": None,
                "baseScoreVersion": "3.1",
            }
        ),
        start=date(2026, 11, 1),
        end=date(2026, 11, 2),
    )
    assert feed.updates[0].cvss is None
    assert feed.ignored == 0


def test_euvd_unknown_or_missing_versions_mean_no_score():
    def parse(item):
        return fetch_euvd(
            mock_client(
                lambda request: httpx.Response(200, json={"total": 1, "items": [item]})
            ),
            start=date(2026, 11, 1),
            end=date(2026, 11, 2),
        )

    unknown = parse(
        {"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": 5.0, "baseScoreVersion": "9.9"}
    )
    assert unknown.updates[0].cvss is None
    assert unknown.ignored == 1

    missing = parse({"id": "EUVD-1", "aliases": "CVE-2026-0001", "baseScore": 9.8})
    assert missing.updates[0].cvss is None
    assert missing.ignored == 0

    zero = parse(
        {
            "id": "EUVD-1",
            "aliases": "CVE-2026-0001",
            "baseScore": 0.0,
            "baseScoreVersion": None,
            "baseScoreVector": None,
        }
    )
    assert zero.updates[0].cvss is None
    assert zero.ignored == 0


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

    feed = fetch_euvd(mock_client(handler), start=date(2026, 11, 1), end=date(2026, 11, 2))
    assert pages == [0, 1]
    assert feed.requests == 2
    assert feed.updates[-1].cve_ids == ("CVE-2026-9999",)

    def short_page(request):
        return httpx.Response(200, json={"total": 2, "items": [{"aliases": "CVE-2026-0001"}]})

    with pytest.raises(SourceError):
        fetch_euvd(mock_client(short_page), start=date(2026, 11, 1), end=date(2026, 11, 2))

    def bad_total(request):
        return httpx.Response(200, json={"total": "many", "items": []})

    with pytest.raises(SourceError):
        fetch_euvd(mock_client(bad_total), start=date(2026, 11, 1), end=date(2026, 11, 2))


def _epss_handler(content: bytes, *, today: date = date(2026, 11, 3), not_found: bool = False):
    def handler(request):
        assert str(request.url).startswith(EPSS_FILE_PREFIX)
        if not_found:
            return httpx.Response(404)
        return httpx.Response(200, content=content)

    return handler


def test_epss_streaming_fixture_parses_every_validated_row():
    content = (FIXTURES / "epss-scores-2026-11-03.csv.gz").read_bytes()
    counter = [0]
    rows = list(
        feeds.fetch_epss_daily(
            mock_client(_epss_handler(content)), today=date(2026, 11, 3), counter=counter
        )
    )
    assert counter[0] == 1
    assert rows == [
        ("CVE-2026-0001", 0.85, 0.97, date(2026, 11, 3)),
        ("CVE-2026-0002", 0.05, 0.30, date(2026, 11, 3)),
        ("CVE-2026-0003", 0.42, 0.88, date(2026, 11, 3)),
    ]


def test_epss_falls_back_to_yesterday_on_404_and_counts_requests():
    content = epss_gzip([("CVE-2026-0001", "0.5", "0.9")], score_date="2026-11-02")
    requested: list[str] = []

    def handler(request):
        requested.append(str(request.url))
        if "2026-11-03" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(200, content=content)

    counter = [0]
    rows = list(
        feeds.fetch_epss_daily(
            mock_client(handler), today=date(2026, 11, 3), counter=counter
        )
    )
    assert counter[0] == 2
    assert len(requested) == 2
    assert rows == [("CVE-2026-0001", 0.5, 0.9, date(2026, 11, 2))]


def test_epss_missing_both_days_is_a_source_failure():
    counter = [0]
    with pytest.raises(SourceError, match="not published yet"):
        list(
            feeds.fetch_epss_daily(
                mock_client(_epss_handler(b"", not_found=True)),
                today=date(2026, 11, 3),
                counter=counter,
            )
        )
    assert counter[0] == 2


@pytest.mark.parametrize(
    "content",
    [
        b"not gzip",
        b"#model_version:v1\ncve,epss,percentile\n",
        b"#model_version:v1,score_date:2026-11-03\ncve,epss\n",
        b"#model_version:v1,score_date:2026-11-03\ncve,epss,percentile\nCVE-2026-0001,1.5,0.5\n",
        b"#model_version:v1,score_date:2026-11-03\ncve,epss,percentile\nCVE-2026-0001,0.5,0.5,extra\n",
        b"#model_version:v1,score_date:not-a-date\ncve,epss,percentile\n",
    ],
)
def test_epss_invalid_files_are_source_errors(content):
    import gzip

    with pytest.raises(SourceError):
        list(
            feeds.fetch_epss_daily(
                mock_client(_epss_handler(gzip.compress(content))),
                today=date(2026, 11, 3),
                counter=[0],
            )
        )


def test_epss_stream_enforces_the_compressed_byte_cap(monkeypatch):
    monkeypatch.setattr(feeds, "EPSS_BYTE_CAP", 10)
    content = epss_gzip([("CVE-2026-0001", "0.5", "0.9")])
    with pytest.raises(SourceError, match="size limit"):
        list(
            feeds.fetch_epss_daily(
                mock_client(_epss_handler(content)),
                today=date(2026, 11, 3),
                counter=[0],
            )
        )


def test_epss_too_many_rows_is_a_source_error(monkeypatch):
    monkeypatch.setattr(feeds, "EPSS_MAX_ROWS", 1)
    content = epss_gzip(
        [("CVE-2026-0001", "0.5", "0.9"), ("CVE-2026-0002", "0.6", "0.9")]
    )
    with pytest.raises(SourceError, match="too many"):
        list(
            feeds.fetch_epss_daily(
                mock_client(_epss_handler(content)),
                today=date(2026, 11, 3),
                counter=[0],
            )
        )


def test_epss_stream_does_not_follow_redirects():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://example.test/other"})

    with pytest.raises(SourceError, match="HTTP 302"):
        list(
            feeds.fetch_epss_daily(
                mock_client(handler), today=date(2026, 11, 3), counter=[0]
            )
        )


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


def test_source_urls_are_the_existing_public_endpoints():
    assert CISA_URL.startswith("https://www.cisa.gov/")
    assert EU_URL.startswith("https://euvdservices.enisa.europa.eu/")
    assert EPSS_URL == "https://api.first.org/data/v1/epss"
    assert CVE_URL == "https://services.nvd.nist.gov/rest/json/cves/2.0"


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


def test_as_float_treats_overflow_as_invalid():
    assert as_float(10 ** 1000) is None
    assert as_float("1e10000") is None
    assert as_float("0.5") == 0.5
