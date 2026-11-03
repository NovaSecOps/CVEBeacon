from __future__ import annotations

from datetime import date, datetime, timedelta

import httpx
import pytest
from watch_support import NOW, mock_client, nvd_cve, nvd_page, write_config

from cvebeacon import cli
from cvebeacon.errors import SourceError
from cvebeacon.sources.epss import EPSS_URL
from cvebeacon.sources.euvd import SEARCH_URL
from cvebeacon.sources.kev import CISA_URL, EU_URL
from cvebeacon.sources.nvd import CVE_URL
from cvebeacon.watch import feeds
from cvebeacon.watch.feeds import iso_timestamp, nvd_windows
from cvebeacon.watch.records import KEVFields, WatchRecord
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.sync import FULL_HISTORY_START, sync_watch


def handler_for(*, nvd=None, euvd=None, cisa=None, eu=None, epss=None):
    def handler(request):
        url = str(request.url)
        for prefix, callback in (
            (CVE_URL, nvd),
            (SEARCH_URL, euvd),
            (CISA_URL, cisa),
            (EU_URL, eu),
            (EPSS_URL, epss),
        ):
            if url.startswith(prefix):
                if callback is None:
                    raise AssertionError(f"unexpected request to {prefix}")
                return callback(request)
        raise AssertionError(f"unexpected URL {url}")

    return handler


def run(config, handler, *, now=NOW, **kwargs):
    with mock_client(handler) as http:
        return sync_watch(config, http, clock=lambda: now, **kwargs)


def metadata(config) -> dict[str, str]:
    return WatchStore(config.watch.database).metadata()


def epss_row(identifier: str) -> dict[str, str]:
    return {
        "cve": identifier,
        "epss": "0.5",
        "percentile": "0.9",
        "date": "2026-11-03",
    }


def test_baseline_stores_cursors_and_no_history(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="baseline")

    def no_request(request):
        raise AssertionError("baseline must not query public sources")

    report = run(config, handler_for(nvd=no_request, euvd=no_request))
    assert report.baseline is True
    assert not report.failures
    assert [summary.source for summary in report.summaries] == ["nvd", "euvd"]
    assert all(summary.requests == 0 for summary in report.summaries)
    stored = metadata(config)
    assert stored["nvd_cursor"] == NOW.isoformat()
    assert stored["euvd_cursor"] == "2026-11-03"
    assert stored["initialized_at"] == NOW.isoformat()
    assert "epss_floor_date" not in stored
    assert WatchStore(config.watch.database).status(epss_floor=0.1)["rows"] == 0


def test_backfill_mode_reads_the_configured_number_of_days(tmp_path):
    config = write_config(
        tmp_path, sources=("nvd", "euvd"), initial="backfill"
    )
    nvd_dates: list[str] = []
    euvd_dates: list[dict[str, str]] = []

    def nvd_request(request):
        nvd_dates.append(dict(request.url.params)["lastModStartDate"])
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def euvd_request(request):
        euvd_dates.append(dict(request.url.params))
        return httpx.Response(200, json={"total": 0, "items": []})

    report = run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert nvd_dates == [iso_timestamp(NOW - timedelta(days=7))]
    assert euvd_dates[0]["fromUpdatedDate"] == "2026-10-27"
    assert euvd_dates[0]["toUpdatedDate"] == "2026-11-03"
    assert report.summaries[0].new == 1
    assert WatchStore(config.watch.database).status(epss_floor=0.1)["rows"] == 1
    assert metadata(config)["nvd_cursor"] == NOW.isoformat()


def test_full_mode_requires_confirmation_before_any_request(tmp_path, capsys):
    config = write_config(tmp_path, initial="full")

    def no_request(request):
        raise AssertionError("cancelled full history must not query sources")

    report = run(
        config,
        handler_for(nvd=no_request),
        assume_yes=False,
        confirm=lambda message: False,
    )
    assert report.cancelled is True
    assert report.summaries == ()
    output = capsys.readouterr().out
    assert "several hours" in output
    assert "NVD window(s)" in output
    assert "4,200 EUVD requests" in output
    assert metadata(config).get("nvd_cursor") is None


def test_full_mode_with_confirmation_walks_consecutive_windows(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="full")
    nvd_starts: list[str] = []
    euvd_dates: list[dict[str, str]] = []

    def nvd_request(request):
        nvd_starts.append(dict(request.url.params)["lastModStartDate"])
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        euvd_dates.append(dict(request.url.params))
        return httpx.Response(200, json={"total": 0, "items": []})

    def unexpected_confirm(message):
        raise AssertionError("--yes must skip the confirmation")

    report = run(
        config,
        handler_for(nvd=nvd_request, euvd=euvd_request),
        assume_yes=True,
        confirm=unexpected_confirm,
    )
    assert not report.cancelled
    assert nvd_starts[0] == "1999-01-01T00:00:00.000Z"
    assert len(nvd_starts) == len(nvd_windows(FULL_HISTORY_START, NOW))
    assert euvd_dates[0]["fromUpdatedDate"] == "1999-01-01"
    assert metadata(config)["nvd_cursor"] == NOW.isoformat()


def test_later_runs_reapply_the_overlap_minutes(tmp_path):
    config = write_config(tmp_path)
    store = WatchStore(config.watch.database)
    store.upsert(
        [],
        meta={
            "nvd_cursor": (NOW - timedelta(hours=1)).isoformat(),
            "initialized_at": NOW.isoformat(),
        },
    )
    starts: list[str] = []

    def nvd_request(request):
        starts.append(dict(request.url.params)["lastModStartDate"])
        return httpx.Response(200, json=nvd_page([]))

    run(config, handler_for(nvd=nvd_request))
    assert starts == [iso_timestamp(NOW - timedelta(hours=1, minutes=15))]


def test_euvd_cursor_is_read_in_days(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"))
    store = WatchStore(config.watch.database)
    store.upsert(
        [],
        meta={
            "nvd_cursor": NOW.isoformat(),
            "euvd_cursor": "2026-11-01",
            "initialized_at": NOW.isoformat(),
        },
    )
    euvd_dates: list[dict[str, str]] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        euvd_dates.append(dict(request.url.params))
        return httpx.Response(200, json={"total": 0, "items": []})

    run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert euvd_dates[0]["fromUpdatedDate"] == "2026-11-01"
    assert euvd_dates[0]["toUpdatedDate"] == "2026-11-03"
    assert metadata(config)["euvd_cursor"] == "2026-11-03"


def test_nvd_failure_does_not_advance_cursors_or_commit_records(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"))
    store = WatchStore(config.watch.database)
    cursor = (NOW - timedelta(hours=1)).isoformat()
    store.upsert([], meta={"nvd_cursor": cursor, "initialized_at": NOW.isoformat()})
    requested: list[str] = []

    def failing_nvd(request):
        requested.append(str(request.url))
        return httpx.Response(500)

    with pytest.raises(SourceError):
        run(config, handler_for(nvd=failing_nvd))
    assert len(requested) == 1
    stored = metadata(config)
    assert stored["nvd_cursor"] == cursor
    assert "euvd_cursor" not in stored
    assert WatchStore(config.watch.database).status(epss_floor=0.1)["rows"] == 0


def test_nvd_api_key_environment_is_used(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "secret")
    config = write_config(tmp_path, initial="backfill")
    seen: list[str | None] = []

    def nvd_request(request):
        seen.append(request.headers.get("apiKey"))
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    run(config, handler_for(nvd=nvd_request))
    assert seen == ["secret"]


def test_cisa_kev_is_downloaded_once_and_overwrites_kev_columns(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="backfill")
    kev_requests: list[str] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def cisa_request(request):
        kev_requests.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "count": 1,
                "dateReleased": "2026-11-03",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-0001",
                        "dateAdded": "2026-11-03",
                        "dueDate": "2026-11-20",
                        "requiredAction": "Apply updates",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ],
            },
        )

    report = run(config, handler_for(nvd=nvd_request, cisa=cisa_request))
    assert len(kev_requests) == 1
    status = WatchStore(config.watch.database).status(epss_floor=0.1)
    assert status["rows"] == 1
    assert status["cisa_kev"] == 1
    summary = next(item for item in report.summaries if item.source == "cisa_kev")
    assert summary.requests == 1
    assert summary.changed == 1


def test_epss_scores_cover_new_records_and_the_daily_floor_runs_once(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    batch_ids: list[str] = []
    floor_offsets: list[int] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def epss_request(request):
        params = dict(request.url.params)
        if "epss-gt" in params:
            floor_offsets.append(int(params["offset"]))
            return httpx.Response(
                200,
                json={"total": 1, "offset": 0, "data": [epss_row("CVE-2026-0001")]},
            )
        identifiers = params["cve"].split(",")
        batch_ids.append(params["cve"])
        return httpx.Response(
            200,
            json={
                "status": "OK",
                "total": len(identifiers),
                "data": [epss_row(identifier) for identifier in identifiers],
            },
        )

    handler = handler_for(nvd=nvd_request, epss=epss_request)
    first = run(config, handler)
    assert batch_ids == ["CVE-2026-0001"]
    assert floor_offsets == [0]
    assert first.summaries[-1].requests == 2

    second = run(config, handler, now=NOW + timedelta(hours=1))
    assert batch_ids == ["CVE-2026-0001"]
    assert floor_offsets == [0]
    assert second.summaries[-1].requests == 0

    third = run(config, handler, now=NOW + timedelta(days=1))
    assert batch_ids == ["CVE-2026-0001"]
    assert floor_offsets == [0, 0]
    assert metadata(config)["epss_floor_date"] == "2026-11-04"


def test_sync_reports_new_then_unchanged(tmp_path):
    config = write_config(tmp_path, initial="backfill")

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    handler = handler_for(nvd=nvd_request)
    first = run(config, handler)
    second = run(config, handler, now=NOW + timedelta(minutes=30))
    assert (first.summaries[0].new, first.summaries[0].changed) == (1, 0)
    assert (second.summaries[0].new, second.summaries[0].changed) == (0, 0)


def test_euvd_aliases_update_only_rows_that_exist(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="backfill")

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def euvd_request(request):
        return httpx.Response(
            200,
            json={
                "total": 1,
                "items": [
                    {
                        "id": "EUVD-2026-1",
                        "aliases": "CVE-2026-0001\nCVE-2026-0002",
                        "baseScore": 7.5,
                        "baseScoreVersion": "3.1",
                        "baseScoreVector": "CVSS:3.1/AV:N",
                        "exploitedSince": "Oct 30, 2026, 12:00:00 AM",
                        "epss": 55.0,
                    }
                ],
            },
        )

    run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    store = WatchStore(config.watch.database)
    assert store.status(epss_floor=0.1)["rows"] == 1
    with store._connect() as db:
        identifiers = {row[0] for row in db.execute("SELECT cve_id FROM watch_cve")}
        row = db.execute("SELECT * FROM watch_cve WHERE cve_id='CVE-2026-0001'").fetchone()
    assert identifiers == {"CVE-2026-0001"}
    assert row["euvd_id"] == "EUVD-2026-1"
    assert row["epss"] is None
    assert '"provider":"euvd"' in row["cvss_json"]


@pytest.mark.parametrize("source", ["euvd", "cisa_kev", "eu_kev", "epss"])
def test_optional_source_failure_exits_four_and_keeps_nvd_data(
    tmp_path, monkeypatch, capsys, source
):
    config = write_config(tmp_path, sources=("nvd", source), initial="backfill")

    def handler(request):
        if str(request.url).startswith(CVE_URL):
            return httpx.Response(200, json=nvd_page([nvd_cve()]))
        return httpx.Response(500)

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 4
    output = capsys.readouterr().out
    assert source in output
    assert "failed" in output
    stored_status = WatchStore(config.watch.database).status(epss_floor=0.1)
    assert stored_status["rows"] == 1
    stored_meta = metadata(config)
    assert stored_meta["nvd_cursor"]
    assert "initialized_at" in stored_meta
    if source == "euvd":
        # The intended first EUVD day is persisted with the NVD commit so a
        # failed optional source resumes from the right date.
        assert stored_meta["euvd_cursor"] == "2026-10-27"


def test_nvd_failure_exits_two_and_commits_nothing(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, initial="backfill")

    def handler(request):
        return httpx.Response(500)

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 2
    assert "nvd" in capsys.readouterr().err
    stored = metadata(config)
    assert "nvd_cursor" not in stored
    assert "initialized_at" not in stored
    assert WatchStore(config.watch.database).status(epss_floor=0.1)["rows"] == 0


def test_watch_commands_never_load_the_inventory(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, initial="backfill")

    def forbidden(*args, **kwargs):
        raise AssertionError("watch commands must not load the inventory")

    monkeypatch.setattr(cli, "load_inventory", forbidden)

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    monkeypatch.setattr(
        cli, "HttpClient", lambda http_config: mock_client(handler_for(nvd=nvd_request))
    )
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 0
    assert cli.main(["--config", str(config.config_path), "watch", "status"]) == 0
    assert "rows: 1" in capsys.readouterr().out
    assert not (config.config_path.parent / "state.db").exists()


def test_full_confirmation_guard_through_the_cli(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, initial="full")

    def forbidden(request):
        raise AssertionError("cancelled full history must not query sources")

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(forbidden))
    monkeypatch.setattr("builtins.input", lambda message: "n")
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 1
    output = capsys.readouterr().out
    assert "cancelled" in output
    assert "several hours" in output


def test_watch_status_reports_cursors_rows_and_signals(tmp_path, capsys):
    config = write_config(tmp_path)
    store = WatchStore(config.watch.database)
    store.upsert(
        [
            WatchRecord(
                cve_id="CVE-2026-0001",
                status="published",
                cisa_kev_added="2026-11-03",
                ssvc_exploitation="active",
            )
        ],
        meta={
            "nvd_cursor": NOW.isoformat(),
            "euvd_cursor": "2026-11-03",
            "epss_floor_date": "2026-11-03",
            "initialized_at": NOW.isoformat(),
        },
    )
    store.apply_epss({"CVE-2026-0001": (0.5, 0.9, date(2026, 11, 3))})
    assert cli.main(["--config", str(config.config_path), "watch", "status"]) == 0
    output = capsys.readouterr().out
    assert f"database: {config.watch.database}" in output
    assert "schema version: 1" in output
    assert f"nvd cursor: {NOW.isoformat()}" in output
    assert "euvd cursor: 2026-11-03" in output
    assert "rows: 1" in output
    assert "with KEV: 1" in output
    assert "with active SSVC: 1" in output
    assert "with EPSS above 0.1: 1" in output


@pytest.mark.parametrize("command", [["watch", "status"], ["watch", "sync"]])
def test_watch_commands_refuse_a_disabled_configuration(tmp_path, capsys, command):
    config = write_config(tmp_path, enabled=False)
    assert cli.main(["--config", str(config.config_path), *command]) == 2
    assert "watch mode is disabled" in capsys.readouterr().err


def test_full_sync_twice_reports_no_changes(tmp_path):
    config = write_config(
        tmp_path,
        sources=("nvd", "euvd", "cisa_kev", "eu_kev", "epss"),
        initial="backfill",
    )

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def euvd_request(request):
        return httpx.Response(
            200,
            json={
                "total": 1,
                "items": [
                    {
                        "id": "EUVD-2026-1",
                        "aliases": "CVE-2026-0001",
                        "baseScore": 7.5,
                        "baseScoreVersion": "3.1",
                        "baseScoreVector": "CVSS:3.1/X",
                        "exploitedSince": "2026-11-01",
                    }
                ],
            },
        )

    def cisa_request(request):
        return httpx.Response(
            200,
            json={
                "count": 1,
                "dateReleased": "2026-11-03",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-0001",
                        "dateAdded": "2026-11-03",
                        "dueDate": "2026-11-20",
                        "requiredAction": "Apply updates",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ],
            },
        )

    def eu_request(request):
        return httpx.Response(
            200,
            json=[
                {
                    "cveId": "CVE-2026-0001",
                    "dateAdded": "2026-11-04",
                    "sources": ["eukev_kev"],
                }
            ],
        )

    def epss_request(request):
        params = dict(request.url.params)
        if "epss-gt" in params:
            return httpx.Response(
                200,
                json={"total": 1, "offset": 0, "data": [epss_row("CVE-2026-0001")]},
            )
        identifiers = params["cve"].split(",")
        return httpx.Response(
            200,
            json={
                "status": "OK",
                "total": len(identifiers),
                "data": [epss_row(identifier) for identifier in identifiers],
            },
        )

    handler = handler_for(
        nvd=nvd_request,
        euvd=euvd_request,
        cisa=cisa_request,
        eu=eu_request,
        epss=epss_request,
    )
    run(config, handler)
    second = run(config, handler, now=NOW + timedelta(minutes=3))
    assert all(summary.changed == 0 for summary in second.summaries)
    assert all(summary.new == 0 for summary in second.summaries)


def test_first_euvd_failure_resumes_from_the_intended_start(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="backfill")
    dates: list[str] = []
    failed = [False]

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        dates.append(dict(request.url.params)["fromUpdatedDate"])
        if not failed[0]:
            failed[0] = True
            return httpx.Response(500)
        return httpx.Response(200, json={"total": 0, "items": []})

    first = run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert first.failures == ("euvd",)
    assert metadata(config)["euvd_cursor"] == "2026-10-27"

    second = run(
        config,
        handler_for(nvd=nvd_request, euvd=euvd_request),
        now=NOW + timedelta(days=1),
    )
    assert not second.failures
    assert dates == ["2026-10-27", "2026-10-27"]


def test_full_history_resumes_from_the_cursor_without_confirming_again(tmp_path):
    config = write_config(tmp_path, initial="full")
    starts: list[str] = []

    def failing_nvd(request):
        starts.append(dict(request.url.params)["lastModStartDate"])
        if len(starts) == 2:
            return httpx.Response(500)
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    with pytest.raises(SourceError):
        run(config, handler_for(nvd=failing_nvd), assume_yes=True)

    first_window_end = nvd_windows(FULL_HISTORY_START, NOW)[0][1]
    stored = metadata(config)
    assert stored["nvd_cursor"] == first_window_end.isoformat()
    assert stored["initial_mode"] == "full"
    assert "initialized_at" not in stored
    assert "initial_complete" not in stored

    resumed: list[str] = []

    def resumed_nvd(request):
        resumed.append(dict(request.url.params)["lastModStartDate"])
        return httpx.Response(200, json=nvd_page([]))

    def unexpected_confirm(message):
        raise AssertionError("a resumed initial run must not ask for confirmation")

    report = run(
        config,
        handler_for(nvd=resumed_nvd),
        assume_yes=False,
        confirm=unexpected_confirm,
    )
    assert report.cancelled is False
    assert resumed[0] == iso_timestamp(first_window_end)
    completed = metadata(config)
    assert completed["initial_complete"] == "true"
    assert "initialized_at" in completed


def test_local_clock_ahead_is_capped_by_the_nvd_timestamp(tmp_path):
    config = write_config(tmp_path, initial="backfill")

    def nvd_request(request):
        return httpx.Response(
            200,
            json={**nvd_page([]), "timestamp": "2026-11-03T10:00:00.000"},
        )

    run(config, handler_for(nvd=nvd_request))
    assert metadata(config)["nvd_cursor"] == "2026-11-03T10:00:00+00:00"


def test_a_long_gap_prints_a_warning_and_still_syncs(tmp_path, capsys):
    config = write_config(tmp_path)
    store = WatchStore(config.watch.database)
    store.upsert(
        [],
        meta={
            "nvd_cursor": (NOW - timedelta(days=200)).isoformat(),
            "initialized_at": NOW.isoformat(),
        },
    )

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    report = run(config, handler_for(nvd=nvd_request))
    assert not report.failures
    assert "more than 120 days old" in capsys.readouterr().out


def test_nvd_sync_splits_a_large_window_in_half(monkeypatch, tmp_path):
    monkeypatch.setattr(feeds, "NVD_WINDOW_RECORD_LIMIT", 4)
    monkeypatch.setattr(feeds, "NVD_PAGE_SIZE", 10)
    config = write_config(tmp_path, initial="backfill")
    windows: list[tuple[datetime, datetime]] = []

    def nvd_request(request):
        params = dict(request.url.params)
        start = datetime.fromisoformat(params["lastModStartDate"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(params["lastModEndDate"].replace("Z", "+00:00"))
        windows.append((start, end))
        if end - start > timedelta(days=1):
            return httpx.Response(
                200,
                json=nvd_page(
                    [nvd_cve(f"CVE-2026-{index}") for index in range(5)], total=5
                ),
            )
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    report = run(config, handler_for(nvd=nvd_request))
    assert not report.failures
    assert any(end - start < timedelta(days=1) for start, end in windows)
    assert metadata(config)["nvd_cursor"] == NOW.isoformat()


def test_euvd_long_ranges_commit_the_cursor_after_each_chunk(tmp_path):
    config = write_config(
        tmp_path, sources=("nvd", "euvd"), initial="backfill", backfill_days=60
    )
    dates: list[str] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        dates.append(dict(request.url.params)["fromUpdatedDate"])
        return httpx.Response(200, json={"total": 0, "items": []})

    report = run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert not report.failures
    assert dates == ["2026-09-04", "2026-10-04", "2026-11-03"]
    assert metadata(config)["euvd_cursor"] == "2026-11-03"


def test_euvd_resumes_from_the_last_committed_chunk(tmp_path):
    config = write_config(
        tmp_path, sources=("nvd", "euvd"), initial="backfill", backfill_days=60
    )
    dates: list[str] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def failing_euvd(request):
        dates.append(dict(request.url.params)["fromUpdatedDate"])
        if len(dates) == 2:
            return httpx.Response(500)
        return httpx.Response(200, json={"total": 0, "items": []})

    first = run(config, handler_for(nvd=nvd_request, euvd=failing_euvd))
    assert first.failures == ("euvd",)
    assert metadata(config)["euvd_cursor"] == "2026-10-03"

    def resumed_euvd(request):
        dates.append(dict(request.url.params)["fromUpdatedDate"])
        return httpx.Response(200, json={"total": 0, "items": []})

    second = run(
        config,
        handler_for(nvd=nvd_request, euvd=resumed_euvd),
        now=NOW + timedelta(hours=1),
    )
    assert not second.failures
    assert dates[2] == "2026-10-03"
    assert metadata(config)["euvd_cursor"] == "2026-11-03"


def test_invalid_euvd_metric_fails_the_step_without_advancing_the_cursor(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="backfill")

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def euvd_request(request):
        return httpx.Response(
            200,
            json={
                "total": 1,
                "items": [
                    {
                        "id": "EUVD-2026-1",
                        "aliases": "CVE-2026-0001",
                        "baseScore": 42,
                        "baseScoreVersion": "3.1",
                    }
                ],
            },
        )

    report = run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert report.failures == ("euvd",)
    assert metadata(config)["euvd_cursor"] == "2026-10-27"
    with WatchStore(config.watch.database)._connect() as db:
        stored = db.execute("SELECT euvd_id FROM watch_cve").fetchone()
    assert stored["euvd_id"] is None


def test_nvd_only_sync_accepts_kev_corrections(tmp_path):
    config = write_config(tmp_path, sources=("nvd",), initial="backfill")
    payload = [
        nvd_cve(
            cisaExploitAdd="2026-11-01",
            cisaActionDue="2026-11-20",
            cisaRequiredAction="Old action",
        )
    ]

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page(payload))

    run(config, handler_for(nvd=nvd_request))
    payload[0] = nvd_cve(
        cisaExploitAdd="2026-11-01",
        cisaActionDue="2026-11-30",
        cisaRequiredAction="Corrected action",
        lastModified="2026-11-03T12:30:00.000",
    )
    second = run(config, handler_for(nvd=nvd_request), now=NOW + timedelta(hours=1))
    summary = next(item for item in second.summaries if item.source == "nvd")
    assert summary.changed == 1
    with WatchStore(config.watch.database)._connect() as db:
        row = db.execute("SELECT cisa_kev_due, cisa_required_action FROM watch_cve").fetchone()
    assert tuple(row) == ("2026-11-30", "Corrected action")


def test_kev_withdrawal_clears_catalog_columns(tmp_path):
    config = write_config(
        tmp_path, sources=("nvd", "cisa_kev", "eu_kev"), initial="backfill"
    )
    cisa_items = [
        {
            "cveID": "CVE-2026-0001",
            "dateAdded": "2026-11-03",
            "dueDate": "2026-11-20",
            "requiredAction": "Apply updates",
            "knownRansomwareCampaignUse": "Known",
        }
    ]
    eu_items = [{"cveId": "CVE-2026-0001", "dateAdded": "2026-11-04"}]

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def cisa_request(request):
        return httpx.Response(
            200, json={"count": len(cisa_items), "vulnerabilities": cisa_items}
        )

    def eu_request(request):
        return httpx.Response(200, json=eu_items)

    handler = handler_for(nvd=nvd_request, cisa=cisa_request, eu=eu_request)
    run(config, handler)

    def empty_nvd(request):
        return httpx.Response(200, json=nvd_page([]))

    def empty_cisa(request):
        return httpx.Response(200, json={"count": 0, "vulnerabilities": []})

    def empty_eu(request):
        return httpx.Response(200, json=[])

    store = WatchStore(config.watch.database)
    with store._connect() as db:
        before = db.execute("SELECT fingerprint FROM watch_cve").fetchone()["fingerprint"]
    second = run(
        config,
        handler_for(nvd=empty_nvd, cisa=empty_cisa, eu=empty_eu),
        now=NOW + timedelta(hours=1),
    )
    assert not second.failures
    with store._connect() as db:
        row = db.execute(
            "SELECT cisa_kev_added, cisa_kev_due, eu_kev_added, fingerprint FROM watch_cve"
        ).fetchone()
    assert tuple(row)[:3] == (None, None, None)
    assert row["fingerprint"] != before


def test_non_alert_euvd_pending_is_applied_when_nvd_inserts_the_cve(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="baseline")

    def no_request(request):
        raise AssertionError("baseline must not query public sources")

    run(config, handler_for(nvd=no_request, euvd=no_request))
    looked_up: list[str] = []

    def nvd_without_the_cve(request):
        params = dict(request.url.params)
        if params.get("cveId"):
            looked_up.append(params["cveId"])
            raise AssertionError("a non-exploited EUVD update is not fetched early")
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        return httpx.Response(
            200,
            json={
                "total": 1,
                "items": [
                    {
                        "id": "EUVD-2026-9",
                        "aliases": "CVE-2026-9999",
                        "baseScore": 7.5,
                        "baseScoreVersion": "3.1",
                    }
                ],
            },
        )

    run(
        config,
        handler_for(nvd=nvd_without_the_cve, euvd=euvd_request),
        now=NOW + timedelta(days=1),
    )
    assert looked_up == []

    def nvd_with_the_cve(request):
        return httpx.Response(
            200, json=nvd_page([nvd_cve("CVE-2026-9999")])
        )

    def empty_euvd(request):
        return httpx.Response(200, json={"total": 0, "items": []})

    run(
        config,
        handler_for(nvd=nvd_with_the_cve, euvd=empty_euvd),
        now=NOW + timedelta(days=2),
    )
    with WatchStore(config.watch.database)._connect() as db:
        row = db.execute(
            "SELECT euvd_id, cvss_json FROM watch_cve WHERE cve_id='CVE-2026-9999'"
        ).fetchone()
    assert row["euvd_id"] == "EUVD-2026-9"
    assert '"score":7.5' in row["cvss_json"]
    assert WatchStore(config.watch.database).pending() == ()


def test_exploited_euvd_for_an_unknown_cve_is_fetched_from_nvd(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="baseline")

    def no_request(request):
        raise AssertionError("baseline must not query public sources")

    run(config, handler_for(nvd=no_request, euvd=no_request))
    looked_up: list[str] = []

    def nvd_request(request):
        params = dict(request.url.params)
        if params.get("cveId"):
            looked_up.append(params["cveId"])
            return httpx.Response(200, json=nvd_page([nvd_cve(params["cveId"])]))
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        return httpx.Response(
            200,
            json={
                "total": 1,
                "items": [
                    {
                        "id": "EUVD-2026-9",
                        "aliases": "CVE-2026-9999",
                        "baseScore": 8.8,
                        "baseScoreVersion": "3.1",
                        "exploitedSince": "Nov 3, 2026, 12:00:00 AM",
                    }
                ],
            },
        )

    report = run(
        config,
        handler_for(nvd=nvd_request, euvd=euvd_request),
        now=NOW + timedelta(days=1),
    )
    assert not report.failures
    assert looked_up == ["CVE-2026-9999"]
    store = WatchStore(config.watch.database)
    with store._connect() as db:
        row = db.execute(
            "SELECT euvd_id, euvd_exploited_since FROM watch_cve WHERE cve_id=?",
            ("CVE-2026-9999",),
        ).fetchone()
    assert tuple(row) == ("EUVD-2026-9", "Nov 3, 2026, 12:00:00 AM")
    assert store.pending() == ()


def test_kev_additions_before_the_baseline_are_not_pending(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="baseline")

    def no_request(request):
        raise AssertionError("baseline must not query public sources")

    run(config, handler_for(nvd=no_request, cisa=no_request))
    assert metadata(config)["initial_window_start"] == "2026-11-03"
    looked_up: list[str] = []

    def nvd_request(request):
        params = dict(request.url.params)
        if params.get("cveId"):
            looked_up.append(params["cveId"])
            return httpx.Response(200, json=nvd_page([nvd_cve(params["cveId"])]))
        return httpx.Response(200, json=nvd_page([]))

    def cisa_request(request):
        return httpx.Response(
            200,
            json={
                "count": 2,
                "vulnerabilities": [
                    {"cveID": "CVE-2026-0001", "dateAdded": "2026-10-01"},
                    {"cveID": "CVE-2026-0002", "dateAdded": "2026-11-03"},
                ],
            },
        )

    run(
        config,
        handler_for(nvd=nvd_request, cisa=cisa_request),
        now=NOW + timedelta(days=1),
    )
    assert looked_up == ["CVE-2026-0002"]
    with WatchStore(config.watch.database)._connect() as db:
        identifiers = {row[0] for row in db.execute("SELECT cve_id FROM watch_cve")}
    assert identifiers == {"CVE-2026-0002"}


def test_pending_fetches_at_most_twenty_five_oldest_first(tmp_path):
    config = write_config(tmp_path)

    def no_request(request):
        raise AssertionError("baseline must not query public sources")

    run(config, handler_for(nvd=no_request))
    start = NOW - timedelta(minutes=30)
    for index in range(30):
        clock = lambda index=index: start + timedelta(minutes=index)
        WatchStore(config.watch.database, clock=clock).apply_kev(
            {f"CVE-2026-{1000 + index}": KEVFields("2026-11-03")},
            {},
            pending_since="1999-01-01",
        )

    looked_up: list[str] = []

    def nvd_request(request):
        params = dict(request.url.params)
        if params.get("cveId"):
            looked_up.append(params["cveId"])
            return httpx.Response(200, json=nvd_page([nvd_cve(params["cveId"])]))
        return httpx.Response(200, json=nvd_page([]))

    report = run(config, handler_for(nvd=nvd_request), now=NOW + timedelta(hours=1))
    assert not report.failures
    assert len(looked_up) == 25
    assert looked_up[0] == "CVE-2026-1000"
    assert looked_up[-1] == "CVE-2026-1024"
    assert len(WatchStore(config.watch.database).pending(limit=100)) == 5


def test_epss_downward_crossing_is_refreshed_after_the_floor_download(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    day = [0]
    batch_ids: list[str] = []
    high = {"cve": "CVE-2026-0001", "epss": "0.8", "percentile": "0.99", "date": "2026-11-03"}
    low = {"cve": "CVE-2026-0001", "epss": "0.05", "percentile": "0.2", "date": "2026-11-04"}

    def nvd_request(request):
        return httpx.Response(
            200, json=nvd_page([nvd_cve()] if day[0] == 0 else [])
        )

    def epss_request(request):
        params = dict(request.url.params)
        if "epss-gt" in params:
            data = [high] if day[0] == 0 else []
            return httpx.Response(
                200, json={"total": len(data), "offset": 0, "data": data}
            )
        batch_ids.append(params["cve"])
        data = [high] if day[0] == 0 else [low]
        return httpx.Response(200, json={"total": len(data), "data": data})

    handler = handler_for(nvd=nvd_request, epss=epss_request)
    run(config, handler)
    day[0] = 1
    second = run(config, handler, now=NOW + timedelta(days=1))
    assert not second.failures
    assert batch_ids == ["CVE-2026-0001", "CVE-2026-0001"]
    store = WatchStore(config.watch.database)
    with store._connect() as db:
        row = db.execute("SELECT epss, epss_date FROM watch_cve").fetchone()
    assert tuple(row) == (0.05, "2026-11-04")
    assert store.status(epss_floor=0.1)["epss_above"] == 0


def test_epss_retries_rows_without_a_score_date(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    day = [0]
    batch_ids: list[str] = []

    def nvd_request(request):
        return httpx.Response(
            200, json=nvd_page([nvd_cve()] if day[0] == 0 else [])
        )

    def failing_epss(request):
        return httpx.Response(500)

    def recovered_epss(request):
        params = dict(request.url.params)
        if "epss-gt" in params:
            return httpx.Response(200, json={"total": 0, "offset": 0, "data": []})
        batch_ids.append(params["cve"])
        return httpx.Response(
            200, json={"total": 1, "data": [epss_row("CVE-2026-0001")]}
        )

    first = run(config, handler_for(nvd=nvd_request, epss=failing_epss))
    assert first.failures == ("epss",)

    day[0] = 1
    second = run(
        config,
        handler_for(nvd=nvd_request, epss=recovered_epss),
        now=NOW + timedelta(hours=1),
    )
    assert not second.failures
    assert batch_ids == ["CVE-2026-0001"]
    with WatchStore(config.watch.database)._connect() as db:
        assert db.execute("SELECT epss_date FROM watch_cve").fetchone()[0] == "2026-11-03"


def test_full_confirmation_eof_is_cancelled(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, initial="full")

    def eof(message):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 1
    assert "cancelled" in capsys.readouterr().out


def test_changing_nvd_totals_fail_without_advancing_the_cursor(tmp_path):
    config = write_config(tmp_path, initial="backfill")
    calls: list[int] = []

    def nvd_request(request):
        start = int(dict(request.url.params)["startIndex"])
        calls.append(start)
        if start == 0:
            return httpx.Response(200, json=nvd_page([nvd_cve()], total=2))
        return httpx.Response(200, json=nvd_page([], start=1, total=1))

    with pytest.raises(SourceError, match="unstable pagination"):
        run(config, handler_for(nvd=nvd_request))
    assert calls == [0, 1] * 3
    assert "nvd_cursor" not in metadata(config)


def test_changing_euvd_totals_fail_without_advancing_the_cursor(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="backfill")
    pages: list[int] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        page = int(dict(request.url.params)["page"])
        pages.append(page)
        if page == 0:
            return httpx.Response(
                200,
                json={
                    "total": 101,
                    "items": [
                        {
                            "id": f"EUVD-{index}",
                            "aliases": f"CVE-2026-{1000 + index}",
                        }
                        for index in range(100)
                    ],
                },
            )
        return httpx.Response(200, json={"total": 100, "items": []})

    report = run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert report.failures == ("euvd",)
    assert pages == [0, 1] * 3
    assert metadata(config)["euvd_cursor"] == "2026-10-27"


def test_changing_epss_floor_totals_fail_without_recording_the_day(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(feeds, "EPSS_PAGE_SIZE", 2)
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    offsets: list[int] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def epss_request(request):
        params = dict(request.url.params)
        if "epss-gt" in params:
            offset = int(params["offset"])
            offsets.append(offset)
            if offset == 0:
                return httpx.Response(
                    200,
                    json={
                        "total": 3,
                        "offset": 0,
                        "data": [
                            epss_row("CVE-2026-0001"),
                            epss_row("CVE-2026-0002"),
                        ],
                    },
                )
            return httpx.Response(200, json={"total": 2, "offset": 2, "data": []})
        return httpx.Response(200, json={"status": "OK", "total": 0, "data": []})

    report = run(config, handler_for(nvd=nvd_request, epss=epss_request))
    assert report.failures == ("epss",)
    assert offsets == [0, 2] * 3
    assert "epss_floor_date" not in metadata(config)


def test_backfill_bounds_kev_pending_to_the_initial_window(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="backfill")
    catalog = [{"cveID": "CVE-2026-0001", "dateAdded": "2026-10-01"}]
    looked_up: list[str] = []

    def nvd_request(request):
        params = dict(request.url.params)
        if params.get("cveId"):
            looked_up.append(params["cveId"])
            return httpx.Response(200, json=nvd_page([nvd_cve(params["cveId"])]))
        return httpx.Response(200, json=nvd_page([]))

    def cisa_request(request):
        return httpx.Response(
            200, json={"count": len(catalog), "vulnerabilities": catalog}
        )

    handler = handler_for(nvd=nvd_request, cisa=cisa_request)
    run(config, handler)
    assert metadata(config)["initial_window_start"] == "2026-10-27"
    assert looked_up == []
    assert WatchStore(config.watch.database).pending() == ()

    catalog.append({"cveID": "CVE-2026-0002", "dateAdded": "2026-11-02"})
    run(config, handler, now=NOW + timedelta(hours=1))
    assert looked_up == ["CVE-2026-0002"]


def test_full_mode_never_stores_kev_pending(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="full")

    def nvd_request(request):
        if dict(request.url.params).get("cveId"):
            raise AssertionError("full mode must not fetch pending KEV CVEs")
        return httpx.Response(200, json=nvd_page([]))

    def cisa_request(request):
        return httpx.Response(
            200,
            json={
                "count": 1,
                "vulnerabilities": [
                    {"cveID": "CVE-2026-9999", "dateAdded": "2026-11-03"}
                ],
            },
        )

    report = run(
        config,
        handler_for(nvd=nvd_request, cisa=cisa_request),
        assume_yes=True,
    )
    assert not report.failures
    assert metadata(config)["initial_mode"] == "full"
    assert metadata(config)["initial_window_start"] == "1999-01-01"
    assert WatchStore(config.watch.database).pending() == ()


def test_unknown_euvd_score_versions_are_ignored_and_counted(
    tmp_path, monkeypatch, capsys
):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="backfill")

    def nvd_request(request):
        return httpx.Response(
            200,
            json=nvd_page([nvd_cve("CVE-2026-0001"), nvd_cve("CVE-2026-0002")]),
        )

    def euvd_request(request):
        return httpx.Response(
            200,
            json={
                "total": 2,
                "items": [
                    {
                        "id": "EUVD-2026-8",
                        "aliases": "CVE-2026-0001",
                        "baseScore": 0.0,
                        "baseScoreVersion": None,
                        "baseScoreVector": None,
                    },
                    {
                        "id": "EUVD-2026-9",
                        "aliases": "CVE-2026-0002",
                        "baseScore": 5.0,
                        "baseScoreVersion": "9.9",
                    },
                ],
            },
        )

    monkeypatch.setattr(
        cli,
        "HttpClient",
        lambda http_config: mock_client(
            handler_for(nvd=nvd_request, euvd=euvd_request)
        ),
    )
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 0
    output = capsys.readouterr().out
    euvd_line = next(line for line in output.splitlines() if line.startswith("euvd:"))
    assert euvd_line.endswith(", 1 score(s) ignored")
    with WatchStore(config.watch.database)._connect() as db:
        rows = {
            row["cve_id"]: row
            for row in db.execute("SELECT cve_id, euvd_id, cvss_json FROM watch_cve")
        }
    assert rows["CVE-2026-0001"]["euvd_id"] == "EUVD-2026-8"
    assert rows["CVE-2026-0002"]["euvd_id"] == "EUVD-2026-9"
    assert '"provider":"euvd"' not in rows["CVE-2026-0001"]["cvss_json"]
    assert '"provider":"euvd"' not in rows["CVE-2026-0002"]["cvss_json"]
