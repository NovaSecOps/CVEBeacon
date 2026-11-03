from __future__ import annotations

from datetime import date, timedelta

import httpx
import pytest
from watch_support import NOW, mock_client, nvd_cve, nvd_page, write_config

from cvebeacon import cli
from cvebeacon.errors import SourceError
from cvebeacon.sources.epss import EPSS_URL
from cvebeacon.sources.euvd import SEARCH_URL
from cvebeacon.sources.kev import CISA_URL, EU_URL
from cvebeacon.sources.nvd import CVE_URL
from cvebeacon.watch.feeds import iso_timestamp, nvd_windows
from cvebeacon.watch.records import WatchRecord
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
    assert "takes a long time" in output
    assert "NVD window(s)" in output
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
        assert "euvd_cursor" not in stored_meta


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
    assert "takes a long time" in output


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
    assert "with EPSS >= 0.1: 1" in output


@pytest.mark.parametrize("command", [["watch", "status"], ["watch", "sync"]])
def test_watch_commands_refuse_a_disabled_configuration(tmp_path, capsys, command):
    config = write_config(tmp_path, enabled=False)
    assert cli.main(["--config", str(config.config_path), *command]) == 2
    assert "watch mode is disabled" in capsys.readouterr().err
