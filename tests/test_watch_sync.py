from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest
from watch_support import NOW, epss_gzip, mock_client, nvd_cve, nvd_page, write_config

from cvebeacon import cli
from cvebeacon.config import HttpConfig
from cvebeacon.errors import SourceError
from cvebeacon.http import HttpClient
from cvebeacon.sources.euvd import SEARCH_URL
from cvebeacon.sources.kev import CISA_URL, EU_URL
from cvebeacon.sources.nvd import CVE_URL
from cvebeacon.watch import feeds
from cvebeacon.watch.feeds import iso_timestamp, nvd_windows
from cvebeacon.watch.records import KEVFields, WatchRecord
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.sync import FULL_HISTORY_START, sync_watch

EPSS_FILE_PREFIX = "https://epss.empiricalsecurity.com/"


@pytest.fixture(autouse=True)
def _small_epss_files(monkeypatch):
    monkeypatch.setattr(feeds, "EPSS_MIN_ROWS", 1, raising=False)


def handler_for(*, nvd=None, euvd=None, cisa=None, eu=None, epss=None):
    def handler(request):
        url = str(request.url)
        for prefix, callback in (
            (CVE_URL, nvd),
            (SEARCH_URL, euvd),
            (CISA_URL, cisa),
            (EU_URL, eu),
            (EPSS_FILE_PREFIX, epss),
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


def epss_row(identifier: str = "CVE-2026-0001") -> dict[str, str]:
    return {"cve": identifier, "epss": "0.5", "percentile": "0.9"}


def cisa_item(identifier: str = "CVE-2026-0001", **overrides) -> dict:
    value = {
        "cveID": identifier,
        "dateAdded": "2026-11-03",
        "dueDate": "2026-11-20",
        "requiredAction": "Apply updates",
        "knownRansomwareCampaignUse": "Known",
    }
    value.update(overrides)
    return value


def euvd_item(identifier: str = "EUVD-2026-1", cve: str = "CVE-2026-0001", **overrides) -> dict:
    value = {
        "id": identifier,
        "aliases": cve,
        "baseScore": 7.5,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/X",
    }
    value.update(overrides)
    return value


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
    assert "epss_file_day" not in stored
    assert WatchStore(config.watch.database).status()["rows"] == 0


def test_backfill_mode_reads_the_configured_number_of_days(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="backfill")
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
    assert euvd_dates[0]["toUpdatedDate"] == "2026-11-04"
    assert report.summaries[0].new == 1
    assert WatchStore(config.watch.database).status()["rows"] == 1
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
    assert "1 EPSS file per day" in output
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
    store.set_metadata(
        {
            "nvd_cursor": (NOW - timedelta(hours=1)).isoformat(),
            "initialized_at": NOW.isoformat(),
        }
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
    store.set_metadata(
        {
            "nvd_cursor": NOW.isoformat(),
            "euvd_cursor": "2026-11-01",
            "initialized_at": NOW.isoformat(),
        }
    )
    euvd_dates: list[dict[str, str]] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        euvd_dates.append(dict(request.url.params))
        return httpx.Response(200, json={"total": 0, "items": []})

    run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert euvd_dates[0]["fromUpdatedDate"] == "2026-11-01"
    assert euvd_dates[0]["toUpdatedDate"] == "2026-11-04"
    assert metadata(config)["euvd_cursor"] == "2026-11-03"


def test_committed_touches_survive_a_later_nvd_failure(tmp_path):
    config = write_config(tmp_path, sources=("nvd",))
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.record_baseline(
        nvd_cursor=(NOW - timedelta(days=200)).isoformat(),
        initialized_at=(NOW - timedelta(days=200)).isoformat(),
    )
    calls: list[dict[str, str]] = []

    def interrupted(request):
        calls.append(dict(request.url.params))
        if len(calls) == 1:
            raw = nvd_cve(lastModified=(NOW - timedelta(days=100)).isoformat())
            return httpx.Response(200, json=nvd_page([raw]))
        return httpx.Response(503)

    with pytest.raises(SourceError):
        run(config, handler_for(nvd=interrupted))
    assert store.view("CVE-2026-0001") is not None
    assert store.pending_evaluations(10) == ("CVE-2026-0001",)
    assert store.metadata()["nvd_cursor"] == (
        NOW - timedelta(days=80, minutes=15)
    ).isoformat()

    resumed: list[dict[str, str]] = []

    def resumed_nvd(request):
        resumed.append(dict(request.url.params))
        return httpx.Response(200, json=nvd_page([]))

    report = run(config, handler_for(nvd=resumed_nvd))
    assert not report.failures
    assert report.touched_ids == ()
    assert resumed[0]["lastModStartDate"] == iso_timestamp(
        NOW - timedelta(days=80, minutes=30)
    )
    assert store.pending_evaluations(10) == ("CVE-2026-0001",)
    store.acknowledge(["CVE-2026-0001"])
    assert store.pending_evaluations(10) == ()


def test_nvd_failure_does_not_advance_cursors_or_commit_records(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"))
    store = WatchStore(config.watch.database)
    cursor = (NOW - timedelta(hours=1)).isoformat()
    store.set_metadata({"nvd_cursor": cursor, "initialized_at": NOW.isoformat()})
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
    assert WatchStore(config.watch.database).status()["rows"] == 0


def test_nvd_api_key_environment_is_used(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "secret")
    config = write_config(tmp_path, initial="backfill")
    seen: list[str | None] = []

    def nvd_request(request):
        seen.append(request.headers.get("apiKey"))
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    run(config, handler_for(nvd=nvd_request))
    assert seen == ["secret"]


def test_cisa_kev_is_downloaded_once_and_overwrites_kev_rows(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="backfill")
    kev_requests: list[str] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def cisa_request(request):
        kev_requests.append(str(request.url))
        return httpx.Response(
            200, json={"count": 1, "vulnerabilities": [cisa_item()]}
        )

    report = run(config, handler_for(nvd=nvd_request, cisa=cisa_request))
    assert len(kev_requests) == 1
    status = WatchStore(config.watch.database).status()
    assert status["rows"] == 1
    assert status["cisa_kev"] == 1
    summary = next(item for item in report.summaries if item.source == "cisa_kev")
    assert summary.requests == 1
    assert summary.changed == 1
    view = WatchStore(config.watch.database).view(
        "CVE-2026-0001", catalogs=("nvd", "cisa_kev")
    )
    assert view.cisa_kev_added == "2026-11-03"


def test_kev_unknown_to_nvd_is_fetched_and_applied_in_the_same_run(tmp_path):
    config = write_config(
        tmp_path, sources=("nvd", "cisa_kev", "eu_kev"), initial="backfill"
    )
    cisa_catalog = [cisa_item("CVE-2026-0002", dateAdded="2026-11-02")]
    eu_catalog = [
        {"cveId": "CVE-2026-0002", "dateAdded": "2026-11-03", "sources": ["eukev_kev"]}
    ]
    looked_up: list[str] = []

    def nvd_request(request):
        params = dict(request.url.params)
        if params.get("cveId"):
            looked_up.append(params["cveId"])
            return httpx.Response(200, json=nvd_page([nvd_cve(params["cveId"])]))
        return httpx.Response(200, json=nvd_page([]))

    def cisa_request(request):
        return httpx.Response(
            200, json={"count": len(cisa_catalog), "vulnerabilities": cisa_catalog}
        )

    def eu_request(request):
        return httpx.Response(200, json=eu_catalog)

    handler = handler_for(nvd=nvd_request, cisa=cisa_request, eu=eu_request)
    first = run(config, handler)
    assert not first.failures
    assert looked_up == ["CVE-2026-0002"]
    view = WatchStore(config.watch.database).view(
        "CVE-2026-0002", catalogs=("nvd", "cisa_kev", "eu_kev")
    )
    assert (
        view.cisa_kev_added,
        view.cisa_kev_due,
        view.cisa_required_action,
        view.cisa_ransomware,
        view.eu_kev_added,
    ) == ("2026-11-02", "2026-11-20", "Apply updates", "Known", "2026-11-03")

    second = run(config, handler, now=NOW + timedelta(minutes=3))
    assert all(summary.new == 0 for summary in second.summaries)
    assert all(summary.changed == 0 for summary in second.summaries)


def test_catalog_replaces_cisa_kev_and_the_view_follows(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="backfill")
    cve = nvd_cve(
        cisaExploitAdd="2026-11-01",
        cisaActionDue="2026-11-20",
        cisaRequiredAction="Apply updates",
    )

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([cve]))

    def cisa_request(request):
        return httpx.Response(200, json={"count": 0, "vulnerabilities": []})

    handler = handler_for(nvd=nvd_request, cisa=cisa_request)
    first = run(config, handler)
    second = run(config, handler, now=NOW + timedelta(minutes=3))
    assert not first.failures
    assert all(summary.changed == 0 for summary in second.summaries)
    store = WatchStore(config.watch.database)
    assert store.view("CVE-2026-0001", catalogs=("nvd", "cisa_kev")).cisa_kev_added is None
    # NVD's own fields are still stored in its raw table.
    with store._connect() as db:
        row = db.execute(
            "SELECT cisa_kev_added FROM watch_cve WHERE cve_id='CVE-2026-0001'"
        ).fetchone()
    assert row["cisa_kev_added"] == "2026-11-01"


def test_daily_epss_file_is_loaded_once_and_updates_the_view(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    requested: list[str] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def epss_request(request):
        requested.append(str(request.url))
        return httpx.Response(
            200,
            content=epss_gzip([("CVE-2026-0001", "0.42", "0.88")]),
        )

    handler = handler_for(nvd=nvd_request, epss=epss_request)
    first = run(config, handler)
    assert len(requested) == 1
    assert "2026-11-03" in requested[0]
    view = WatchStore(config.watch.database).view("CVE-2026-0001")
    assert (view.epss, view.epss_percentile) == (0.42, 0.88)
    assert metadata(config)["epss_file_day"] == "2026-11-03"

    second = run(config, handler, now=NOW + timedelta(hours=1))
    assert len(requested) == 1
    assert second.summaries[-1].requests == 0
    assert second.summaries[-1].changed == 0

    third = run(config, handler, now=NOW + timedelta(days=1))
    assert len(requested) == 2
    assert "2026-11-04" in requested[1]


def test_sync_reports_new_then_unchanged(tmp_path):
    config = write_config(tmp_path, initial="backfill")

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    handler = handler_for(nvd=nvd_request)
    first = run(config, handler)
    second = run(config, handler, now=NOW + timedelta(minutes=30))
    assert (first.summaries[0].new, first.summaries[0].changed) == (1, 0)
    assert (second.summaries[0].new, second.summaries[0].changed) == (0, 0)


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
    stored_status = WatchStore(config.watch.database).status()
    assert stored_status["rows"] == 1
    stored_meta = metadata(config)
    assert stored_meta["nvd_cursor"]
    assert "initialized_at" in stored_meta
    if source == "euvd":
        assert stored_meta["euvd_cursor"] == stored_meta["initial_window_start"]


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
    assert WatchStore(config.watch.database).status()["rows"] == 0


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
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"))
    store = WatchStore(config.watch.database)
    store.set_metadata(
        {
            "nvd_cursor": NOW.isoformat(),
            "euvd_cursor": "2026-11-03",
            "initialized_at": NOW.isoformat(),
        }
    )
    store.upsert_nvd(
        [
            WatchRecord(
                cve_id="CVE-2026-0001",
                status="published",
                ssvc_exploitation="active",
            )
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
    store.replace_epss([("CVE-2026-0001", 0.5, 0.9, date(2026, 11, 3))])
    assert cli.main(["--config", str(config.config_path), "watch", "status"]) == 0
    output = capsys.readouterr().out
    assert f"database: {config.watch.database}" in output
    assert "schema version: 2" in output
    assert f"nvd cursor: {NOW.isoformat()}" in output
    assert "euvd cursor: 2026-11-03" in output
    assert "epss score date: 2026-11-03" in output
    assert "rows: 1" in output
    assert "euvd items: 0" in output
    assert "KEV catalog entries: CISA 2, EU 0" in output
    assert "watched CVEs in KEV: 1 (CISA 1, EU 0)" in output
    assert "with active SSVC: 1" in output
    assert "with EPSS: 1" in output
    assert "lookups pending/backing off: 0" in output


@pytest.mark.parametrize("command", [["watch", "status"], ["watch", "sync"]])
def test_watch_commands_refuse_a_disabled_configuration(tmp_path, capsys, command):
    config = write_config(tmp_path, enabled=False)
    assert cli.main(["--config", str(config.config_path), *command]) == 2
    assert "watch mode is disabled" in capsys.readouterr().err


def test_full_sync_twice_reports_no_changes(tmp_path):
    config = write_config(
        tmp_path,
        sources=("nvd", "euvd", "cisa_kev", "eu_kev", "epss"),
        initial="full",
    )

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def euvd_request(request):
        return httpx.Response(
            200,
            json={"total": 1, "items": [euvd_item(exploitedSince="2026-11-01")]},
        )

    def cisa_request(request):
        return httpx.Response(
            200, json={"count": 1, "vulnerabilities": [cisa_item()]}
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
        return httpx.Response(
            200, content=epss_gzip([("CVE-2026-0001", "0.5", "0.9")])
        )

    handler = handler_for(
        nvd=nvd_request,
        euvd=euvd_request,
        cisa=cisa_request,
        eu=eu_request,
        epss=epss_request,
    )
    first = run(config, handler, assume_yes=True)
    assert not first.failures
    second = run(config, handler, now=NOW + timedelta(minutes=3))
    assert all(summary.changed == 0 for summary in second.summaries)
    assert all(summary.new == 0 for summary in second.summaries)
    assert second.touched_ids == ()


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
    assert "initial_complete" not in completed
    assert "initialized_at" in completed


def test_local_clock_ahead_is_capped_by_the_nvd_timestamp(tmp_path):
    config = write_config(tmp_path, initial="backfill")

    def nvd_request(request):
        return httpx.Response(
            200,
            json={**nvd_page([]), "timestamp": "2026-11-03T10:00:00.000Z"},
        )

    run(config, handler_for(nvd=nvd_request))
    assert metadata(config)["nvd_cursor"] == "2026-11-03T10:00:00+00:00"


def test_a_long_gap_prints_a_warning_and_still_syncs(tmp_path, capsys):
    config = write_config(tmp_path)
    store = WatchStore(config.watch.database)
    store.set_metadata(
        {
            "nvd_cursor": (NOW - timedelta(days=200)).isoformat(),
            "initialized_at": NOW.isoformat(),
        }
    )

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    report = run(config, handler_for(nvd=nvd_request))
    assert not report.failures
    assert "more than 120 days old" in capsys.readouterr().out


def test_nvd_sync_splits_a_large_window_before_one_hour(monkeypatch, tmp_path):
    monkeypatch.setattr(feeds, "NVD_PAGE_SIZE", 4)
    config = write_config(tmp_path, initial="backfill")
    windows: list[tuple[datetime, datetime]] = []

    def nvd_request(request):
        params = dict(request.url.params)
        start = datetime.fromisoformat(params["lastModStartDate"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(params["lastModEndDate"].replace("Z", "+00:00"))
        windows.append((start, end))
        if end - start > timedelta(hours=1):
            return httpx.Response(
                200,
                json=nvd_page(
                    [nvd_cve(f"CVE-2026-{index}") for index in range(5)], total=5
                ),
            )
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    report = run(config, handler_for(nvd=nvd_request))
    assert not report.failures
    assert any(end - start <= timedelta(hours=1) for start, end in windows)
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
                "items": [euvd_item(baseScore=42)],
            },
        )

    report = run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert report.failures == ("euvd",)
    assert metadata(config)["euvd_cursor"] == "2026-10-27"
    assert WatchStore(config.watch.database).view("CVE-2026-0001").euvd_id is None


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
    view = WatchStore(config.watch.database).view("CVE-2026-0001")
    assert (view.cisa_kev_due, view.cisa_required_action) == (
        "2026-11-30",
        "Corrected action",
    )


def test_kev_withdrawal_clears_catalog_rows_and_the_view(tmp_path):
    config = write_config(
        tmp_path, sources=("nvd", "cisa_kev", "eu_kev"), initial="backfill"
    )
    cisa_items = [cisa_item()]
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
    store = WatchStore(config.watch.database)

    def empty_nvd(request):
        return httpx.Response(200, json=nvd_page([]))

    def empty_cisa(request):
        return httpx.Response(200, json={"count": 0, "vulnerabilities": []})

    def empty_eu(request):
        return httpx.Response(200, json=[])

    second = run(
        config,
        handler_for(nvd=empty_nvd, cisa=empty_cisa, eu=empty_eu),
        now=NOW + timedelta(hours=1),
    )
    assert not second.failures
    view = store.view("CVE-2026-0001", catalogs=("nvd", "cisa_kev", "eu_kev"))
    assert (view.cisa_kev_added, view.eu_kev_added) == (None, None)


def test_non_alert_euvd_is_visible_as_soon_as_nvd_inserts_the_cve(tmp_path):
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
            json={"total": 1, "items": [euvd_item(cve="CVE-2026-9999")]},
        )

    run(
        config,
        handler_for(nvd=nvd_without_the_cve, euvd=euvd_request),
        now=NOW + timedelta(days=1),
    )
    assert looked_up == []

    def nvd_with_the_cve(request):
        return httpx.Response(200, json=nvd_page([nvd_cve("CVE-2026-9999")]))

    def empty_euvd(request):
        return httpx.Response(200, json={"total": 0, "items": []})

    run(
        config,
        handler_for(nvd=nvd_with_the_cve, euvd=empty_euvd),
        now=NOW + timedelta(days=2),
    )
    view = WatchStore(config.watch.database).view(
        "CVE-2026-9999", catalogs=("nvd", "euvd")
    )
    assert view.euvd_id == "EUVD-2026-1"
    assert any(entry.provider == "euvd" for entry in view.cvss)


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
                    euvd_item(
                        cve="CVE-2026-9999",
                        exploitedSince="Nov 3, 2026, 12:00:00 AM",
                    )
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
    view = WatchStore(config.watch.database).view(
        "CVE-2026-9999", catalogs=("nvd", "euvd")
    )
    assert (view.euvd_id, view.euvd_exploited_since) == (
        "EUVD-2026-1",
        "Nov 3, 2026, 12:00:00 AM",
    )


def test_kev_additions_before_the_baseline_are_not_looked_up(tmp_path):
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


def test_lookups_fetch_at_most_twenty_five_oldest_first(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"))

    def no_request(request):
        raise AssertionError("baseline must not query public sources")

    run(config, handler_for(nvd=no_request, cisa=no_request))
    catalog = [
        {"cveID": f"CVE-2026-{1000 + index}", "dateAdded": "2026-11-03"}
        for index in range(30)
    ]
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

    report = run(
        config,
        handler_for(nvd=nvd_request, cisa=cisa_request),
        now=NOW + timedelta(hours=1),
    )
    assert not report.failures
    assert len(looked_up) == 25
    assert looked_up[0] == "CVE-2026-1000"
    assert looked_up[-1] == "CVE-2026-1024"
    assert WatchStore(config.watch.database).status()["lookups"] == 5


def test_failed_lookups_back_off_without_resetting_the_catalog(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="baseline")

    def no_request(request):
        raise AssertionError("baseline must not query public sources")

    run(config, handler_for(nvd=no_request, cisa=no_request))
    catalog = [cisa_item("CVE-2026-9999", dateAdded="2026-11-03")]

    def nvd_request(request):
        if dict(request.url.params).get("cveId"):
            return httpx.Response(500)
        return httpx.Response(200, json=nvd_page([]))

    def cisa_request(request):
        return httpx.Response(
            200, json={"count": len(catalog), "vulnerabilities": catalog}
        )

    handler = handler_for(nvd=nvd_request, cisa=cisa_request)
    first = run(config, handler, now=NOW + timedelta(minutes=1))
    assert not first.failures
    summary = next(item for item in first.summaries if item.source == "nvd")
    assert summary.lookup_failures == 1
    assert summary.requests == 2
    assert WatchStore(config.watch.database).status()["lookups"] == 1

    # Before the backoff expires no lookup is attempted.
    second = run(config, handler, now=NOW + timedelta(minutes=30))
    assert next(item for item in second.summaries if item.source == "nvd").requests == 1
    assert next(item for item in second.summaries if item.source == "nvd").lookup_failures == 0

    # After it expires the unchanged catalog does not reset the attempt count.
    third = run(config, handler, now=NOW + timedelta(hours=2))
    assert next(item for item in third.summaries if item.source == "nvd").lookup_failures == 1
    with WatchStore(config.watch.database)._connect() as db:
        row = db.execute(
            "SELECT attempts FROM watch_lookup WHERE cve_id='CVE-2026-9999'"
        ).fetchone()
    assert row["attempts"] == 2


def test_epss_downward_crossing_updates_the_view(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    requested: list[str] = []
    content = {
        "2026-11-03": epss_gzip([("CVE-2026-0001", "0.8", "0.99")], score_date=date(2026, 11, 3)),
        "2026-11-04": epss_gzip([("CVE-2026-0001", "0.05", "0.2")], score_date=date(2026, 11, 4)),
    }

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()] if not requested else []))

    def epss_request(request):
        requested.append(str(request.url))
        day = "2026-11-04" if "2026-11-04" in str(request.url) else "2026-11-03"
        return httpx.Response(200, content=content[day])

    handler = handler_for(nvd=nvd_request, epss=epss_request)
    run(config, handler)
    second = run(config, handler, now=NOW + timedelta(days=1))
    assert not second.failures
    view = WatchStore(config.watch.database).view("CVE-2026-0001")
    assert (view.epss, view.epss_date) == (0.05, "2026-11-04")
    assert "CVE-2026-0001" in second.touched_ids


def test_epss_missing_score_removes_the_previous_value(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    contents = {
        "2026-11-03": epss_gzip([("CVE-2026-0001", "0.8", "0.99")], score_date=date(2026, 11, 3)),
        "2026-11-04": epss_gzip([("CVE-2026-0002", "0.2", "0.5")], score_date=date(2026, 11, 4)),
    }
    calls = [0]

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()] if calls[0] == 0 else []))

    def epss_request(request):
        day = "2026-11-04" if "2026-11-04" in str(request.url) else "2026-11-03"
        return httpx.Response(200, content=contents[day])

    handler = handler_for(nvd=nvd_request, epss=epss_request)
    run(config, handler)
    calls[0] += 1
    second = run(config, handler, now=NOW + timedelta(days=1))
    assert not second.failures
    view = WatchStore(config.watch.database).view("CVE-2026-0001")
    assert view.epss is None
    assert "CVE-2026-0001" in second.touched_ids


def test_bad_epss_file_keeps_the_previous_table_and_retries(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    good = epss_gzip([("CVE-2026-0001", "0.8", "0.99")], score_date=date(2026, 11, 3))
    requested = [0]

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def epss_request(request):
        requested[0] += 1
        if requested[0] == 2:
            return httpx.Response(200, content=b"broken")
        return httpx.Response(200, content=good)

    handler = handler_for(nvd=nvd_request, epss=epss_request)
    run(config, handler)
    failing = run(config, handler, now=NOW + timedelta(days=1))
    assert failing.failures == ("epss",)
    assert WatchStore(config.watch.database).view("CVE-2026-0001").epss == 0.8
    assert metadata(config)["epss_file_day"] == "2026-11-03"

    retried = run(config, handler, now=NOW + timedelta(days=1, hours=1))
    assert not retried.failures
    assert requested[0] == 3


def test_epss_403_falls_back_and_records_the_file_day(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    requested: list[str] = []
    nvd_calls = [0]
    published = [False]
    yesterday = epss_gzip(
        [("CVE-2026-0001", "0.2", "0.5")], score_date="2026-11-02"
    )
    today = epss_gzip(
        [("CVE-2026-0001", "0.4", "0.7")], score_date="2026-11-03"
    )

    def nvd_request(request):
        nvd_calls[0] += 1
        return httpx.Response(
            200, json=nvd_page([nvd_cve()] if nvd_calls[0] == 1 else [])
        )

    def epss_request(request):
        url = str(request.url)
        requested.append(url)
        if "2026-11-03" in url:
            if published[0]:
                return httpx.Response(200, content=today)
            return httpx.Response(403)
        return httpx.Response(200, content=yesterday)

    handler = handler_for(nvd=nvd_request, epss=epss_request)
    first = run(config, handler)
    assert not first.failures
    assert len(requested) == 2
    assert metadata(config)["epss_file_day"] == "2026-11-02"
    assert WatchStore(config.watch.database).view("CVE-2026-0001").epss == 0.2

    # Yesterday's file is already loaded, so only today is probed again.
    second = run(config, handler, now=NOW + timedelta(hours=1))
    assert not second.failures
    assert len(requested) == 3
    assert metadata(config)["epss_file_day"] == "2026-11-02"

    published[0] = True
    third = run(config, handler, now=NOW + timedelta(hours=2))
    assert not third.failures
    assert len(requested) == 4
    assert metadata(config)["epss_file_day"] == "2026-11-03"
    assert WatchStore(config.watch.database).view("CVE-2026-0001").epss == 0.4

    fourth = run(config, handler, now=NOW + timedelta(hours=3))
    assert not fourth.failures
    assert len(requested) == 4


def test_too_few_epss_rows_keeps_the_previous_table(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds, "EPSS_MIN_ROWS", 5)
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.record_baseline(
        nvd_cursor=(NOW - timedelta(minutes=5)).isoformat(),
        initialized_at=NOW.isoformat(),
    )
    store.upsert_nvd([WatchRecord("CVE-2026-0001", "published")])
    store.replace_epss(
        [("CVE-2026-0001", 0.8, 0.9, date(2026, 11, 2))]
    )

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def epss_request(request):
        return httpx.Response(
            200,
            content=epss_gzip(
                [("CVE-2026-0001", "0.1", "0.2")], score_date="2026-11-03"
            ),
        )

    report = run(
        config, handler_for(nvd=nvd_request, epss=epss_request)
    )
    assert report.failures == ("epss",)
    assert store.view("CVE-2026-0001").epss == 0.8
    assert store.status()["epss_rows"] == 1
    assert store.metadata()["epss_file_day"] == "2026-11-02"


def test_corrupt_epss_deflate_is_an_optional_cli_failure(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, sources=("nvd", "epss"), initial="backfill")
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.record_baseline(
        nvd_cursor=(NOW - timedelta(minutes=5)).isoformat(),
        initialized_at=NOW.isoformat(),
    )
    store.upsert_nvd([WatchRecord("CVE-2026-0001", "published")])
    store.replace_epss(
        [("CVE-2026-0001", 0.8, 0.9, date(2026, 11, 2))]
    )
    corrupt = bytearray(epss_gzip([("CVE-2026-0001", 0.4, 0.8)]))
    corrupt[10] = 0x07

    def handler(request):
        if str(request.url).startswith(CVE_URL):
            return httpx.Response(200, json=nvd_page([]))
        return httpx.Response(200, content=bytes(corrupt))

    monkeypatch.setattr(cli, "HttpClient", lambda http_config: mock_client(handler))
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 4
    output = capsys.readouterr().out
    assert "nvd:" in output
    assert "epss:" in output
    assert "failed" in output
    assert store.view("CVE-2026-0001").epss == 0.8
    assert store.metadata()["epss_file_day"] == "2026-11-02"


def test_a_backward_clock_does_not_regress_cursors_or_reload_epss(tmp_path):
    config = write_config(
        tmp_path, sources=("nvd", "euvd", "epss"), initial="backfill"
    )
    euvd_dates: list[dict[str, str]] = []
    epss_urls: list[str] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def euvd_request(request):
        euvd_dates.append(dict(request.url.params))
        return httpx.Response(200, json={"total": 0, "items": []})

    def epss_request(request):
        epss_urls.append(str(request.url))
        return httpx.Response(
            200,
            content=epss_gzip(
                [("CVE-2026-0001", "0.5", "0.9")], score_date="2026-11-03"
            ),
        )

    handler = handler_for(
        nvd=nvd_request, euvd=euvd_request, epss=epss_request
    )
    first = run(config, handler)
    assert not first.failures
    assert metadata(config)["euvd_cursor"] == "2026-11-03"
    assert metadata(config)["epss_file_day"] == "2026-11-03"

    euvd_dates.clear()
    epss_urls.clear()
    backward = run(config, handler, now=NOW - timedelta(days=3))
    assert not backward.failures
    assert euvd_dates == []
    assert epss_urls == []
    assert metadata(config)["euvd_cursor"] == "2026-11-03"
    assert metadata(config)["epss_file_day"] == "2026-11-03"

    forward = run(config, handler, now=NOW + timedelta(hours=1))
    assert not forward.failures
    assert len(euvd_dates) == 1
    assert epss_urls == []


def test_euvd_duplicate_page_does_not_commit_the_cursor(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "euvd"), initial="backfill")
    catalog = [
        {
            "id": f"EUVD-2026-{index}",
            "aliases": f"CVE-2026-{1000 + index}",
            "dateUpdated": "Nov 1, 2026, 12:00:00 PM",
        }
        for index in range(101)
    ]

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        page = int(dict(request.url.params)["page"])
        items = catalog[:100] if page == 0 else [catalog[99]]
        return httpx.Response(200, json={"total": 101, "items": items})

    report = run(
        config, handler_for(nvd=nvd_request, euvd=euvd_request)
    )
    assert report.failures == ("euvd",)
    assert metadata(config)["euvd_cursor"] == "2026-10-27"
    with WatchStore(config.watch.database)._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM watch_euvd_item").fetchone()[0] == 0


def test_euvd_large_chunks_split_and_commit_each_subchunk(tmp_path):
    config = write_config(
        tmp_path,
        sources=("nvd", "euvd"),
        initial="backfill",
        backfill_days=60,
    )
    requested: list[tuple[str, str]] = []

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([]))

    def euvd_request(request):
        params = dict(request.url.params)
        requested.append(
            (params["fromUpdatedDate"], params["toUpdatedDate"])
        )
        if params["fromUpdatedDate"] == "2026-09-04":
            if params["toUpdatedDate"] == "2026-10-04":
                return httpx.Response(
                    200,
                    json={
                        "total": 10_001,
                        "items": [
                            {"id": f"EUVD-parent-{index}"}
                            for index in range(100)
                        ],
                    },
                )
            return httpx.Response(
                200,
                json={
                    "total": 1,
                    "items": [
                        {
                            "id": "EUVD-left",
                            "aliases": "CVE-2026-0001",
                            "dateUpdated": "Nov 1, 2026, 12:00:00 PM",
                        }
                    ],
                },
            )
        return httpx.Response(500)

    report = run(
        config, handler_for(nvd=nvd_request, euvd=euvd_request)
    )
    assert report.failures == ("euvd",)
    assert requested == [
        ("2026-09-04", "2026-10-04"),
        ("2026-09-04", "2026-09-19"),
        ("2026-09-19", "2026-10-04"),
    ]
    assert metadata(config)["euvd_cursor"] == "2026-09-18"
    with WatchStore(config.watch.database)._connect() as db:
        identifiers = {
            row[0] for row in db.execute("SELECT euvd_id FROM watch_euvd_item")
        }
    assert identifiers == {"EUVD-left"}


def test_successful_retry_counts_every_attempt():
    calls: list[str] = []

    def handler(request):
        calls.append(str(request.url))
        if len(calls) == 1:
            return httpx.Response(503)
        return httpx.Response(200, json=nvd_page([]))

    http = HttpClient(
        HttpConfig(retries=2, backoff_seconds=0),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _: None,
    )
    feed = feeds.fetch_nvd_window(
        http,
        start=datetime(2026, 11, 1, tzinfo=timezone.utc),
        end=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    assert len(calls) == 2
    assert feed.requests == 2
    assert http.requests == 2


def test_later_page_exhaustion_counts_every_get_in_the_summary(tmp_path):
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
                        {"id": f"EUVD-{index}"} for index in range(100)
                    ],
                },
            )
        return httpx.Response(503)

    http = HttpClient(
        HttpConfig(retries=2, backoff_seconds=0),
        client=httpx.Client(
            transport=httpx.MockTransport(
                handler_for(nvd=nvd_request, euvd=euvd_request)
            )
        ),
        sleep=lambda _: None,
    )
    report = sync_watch(config, http, clock=lambda: NOW)
    assert report.failures == ("euvd",)
    assert pages == [0, 1, 1, 1]
    summary = next(item for item in report.summaries if item.source == "euvd")
    assert summary.requests == 4


def test_enabling_cisa_catalog_refreshes_a_stale_view(tmp_path):
    base = write_config(tmp_path, sources=("nvd",), initial="backfill")
    raw = nvd_cve(
        cisaExploitAdd="2026-11-01",
        cisaActionDue="2026-11-20",
        cisaRequiredAction="Apply",
    )

    def only_nvd(request):
        return httpx.Response(200, json=nvd_page([raw]))

    run(base, handler_for(nvd=only_nvd))
    store = WatchStore(base.watch.database)
    old = store.view("CVE-2026-0001")
    assert old.cisa_kev_added == "2026-11-01"

    config = replace(
        base, watch=replace(base.watch, sources=("nvd", "cisa_kev"))
    )

    def with_empty_catalog(request):
        if str(request.url).startswith(CISA_URL):
            return httpx.Response(
                200, json={"count": 0, "vulnerabilities": []}
            )
        return httpx.Response(200, json=nvd_page([raw]))

    report = run(config, handler_for(nvd=with_empty_catalog, cisa=with_empty_catalog), now=NOW + timedelta(hours=1))
    assert not report.failures
    assert "CVE-2026-0001" in report.touched_ids
    new = store.view("CVE-2026-0001", catalogs=config.watch.sources)
    assert old.cisa_kev_added == "2026-11-01" and new.cisa_kev_added is None
    assert old.fingerprint() != new.fingerprint()
    with store._connect() as db:
        persisted = db.execute(
            "SELECT fingerprint FROM watch_view WHERE cve_id='CVE-2026-0001'"
        ).fetchone()[0]
    assert persisted == new.fingerprint()


def test_disabling_cisa_catalog_restores_nvd_fields_and_touches(tmp_path):
    config = write_config(
        tmp_path, sources=("nvd", "cisa_kev"), initial="backfill"
    )
    raw = nvd_cve(
        cisaExploitAdd="2026-11-01",
        cisaActionDue="2026-11-20",
        cisaRequiredAction="Apply",
    )

    def handler(request):
        if str(request.url).startswith(CISA_URL):
            return httpx.Response(
                200, json={"count": 0, "vulnerabilities": []}
            )
        return httpx.Response(200, json=nvd_page([raw]))

    run(
        config,
        handler_for(nvd=handler, cisa=handler),
    )
    store = WatchStore(config.watch.database)
    assert store.view("CVE-2026-0001", catalogs=config.watch.sources).cisa_kev_added is None

    disabled = replace(
        config, watch=replace(config.watch, sources=("nvd",))
    )
    report = run(
        disabled,
        handler_for(nvd=handler),
        now=NOW + timedelta(hours=1),
    )
    assert not report.failures
    assert "CVE-2026-0001" in report.touched_ids
    view = store.view("CVE-2026-0001")
    assert view.cisa_kev_added == "2026-11-01"



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
                        {"id": f"EUVD-{index}", "aliases": f"CVE-2026-{1000 + index}"}
                        for index in range(100)
                    ],
                },
            )
        return httpx.Response(500)

    report = run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert report.failures == ("euvd",)
    summary = next(item for item in report.summaries if item.source == "euvd")
    assert summary.requests == 2
    assert pages == [0, 1]


def test_failed_lookups_do_not_fail_the_run_or_exit_code(tmp_path, monkeypatch, capsys):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="baseline")

    def no_request(request):
        raise AssertionError("baseline must not query public sources")

    run(config, handler_for(nvd=no_request, cisa=no_request))
    catalog = [cisa_item("CVE-2026-9999", dateAdded="2026-11-03")]

    def nvd_request(request):
        if dict(request.url.params).get("cveId"):
            return httpx.Response(500)
        return httpx.Response(200, json=nvd_page([]))

    def cisa_request(request):
        return httpx.Response(
            200, json={"count": len(catalog), "vulnerabilities": catalog}
        )

    monkeypatch.setattr(
        cli,
        "HttpClient",
        lambda http_config: mock_client(
            handler_for(nvd=nvd_request, cisa=cisa_request)
        ),
    )
    assert cli.main(["--config", str(config.config_path), "watch", "sync"]) == 0
    output = capsys.readouterr().out
    assert "1 lookup(s) failed" in output
    assert cli.main(["--config", str(config.config_path), "watch", "status"]) == 0
    assert "lookups pending/backing off: 1" in capsys.readouterr().out


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
                        {"id": f"EUVD-{index}", "aliases": f"CVE-2026-{1000 + index}"}
                        for index in range(100)
                    ],
                },
            )
        return httpx.Response(200, json={"total": 100, "items": []})

    report = run(config, handler_for(nvd=nvd_request, euvd=euvd_request))
    assert report.failures == ("euvd",)
    assert pages == [0, 1] * 3
    assert metadata(config)["euvd_cursor"] == "2026-10-27"


def test_backfill_bounds_lookups_to_the_initial_window(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="backfill")
    catalog = [cisa_item("CVE-2026-0001", dateAdded="2026-10-01")]
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

    catalog.append(cisa_item("CVE-2026-0002", dateAdded="2026-11-02"))
    run(config, handler, now=NOW + timedelta(hours=1))
    assert looked_up == ["CVE-2026-0002"]


def test_full_mode_never_looks_up_kev_cves(tmp_path):
    config = write_config(tmp_path, sources=("nvd", "cisa_kev"), initial="full")

    def nvd_request(request):
        if dict(request.url.params).get("cveId"):
            raise AssertionError("full mode must not fetch KEV lookups")
        return httpx.Response(200, json=nvd_page([]))

    def cisa_request(request):
        return httpx.Response(
            200,
            json={"count": 1, "vulnerabilities": [cisa_item("CVE-2026-9999")]},
        )

    report = run(
        config,
        handler_for(nvd=nvd_request, cisa=cisa_request),
        assume_yes=True,
    )
    assert not report.failures
    assert metadata(config)["initial_mode"] == "full"
    assert metadata(config)["initial_window_start"] == "1999-01-01"
    assert WatchStore(config.watch.database).status()["lookups"] == 0


def test_initial_evaluation_is_marked_only_once(tmp_path):
    config = write_config(
        tmp_path,
        initial="backfill",
        extra="""
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["soc-email"]
""",
    )

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    handler = handler_for(nvd=nvd_request)
    first = run(config, handler)
    assert first.initial_evaluation is True
    store = WatchStore(config.watch.database)
    store.evaluate_touched(
        config.watch.rules,
        catalogs=config.watch.sources,
        initial=first.initial_evaluation,
    )
    second = run(config, handler, now=NOW + timedelta(hours=1))
    assert second.initial_evaluation is False
    assert all(event.initial for event in store.events())


def test_rule_epss_thresholds_reach_the_sync_touched_set(tmp_path):
    config = write_config(
        tmp_path,
        sources=("nvd", "epss"),
        initial="backfill",
        extra="""
[[watch.rules]]
name = "epss-watch"
condition = { epss_min = 0.3 }
channels = ["soc-email"]
""",
    )

    def nvd_request(request):
        return httpx.Response(200, json=nvd_page([nvd_cve()]))

    def epss_request(request):
        score = "0.4" if "2026-11-04" in str(request.url) else "0.2"
        day = "2026-11-04" if score == "0.4" else "2026-11-03"
        return httpx.Response(200, content=epss_gzip([epss_row() | {"epss": score}], score_date=day))

    handler = handler_for(nvd=nvd_request, epss=epss_request)
    first = run(config, handler)
    assert not first.failures
    assert "CVE-2026-0001" in first.touched_ids
    WatchStore(config.watch.database).acknowledge(first.touched_ids)

    second = run(config, handler, now=NOW + timedelta(days=1))
    assert not second.failures
    assert second.touched_ids == ("CVE-2026-0001",)
    result = WatchStore(config.watch.database).evaluate_touched(
        config.watch.rules, catalogs=config.watch.sources
    )
    assert result.by_kind == (("match", 1),)


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
    store = WatchStore(config.watch.database)
    view1 = store.view("CVE-2026-0001", catalogs=("nvd", "euvd"))
    view2 = store.view("CVE-2026-0002", catalogs=("nvd", "euvd"))
    assert view1.euvd_id == "EUVD-2026-8"
    assert view2.euvd_id == "EUVD-2026-9"
    assert not any(entry.provider == "euvd" for entry in view1.cvss)
    assert not any(entry.provider == "euvd" for entry in view2.cvss)
