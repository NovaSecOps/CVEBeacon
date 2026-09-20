from types import SimpleNamespace

import httpx
import pytest

from cvebeacon.config import HttpConfig
from cvebeacon.errors import SchedulingError, SourceError
from cvebeacon.http import HttpClient
from cvebeacon.scheduling import install, make_plan


@pytest.mark.parametrize("hours", [5, 7, 11, 13, 23])
def test_cron_cannot_silently_run_at_shorter_midnight_interval(tmp_path, monkeypatch, hours):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    with pytest.raises(SchedulingError, match="divide 24"):
        make_plan(tmp_path / "config", hours)


def test_cron_read_permission_failure_never_writes(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout="", stderr="permission denied")
    with pytest.raises(SchedulingError): install(make_plan(tmp_path / "config", 4), run=run)
    assert calls == [["crontab", "-l"]]


def test_cron_percent_path_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("cvebeacon.scheduling.platform.system", lambda: "Linux")
    with pytest.raises(SchedulingError, match="percent"):
        make_plan(tmp_path / "config%name", 4)


def test_upstream_message_header_cannot_leak_secrets():
    raw = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(400, headers={"message": "token=topsecret"})))
    with pytest.raises(SourceError) as error:
        HttpClient(HttpConfig(), client=raw).post_json("https://example.test/topsecret", source="teams")
    assert "topsecret" not in str(error.value)


def test_redirect_cannot_forward_credentials_or_fake_acceptance():
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(307, headers={"Location": "https://other.example.test/collect"})
    raw = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    with pytest.raises(SourceError):
        HttpClient(HttpConfig(), client=raw).post_json("https://example.test/token", source="graph_token", data={"client_secret": "secret"})
    assert len(requests) == 1


def test_invalid_retry_after_falls_back():
    assert HttpClient._retry_after("NaN", 2) == 2


@pytest.mark.parametrize("failure", ["500", "connect", "truncated"])
def test_http_failure_never_returns_an_empty_success(failure):
    calls = []
    def handler(request):
        calls.append(request)
        if failure == "connect": raise httpx.ConnectError("DNS failed secret", request=request)
        if failure == "500": return httpx.Response(500)
        return httpx.Response(200, content=b'{"items": [')
    client = HttpClient(HttpConfig(retries=1), client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)
    with pytest.raises(SourceError) as error:
        client.get_json("https://example.test/secret", source="nvd")
    assert "secret" not in str(error.value)
    assert len(calls) == (1 if failure == "truncated" else 2)
