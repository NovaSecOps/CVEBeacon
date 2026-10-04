import ssl

import pytest

from cvebeacon_automation.common import AutomationError
from cvebeacon_automation.http import HTTPS, TransportError, endpoint, tls_context


@pytest.mark.parametrize("url", ["http://example.invalid", "https://user:secret@example.invalid", "https://example.invalid/#fragment", "https://example.invalid\\evil", "https://example.invalid\nX: bad", "https://example.invalid:99999", "https://[fe80::1%eth0]/"])
def test_https_strict(url):
    with pytest.raises(AutomationError):
        endpoint(url)


def test_no_env_tls_keylogging(monkeypatch, tmp_path):
    canary = tmp_path / "keys.txt"
    monkeypatch.setenv("SSLKEYLOGFILE", str(canary))
    context = tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.keylog_filename is None
    assert not canary.exists()


def test_origin_allowlist_rejects_without_network():
    transport = HTTPS("https://approved.invalid")
    with pytest.raises(TransportError, match="endpoint_outside_allowlist"):
        transport.request("POST", "https://attacker.invalid", body=b"secret")


def test_bounded_request_rejects_before_network():
    transport = HTTPS("https://approved.invalid", max_body=8)
    with pytest.raises(TransportError, match="http_body_limit"):
        transport.request("POST", "https://approved.invalid", body=b"123456789")
