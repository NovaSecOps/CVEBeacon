"""Bulk import of authorised web sites from CSV or URL lists."""
import csv
from datetime import datetime, timedelta, timezone
import html
import io
import json
import re

import pytest

from cvebeacon import dashboard_web, web_assets, web_assets_import as imp
from cvebeacon.errors import ConfigurationError
from cvebeacon.locking import OperationLock
from cvebeacon.web_assets import paths, read_allowlist

from test_dashboard import setup  # noqa: F401  (fixture)
from test_dashboard_accounts import PASSWORD, accounts, csrf, login  # noqa: F401  (accounts is a fixture)
from test_dashboard_web import grant, save, web  # noqa: F401  (web is a fixture)

HEADER = "hostname,scheme,port,path,allow_redirects,max_redirects,expires_at,allow_private_address\n"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def fields(page):
    data = {}
    for tag in re.findall(r'<input[^>]*type="hidden"[^>]*>', page):
        name = re.search(r'name="([^"]+)"', tag)[1]
        data[name] = html.unescape(re.search(r'value="([^"]*)"', tag, re.S)[1])
    return data


def nested_forms(page):
    depth = 0
    for tag in re.findall(r"</?form\b", page):
        depth += -1 if tag == "</form" else 1
        if depth not in (0, 1):
            return True
    return depth != 0


def preview(client, text, client_name="Acme", **extra):
    return client.post("/web-assets/import/preview", data={
        "csrf": csrf(client), "client": client_name, "csv_text": text, **extra})


def do_import(client, text, client_name="Acme", attest=True, private=False, mutate=None):
    page = preview(client, text, client_name)
    assert page.status_code == 200, page.text
    data = fields(page.text)
    data.pop("csrf", None)
    data["csrf"] = csrf(client)
    if attest:
        data["attest"] = "yes"
    if private:
        data["attest_private"] = "yes"
    if mutate:
        mutate(data)
    return client.post("/web-assets/import/save", data=data)


def saved(config, name="Acme"):
    return read_allowlist(paths(config, name)[0], name)[0]["assets"]


def test_template_downloads_and_parses_to_two_rows(web):
    _, _, _, client = web
    response = client.get("/web-assets/import-template")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "web-sites-template.csv" in response.headers["Content-Disposition"]
    text = response.data.decode("utf-8")
    assert text.splitlines()[0] == HEADER.strip()
    assert "www.example.com,https,443,/,yes,2,,no" in text and "shop.example.com" in text
    records, unknown = imp.parse_rows(text, NOW)
    assert unknown == [] and [error for _, _, error in records] == [None, None]
    assert [entry["hostname"] for _, entry, _ in records] == ["www.example.com", "shop.example.com"]


def test_import_card_and_template_link_on_page(web):
    _, _, _, client = web
    page = client.get("/web-assets?client=Acme").text
    assert "/web-assets/import-template" in page and 'name="csv_file"' in page
    assert "<style" not in page.split("import-sites")[1].split("</form>")[0]


def test_fifty_rows_import_with_defaults_and_audit(web):
    config, users, _, client = web
    text = "hostname\n" + "".join(f"site{n}.example.com\n" for n in range(50))
    response = do_import(client, text)
    assert response.status_code == 303 and "imported=50" in response.headers["Location"]
    page = client.get(response.headers["Location"]).text
    assert "Imported 50 sites. Run detection when you" in page and "ready." in page
    assets = saved(config)
    assert len(assets) == 50
    first = assets[0]
    assert (first["scheme"], first["port"], first["path"]) == ("https", 443, "/")
    assert first["allow_redirects"] is True and first["max_redirects"] == 2
    assert first["allow_private_address"] is False and "expires_at" not in first
    assert {a["authorized_by"] for a in assets} == {"admin"}
    assert len({a["authorized_at"] for a in assets}) == 1
    entries = users.audit_entries()
    adds = [e for e in entries if e.action.startswith("web_asset_add:")]
    assert len(adds) == 50 and all("Acme" in e.action for e in adds)
    summary = [e for e in entries if e.action.startswith("web_asset_import:")]
    assert len(summary) == 1 and json.loads(summary[0].action.split(":", 1)[1]) == {"client": "Acme", "count": 50}
    assert not users.verify_audit()


def test_browser_cannot_supply_authorisation_fields(web):
    config, _, _, client = web
    text = "hostname,authorized_by,authorized_at\nforged.example.com,someone,2000-01-01T00:00:00Z\n"
    page = preview(client, text)
    assert "Ignored unknown column" in page.text
    assert do_import(client, text, mutate=lambda d: d.update(authorized_by="x")).status_code == 303
    entry = saved(config)[0]
    assert entry["authorized_by"] == "admin" and entry["authorized_at"].startswith(str(datetime.now(timezone.utc).year))


def test_url_list_with_and_without_header(web):
    config, _, _, client = web
    text = "https://shop.example.com/\nhttp://plain.example.com\nhttps://app.example.com:8443/app\n"
    assert do_import(client, text).status_code == 303
    rows = {a["hostname"]: a for a in saved(config)}
    assert (rows["shop.example.com"]["scheme"], rows["shop.example.com"]["port"], rows["shop.example.com"]["path"]) == ("https", 443, "/")
    assert (rows["plain.example.com"]["scheme"], rows["plain.example.com"]["port"]) == ("http", 80)
    assert (rows["app.example.com"]["port"], rows["app.example.com"]["path"]) == (8443, "/app")
    assert do_import(client, "url\nhttps://two.example.com:9443/x\n").status_code == 303
    two = next(a for a in saved(config) if a["hostname"] == "two.example.com")
    assert (two["scheme"], two["port"], two["path"]) == ("https", 9443, "/x")


@pytest.mark.parametrize("row,reason", [
    ("a.example.com,ftp,443,/,yes,2,,no", "scheme"),
    ("a.example.com,https,0,/,yes,2,,no", "port"),
    ("a.example.com,https,70000,/,yes,2,,no", "port"),
    ("a.example.com,https,443,about,yes,2,,no", "path"),
    ("a.example.com,https,443,/?q=1,yes,2,,no", "path"),
    ("a.example.com,https,443,/,maybe,2,,no", "yes or no"),
    ("a.example.com,https,443,/,yes,11,,no", "0 to 10"),
    ("a.example.com,https,443,/,yes,2,2000-01-01,no", "future"),
    ("a.example.com,https,443,/,yes,2,soon,no", "ISO"),
    ("https://a.example.com/x,https,443,/,yes,2,,no", "scheme"),
    ("a.example.com/path,https,443,/,yes,2,,no", "path"),
    ("user@a.example.com,https,443,/,yes,2,,no", "user name"),
    ("=cmd,https,443,/,yes,2,,no", "valid"),
    ("+1,https,443,/,yes,2,,no", "valid"),
    ("-bad.example.com,https,443,/,yes,2,,no", "valid"),
    ("a.example.com,https,443,/,yes,2,,no,extra", "more cells"),
])
def test_bad_rows_are_errors_and_good_rows_still_save(web, row, reason):
    config, _, _, client = web
    text = HEADER + row + "\ngood.example.com,https,443,/,yes,2,,no\n"
    page = preview(client, text)
    assert page.status_code == 200
    assert "Error" in page.text and reason in html.unescape(page.text)
    assert do_import(client, text).status_code == 303
    assert [a["hostname"] for a in saved(config)] == ["good.example.com"]


def test_row_numbers_and_normalised_expiry(web):
    config, _, _, client = web
    year = datetime.now(timezone.utc).year + 2
    text = HEADER + f"a.example.com,https,443,/,no,5,{year}-03-04,no\nb.example.com,,,,,,{year}-03-04T10:00:00+02:00,\n"
    assert do_import(client, text).status_code == 303
    a, b = saved(config)
    assert a["expires_at"] == f"{year}-03-04T23:59:59+00:00" and a["allow_redirects"] is False
    assert b["expires_at"] == f"{year}-03-04T08:00:00+00:00"


def test_duplicates_and_already_saved_are_skipped(web):
    config, _, _, client = web
    assert save(client, hostname="Saved.Example.com").status_code == 303
    text = ("hostname\nsaved.example.com\nnew.example.com\nNEW.example.com.\n"
            "other.example.com\n")
    page = preview(client, text).text
    assert "Already saved" in page and "Duplicate in this file" in page
    assert "Save 2 sites" in page
    assert do_import(client, text).status_code == 303
    assert [a["hostname"] for a in saved(config)] == ["Saved.Example.com", "new.example.com", "other.example.com"]


def test_conflicting_private_settings_for_one_endpoint_is_an_error(web):
    _, _, _, client = web
    page = preview(client, HEADER + "a.example.com,https,443,/,yes,2,,no\na.example.com,https,443,/x,yes,2,,yes\n").text
    assert "different private" in page and "Save 1 site" in page


def test_bounds_are_refused_politely(web):
    config, _, _, client = web
    cases = {
        "rows": "hostname\n" + "a.example.com\n" * 1001,
        "size": "hostname\n" + "#" * (256 * 1024),
        "empty": "  \n",
    }
    for text in cases.values():
        response = preview(client, text)
        assert response.status_code == 400 and "could not be checked" not in response.text
    assert "more than 1,000 rows" in preview(client, cases["rows"]).text
    assert "larger than 256 KiB" in preview(client, cases["size"]).text
    for data, message in ((b"\xff\xfe\x00bad", "UTF-8"), (b"hostname\n\x00\x01\x02", "binary"),
                          (b"\x89PNG\r\n\x1a\n\xff\xff", "UTF-8")):
        response = client.post("/web-assets/import/preview", data={
            "csrf": csrf(client), "client": "Acme", "csv_file": (io.BytesIO(data), "sites.csv")},
            content_type="multipart/form-data")
        assert response.status_code == 400 and message in response.text
    assert not paths(config, "Acme")[0].exists()


def test_file_upload_with_bom_is_accepted(web):
    config, _, _, client = web
    data = b"\xef\xbb\xbf" + HEADER.encode() + b"bom.example.com,https,443,/,yes,2,,no\r\n"
    response = client.post("/web-assets/import/preview", data={
        "csrf": csrf(client), "client": "Acme", "csv_file": (io.BytesIO(data), "sites.csv")},
        content_type="multipart/form-data")
    assert response.status_code == 200 and "Save 1 site" in response.text
    assert "bom.example.com" in response.text


def test_file_and_paste_together_are_refused(web):
    _, _, _, client = web
    response = client.post("/web-assets/import/preview", data={
        "csrf": csrf(client), "client": "Acme", "csv_text": "hostname\na.example.com",
        "csv_file": (io.BytesIO(b"hostname\nb.example.com\n"), "sites.csv")},
        content_type="multipart/form-data")
    assert response.status_code == 400 and "not both" in response.text


def test_total_past_one_thousand_assets_is_refused(web):
    config, _, _, client = web
    path, _ = paths(config, "Acme")
    document = {"client": "Acme", "assets": [
        {"hostname": f"s{n}.example.com", "scheme": "https", "port": 443, "path": "/",
         "authorized_by": "admin", "authorized_at": "2020-01-01T00:00:00+00:00"} for n in range(999)]}
    web_assets.save_allowlist(path, document)
    response = preview(client, "hostname\na.example.com\nb.example.com\n")
    assert response.status_code == 400 and "past 1,000" in response.text
    assert len(saved(config)) == 999


def test_attestation_is_required(web):
    config, users, _, client = web
    response = do_import(client, "hostname\na.example.com\n", attest=False)
    assert response.status_code == 400 and "Attest authorisation" in response.text
    assert not paths(config, "Acme")[0].exists()
    assert not any(e.action.startswith("web_asset") for e in users.audit_entries())


def test_private_addresses_need_a_second_confirmation(web):
    config, _, _, client = web
    text = HEADER + "10.0.0.5,http,80,/,yes,2,,yes\npublic.example.com,https,443,/,yes,2,,no\n"
    page = preview(client, text).text
    assert 'name="attest_private"' in page and "1 of these site" in page
    assert "all 2 sites listed above" in page
    response = do_import(client, text)
    assert response.status_code == 400 and "private addresses" in response.text
    assert not paths(config, "Acme")[0].exists()
    assert do_import(client, text, private=True).status_code == 303
    assert len(saved(config)) == 2
    assert 'name="attest_private"' not in preview(client, "hostname\nplain.example.com\n").text


def test_requests_without_csrf_permission_or_accounts_are_refused(web):
    config, users, app, client = web
    base = {"client": "Acme", "csv_text": "hostname\na.example.com\n"}
    for url in ("/web-assets/import/preview", "/web-assets/import/save"):
        assert client.post(url, data={**base, "attest": "yes"}).status_code == 400
        assert client.post(url, data={**base, "attest": "yes", "csrf": "wrong"}).status_code == 400
    login(client, "reader")
    token = csrf(client)
    for url in ("/web-assets/import/preview", "/web-assets/import/save"):
        assert client.post(url, data={**base, "csrf": token, "attest": "yes"}).status_code == 403
    assert not paths(config, "Acme")[0].exists()
    grant(users, {"view", "manage_web_assets"})
    login(client, "reader")
    assert do_import(client, "hostname\na.example.com\n").status_code == 303
    assert saved(config)[0]["authorized_by"] == "reader"


def test_no_accounts_refuses_import(setup):
    pytest.importorskip("cvebeacon_extensions")
    config, _, client = setup[:3]
    token = client.get("/").text
    for url in ("/web-assets/import/preview", "/web-assets/import/save"):
        response = client.post(url, data={"client": "Acme", "csv_text": "hostname\na.example.com\n",
                                          "attest": "yes", "version": "new", "digest": "0" * 64})
        assert response.status_code in {400, 403}
    assert not paths(config, "Acme")[0].exists()


def test_permission_revoked_before_commit_writes_nothing(web, monkeypatch):
    config, users, _, client = web
    grant(users, {"view", "manage_web_assets"})
    login(client, "reader")
    proof = users.authenticate("admin", PASSWORD)
    validate = dashboard_web.validate_allowlist

    def revoke(*args):
        validate(*args)
        users.save_role("web-editor", {"view"}, authorization=proof)

    page = preview(client, "hostname\na.example.com\n")
    data = fields(page.text)
    monkeypatch.setattr(dashboard_web, "validate_allowlist", revoke)
    data.update(csrf=csrf(client), attest="yes")
    assert client.post("/web-assets/import/save", data=data).status_code == 400
    assert not paths(config, "Acme")[0].exists()
    assert not any("a.example.com" in e.action for e in users.audit_entries())


def test_allowlist_changed_between_preview_and_save_writes_nothing(web):
    config, users, _, client = web
    page = preview(client, "hostname\na.example.com\n")
    data = fields(page.text)
    assert save(client, hostname="other.example.com").status_code == 303
    before = paths(config, "Acme")[0].read_bytes()
    data.update(csrf=csrf(client), attest="yes")
    response = client.post("/web-assets/import/save", data=data)
    assert response.status_code == 400 and imp.CHANGED in response.text
    assert paths(config, "Acme")[0].read_bytes() == before


def test_tampered_text_or_digest_writes_nothing(web):
    config, _, _, client = web
    text = "hostname\na.example.com\n"
    response = do_import(client, text, mutate=lambda d: d.update(csv_text="hostname\nb.example.com\n"))
    assert response.status_code == 400 and imp.CHANGED in response.text
    response = do_import(client, text, mutate=lambda d: d.update(digest="0" * 64))
    assert response.status_code == 400
    assert not paths(config, "Acme")[0].exists()


@pytest.mark.parametrize("token", [None, "unknown"])
def test_missing_or_unknown_preview_token_writes_nothing(web, token):
    config, _, _, client = web

    def mutate(data):
        if token is None:
            data.pop("preview_token", None)
        else:
            data["preview_token"] = token

    assert do_import(client, "hostname\na.example.com\n", mutate=mutate).status_code == 400
    assert not paths(config, "Acme")[0].exists()


def test_replacing_rows_and_digest_together_is_refused(web):
    config, _, _, client = web
    original = preview(client, "hostname\na.example.com\n")
    changed = preview(client, "hostname,allow_private_address\nb.example.com,yes\n")
    assert original.status_code == changed.status_code == 200
    data, replacement = fields(original.text), fields(changed.text)
    data.update(csv_text=replacement["csv_text"], digest=replacement["digest"],
                csrf=csrf(client), attest="yes", attest_private="yes")
    response = client.post("/web-assets/import/save", data=data)
    assert response.status_code == 400 and imp.CHANGED in response.text
    assert not paths(config, "Acme")[0].exists()


def test_preview_is_bound_to_the_canonical_client(web):
    config, _, _, client = web
    name = "Other Client"
    response = do_import(client, "hostname\na.example.com\n", mutate=lambda d: d.update(client=name))
    assert response.status_code == 400 and imp.CHANGED in response.text
    assert not paths(config, name)[0].exists()
    assert do_import(client, "hostname\na.example.com\n", mutate=lambda d: d.update(client="acme")).status_code == 303
    assert [a["hostname"] for a in saved(config)] == ["a.example.com"]


def test_preview_is_bound_to_the_signed_in_session(web):
    config, users, app, client = web
    grant(users, {"view", "manage_web_assets"})
    page = preview(client, "hostname\na.example.com\n")
    assert page.status_code == 200
    data = fields(page.text)
    other = app.test_client()
    login(other, "reader")
    response = other.post("/web-assets/import/save", data={**data, "csrf": csrf(other), "attest": "yes"})
    assert response.status_code == 400 and imp.CHANGED in response.text
    assert not paths(config, "Acme")[0].exists()


def test_preview_cannot_be_replayed_after_restoring_allowlist(web):
    config, users, _, client = web
    assert save(client, hostname="keep.example.com").status_code == 303
    path = paths(config, "Acme")[0]
    original = path.read_bytes()
    page = preview(client, "hostname\na.example.com\n")
    assert page.status_code == 200
    data = {**fields(page.text), "csrf": csrf(client), "attest": "yes"}
    assert client.post("/web-assets/import/save", data=data).status_code == 303
    web_assets.replace_bytes(path, original)
    audit = users.audit_entries()
    response = client.post("/web-assets/import/save", data=data)
    assert response.status_code == 400 and imp.CHANGED in response.text
    assert path.read_bytes() == original and users.audit_entries() == audit


def test_expired_preview_cannot_be_saved(web, monkeypatch):
    config, _, _, client = web
    clock = [100.0]
    monkeypatch.setattr(imp, "monotonic", lambda: clock[0], raising=False)
    page = preview(client, "hostname\na.example.com\n")
    assert page.status_code == 200
    clock[0] += 901
    response = client.post("/web-assets/import/save", data={**fields(page.text), "csrf": csrf(client), "attest": "yes"})
    assert response.status_code == 400 and imp.CHANGED in response.text
    assert not paths(config, "Acme")[0].exists()


def test_permission_revoked_during_preview_is_refused(web, monkeypatch):
    config, users, _, client = web
    grant(users, {"view", "manage_web_assets"})
    login(client, "reader")
    proof = users.authenticate("admin", PASSWORD)
    validate = dashboard_web.validate_allowlist

    def revoke(*args):
        validate(*args)
        users.save_role("web-editor", {"view"}, authorization=proof)

    monkeypatch.setattr(dashboard_web, "validate_allowlist", revoke)
    response = preview(client, "hostname\na.example.com\n")
    assert response.status_code == 403 and "Save 1 site" not in response.text
    assert not paths(config, "Acme")[0].exists()


def test_busy_lock_gives_409_and_no_write(web):
    config, users, _, client = web
    page = preview(client, "hostname\na.example.com\n")
    data = fields(page.text)
    data.update(csrf=csrf(client), attest="yes")
    lock = OperationLock(config, "web-assets")
    assert lock.acquire()
    try:
        response = client.post("/web-assets/import/save", data=data)
    finally:
        lock.release()
    assert response.status_code == 409
    assert not paths(config, "Acme")[0].exists()
    assert not any(e.action.startswith("web_asset") for e in users.audit_entries())


def test_companion_refusal_is_shown_and_nothing_saved(web, monkeypatch):
    config, users, _, client = web

    def refuse(*args):
        raise ConfigurationError("companion says no")

    monkeypatch.setattr(dashboard_web, "validate_allowlist", refuse)
    response = preview(client, "hostname\na.example.com\n")
    assert response.status_code == 400 and "companion says no" in response.text
    data = {"csrf": csrf(client), "client": "Acme", "csv_text": "hostname\na.example.com\n",
            "version": "new", "digest": imp.digest([]), "attest": "yes"}
    response = client.post("/web-assets/import/save", data=data)
    assert response.status_code == 400
    assert not paths(config, "Acme")[0].exists()
    assert not any(e.action.startswith("web_asset") for e in users.audit_entries())


def test_write_failure_rolls_back(web, monkeypatch):
    config, users, _, client = web
    assert save(client, hostname="keep.example.com").status_code == 303
    before = paths(config, "Acme")[0].read_bytes()
    page = preview(client, "hostname\na.example.com\n")
    data = fields(page.text)
    data.update(csrf=csrf(client), attest="yes")
    real = imp.save_allowlist

    def fail(path, document):
        real(path, document)
        raise OSError("disk")

    monkeypatch.setattr(imp, "save_allowlist", fail)
    assert client.post("/web-assets/import/save", data=data).status_code == 400
    assert paths(config, "Acme")[0].read_bytes() == before
    assert not any("a.example.com" in e.action for e in users.audit_entries())
    monkeypatch.setattr(imp, "save_allowlist", real)
    assert client.post("/web-assets/import/save", data=data).status_code == 303


def test_new_client_name_creates_allowlist(web):
    config, _, _, client = web
    assert not paths(config, "Brand New Client")[0].exists()
    assert do_import(client, "hostname\nfresh.example.com\n", "Brand New Client").status_code == 303
    assert [a["hostname"] for a in saved(config, "Brand New Client")] == ["fresh.example.com"]


def test_formula_cells_are_text_and_rejected(web):
    config, _, _, client = web
    text = HEADER + "=HYPERLINK(1),https,443,/,yes,2,,no\n@SUM(1),https,443,/,yes,2,,no\n"
    page = preview(client, text)
    assert page.status_code == 200 and "Nothing to add" in page.text
    assert not paths(config, "Acme")[0].exists()


def test_confirmation_page_markup_and_csp(web):
    _, _, _, client = web
    response = preview(client, HEADER + "10.0.0.5,http,80,/,yes,2,,yes\n")
    page = response.text
    assert not re.search(r"<script(?![^>]*\ssrc=)|style=|\son[a-z]+=", page)
    assert not nested_forms(page)
    assert "unsafe-inline" not in response.headers.get("Content-Security-Policy", "")
    index = client.get("/web-assets?client=Acme").text
    assert not re.search(r"<script(?![^>]*\ssrc=)|style=", index.split('id="import-sites"')[1][:3000])
    assert not nested_forms(index)


def test_import_endpoints_have_their_own_request_limits(web):
    _, _, app, client = web
    big = "hostname\n" + "a" * (1024 * 1024 + 10)
    response = client.post("/web-assets/import/preview", data={
        "csrf": csrf(client), "client": "Acme", "csv_text": big})
    assert response.status_code == 413
    other = client.post("/web-assets/save", data={"csrf": "x", "client": "Acme", "pad": "a" * 9000})
    assert other.status_code in {400, 403, 413}
