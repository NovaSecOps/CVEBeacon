"""Channel test offer, submit and result pages."""

from __future__ import annotations

import re
import sys
import textwrap
import time

import pytest

from cvebeacon import dashboard
from cvebeacon.dashboard_jobs import JobStore, build_command
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from watch_support import write_config

PASSWORD = "Synthetic channel test password 123"
CHANNELS = """
[watch.channels.sink]
type = "webhook"
url = "http://127.0.0.1:9/sink"
allow_insecure = true

[watch.channels.paused]
type = "webhook"
enabled = false
url = "https://example.invalid/paused"
"""


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def fake_scheduler():
    def run(args, **kwargs):
        if args == ["crontab", "-l"]:
            return _Result(stdout="")
        return _Result()

    return run


def make_config(tmp_path):
    return write_config(
        tmp_path,
        sources=("nvd",),
        initial="baseline",
        channels=CHANNELS,
        extra="",
    )


def make_accounts(config):
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    for name in ("viewer", "tester", "empty"):
        users.add(name, password=PASSWORD)
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("viewer-only", {"view"}, authorization=admin)
    users.save_role("tester-only", {"view", "test_channel"}, authorization=admin)
    users.save_role("empty", set(), authorization=admin)
    for name, role in (
        ("viewer", "viewer-only"),
        ("tester", "tester-only"),
        ("empty", "empty"),
    ):
        users.edit_user(name, role=role, disabled=False, authorization=admin)
    return users


@pytest.fixture
def app_client(tmp_path):
    config = make_config(tmp_path)
    make_accounts(config)
    app = dashboard.create_app(config)
    app.extensions["dashboard_schedule_runner"] = fake_scheduler()
    client = app.test_client()
    yield config, app, client
    app.extensions["dashboard_jobs"].shutdown()


def csrf(client, path="/account"):
    page = client.get(path)
    assert page.status_code == 200
    return re.search(r'name="csrf" value="([^"]+)"', page.text)[1]


def login(client, username="admin"):
    token = csrf(client, "/login")
    response = client.post(
        "/login",
        data={"csrf": token, "username": username, "password": PASSWORD},
    )
    assert response.status_code == 303


def submit(client, path, **values):
    return client.post(path, data={"csrf": csrf(client), **values})


def fake_job(script, *arguments):
    return [sys.executable, "-c", textwrap.dedent(script), *map(str, arguments)]


def script_builder(script):
    """A fake command builder that ends its argv with the channel name."""

    def builder(config, operation, *, channel=None, **kwargs):
        return fake_job(script, channel)

    return builder


def set_builder(app, builder):
    app.extensions["dashboard_jobs"].command_builder = builder


def job_id(response):
    location = response.headers["Location"]
    return int(location.rstrip("/").rsplit("/", 1)[1])


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("condition was not reached in time")


def test_form_offers_a_test_for_an_enabled_channel(app_client):
    _, _, client = app_client
    login(client, "tester")
    page = client.get("/operations/channels/sink/test")
    assert page.status_code == 200
    assert 'Test channel "sink"' in page.text
    assert "Send a test message" in page.text
    assert 'action="/operations/channels/sink/test"' in page.text
    assert 'name="csrf"' in page.text
    assert "Nothing is sent until you press the button." in page.text


def test_disabled_and_unknown_channels_return_404(app_client):
    _, app, client = app_client
    login(client)
    assert client.get("/operations/channels/paused/test").status_code == 404
    assert client.get("/operations/channels/missing/test").status_code == 404
    assert submit(client, "/operations/channels/paused/test").status_code == 404
    assert submit(client, "/operations/channels/missing/test").status_code == 404
    assert app.extensions["dashboard_jobs"].store.recent() == ()


def test_submit_requires_permission_and_csrf(app_client):
    _, app, client = app_client
    login(client, "viewer")
    page = client.get("/operations/channels/sink/test")
    assert page.status_code == 200
    assert "Ask someone who may send tests." in page.text
    assert submit(client, "/operations/channels/sink/test").status_code == 403
    client.get("/logout")

    login(client, "tester")
    assert client.post("/operations/channels/sink/test", data={}).status_code == 400
    calls = []

    def builder(config, operation, *, channel=None, **kwargs):
        calls.append((operation, channel))
        return fake_job("print('sent')", channel)

    set_builder(app, builder)
    response = submit(client, "/operations/channels/sink/test")
    assert response.status_code == 303
    assert calls == [("notify-test", "sink")]
    identifier = job_id(response)
    assert response.headers["Location"] == f"/operations/channels/sink/test/{identifier}"
    job = app.extensions["dashboard_jobs"].wait(identifier)
    assert job.status == "succeeded"


def test_successful_result_uses_honest_copy_and_offers_next_steps(app_client):
    _, app, client = app_client
    login(client)
    set_builder(app, script_builder("print('accepted by the fake service')"))
    response = submit(client, "/operations/channels/sink/test")
    job = app.extensions["dashboard_jobs"].wait(job_id(response))

    page = client.get(f"/operations/channels/sink/test/{job.id}")
    assert page.status_code == 200
    assert (
        'The test message was accepted by "sink" (webhook). Accepted means the '
        "service took the message. Open the destination and check that it "
        "arrived before you rely on this channel."
    ) in page.text
    assert "Back to alert channels" in page.text
    assert "Choose alert rules" in page.text
    assert "Go to Home" in page.text
    assert "View the job" in page.text
    assert "accepted by the fake service" in page.text
    assert 'http-equiv="refresh"' not in page.text
    lowered = page.text.casefold()
    for word in ("protected", "working", "healthy", "all set", "not affected"):
        assert word not in lowered


def test_viewer_sees_the_result_without_edit_links(app_client):
    _, app, client = app_client
    login(client, "tester")
    set_builder(app, script_builder("print('sent')"))
    response = submit(client, "/operations/channels/sink/test")
    job = app.extensions["dashboard_jobs"].wait(job_id(response))
    client.get("/logout")

    login(client, "viewer")
    page = client.get(f"/operations/channels/sink/test/{job.id}")
    assert page.status_code == 200
    assert 'The test message was accepted by "sink" (webhook).' in page.text
    assert "Go to Home" in page.text
    assert "Back to alert channels" not in page.text
    assert "Choose alert rules" not in page.text


def test_failed_delivery_result_offers_retry_and_edit(app_client):
    _, app, client = app_client
    login(client)
    set_builder(app, script_builder("import sys; sys.exit(3)"))
    response = submit(client, "/operations/channels/sink/test")
    job = app.extensions["dashboard_jobs"].wait(job_id(response))

    page = client.get(f"/operations/channels/sink/test/{job.id}")
    assert page.status_code == 200
    assert "The test message was not delivered." in page.text
    assert (
        "Check that the address or webhook is correct, that the secret is still "
        "valid, and that this server can reach the service."
    ) in page.text
    assert "Send the test again" in page.text
    assert "Edit the channel" in page.text

    token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    again = client.post(
        "/operations/channels/sink/test", data={"csrf": token}
    )
    assert again.status_code == 303
    second = app.extensions["dashboard_jobs"].wait(job_id(again))
    assert second.id != job.id


def test_other_failure_shows_the_exit_meaning(app_client):
    _, app, client = app_client
    login(client)
    set_builder(app, script_builder("import sys; sys.exit(2)"))
    response = submit(client, "/operations/channels/sink/test")
    job = app.extensions["dashboard_jobs"].wait(job_id(response))
    page = client.get(f"/operations/channels/sink/test/{job.id}")
    assert page.status_code == 200
    assert "The test could not run. Validation or operational failure." in page.text


def test_queued_and_running_results_show_progress_without_claims(app_client):
    _, app, client = app_client
    login(client)
    set_builder(
        app,
        script_builder("import time; time.sleep(30)"),
    )
    manager = app.extensions["dashboard_jobs"]
    first_response = submit(client, "/operations/channels/sink/test")
    first_id = job_id(first_response)
    assert manager.wait(first_id, statuses=frozenset({"running"})).status == "running"

    running_page = client.get(f"/operations/channels/sink/test/{first_id}")
    assert running_page.status_code == 200
    assert 'Sending the test message to "sink"...' in running_page.text
    assert 'http-equiv="refresh"' in running_page.text
    assert 'The test message was accepted by "sink" (webhook).' not in running_page.text

    second_response = submit(client, "/operations/channels/sink/test")
    second_id = job_id(second_response)
    wait_for(lambda: manager.store.get(second_id).status == "queued")
    queued_page = client.get(f"/operations/channels/sink/test/{second_id}")
    assert queued_page.status_code == 200
    assert "The test is waiting to start." in queued_page.text
    assert "Queue position 1" in queued_page.text
    assert 'http-equiv="refresh"' in queued_page.text

    assert manager.cancel(second_id)
    assert manager.cancel(first_id)
    assert manager.wait(second_id).status == "cancelled"
    assert manager.wait(first_id).status == "cancelled"


def test_cancelled_test_result(app_client):
    _, app, client = app_client
    login(client)
    set_builder(
        app,
        script_builder(
            """
            import time
            for _ in range(3000):
                time.sleep(0.01)
            """
        ),
    )
    manager = app.extensions["dashboard_jobs"]
    response = submit(client, "/operations/channels/sink/test")
    identifier = job_id(response)
    assert manager.wait(identifier, statuses=frozenset({"running"}))
    assert manager.cancel(identifier)
    job = manager.wait(identifier)
    assert job.status == "cancelled"

    page = client.get(f"/operations/channels/sink/test/{job.id}")
    assert page.status_code == 200
    assert "The test was cancelled." in page.text
    assert 'http-equiv="refresh"' not in page.text


def test_result_rejects_foreign_jobs(app_client):
    config, app, client = app_client
    login(client)
    store = app.extensions["dashboard_jobs"].store

    scan = store.create("scan", "admin", ["cvebeacon", "scan"])
    other = store.create(
        "notify-test",
        "admin",
        build_command(config, "notify-test", channel="paused"),
    )
    empty = store.create("notify-test", "admin", [])

    assert client.get(f"/operations/channels/sink/test/{scan.id}").status_code == 404
    assert client.get(f"/operations/channels/sink/test/{other.id}").status_code == 404
    assert client.get(f"/operations/channels/sink/test/{empty.id}").status_code == 404
    assert client.get("/operations/channels/sink/test/999999").status_code == 404
    assert client.get("/operations/channels/sink/test/0").status_code == 404


def test_result_requires_view(app_client):
    config, app, client = app_client
    job = app.extensions["dashboard_jobs"].store.create(
        "notify-test",
        "admin",
        build_command(config, "notify-test", channel="sink"),
    )
    login(client, "empty")
    assert client.get(f"/operations/channels/sink/test/{job.id}").status_code == 403


def test_account_less_mode_explains_and_blocks_sending(tmp_path):
    config = make_config(tmp_path)
    app = dashboard.create_app(config)
    client = app.test_client()
    page = client.get("/operations/channels/sink/test")
    assert page.status_code == 200
    assert "Operations need an account" in page.text
    assert 'action="/operations/channels/sink/test"' not in page.text
    with client.session_transaction() as session:
        token = session["csrf"]
    response = client.post(
        "/operations/channels/sink/test", data={"csrf": token}
    )
    assert response.status_code == 403
    app.extensions["dashboard_jobs"].shutdown()


def test_existing_operations_test_route_still_redirects_to_the_job(app_client):
    _, app, client = app_client
    login(client)
    set_builder(app, script_builder("print('sent')"))
    response = submit(client, "/operations/test", channel="sink")
    assert response.status_code == 303
    identifier = job_id(response)
    assert response.headers["Location"] == f"/operations/jobs/{identifier}"
    assert app.extensions["dashboard_jobs"].wait(identifier).status == "succeeded"


def test_log_output_is_escaped(app_client):
    _, app, client = app_client
    login(client)
    set_builder(
        app,
        script_builder("print('<script>alert(1)</script>')"),
    )
    response = submit(client, "/operations/channels/sink/test")
    job = app.extensions["dashboard_jobs"].wait(job_id(response))
    page = client.get(f"/operations/channels/sink/test/{job.id}")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "<script>alert(1)</script>" not in page.text
