from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cvebeacon.config import load_config
from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.channels import ChannelConfig, SecretRef


def write(tmp_path: Path, body: str):
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return load_config(path)


WATCH = """
[watch]
enabled = true
sources = ["nvd"]
"""

ALL_CHANNELS = WATCH + """
[watch.channels.mail]
type = "smtp"
host = "smtp.example.org"
port = 587
security = "starttls"
username = "beacon"
password_env = "TEST_SMTP_PASSWORD"
from = "beacon@example.org"
to = ["soc@example.org", "oncall@example.org"]
cc = ["cc@example.org"]
bcc = ["archive@example.org"]

[watch.channels.graph]
type = "graph"
tenant_id = "tenant"
client_id = "client"
client_secret_env = "TEST_GRAPH_SECRET"
sender = "beacon@example.org"
to = ["soc@example.org"]

[watch.channels.teams]
type = "teams"
webhook_url_env = "TEST_TEAMS_URL"

[watch.channels.slack]
type = "slack"
webhook_url_env = "TEST_SLACK_URL"
grouping = "event"
max_items = 5
min_interval_seconds = 2

[watch.channels.discord]
type = "discord"
webhook_url_env = "TEST_DISCORD_URL"

[watch.channels.telegram]
type = "telegram"
bot_token_env = "TEST_TELEGRAM_TOKEN"
chat_id = -1001234567890

[watch.channels.matrix]
type = "matrix"
homeserver = "https://matrix.example.org"
room_id = "!room:example.org"
access_token_env = "TEST_MATRIX_TOKEN"

[watch.channels.ntfy]
type = "ntfy"
topic = "cvebeacon"
token_env = "TEST_NTFY_TOKEN"
priority = 5

[watch.channels.gotify]
type = "gotify"
server = "https://gotify.example.org"
app_token_env = "TEST_GOTIFY_TOKEN"
priority = 8

[watch.channels.hook]
type = "webhook"
url = "https://example.org/hook"
header_name = "X-Beacon-Secret"
header_value_env = "TEST_HOOK_SECRET"

[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["mail", "hook"]
"""


def set_secrets(monkeypatch) -> None:
    for name in (
        "TEST_SMTP_PASSWORD",
        "TEST_GRAPH_SECRET",
        "TEST_TEAMS_URL",
        "TEST_SLACK_URL",
        "TEST_DISCORD_URL",
        "TEST_TELEGRAM_TOKEN",
        "TEST_MATRIX_TOKEN",
        "TEST_NTFY_TOKEN",
        "TEST_GOTIFY_TOKEN",
        "TEST_HOOK_SECRET",
    ):
        monkeypatch.setenv(name, "canary-" + name.casefold())
    monkeypatch.setenv("TEST_TEAMS_URL", "https://example.webhook.office.com/webhookb2/abc")
    monkeypatch.setenv(
        "TEST_SLACK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    )
    monkeypatch.setenv(
        "TEST_DISCORD_URL",
        "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz",
    )


def test_every_channel_type_parses(tmp_path, monkeypatch):
    set_secrets(monkeypatch)
    config = write(tmp_path, ALL_CHANNELS)
    channels = {channel.name: channel for channel in config.watch.channels}
    assert set(channels) == {
        "mail",
        "graph",
        "teams",
        "slack",
        "discord",
        "telegram",
        "matrix",
        "ntfy",
        "gotify",
        "hook",
    }
    mail = channels["mail"]
    assert mail.type == "smtp"
    assert mail.options["host"] == "smtp.example.org"
    assert mail.options["to"] == ("soc@example.org", "oncall@example.org")
    assert mail.options["cc"] == ("cc@example.org",)
    assert mail.secret("password").resolve() == "canary-test_smtp_password"
    assert channels["slack"].grouping == "event"
    assert channels["slack"].max_items == 5
    assert channels["slack"].min_interval_seconds == 2
    assert channels["telegram"].options["chat_id"] == "-1001234567890"
    assert channels["telegram"].min_interval_seconds == 3
    assert channels["ntfy"].options["server"] == "https://ntfy.sh"
    assert channels["ntfy"].options["priority"] == 5
    assert channels["gotify"].options["priority"] == 8
    assert channels["hook"].options["header_name"] == "X-Beacon-Secret"


def test_channel_name_is_validated(tmp_path):
    with pytest.raises(ConfigurationError, match="watch channel name"):
        write(tmp_path, WATCH + '[watch.channels."bad name"]\ntype = "teams"\nwebhook_url_env = "X"\n')


def test_unknown_channel_type_and_key_are_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="must be one of"):
        write(tmp_path, WATCH + '[watch.channels.a]\ntype = "pager"\n')
    with pytest.raises(ConfigurationError, match="unknown key"):
        write(tmp_path, WATCH + '[watch.channels.a]\ntype = "teams"\nwebhook_url_env = "X"\nmagic = 1\n')


def test_rule_must_name_a_configured_channel(tmp_path):
    with pytest.raises(ConfigurationError) as excinfo:
        write(
            tmp_path,
            WATCH
            + """
[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["missing"]
""",
        )
    message = str(excinfo.value)
    assert "critical" in message
    assert "missing" in message


def test_disabled_channel_is_allowed_for_a_rule(tmp_path):
    config = write(
        tmp_path,
        WATCH
        + """
[watch.channels.off]
type = "webhook"
enabled = false
url = "https://example.org/hook"

[[watch.rules]]
name = "critical"
condition = { cvss_min = 9 }
channels = ["off"]
""",
    )
    assert config.watch.channels[0].enabled is False


def test_secret_file_must_be_private_and_is_stripped(tmp_path):
    secret = tmp_path / "token.txt"
    secret.write_text("  s3cret\n", encoding="utf-8")
    os.chmod(secret, 0o600)
    config = write(
        tmp_path,
        WATCH
        + f"""
[watch.channels.hook]
type = "webhook"
url = "https://example.org/hook"
header_name = "X-Auth"
header_value_file = "{secret.name}"
""",
    )
    reference = config.watch.channels[0].secret("header_value")
    assert isinstance(reference, SecretRef)
    assert reference.peek() == "s3cret"
    assert reference.resolve() == "s3cret"

    if os.name != "posix":
        return  # POSIX permission bits are not enforced on Windows; administrators use ACLs.
    os.chmod(secret, 0o644)
    with pytest.raises(ConfigurationError, match="group or other"):
        write(
            tmp_path,
            WATCH
            + f"""
[watch.channels.hook]
type = "webhook"
url = "https://example.org/hook"
header_name = "X-Auth"
header_value_file = "{secret.name}"
""",
        )


def test_secret_file_is_bounded(tmp_path):
    secret = tmp_path / "big.txt"
    secret.write_bytes(b"x" * (16 * 1024 + 1))
    os.chmod(secret, 0o600)
    with pytest.raises(ConfigurationError, match="at most"):
        write(
            tmp_path,
            WATCH
            + f"""
[watch.channels.hook]
type = "webhook"
url = "https://example.org/hook"
header_name = "X-Auth"
header_value_file = "{secret.name}"
""",
        )


def test_each_secret_pair_requires_a_reference(tmp_path):
    with pytest.raises(ConfigurationError, match="requires webhook_url_env or webhook_url_file"):
        write(tmp_path, WATCH + '[watch.channels.a]\ntype = "teams"\n')
    with pytest.raises(ConfigurationError, match="requires bot_token_env or bot_token_file"):
        write(
            tmp_path,
            WATCH + '[watch.channels.a]\ntype = "telegram"\nchat_id = 1\n',
        )


def test_smtp_security_none_requires_allow_insecure(tmp_path, caplog):
    with pytest.raises(ConfigurationError, match="allow_insecure"):
        write(
            tmp_path,
            WATCH
            + """
[watch.channels.mail]
type = "smtp"
host = "127.0.0.1"
security = "none"
from = "beacon@example.org"
to = ["soc@example.org"]
""",
        )
    config = write(
        tmp_path,
        WATCH
        + """
[watch.channels.mail]
type = "smtp"
host = "127.0.0.1"
security = "none"
allow_insecure = true
from = "beacon@example.org"
to = ["soc@example.org"]
""",
    )
    assert config.watch.channels[0].options["port"] == 25
    assert any("without TLS" in record.message for record in caplog.records)


def test_telegram_requires_a_three_second_interval(tmp_path):
    with pytest.raises(ConfigurationError, match="at least 3"):
        write(
            tmp_path,
            WATCH
            + """
[watch.channels.tg]
type = "telegram"
bot_token_env = "TOKEN"
chat_id = 1
min_interval_seconds = 1
""",
        )


@pytest.mark.parametrize(
    "body,match",
    [
        (
            'type = "slack"\nwebhook_url_env = "URL"\n',
            "hooks.slack.com",
        ),
        (
            'type = "discord"\nwebhook_url_env = "URL"\n',
            "Discord webhook URL",
        ),
        (
            'type = "webhook"\nurl = "http://example.org/hook"\n',
            "HTTPS",
        ),
        (
            'type = "gotify"\nserver = "http://example.org"\napp_token_env = "X"\n',
            "HTTPS",
        ),
        (
            'type = "matrix"\nhomeserver = "https://matrix.example.org/path"\n'
            'room_id = "!room:example.org"\naccess_token_env = "X"\n',
            "origin",
        ),
        (
            'type = "matrix"\nhomeserver = "https://matrix.example.org"\n'
            'room_id = "room"\naccess_token_env = "X"\n',
            "Matrix room id",
        ),
        (
            'type = "ntfy"\ntopic = "bad topic"\n',
            "letters, digits",
        ),
        (
            'type = "ntfy"\ntopic = "ok"\npriority = 6\n',
            "integer from 1 to 5",
        ),
        (
            'type = "telegram"\nbot_token_env = "X"\nchat_id = "not a chat"\n',
            "chat id",
        ),
    ],
)
def test_channel_specific_validation(tmp_path, monkeypatch, body, match):
    # Each snippet starts a channel table; the invalid value is the last key.
    monkeypatch.setenv("URL", "https://example.org/hook")
    with pytest.raises(ConfigurationError, match=match):
        write(tmp_path, WATCH + "[watch.channels.a]\n" + body)


def test_webhook_http_is_allowed_only_with_allow_insecure(tmp_path):
    config = write(
        tmp_path,
        WATCH
        + """
[watch.channels.a]
type = "webhook"
url = "http://127.0.0.1:8080/hook"
allow_insecure = true
""",
    )
    assert config.watch.channels[0].options["url"].startswith("http://")


def test_webhook_header_needs_a_value_and_name(tmp_path):
    with pytest.raises(ConfigurationError, match="header_value_env"):
        write(
            tmp_path,
            WATCH
            + """
[watch.channels.a]
type = "webhook"
url = "https://example.org/hook"
header_name = "X-Auth"
""",
        )
    with pytest.raises(ConfigurationError, match="header_name"):
        write(
            tmp_path,
            WATCH
            + """
[watch.channels.a]
type = "webhook"
url = "https://example.org/hook"
header_value_env = "SECRET"
""",
        )


def test_channel_number_limits_are_strict(tmp_path):
    for snippet, match in (
        ('max_items = 0\n', "max_items"),
        ('max_items = 101\n', "max_items"),
        ('min_interval_seconds = 3601\n', "min_interval_seconds"),
        ('timeout_seconds = 0\n', "timeout_seconds"),
        ('grouping = "daily"\n', "grouping"),
        ('enabled = "yes"\n', "true or false"),
    ):
        with pytest.raises(ConfigurationError, match=match):
            write(
                tmp_path,
                WATCH
                + '[watch.channels.a]\ntype = "webhook"\nurl = "https://example.org/hook"\n'
                + snippet,
            )


def test_watch_channels_must_be_a_table(tmp_path):
    with pytest.raises(ConfigurationError, match="must be a table"):
        write(tmp_path, WATCH + "channels = true\n")


def test_secret_env_names_are_validated_without_echoing_the_value(tmp_path):
    canary = "123456:CANARY-PASTED-TOKEN"
    with pytest.raises(ConfigurationError) as excinfo:
        write(
            tmp_path,
            WATCH
            + f"""
[watch.channels.a]
type = "telegram"
bot_token_env = "{canary}"
chat_id = 1
""",
        )
    message = str(excinfo.value)
    assert canary not in message
    assert "must be an environment variable name" in message


def test_runtime_secret_errors_do_not_echo_a_bad_env_name():
    reference = SecretRef("bot token", "123456:CANARY-PASTED-TOKEN")
    with pytest.raises(ConfigurationError) as excinfo:
        reference.resolve()
    message = str(excinfo.value)
    assert "CANARY" not in message
    assert "is not set" in message
