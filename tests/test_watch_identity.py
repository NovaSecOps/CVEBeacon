from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone

import pytest
from watch_support import NOW, write_config

from cvebeacon import cli
from cvebeacon.errors import ConfigurationError, StateError
from cvebeacon.passwords import (
    DUMMY_HASH,
    hash_password_value,
    read_new_password,
    validate_password,
    verify_password,
)
from cvebeacon.watch.records import ReportedMark, WatchRecord
from cvebeacon.watch.reporting import ReportService
from cvebeacon.watch.reported import identity_label
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.users import UserStore

PASSWORD = "correct horse battery staple"
IDENTIFIER = "CVE-2026-0001"


def config_with(tmp_path, extra: str = "", *, channels: str = ""):
    return write_config(tmp_path, channels=channels, extra=extra)


def reporting(mode: str) -> str:
    return f'\n[watch.reporting]\nidentity = "{mode}"\n'


def open_report(store, *args, **kwargs):
    return ReportService(store, None, "open").report_cve(*args, **kwargs)


def open_unreport(store, *args, **kwargs):
    return ReportService(store, None, "open").unreport_cve(*args, **kwargs)


def seed(config) -> WatchStore:
    store = WatchStore(config.watch.database, clock=lambda: NOW)
    store.upsert_nvd(
        [
            WatchRecord(
                IDENTIFIER,
                "published",
                description="Acme Widget allows remote code execution.",
            )
        ],
        catalogs=config.watch.sources,
    )
    return store


def prompt(monkeypatch, *values: str) -> None:
    pending = iter(values)
    monkeypatch.setattr(
        "cvebeacon.passwords.getpass.getpass", lambda _: next(pending)
    )


def no_prompt(monkeypatch) -> None:
    def fail(_):
        raise AssertionError("a password prompt should not run")

    monkeypatch.setattr("cvebeacon.passwords.getpass.getpass", fail)


def audit_rows(path) -> list[tuple]:
    with sqlite3.connect(path) as db:
        return db.execute(
            "SELECT action,username,os_account,host FROM cb_user_audit ORDER BY id"
        ).fetchall()


def test_identity_config_defaults_and_accepts_each_mode(tmp_path):
    assert config_with(tmp_path).watch.reporting_identity == "open"
    for mode in ("open", "registered", "authenticated"):
        config = config_with(tmp_path, reporting(mode.upper()))
        assert config.watch.reporting_identity == mode


@pytest.mark.parametrize(
    "extra,match",
    [
        ('\n[watch.reporting]\nidentity = "trusted"\n', "identity"),
        ('\n[watch.reporting]\nmode = "open"\n', "unknown watch.reporting"),
        ('\n[watch.reporting]\nidentity = ""\n', "identity"),
        ('\n[watch.reporting]\nidentity = true\n', "identity"),
    ],
)
def test_identity_config_is_strict(tmp_path, extra, match):
    with pytest.raises(ConfigurationError, match=match):
        config_with(tmp_path, extra)


def test_users_database_sits_beside_the_watch_database(tmp_path):
    config = config_with(tmp_path)
    assert config.watch.users_database == (tmp_path / "cvebeacon-users.db")


def test_password_hash_matches_the_dashboard_scheme():
    first = hash_password_value(PASSWORD)
    second = hash_password_value(PASSWORD)
    assert first.startswith("scrypt:32768:8:1$")
    assert first != second
    assert verify_password(first, PASSWORD)
    assert not verify_password(first, "wrong password value")
    assert not verify_password(first, "")
    assert not verify_password("plaintext", PASSWORD)
    assert len(DUMMY_HASH.split("$")) == 3
    assert DUMMY_HASH.startswith("scrypt:32768:8:1$")


@pytest.mark.parametrize(
    "value,error",
    [
        ("short", "12–1024"),
        ("x" * 1025, "12–1024"),
        (" " * 12, "12–1024"),
    ],
)
def test_password_length_and_whitespace_rules(value, error):
    with pytest.raises(ConfigurationError, match=error):
        validate_password(value)


def test_password_rejects_the_username_or_email():
    forbidden = ("alice-alice-alice", "alice@example.com")
    for value in forbidden:
        with pytest.raises(ConfigurationError, match="username or email"):
            validate_password(value, forbidden=forbidden)
    for value in ("ALICE-ALICE-ALICE", "ALICE@EXAMPLE.COM"):
        with pytest.raises(ConfigurationError, match="username or email"):
            validate_password(value, forbidden=forbidden)
    validate_password("x" * 12, forbidden=forbidden)


def test_new_password_prompts_twice_and_checks_confirmation(monkeypatch):
    prompt(monkeypatch, PASSWORD, PASSWORD)
    assert read_new_password("Password: ") == PASSWORD

    prompt(monkeypatch, PASSWORD, PASSWORD + "x")
    with pytest.raises(ConfigurationError, match="confirmation"):
        read_new_password("Password: ")


def test_new_password_refuses_an_echoing_terminal(monkeypatch):
    import getpass
    import warnings

    def echoing(_):
        warnings.warn("no terminal", getpass.GetPassWarning)

    monkeypatch.setattr("cvebeacon.passwords.getpass.getpass", echoing)
    with pytest.raises(ConfigurationError, match="hidden password input"):
        read_new_password("Password: ")


def test_add_stores_a_hash_and_never_a_password(tmp_path):
    path = tmp_path / "users.db"
    store = UserStore(path, clock=lambda: NOW)
    user = store.add(
        "alice",
        password=PASSWORD,
        display_name="Alice Smith",
        email="alice@example.com",
        is_admin=True,
    )
    assert (user.username, user.display_name, user.email, user.is_admin) == (
        "alice",
        "Alice Smith",
        "alice@example.com",
        True,
    )
    assert "password_hash" not in repr(user)
    with sqlite3.connect(path) as db:
        encoded = db.execute(
            "SELECT password_hash FROM cb_user WHERE username='alice'"
        ).fetchone()[0]
    assert encoded.startswith("scrypt:32768:8:1$")
    assert verify_password(encoded, PASSWORD)
    assert PASSWORD not in encoded


def test_users_database_is_owner_only_on_posix(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permissions only")
    path = tmp_path / "users.db"
    UserStore(path, clock=lambda: NOW).add("alice")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"username": ""}, "username"),
        ({"username": "x" * 65}, "username"),
        ({"username": "alice smith"}, "username"),
        ({"username": "ali/ce"}, "username"),
        ({"username": "alice", "display_name": "x" * 101}, "display name"),
        ({"username": "alice", "display_name": "ali\nce"}, "display name"),
        ({"username": "alice", "email": "not-an-email"}, "email"),
        ({"username": "alice", "password": "short"}, "12–1024"),
    ],
)
def test_user_validation(tmp_path, kwargs, match):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    with pytest.raises(ConfigurationError, match=match):
        store.add(**kwargs)
    assert store.users() == ()


def test_usernames_and_emails_are_unique_case_insensitively(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", email="alice@example.com")
    with pytest.raises(ConfigurationError, match="already registered"):
        store.add("ALICE")
    with pytest.raises(ConfigurationError, match="already registered"):
        store.add("bob", email="ALICE@EXAMPLE.COM")
    with pytest.raises(ConfigurationError, match="already registered"):
        store.add("bob", email="Alice@Example.com")
    store.add("carol", email="carol@example.com")
    with pytest.raises(ConfigurationError, match="already registered"):
        store.add("CAROL@EXAMPLE.COM")


def test_users_without_passwords_are_registered_but_cannot_log_in(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    user = store.add("alice", display_name="Alice Smith")
    assert store.resolve_enabled("alice") == user
    assert store.authenticate("alice", "") is None
    assert store.authenticate("alice", PASSWORD) is None


def test_authentication_uses_the_username_not_the_email(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add(
        "alice",
        password=PASSWORD,
        display_name="Alice Smith",
        email="alice@example.com",
    )
    assert store.authenticate("alice", PASSWORD).username == "alice"
    assert store.authenticate("ALICE", PASSWORD).username == "alice"
    assert store.authenticate("alice@example.com", PASSWORD) is None
    assert store.authenticate("ALICE@EXAMPLE.COM", PASSWORD) is None
    assert store.authenticate("alice", "wrong password value") is None
    assert store.authenticate("nobody", PASSWORD) is None
    assert store.resolve_enabled("alice@example.com").username == "alice"


def test_unknown_and_disabled_users_run_the_dummy_hash(
    tmp_path, monkeypatch
):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", password=PASSWORD)
    calls: list[str] = []
    monkeypatch.setattr(
        "cvebeacon.watch.users.verify_password",
        lambda encoded, password: calls.append(encoded) or False,
    )
    assert store.authenticate("nobody", PASSWORD) is None
    assert calls == [DUMMY_HASH]
    store.disable("alice")
    calls.clear()
    assert store.authenticate("alice", PASSWORD) is None
    assert calls == [DUMMY_HASH]


def test_lockout_after_five_failures_and_unlock(tmp_path):
    now = [NOW]
    store = UserStore(tmp_path / "users.db", clock=lambda: now[0])
    store.add("alice", password=PASSWORD)
    for _ in range(5):
        assert store.authenticate("alice", "wrong password value") is None
    locked = store.find("alice")
    assert locked is not None and locked.failed_logins == 5
    assert locked.locked_until is not None
    assert store.authenticate("alice", PASSWORD) is None
    now[0] = NOW + timedelta(minutes=16)
    assert store.authenticate("alice", PASSWORD).username == "alice"
    unlocked = store.find("alice")
    assert unlocked.failed_logins == 0 and unlocked.locked_until is None

    for _ in range(5):
        store.authenticate("alice", "wrong password value")
    assert store.find("alice").locked_until is not None
    store.unlock("alice")
    assert store.authenticate("alice", PASSWORD).username == "alice"


def test_success_resets_the_consecutive_failure_count(tmp_path):
    now = [NOW]
    store = UserStore(tmp_path / "users.db", clock=lambda: now[0])
    store.add("alice", password=PASSWORD)
    for _ in range(4):
        store.authenticate("alice", "wrong password value")
    assert store.authenticate("alice", PASSWORD).username == "alice"
    for _ in range(4):
        store.authenticate("alice", "wrong password value")
    current = store.find("alice")
    assert current.failed_logins == 4
    assert current.locked_until is None


def test_user_admin_actions_are_audited(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", password=PASSWORD)
    store.set_password("alice", PASSWORD + " two")
    store.disable("alice")
    store.enable("alice")
    store.unlock("alice")
    entries = store.audit_entries()
    assert [entry.action for entry in entries] == [
        "add",
        "passwd",
        "disable",
        "enable",
        "unlock",
    ]
    assert all(entry.username == "alice" for entry in entries)
    assert all(entry.os_account and entry.host for entry in entries)
    assert store.verify_audit() is None


def test_failed_logins_are_audited_without_the_password(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", password=PASSWORD)
    store.authenticate("alice", "wrong password value")
    store.authenticate("ali\nce", "wrong password value")
    rows = audit_rows(store.path)
    assert rows[-2][0] == "login_failed" and rows[-2][1] == "alice"
    assert rows[-1][0] == "login_failed" and "\n" not in rows[-1][1]
    assert all("wrong password value" not in " ".join(map(str, row)) for row in rows)


def test_user_audit_chain_detects_edits_and_deletions(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", password=PASSWORD)
    store.disable("alice")
    store.enable("alice")
    assert store.verify_audit() is None
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE cb_user_audit SET action='unlock' WHERE id=1")
    broken = store.verify_audit()
    assert broken == 1

    fresh = UserStore(tmp_path / "fresh-users.db", clock=lambda: NOW)
    fresh.add("alice", password=PASSWORD)
    fresh.disable("alice")
    fresh.enable("alice")
    with sqlite3.connect(fresh.path) as db:
        db.execute("DELETE FROM cb_user_audit WHERE id=2")
    broken = fresh.verify_audit()
    assert broken == 3


def test_cli_users_verify_reports_a_broken_chain(tmp_path, capsys):
    config = config_with(tmp_path, reporting("registered"))
    store = UserStore(config.watch.users_database, clock=lambda: NOW)
    store.add("alice")
    store.disable("alice")
    assert cli.main(["--config", str(config.config_path), "users", "verify"]) == 0
    assert "verified" in capsys.readouterr().out
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE cb_user_audit SET action='enable' WHERE id=1")
    assert cli.main(["--config", str(config.config_path), "users", "verify"]) == 2
    assert "broken at row 1" in capsys.readouterr().err


def test_open_mode_keeps_the_free_text_identity(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    outcome = open_report(store, IDENTIFIER, by="alice")
    assert outcome.entry is not None
    assert outcome.entry.identity_mode == "open"
    assert outcome.entry.user_id is None and outcome.entry.username is None
    assert outcome.entry.os_account and outcome.entry.host
    assert store.verify_reports() is None


def test_registered_mode_requires_an_enabled_user(tmp_path, capsys):
    config = config_with(tmp_path, reporting("registered"))
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    alice = users.add("alice", display_name="Alice Smith", email="alice@example.com")
    users.add("bob")
    users.disable("bob")
    base = ["--config", str(config.config_path), "watch", "report", IDENTIFIER]

    assert cli.main([*base, "--by", "ALICE"]) == 0
    entry = store.reported_entries()[0]
    assert (entry.by, entry.username, entry.identity_mode) == (
        "Alice Smith",
        "alice",
        "registered",
    )
    assert entry.user_id == alice.id
    assert entry.os_account and entry.host

    open_unreport(store, IDENTIFIER, by="Alice Smith")
    assert cli.main([*base, "--by", "alice@example.com"]) == 0
    open_unreport(store, IDENTIFIER, by="Alice Smith")
    assert cli.main([*base, "--by", "bob"]) == 2
    assert "enabled CVEBeacon user" in capsys.readouterr().err
    assert cli.main([*base, "--by", "nobody"]) == 2
    assert "enabled CVEBeacon user" in capsys.readouterr().err
    assert cli.main([*base]) == 2
    assert "reported by is required" in capsys.readouterr().err
    assert cli.main([*base, "--by", "alice", "--user", "alice"]) == 2
    assert "only available" in capsys.readouterr().err


def test_authenticated_mode_prompts_and_records_the_user(
    tmp_path, monkeypatch, capsys
):
    config = config_with(tmp_path, reporting("authenticated"))
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    alice = users.add(
        "alice",
        password=PASSWORD,
        display_name="Alice Smith",
        email="alice@example.com",
    )
    prompt(monkeypatch, PASSWORD)
    assert cli.main(
        ["--config", str(config.config_path), "watch", "report", IDENTIFIER, "--user", "alice"]
    ) == 0
    output = capsys.readouterr().out
    assert "Alice Smith (alice)" in output
    entry = store.reported_entries()[0]
    assert (entry.user_id, entry.username, entry.identity_mode) == (
        alice.id,
        "alice",
        "authenticated",
    )
    assert entry.by == "Alice Smith"


def test_authenticated_mode_refuses_by_and_requires_user(tmp_path, monkeypatch, capsys):
    config = config_with(tmp_path, reporting("authenticated"))
    seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD)
    no_prompt(monkeypatch)
    base = ["--config", str(config.config_path), "watch", "report", IDENTIFIER]
    assert cli.main([*base, "--by", "alice"]) == 2
    assert "--by is not available" in capsys.readouterr().err
    assert cli.main(base) == 2
    assert "--user is required" in capsys.readouterr().err
    assert WatchStore(config.watch.database).reported_entries() == ()


def test_authenticated_failures_are_generic_and_write_no_report(
    tmp_path, monkeypatch, capsys
):
    config = config_with(tmp_path, reporting("authenticated"))
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD)
    users.add("carol", password=PASSWORD)
    users.disable("carol")
    base = ["--config", str(config.config_path), "watch", "report", IDENTIFIER]

    messages = []
    for username, value in (
        ("alice", "wrong password value"),
        ("nobody", PASSWORD),
        ("carol", PASSWORD),
    ):
        prompt(monkeypatch, value)
        assert cli.main([*base, "--user", username]) == 2
        messages.append(capsys.readouterr().err)
        assert store.reported_entries() == ()
    assert messages[0] == messages[1] == messages[2]
    assert "invalid username or password" in messages[0]


def test_authenticated_unreport_records_the_identity(tmp_path, monkeypatch, capsys):
    config = config_with(tmp_path, reporting("authenticated"))
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD, display_name="Alice Smith")
    ReportService(store, users.path, "authenticated").report_cve(
        IDENTIFIER, user="alice", password=PASSWORD
    )
    prompt(monkeypatch, PASSWORD)
    assert cli.main(
        [
            "--config",
            str(config.config_path),
            "watch",
            "unreport",
            IDENTIFIER,
            "--user",
            "alice",
            "--note",
            "Sent in error",
        ]
    ) == 0
    entry = store.reported_entries()[-1]
    assert (entry.action, entry.by, entry.username, entry.identity_mode) == (
        "unreport",
        "Alice Smith",
        "alice",
        "authenticated",
    )


def test_authenticated_lockout_stays_generic_until_unlock(
    tmp_path, monkeypatch, capsys
):
    config = config_with(tmp_path, reporting("authenticated"))
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD)
    prompt(monkeypatch, *(["wrong password value"] * 6), PASSWORD)
    base = ["--config", str(config.config_path), "watch", "report", IDENTIFIER]

    for _ in range(6):
        assert cli.main([*base, "--user", "alice"]) == 2
        assert "invalid username or password" in capsys.readouterr().err
    assert store.reported_entries() == ()
    assert users.find("alice").locked_until is not None

    assert cli.main(["--config", str(config.config_path), "users", "unlock", "alice"]) == 0
    assert cli.main([*base, "--user", "alice"]) == 0
    assert len(store.reported_entries()) == 1


def test_password_is_never_a_command_line_option(tmp_path, capsys):
    for argv in (
        [
            "--config",
            str(tmp_path / "config.toml"),
            "users",
            "add",
            "alice",
            "--password",
            PASSWORD,
        ],
        [
            "--config",
            str(tmp_path / "config.toml"),
            "watch",
            "report",
            IDENTIFIER,
            "--user",
            "alice",
            "--password",
            PASSWORD,
        ],
    ):
        assert cli.main(argv) == 2
        error = capsys.readouterr().err
        assert PASSWORD not in error
        assert "command line" in error


def test_cli_users_add_passwd_and_list_never_print_secrets(
    tmp_path, monkeypatch, capsys
):
    config = config_with(tmp_path, reporting("registered"))
    prompt(monkeypatch, PASSWORD, PASSWORD)
    base = ["--config", str(config.config_path), "users"]
    assert cli.main([*base, "add", "alice", "--name", "Alice Smith", "--email", "alice@example.com"]) == 0
    output = capsys.readouterr()
    assert "added alice" in output.out
    assert PASSWORD not in output.out + output.err
    assert "scrypt" not in output.out + output.err

    users = UserStore(config.watch.users_database)
    with sqlite3.connect(users.path) as db:
        first = db.execute("SELECT password_hash FROM cb_user WHERE username='alice'").fetchone()[0]
    prompt(monkeypatch, PASSWORD + " two", PASSWORD + " two")
    assert cli.main([*base, "passwd", "alice"]) == 0
    output = capsys.readouterr()
    assert PASSWORD + " two" not in output.out + output.err
    assert "scrypt" not in output.out + output.err
    with sqlite3.connect(users.path) as db:
        second = db.execute("SELECT password_hash FROM cb_user WHERE username='alice'").fetchone()[0]
    assert first != second

    assert cli.main([*base, "list"]) == 0
    output = capsys.readouterr()
    assert "alice" in output.out and "Alice Smith" in output.out
    assert "alice@example.com" in output.out
    assert "scrypt" not in output.out + output.err
    assert PASSWORD not in output.out + output.err
    with sqlite3.connect(users.path) as db:
        audit = " ".join(
            str(row) for row in db.execute("SELECT * FROM cb_user_audit")
        )
    assert PASSWORD not in audit
    assert PASSWORD + " two" not in audit


def test_cli_users_add_no_password_skips_the_prompt(tmp_path, monkeypatch, capsys):
    config = config_with(tmp_path, reporting("registered"))
    no_prompt(monkeypatch)
    assert cli.main(["--config", str(config.config_path), "users", "add", "alice", "--no-password"]) == 0
    with sqlite3.connect(UserStore(config.watch.users_database).path) as db:
        assert db.execute("SELECT password_hash FROM cb_user").fetchone()[0] is None


@pytest.mark.parametrize(
    "args",
    [
        ["users", "passwd", "nobody"],
        ["users", "disable", "nobody"],
        ["users", "enable", "nobody"],
        ["users", "unlock", "nobody"],
    ],
)
def test_cli_users_unknown_user_is_an_error(tmp_path, capsys, args):
    config = config_with(tmp_path)
    assert cli.main(["--config", str(config.config_path), *args]) == 2
    assert "user not found" in capsys.readouterr().err


def test_reports_chain_detects_edits_and_deletions(tmp_path, capsys):
    config = config_with(tmp_path)
    store = seed(config)
    open_report(store, IDENTIFIER, by="first")
    open_report(store, IDENTIFIER, by="second", force=True)
    open_report(store, IDENTIFIER, by="third", force=True)
    assert store.verify_reports() is None
    assert cli.main(["--config", str(config.config_path), "watch", "reported", "--verify"]) == 0
    assert "verified" in capsys.readouterr().out

    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET by='mallory' WHERE id=1")
    broken = store.verify_reports()
    assert broken == 1
    assert cli.main(["--config", str(config.config_path), "watch", "reported", "--verify"]) == 2
    assert "broken at row 1" in capsys.readouterr().err


def test_reports_chain_detects_a_deleted_middle_row(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    open_report(store, IDENTIFIER, by="first")
    open_report(store, IDENTIFIER, by="second", force=True)
    open_report(store, IDENTIFIER, by="third", force=True)
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM watch_report WHERE id=2")
    broken = store.verify_reports()
    assert broken == 3


def test_reports_chain_rejects_a_non_ascii_chain_value(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    open_report(store, IDENTIFIER, by="first")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET chain='not-a-chain-\u00e9' WHERE id=1")
    broken = store.verify_reports()
    assert broken == 1


def test_schema_five_database_migrates_report_identity_in_place(tmp_path):
    path = tmp_path / "watch.db"
    WatchStore(path, clock=lambda: NOW).initialize()
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE watch_report RENAME TO watch_report_new")
        db.execute(
            "CREATE TABLE watch_report ("
            "id INTEGER PRIMARY KEY, cve_id TEXT NOT NULL, "
            "action TEXT NOT NULL, by TEXT NOT NULL, note TEXT, at TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO watch_report(cve_id,action,by,note,at) VALUES (?,?,?,?,?)",
            (IDENTIFIER, "report", "legacy", "old note", NOW.isoformat()),
        )
        db.execute("DROP TABLE watch_report_new")
        db.execute("UPDATE watch_meta SET value='5' WHERE key='schema_version'")
    store = WatchStore(path, clock=lambda: NOW)
    store.initialize()
    assert store.metadata()["schema_version"] == "7"
    entries = store.reported_entries()
    assert len(entries) == 1
    entry = entries[0]
    assert (entry.cve_id, entry.by, entry.note) == (IDENTIFIER, "legacy", "old note")
    assert (entry.user_id, entry.username, entry.identity_mode) == (None, None, None)
    assert (entry.os_account, entry.host) == (None, None)
    assert entry.chain is None
    assert entry.chain_version == 0
    assert entry.legacy is True
    assert store.verify_reports() is None
    assert store.report_chain_counts() == (0, 1)

    store.upsert_nvd(
        [WatchRecord(IDENTIFIER, "published", description="Acme Widget.")],
        catalogs=("nvd",),
    )
    open_report(store, IDENTIFIER, by="new", force=True)
    assert store.verify_reports() is None
    assert store.report_chain_counts() == (1, 1)
    assert len(store.reported_entries()[-1].chain) == 64


def test_reported_export_formats_carry_the_audit_fields(tmp_path, capsys):
    config = config_with(tmp_path, reporting("registered"))
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", display_name="Alice Smith", email="alice@example.com")
    users.add("bob", display_name="Bob")
    reporting_service = ReportService(store, users.path, "registered")
    reporting_service.report_cve(
        IDENTIFIER, by="alice", note="=1+1"
    )
    reporting_service.report_cve(IDENTIFIER, by="bob", force=True)
    base = ["--config", str(config.config_path), "watch", "reported", "--all"]

    assert cli.main([*base, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 2
    assert payload[0]["username"] == "alice"
    assert payload[0]["identity_mode"] == "registered"
    assert payload[0]["note"] == "=1+1"
    assert len(payload[0]["chain"]) == 64
    assert "password" not in json.dumps(payload).casefold()

    assert cli.main([*base, "--format", "csv"]) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert len(rows) == 2
    assert rows[0]["username"] == "alice"
    assert rows[0]["identity_mode"] == "registered"
    assert rows[0]["note"] == "'=1+1"
    assert rows[0]["chain"] and "password" not in ",".join(rows[0]).casefold()

    assert cli.main([*base, "--format", "text"]) == 0
    output = capsys.readouterr().out
    assert "Alice Smith (alice)" in output
    assert "=1+1" in output


def test_export_formats_require_the_full_audit_trail(tmp_path, capsys):
    config = config_with(tmp_path)
    seed(config)
    assert cli.main(["--config", str(config.config_path), "watch", "reported", "--format", "json"]) == 2
    assert "--all" in capsys.readouterr().err


def test_notice_text_uses_display_name_username_and_email(tmp_path):
    config = config_with(tmp_path, reporting("registered"))
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", display_name="Alice Smith", email="alice@example.com")
    ReportService(store, users.path, "registered").report_cve(
        IDENTIFIER, by="alice", notify_channels=("hook",)
    )
    with sqlite3.connect(store.path) as db:
        details = json.loads(
            db.execute(
                "SELECT details_json FROM watch_event WHERE rule='@reported'"
            ).fetchone()[0]
        )
    assert details["username"] == "alice"
    assert details["email"] == "alice@example.com"
    from cvebeacon.watch.records import CVSSEntry, DeliveryEvent, WatchView
    from cvebeacon.watch.messages import build_messages

    view = WatchView(IDENTIFIER, "published", cvss=(CVSSEntry("nvd", "nvd", "3.1", 9.8),))
    event = DeliveryEvent(
        1,
        "@reported",
        IDENTIFIER,
        "reported",
        (),
        False,
        NOW.isoformat(),
        view,
        details,
        "pending",
    )
    message = build_messages(
        (event,), channel_type="slack", grouping="run", max_items=20, names={}
    )[0]
    assert (
        "[REPORTED] CVE-2026-0001 reported to clients by "
        "Alice Smith (alice) <alice@example.com> at " in message.text
    )


def test_report_mark_display_includes_the_username():
    mark = ReportedMark(
        IDENTIFIER,
        "Alice Smith",
        None,
        "2026-11-03T12:00:00+00:00",
        username="alice",
    )
    assert identity_label(mark.by, mark.username) == "Alice Smith (alice)"


def test_registered_mode_rejects_unknown_and_disabled_users(tmp_path):
    config = config_with(tmp_path, reporting("registered"))
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", display_name="Alice Smith")
    reporting_service = ReportService(store, users.path, "registered")
    with pytest.raises(ConfigurationError, match="enabled CVEBeacon user"):
        reporting_service.report_cve(IDENTIFIER, by="Mallory")
    with pytest.raises(ConfigurationError, match="reported by is required"):
        reporting_service.report_cve(IDENTIFIER)
    users.disable("alice")
    with pytest.raises(ConfigurationError, match="enabled CVEBeacon user"):
        reporting_service.report_cve(IDENTIFIER, by="Alice Smith")
    assert store.reported_entries() == ()


def test_unknown_identity_mode_is_rejected(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    with pytest.raises(ConfigurationError, match="identity"):
        ReportService(store, config.watch.users_database, "trusted")
