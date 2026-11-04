from __future__ import annotations

import os
import sqlite3
import stat
from datetime import timedelta
from pathlib import Path

import pytest
from watch_support import NOW, write_config

from cvebeacon import cli
from cvebeacon.errors import CVEBeaconError, ConfigurationError, StateError
from cvebeacon.passwords import DUMMY_HASH
from cvebeacon.watch.identity import ReportIdentity
from cvebeacon.watch.records import WatchRecord
from cvebeacon.watch.reporting import ReportService
from cvebeacon.watch.store import WatchStore
from cvebeacon.watch.users import (
    BOOTSTRAP,
    AuthenticatedUser,
    User,
    UserStore,
)

PASSWORD = "correct horse battery staple"
IDENTIFIER = "CVE-2026-0001"


def config_with(tmp_path, mode: str = "open"):
    return write_config(
        tmp_path,
        channels="",
        extra=f'\n[watch.reporting]\nidentity = "{mode}"\n',
    )


def prompt(monkeypatch, *values: str) -> None:
    pending = iter(values)
    monkeypatch.setattr(
        "cvebeacon.passwords.getpass.getpass", lambda _: next(pending)
    )


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


def service(config, store) -> ReportService:
    return ReportService(
        store, config.watch.users_database, config.watch.reporting_identity
    )


def open_service(store) -> ReportService:
    return ReportService(store, None, "open")


def test_authenticated_mode_needs_a_real_login(tmp_path):
    config = config_with(tmp_path, "authenticated")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice")
    actor = service(config, store)

    with pytest.raises(CVEBeaconError, match="invalid username or password"):
        actor.report_cve(IDENTIFIER, user="alice", password=PASSWORD)
    assert store.reported_entries() == ()
    with pytest.raises(CVEBeaconError, match="invalid username or password"):
        actor.unreport_cve(IDENTIFIER, user="alice", password=PASSWORD)
    assert store.reported_entries() == ()


def test_authenticated_login_type_is_not_a_roster_lookup(tmp_path):
    config = config_with(tmp_path, "authenticated")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD)

    roster = users.find("alice")
    assert isinstance(roster, User)
    assert not isinstance(roster, AuthenticatedUser)
    proof = users.authenticate("alice", PASSWORD)
    assert isinstance(proof, AuthenticatedUser)
    assert proof.user.id == roster.id
    assert proof.login_id > 0


def test_service_has_no_caller_selected_mode_and_no_downgrade(tmp_path):
    config = config_with(tmp_path, "authenticated")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD)
    users.add("bob")
    actor = service(config, store)
    before = store.reported_entries()

    with pytest.raises(TypeError):
        ReportService(store, config.watch.users_database)
    with pytest.raises(AttributeError):
        actor.mode = "open"
    for call in (
        lambda: actor.report_cve(IDENTIFIER, by="alice"),
        lambda: actor.report_cve(IDENTIFIER),
        lambda: actor.report_cve(IDENTIFIER, by="alice", user="alice", password=PASSWORD),
        lambda: actor.unreport_cve(IDENTIFIER, by="alice"),
        lambda: actor.unreport_cve(IDENTIFIER),
    ):
        with pytest.raises(CVEBeaconError):
            call()
    assert store.reported_entries() == before


def test_open_and_registered_modes_refuse_authentication_arguments(tmp_path):
    config = config_with(tmp_path, "open")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD)
    users.add("bob")

    with pytest.raises(CVEBeaconError, match="only available"):
        open_service(store).report_cve(
            IDENTIFIER, by="alice", user="alice", password=PASSWORD
        )
    registered = service(config_with(tmp_path, "registered"), store)
    with pytest.raises(CVEBeaconError, match="only available"):
        registered.report_cve(IDENTIFIER, by="alice", user="alice")


def test_registered_service_uses_the_roster_without_a_password(tmp_path):
    config = config_with(tmp_path, "registered")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", display_name="Alice Smith")
    users.add("bob", display_name="Bob Jones")
    actor = service(config, store)

    outcome = actor.report_cve(IDENTIFIER, by="alice")
    assert outcome.entry is not None
    assert (outcome.entry.by, outcome.entry.username) == ("Alice Smith", "alice")
    assert outcome.entry.identity_mode == "registered"
    assert actor.unreport_cve(IDENTIFIER, by="bob").changed is True


def test_fabricated_and_stale_identities_are_rejected_inside_the_write(tmp_path):
    config = config_with(tmp_path, "registered")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD, display_name="Alice Smith")
    alice = users.find("alice")

    forged = User(
        9999,
        "ghost",
        "Ghost",
        None,
        False,
        False,
        NOW.isoformat(),
        NOW.isoformat(),
        None,
        0,
        None,
    )
    ghost = ReportIdentity("registered", "Ghost", user=forged)
    with pytest.raises(ConfigurationError, match="no longer exists"):
        store._report_cve(
            IDENTIFIER,
            identity=ghost,
            recheck=lambda: users.require_current(ghost),
        )
    assert store.reported_entries() == ()

    identity = ReportIdentity("registered", "Alice Smith", user=alice)
    users.disable("alice")
    with pytest.raises(ConfigurationError, match="disabled"):
        store._report_cve(
            IDENTIFIER,
            identity=identity,
            recheck=lambda: users.require_current(identity),
        )
    assert store.reported_entries() == ()


def test_authenticated_proof_must_come_from_a_login_row(tmp_path):
    config = config_with(tmp_path, "authenticated")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD, display_name="Alice Smith")
    roster = users.find("alice")
    fake = AuthenticatedUser(roster, 9999)
    identity = ReportIdentity(
        "authenticated",
        "Alice Smith",
        user=roster,
        authenticated=fake,
    )
    with pytest.raises(ConfigurationError, match="successful login"):
        store._report_cve(
            IDENTIFIER,
            identity=identity,
            recheck=lambda: users.require_current(identity),
        )
    assert store.reported_entries() == ()

    proof = users.authenticate("alice", PASSWORD)
    identity = ReportIdentity(
        "authenticated",
        "Alice Smith",
        user=proof.user,
        authenticated=proof,
    )
    users.disable("alice")
    with pytest.raises(ConfigurationError, match="disabled"):
        store._report_cve(
            IDENTIFIER,
            identity=identity,
            recheck=lambda: users.require_current(identity),
        )
    assert store.reported_entries() == ()


def test_migration_never_rechains_a_downgraded_edited_row(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    for name in ("first", "second", "third"):
        open_service(store).report_cve(IDENTIFIER, by=name, force=True)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET by='Mallory' WHERE id=1")
        before = db.execute("SELECT chain FROM watch_report ORDER BY id").fetchall()
    assert store.verify_reports() == 1
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_meta SET value='5' WHERE key='schema_version'")
    reopened = WatchStore(store.path, clock=lambda: NOW)
    reopened.initialize()
    with sqlite3.connect(store.path) as db:
        after = db.execute("SELECT chain FROM watch_report ORDER BY id").fetchall()
        by = db.execute("SELECT by FROM watch_report WHERE id=1").fetchone()[0]
    assert after == before
    assert by == "Mallory"
    assert reopened.metadata()["schema_version"] == "7"
    assert reopened.verify_reports() == 1


def test_migration_never_rechains_a_downgraded_deleted_row(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    for name in ("first", "second", "third"):
        open_service(store).report_cve(IDENTIFIER, by=name, force=True)
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM watch_report WHERE id=2")
        db.execute("UPDATE watch_meta SET value='5' WHERE key='schema_version'")
    reopened = WatchStore(store.path, clock=lambda: NOW)
    reopened.initialize()
    assert reopened.verify_reports() == 3


def test_downgraded_pre_fix_v6_rows_are_not_rechained(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    open_service(store).report_cve(IDENTIFIER, by="first")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET by='Mallory' WHERE id=1")
        db.execute("ALTER TABLE watch_report DROP COLUMN chain_version")
        db.execute("UPDATE watch_meta SET value='6' WHERE key='schema_version'")
    reopened = WatchStore(store.path, clock=lambda: NOW)
    reopened.initialize()
    assert reopened.metadata()["schema_version"] == "7"
    assert reopened.verify_reports() == 1


def test_verify_does_not_create_a_missing_watch_store_or_table(tmp_path):
    watch = WatchStore(tmp_path / "missing-watch.db")
    with pytest.raises(StateError, match="not found"):
        watch.verify_reports()
    assert not watch.path.exists()

    path = tmp_path / "watch.db"
    store = WatchStore(path, clock=lambda: NOW)
    store.initialize()
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE watch_report")
    with pytest.raises(StateError, match="missing"):
        store.verify_reports()
    with sqlite3.connect(path) as db:
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='watch_report'"
        ).fetchone()
    assert table is None


def test_verify_does_not_create_a_missing_user_store_or_table(tmp_path):
    users = UserStore(tmp_path / "missing-users.db", clock=lambda: NOW)
    with pytest.raises(StateError, match="not found"):
        users.verify_audit()
    assert not users.path.exists()

    path = tmp_path / "users.db"
    store = UserStore(path, clock=lambda: NOW)
    store.initialize()
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE cb_user_audit")
    with pytest.raises(StateError, match="missing"):
        store.verify_audit()
    with sqlite3.connect(path) as db:
        table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='cb_user_audit'"
        ).fetchone()
    assert table is None


def test_verify_accepts_an_existing_empty_trail(tmp_path):
    watch = WatchStore(tmp_path / "watch.db")
    watch.initialize()
    assert watch.verify_reports() is None
    assert watch.report_chain_counts() == (0, 0)

    users = UserStore(tmp_path / "users.db")
    users.initialize()
    assert users.verify_audit() is None


def test_malformed_report_row_types_are_reported_as_broken(tmp_path, capsys):
    config = config_with(tmp_path)
    store = seed(config)
    open_service(store).report_cve(IDENTIFIER, by="first")
    open_service(store).report_cve(IDENTIFIER, by="second", force=True)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET user_id='not-an-integer' WHERE id=1")
    assert store.verify_reports() == 1
    assert cli.main(
        ["--config", str(config.config_path), "watch", "reported", "--verify"]
    ) == 2
    assert "broken at row 1" in capsys.readouterr().err

    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET note=CAST('blob' AS BLOB) WHERE id=1")
    assert store.verify_reports() == 1


def test_malformed_user_audit_row_types_are_reported_as_broken(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", password=PASSWORD)
    store.disable("alice")
    assert store.verify_audit() is None
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE cb_user_audit SET action=CAST('blob' AS BLOB) WHERE id=1")
    assert store.verify_audit() == 1


def test_unicode_emails_have_one_case_insensitive_lookup_key(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", email="É@example.com")
    with pytest.raises(ConfigurationError, match="already registered"):
        store.add("bob", email="é@example.com")
    assert store.resolve_enabled("é@EXAMPLE.COM").username == "alice"
    assert store.resolve_enabled("É@example.com").username == "alice"

    store.add("carol", email="carol@example.com")
    with pytest.raises(ConfigurationError, match="already registered"):
        store.add("CAROL@EXAMPLE.COM")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file model")
def test_users_database_rejects_a_symlink_target(tmp_path):
    target = tmp_path / "target.db"
    target.write_bytes(b"")
    link = tmp_path / "users.db"
    link.symlink_to(target)
    with pytest.raises(StateError):
        UserStore(link, clock=lambda: NOW).users()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file model")
def test_users_database_rejects_a_permissive_preexisting_file(tmp_path):
    path = tmp_path / "users.db"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    os.close(descriptor)
    os.chmod(path, 0o644)
    with pytest.raises(StateError, match="group or other"):
        UserStore(path, clock=lambda: NOW).users()
    assert stat.S_IMODE(path.stat().st_mode) & 0o077


@pytest.mark.skipif(os.name != "posix", reason="POSIX file model")
def test_users_database_rejects_a_group_writable_parent(tmp_path):
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o777)
    try:
        with pytest.raises(StateError, match="directory"):
            UserStore(parent / "users.db", clock=lambda: NOW).initialize()
    finally:
        parent.chmod(0o700)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file model")
def test_users_database_detects_replacement_between_check_and_open(
    tmp_path, monkeypatch
):
    path = tmp_path / "users.db"
    store = UserStore(path, clock=lambda: NOW)
    store.initialize()
    import cvebeacon.watch.users as users_module
    import sqlite3 as sqlite_module

    real_connect = sqlite_module.connect

    def swapping_connect(database, *args, **kwargs):
        path.unlink()
        # Owner-only like the original, so only the replacement is detected
        # regardless of the process umask.
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(users_module.sqlite3, "connect", swapping_connect)
    with pytest.raises(StateError, match="replaced"):
        store.users()


def test_password_validation_precedes_confirmation(monkeypatch, capsys):
    from cvebeacon.passwords import read_new_password

    values = iter(["short", "different"])
    monkeypatch.setattr(
        "cvebeacon.passwords.getpass.getpass", lambda _: next(values)
    )
    with pytest.raises(ConfigurationError, match="12–1024"):
        read_new_password("Password: ")

    values = iter(["short", "different"])
    monkeypatch.setattr(
        "cvebeacon.passwords.getpass.getpass", lambda _: next(values)
    )
    assert cli.main(["dashboard", "hash-password"]) == 2
    assert "12–1024" in capsys.readouterr().err


def test_password_option_never_echoes_the_attempted_value(capsys):
    secret = "synthetic-argparse-secret"
    cases = [
        ["users", "add", "alice", "--password", secret],
        ["users", "add", "alice", "--pass", secret],
        [
            "--config",
            "absent.toml",
            "watch",
            "report",
            IDENTIFIER,
            "--user",
            "alice",
            "--password",
            secret,
        ],
        ["dashboard", "hash-password", "--password", secret],
    ]
    for argv in cases:
        assert cli.main(argv) == 2
        error = capsys.readouterr().err
        assert secret not in error
        assert "command line" in error


def test_surrogate_passwords_fail_validation_cleanly(tmp_path):
    from cvebeacon.passwords import validate_password

    with pytest.raises(ConfigurationError, match="UTF-8|valid"):
        validate_password("x" * 11 + "\ud800")
    with pytest.raises(ConfigurationError, match="UTF-8|valid"):
        UserStore(tmp_path / "users.db", clock=lambda: NOW).add(
            "alice", password="x" * 11 + "\ud800"
        )


def test_dummy_hash_covers_passwordless_and_locked_accounts(
    tmp_path, monkeypatch
):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice")
    store.add("bob", password=PASSWORD)
    calls: list[str] = []
    monkeypatch.setattr(
        "cvebeacon.watch.users.verify_password",
        lambda encoded, password: calls.append(encoded) or False,
    )
    assert store.authenticate("alice", PASSWORD) is None
    assert calls == [DUMMY_HASH]
    for _ in range(5):
        store.authenticate("bob", "wrong password value")
    calls.clear()
    assert store.authenticate("bob", PASSWORD) is None
    assert calls == [DUMMY_HASH]


def test_successful_login_is_audited(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", password=PASSWORD)
    proof = store.authenticate("alice", PASSWORD)
    assert proof is not None
    entries = store.audit_entries()
    assert any(
        entry.id == proof.login_id
        and entry.action == "login"
        and entry.username == "alice"
        for entry in entries
    )


def test_lockout_uses_the_wall_clock_and_backward_jumps_keep_it_locked(tmp_path):
    now = [NOW]
    store = UserStore(tmp_path / "users.db", clock=lambda: now[0])
    store.add("alice", password=PASSWORD)
    for _ in range(5):
        store.authenticate("alice", "wrong password value")
    now[0] = NOW - timedelta(hours=1)
    assert store.authenticate("alice", PASSWORD) is None
    now[0] = NOW + timedelta(minutes=16)
    assert store.authenticate("alice", PASSWORD) is not None


def test_security_documentation_is_explicit():
    docs = Path(__file__).resolve().parents[1] / "docs"
    watch = (docs / "WATCH.md").read_text(encoding="utf-8")
    deploy = (docs / "DEPLOY.md").read_text(encoding="utf-8")
    assert "umask 077" in deploy
    assert "install -m 600" in deploy or "chmod 600" in deploy
    assert "users-backup.db" in deploy
    assert "icacls" in deploy
    assert "ProgramData" in deploy
    assert "#windows-data-directory-acls" in watch
    assert "unkeyed" in watch.casefold()
    assert "not a signature" in watch.casefold() or "not authentication" in watch.casefold()
    assert "user-admin audit log only" in watch.casefold()
    assert "wall-clock" in watch.casefold()
    assert "host clock" in watch.casefold()
    assert "administrator login" in watch.casefold()
    assert "--admin-user" in watch
    assert "bootstrap" in watch.casefold()
    assert "service account" in watch.casefold()
    assert "planned dashboard" in watch.casefold()
    assert "must be owned by" in watch.casefold()
    assert "cvebeacon account or root" in watch.casefold()
    assert "sticky-bit" in watch.casefold()
    assert "read-only" in watch.casefold()
    assert "highest legacy row id" in watch.casefold()
    assert "total rewrite" in watch.casefold()
    assert "not covered by either chain" in watch.casefold()
    assert "empty actor" in watch.casefold()
    assert "every ancestor" in watch.casefold()
    assert "chmod go-w" in watch.casefold()
    assert "0700" in watch.casefold()
    assert "store id" in watch.casefold()
    assert "inode number" in watch.casefold()


OLD_USER_SCHEMA = (
    """CREATE TABLE cb_user (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT,
        email TEXT COLLATE NOCASE,
        password_hash TEXT,
        is_admin INTEGER NOT NULL DEFAULT 0,
        disabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        password_changed_at TEXT,
        failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT
    )""",
    "CREATE UNIQUE INDEX cb_user_email ON cb_user(email) WHERE email IS NOT NULL",
    """CREATE TABLE cb_user_audit (
        id INTEGER PRIMARY KEY, action TEXT NOT NULL, username TEXT NOT NULL,
        at TEXT NOT NULL, os_account TEXT, host TEXT, chain TEXT NOT NULL)""",
)


def old_user_database(path, email: str, other_email: str | None = None):
    with sqlite3.connect(path) as db:
        for statement in OLD_USER_SCHEMA:
            db.execute(statement)
        now = NOW.isoformat()
        db.execute(
            "INSERT INTO cb_user(username,email,created_at,updated_at) "
            "VALUES ('alice',?,?,?)",
            (email, now, now),
        )
        if other_email is not None:
            db.execute(
                "INSERT INTO cb_user(username,email,created_at,updated_at) "
                "VALUES ('bob',?,?,?)",
                (other_email, now, now),
            )
    os.chmod(path, 0o600)


def test_old_account_emails_gain_a_unicode_lookup_key(tmp_path):
    path = tmp_path / "users.db"
    old_user_database(path, "É@example.com")
    store = UserStore(path, clock=lambda: NOW)
    store.initialize()
    assert store.resolve_enabled("é@example.com").username == "alice"


def test_old_account_email_collisions_fail_closed(tmp_path):
    path = tmp_path / "users.db"
    old_user_database(path, "É@example.com", "é@example.com")
    with pytest.raises(StateError, match="collide"):
        UserStore(path, clock=lambda: NOW).initialize()


def test_no_password_is_rejected_in_authenticated_mode(tmp_path, capsys):
    config = config_with(tmp_path, "authenticated")
    assert cli.main(
        [
            "--config",
            str(config.config_path),
            "users",
            "add",
            "alice",
            "--admin",
            "--no-password",
        ]
    ) == 2
    assert "--no-password" in capsys.readouterr().err


def test_account_backup_recipe_stays_owner_only_under_a_permissive_umask(tmp_path):
    import shutil
    import subprocess

    if not shutil.which("sqlite3") or not shutil.which("install"):
        pytest.skip("sqlite3 and install are not available")
    source = tmp_path / "cvebeacon-users.db"
    destination = tmp_path / "users-backup.db"
    subprocess.run(
        [
            "sqlite3",
            str(source),
            "CREATE TABLE cb_user(username TEXT); INSERT INTO cb_user VALUES ('alice');",
        ],
        check=True,
    )
    os.chmod(source, 0o600)
    subprocess.run(
        [
            "sh",
            "-c",
            (
                f"umask 022; install -m 600 /dev/null '{destination}'; "
                f"umask 077; sqlite3 '{source}' '.backup {destination}'"
            ),
        ],
        check=True,
    )
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_stale_identity_is_rejected_for_unreport_too(tmp_path):
    config = config_with(tmp_path, "registered")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", display_name="Alice Smith")
    open_service(store).report_cve(IDENTIFIER, by="setup")
    alice = users.find("alice")
    identity = ReportIdentity("registered", "Alice Smith", user=alice)
    users.disable("alice")
    with pytest.raises(ConfigurationError, match="disabled"):
        store._unreport_cve(
            IDENTIFIER,
            identity=identity,
            recheck=lambda: users.require_current(identity),
        )
    assert len(store.reported_entries()) == 1


def test_cli_users_verify_reports_a_malformed_row_without_a_traceback(
    tmp_path, capsys
):
    config = config_with(tmp_path, "registered")
    store = UserStore(config.watch.users_database, clock=lambda: NOW)
    store.add("alice")
    store.disable("alice")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE cb_user_audit SET action=CAST('blob' AS BLOB) WHERE id=1")
    assert cli.main(["--config", str(config.config_path), "users", "verify"]) == 2
    assert "broken at row 1" in capsys.readouterr().err


def test_authenticated_admin_bootstrap_and_admin_login(tmp_path, monkeypatch, capsys):
    config = config_with(tmp_path, "authenticated")
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    base = ["--config", str(config.config_path), "users"]

    prompt(monkeypatch, PASSWORD, PASSWORD)
    assert cli.main([*base, "add", "alice", "--admin"]) == 0
    alice = users.find("alice")
    assert alice is not None and alice.is_admin
    assert users.audit_entries()[-1].actor == "(bootstrap)"

    assert cli.main([*base, "add", "bob"]) == 2
    assert "administrator login required" in capsys.readouterr().err
    assert users.find("bob") is None

    prompt(monkeypatch, PASSWORD, PASSWORD, PASSWORD)
    assert cli.main([*base, "add", "bob", "--admin-user", "alice"]) == 0
    bob = users.find("bob")
    assert bob is not None and not bob.is_admin
    assert users.audit_entries()[-1].actor == "alice"

    prompt(monkeypatch, PASSWORD)
    assert cli.main([*base, "add", "carol", "--admin-user", "bob"]) == 2
    assert "administrator login required" in capsys.readouterr().err
    assert users.find("carol") is None


def test_admin_only_user_actions_require_an_admin_login(tmp_path, monkeypatch, capsys):
    config = config_with(tmp_path, "authenticated")
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    base = ["--config", str(config.config_path), "users"]
    prompt(monkeypatch, PASSWORD, PASSWORD)
    cli.main([*base, "add", "alice", "--admin"])
    prompt(monkeypatch, PASSWORD, PASSWORD, PASSWORD)
    cli.main([*base, "add", "bob", "--admin-user", "alice"])

    assert cli.main([*base, "disable", "bob"]) == 2
    assert "administrator login required" in capsys.readouterr().err
    prompt(monkeypatch, PASSWORD)
    assert cli.main([*base, "disable", "bob", "--admin-user", "bob"]) == 2
    assert "administrator login required" in capsys.readouterr().err
    assert users.find("bob").disabled is False

    prompt(monkeypatch, PASSWORD)
    assert cli.main([*base, "disable", "bob", "--admin-user", "alice"]) == 0
    assert users.find("bob").disabled is True
    assert users.audit_entries()[-1].actor == "alice"
    assert users.verify_audit() is None
    action_id = users.audit_entries()[-1].id
    with sqlite3.connect(users.path) as db:
        db.execute("UPDATE cb_user_audit SET actor=NULL WHERE id=?", (action_id,))
    assert users.verify_audit() == action_id
    prompt(monkeypatch, PASSWORD)
    assert cli.main([*base, "enable", "bob", "--admin-user", "alice"]) == 0
    prompt(monkeypatch, PASSWORD)
    assert cli.main([*base, "unlock", "bob", "--admin-user", "alice"]) == 0


def test_users_change_their_own_password_or_an_admin_resets_it(
    tmp_path, monkeypatch, capsys
):
    config = config_with(tmp_path, "authenticated")
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    base = ["--config", str(config.config_path), "users"]
    prompt(monkeypatch, PASSWORD, PASSWORD)
    cli.main([*base, "add", "alice", "--admin"])
    prompt(monkeypatch, PASSWORD, PASSWORD, PASSWORD)
    cli.main([*base, "add", "bob", "--admin-user", "alice"])

    new_self = PASSWORD + " self"
    prompt(monkeypatch, PASSWORD, new_self, new_self)
    assert cli.main([*base, "passwd", "bob"]) == 0
    assert any(
        entry.action == "passwd" and entry.actor == "bob"
        for entry in users.audit_entries()
    )
    assert users.authenticate("bob", new_self) is not None
    assert users.authenticate("bob", PASSWORD) is None

    new_admin = PASSWORD + " reset"
    prompt(monkeypatch, PASSWORD, new_admin, new_admin)
    assert cli.main([*base, "passwd", "bob", "--admin-user", "alice"]) == 0
    assert any(
        entry.action == "passwd" and entry.actor == "alice"
        for entry in users.audit_entries()
    )
    assert users.authenticate("bob", new_admin) is not None

    prompt(monkeypatch, "wrong password value")
    assert cli.main([*base, "passwd", "bob", "--admin-user", "alice"]) == 2
    assert "administrator login required" in capsys.readouterr().err


def test_report_holds_the_user_lock_through_the_report_write(
    tmp_path, monkeypatch
):
    config = config_with(tmp_path, "authenticated")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD)
    actor = service(config, store)
    original = store._report_cve

    def locked_check(*args, **kwargs):
        with sqlite3.connect(users.path, timeout=0) as db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                db.execute("BEGIN IMMEDIATE")
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "_report_cve", locked_check)
    assert actor.report_cve(
        IDENTIFIER, user="alice", password=PASSWORD
    ).changed is True


def test_unreport_holds_the_user_lock_through_the_write(tmp_path, monkeypatch):
    config = config_with(tmp_path, "authenticated")
    store = seed(config)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    users.add("alice", password=PASSWORD)
    actor = service(config, store)
    actor.report_cve(IDENTIFIER, user="alice", password=PASSWORD)
    original = store._unreport_cve

    def locked_check(*args, **kwargs):
        with sqlite3.connect(users.path, timeout=0) as db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                db.execute("BEGIN IMMEDIATE")
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "_unreport_cve", locked_check)
    assert actor.unreport_cve(
        IDENTIFIER, user="alice", password=PASSWORD
    ).changed is True


def test_flipped_chain_version_cannot_launder_an_edit(tmp_path, capsys):
    config = config_with(tmp_path)
    store = seed(config)
    for name in ("first", "second", "third"):
        open_service(store).report_cve(IDENTIFIER, by=name, force=True)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET by='Mallory' WHERE id=2")
    assert store.verify_reports() == 2
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET chain_version=0, chain=NULL")
    assert store.verify_reports() == 1
    assert cli.main(
        ["--config", str(config.config_path), "watch", "reported", "--verify"]
    ) == 2
    assert "broken at row 1" in capsys.readouterr().err


def test_nulling_identity_and_flipping_chain_version_is_still_broken(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    for name in ("first", "second", "third"):
        open_service(store).report_cve(IDENTIFIER, by=name, force=True)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE watch_report SET by='Mallory', username='mallory', "
            "note='forged', user_id=NULL, identity_mode=NULL, os_account=NULL, "
            "host=NULL, chain_version=0, chain=NULL WHERE id=2"
        )
    assert store.verify_reports() == 2


def test_dropped_chain_columns_fail_closed(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    open_service(store).report_cve(IDENTIFIER, by="first")
    with sqlite3.connect(store.path) as db:
        db.execute("ALTER TABLE watch_report DROP COLUMN chain")
        db.execute("ALTER TABLE watch_report DROP COLUMN chain_version")
        db.execute("UPDATE watch_meta SET value='5' WHERE key='schema_version'")
    with pytest.raises(StateError, match="boundary exists"):
        store.verify_reports()


def test_verify_requires_a_legacy_boundary(tmp_path):
    store = WatchStore(tmp_path / "watch.db")
    store.initialize()
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM watch_meta WHERE key='report_legacy_max_id'")
    with pytest.raises(StateError, match="boundary is missing"):
        store.verify_reports()


def test_empty_schema6_chains_are_damage_not_legacy(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    open_service(store).report_cve(IDENTIFIER, by="first")
    open_service(store).report_cve(IDENTIFIER, by="second", force=True)
    with sqlite3.connect(store.path) as db:
        db.execute("ALTER TABLE watch_report DROP COLUMN chain_version")
        db.execute("UPDATE watch_report SET chain=NULL")
        db.execute("DELETE FROM watch_meta WHERE key='report_legacy_max_id'")
        db.execute("UPDATE watch_meta SET value='6' WHERE key='schema_version'")
    reopened = WatchStore(store.path, clock=lambda: NOW)
    reopened.initialize()
    assert reopened.verify_reports() == 1


def test_old_username_email_collision_fails_migration(tmp_path):
    path = tmp_path / "users.db"
    old_user_database(path, "é@example.com")
    now = NOW.isoformat()
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO cb_user(username,email,created_at,updated_at) "
            "VALUES ('É@example.com',NULL,?,?)",
            (now, now),
        )
    with pytest.raises(StateError, match="collide"):
        UserStore(path, clock=lambda: NOW).initialize()


def test_invalid_utf8_report_text_is_a_controlled_broken_row(tmp_path, capsys):
    config = config_with(tmp_path)
    store = seed(config)
    open_service(store).report_cve(IDENTIFIER, by="first")
    open_service(store).report_cve(IDENTIFIER, by="second", force=True)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET by=CAST(X'80' AS TEXT)")
    assert store.verify_reports() == 1
    assert cli.main(
        ["--config", str(config.config_path), "watch", "reported", "--verify"]
    ) == 2
    assert "broken at row 1" in capsys.readouterr().err
    with pytest.raises(StateError, match="invalid"):
        store.reported_entries()
    listing = ["--config", str(config.config_path), "watch", "reported"]
    for extra in (
        (),
        ("--all",),
        ("--all", "--format", "csv"),
        ("--all", "--format", "json"),
    ):
        assert cli.main([*listing, *extra]) == 2
        assert "invalid" in capsys.readouterr().err


def test_invalid_utf8_user_audit_text_is_a_controlled_broken_row(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice")
    store.disable("alice")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE cb_user_audit SET action=CAST(X'80' AS TEXT) WHERE id=1")
    assert store.verify_audit() == 1


def test_missing_report_chain_column_is_a_controlled_failure(tmp_path, capsys):
    config = config_with(tmp_path)
    store = seed(config)
    open_service(store).report_cve(IDENTIFIER, by="first")
    with sqlite3.connect(store.path) as db:
        db.execute("ALTER TABLE watch_report DROP COLUMN chain")
    with pytest.raises(StateError, match="missing required columns"):
        store.verify_reports()
    assert cli.main(
        ["--config", str(config.config_path), "watch", "reported", "--verify"]
    ) == 2
    assert "missing required columns" in capsys.readouterr().err


def test_missing_user_audit_chain_column_is_a_controlled_failure(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice")
    with sqlite3.connect(store.path) as db:
        db.execute("ALTER TABLE cb_user_audit DROP COLUMN chain")
    with pytest.raises(StateError, match="missing required columns"):
        store.verify_audit()


def test_expired_lock_does_not_rearm_after_one_failure(tmp_path):
    now = [NOW]
    store = UserStore(tmp_path / "users.db", clock=lambda: now[0])
    store.add("alice", password=PASSWORD)
    for _ in range(5):
        store.authenticate("alice", "wrong password value")
    now[0] = NOW + timedelta(minutes=16)
    assert store.authenticate("alice", "wrong password value") is None
    current = store.find("alice")
    assert current.failed_logins == 1
    assert current.locked_until is None
    assert store.authenticate("alice", PASSWORD) is not None


def test_password_like_invalid_username_is_not_retained(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add("alice", password=PASSWORD)
    secret = "Tr0ub4dor&3-my-real-pass"
    assert store.authenticate(secret, "wrong password value") is None
    row = store.audit_entries()[-1]
    assert row.action == "login_failed"
    assert row.username == "(invalid name)"
    assert all(secret not in str(entry) for entry in store.audit_entries())


def test_parent_directory_ownership_is_checked(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX ownership model")
    real_euid = os.geteuid()
    monkeypatch.setattr(
        "cvebeacon.watch.users.os.geteuid", lambda: real_euid + 1
    )
    with pytest.raises(StateError, match="directory must be owned"):
        UserStore(tmp_path / "users.db", clock=lambda: NOW).initialize()


def test_password_spellings_never_echo_the_value(capsys):
    secret = "synthetic-argparse-secret"
    cases = [
        ["users", "add", "alice", "-p" + secret],
        ["users", "add", "alice", "--pwd", secret],
        ["users", "add", "alice", "--pw=" + secret],
        [
            "--config",
            "absent.toml",
            "watch",
            "report",
            IDENTIFIER,
            "--user",
            "alice",
            "--p",
            secret,
        ],
    ]
    for argv in cases:
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code
        assert code == 2
        error = capsys.readouterr().err
        assert secret not in error
        assert "command line" in error or "unrecognized arguments" in error


def test_creation_rejects_normalized_username_email_collisions(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.initialize()
    now = NOW.isoformat()
    with sqlite3.connect(store.path) as db:
        db.execute(
            "INSERT INTO cb_user(username,created_at,updated_at) VALUES (?,?,?)",
            ("É@example.com", now, now),
        )
    with pytest.raises(ConfigurationError, match="already registered"):
        store.add("bob", email="é@example.com")


def test_schema6_with_no_chain_column_fails_closed(tmp_path):
    config = config_with(tmp_path)
    store = seed(config)
    open_service(store).report_cve(IDENTIFIER, by="first")
    with sqlite3.connect(store.path) as db:
        db.execute("ALTER TABLE watch_report DROP COLUMN chain")
        db.execute("UPDATE watch_meta SET value='6' WHERE key='schema_version'")
    with pytest.raises(StateError, match="no chain column"):
        store.verify_reports()


def test_data_directory_created_0700_under_umask_002(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX directory modes")
    old = os.umask(0o002)
    try:
        users_parent = tmp_path / "user-data"
        UserStore(users_parent / "users.db", clock=lambda: NOW).initialize()
        assert stat.S_IMODE(users_parent.stat().st_mode) == 0o700
        watch_parent = tmp_path / "watch-data"
        WatchStore(watch_parent / "watch.db").initialize()
        assert stat.S_IMODE(watch_parent.stat().st_mode) == 0o700
    finally:
        os.umask(old)


def test_directory_error_names_the_path_and_fix(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX directory modes")
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o775)
    try:
        with pytest.raises(StateError) as caught:
            UserStore(parent / "users.db", clock=lambda: NOW).initialize()
        message = str(caught.value)
        assert str(parent) in message
        assert "chmod go-w" in message
    finally:
        parent.chmod(0o700)


def test_account_file_rejects_a_writable_ancestor(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX directory modes")
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o770)
    data = unsafe / "data"
    data.mkdir(mode=0o700)
    try:
        with pytest.raises(StateError, match="chmod go-w"):
            UserStore(data / "users.db", clock=lambda: NOW).initialize()
    finally:
        unsafe.chmod(0o700)


def test_bootstrap_is_checked_inside_the_add_transaction(tmp_path):
    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)
    store.add(
        "alice",
        password=PASSWORD,
        is_admin=True,
        authorization=BOOTSTRAP,
    )
    with pytest.raises(ConfigurationError, match="administrator login"):
        store.add(
            "bob",
            password=PASSWORD,
            is_admin=True,
            authorization=BOOTSTRAP,
        )
    assert store.find("bob") is None


def test_admin_and_self_authorization_are_rechecked_inside_mutations(tmp_path):
    now = [NOW]
    store = UserStore(tmp_path / "users.db", clock=lambda: now[0])
    store.add("alice", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    store.add("bob", password=PASSWORD)
    admin = store.authenticate("alice", PASSWORD)
    self_proof = store.authenticate("bob", PASSWORD)

    store.disable("alice", authorization=admin)
    with pytest.raises(ConfigurationError, match="disabled"):
        store.add(
            "carol",
            password=PASSWORD,
            authorization=admin,
        )
    with pytest.raises(ConfigurationError, match="disabled"):
        store.disable("bob", authorization=admin)
    assert store.find("carol") is None
    assert store.find("bob").disabled is False

    store.enable("alice", authorization=None)
    admin = store.authenticate("alice", PASSWORD)
    now[0] = NOW + timedelta(seconds=1)
    reset = PASSWORD + " reset"
    store.set_password("bob", reset, authorization=admin)
    with pytest.raises(ConfigurationError, match="predates"):
        store.set_password(
            "bob", PASSWORD + " stale", authorization=self_proof
        )
    assert store.authenticate("bob", reset) is not None


def test_report_identity_must_match_its_account(tmp_path):
    config = config_with(tmp_path)
    users = UserStore(config.watch.users_database, clock=lambda: NOW)
    alice = users.add(
        "alice", display_name="Alice Smith", email="alice@example.com"
    )
    with pytest.raises(ConfigurationError, match="display identity"):
        ReportIdentity("registered", "Mallory", user=alice)
    with pytest.raises(ConfigurationError, match="email identity"):
        ReportIdentity(
            "registered",
            "Alice Smith",
            user=alice,
            email="mallory@example.com",
        )


def test_listing_and_export_reject_malformed_rows(tmp_path, capsys):
    config = config_with(tmp_path)
    store = seed(config)
    open_service(store).report_cve(IDENTIFIER, by="first")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET user_id='x' WHERE id=1")
    assert cli.main(
        ["--config", str(config.config_path), "watch", "reported", "--all"]
    ) == 2
    assert "invalid" in capsys.readouterr().err
    assert cli.main(
        [
            "--config",
            str(config.config_path),
            "watch",
            "reported",
            "--all",
            "--format",
            "json",
        ]
    ) == 2
    assert "invalid" in capsys.readouterr().err

    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE watch_report SET user_id=1, note=CAST('blob' AS BLOB)")
    assert cli.main(
        ["--config", str(config.config_path), "watch", "reported", "--all"]
    ) == 2
    assert "invalid" in capsys.readouterr().err


def test_empty_and_populated_csv_exports_share_a_header(tmp_path, capsys):
    config = config_with(tmp_path)
    store = seed(config)
    base = [
        "--config",
        str(config.config_path),
        "watch",
        "reported",
        "--all",
        "--format",
        "csv",
    ]
    assert cli.main(base) == 0
    empty_header = capsys.readouterr().out.splitlines()[0]
    open_service(store).report_cve(IDENTIFIER, by="first")
    assert cli.main(base) == 0
    full_header = capsys.readouterr().out.splitlines()[0]
    assert empty_header == full_header
    assert "chain_version" in full_header and "legacy" in full_header


def test_concurrent_bootstrap_creates_only_one_administrator(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    store = UserStore(tmp_path / "users.db", clock=lambda: NOW)

    def bootstrap(index: int) -> bool:
        try:
            store.add(
                f"admin{index}",
                password=PASSWORD,
                is_admin=True,
                authorization=BOOTSTRAP,
            )
            return True
        except ConfigurationError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(bootstrap, (1, 2)))
    assert sorted(results) == [False, True]
    assert sum(user.is_admin for user in store.users()) == 1


def test_concurrent_creation_between_check_and_open_is_revalidated(
    tmp_path, monkeypatch
):
    import shutil

    path = tmp_path / "users.db"
    store = UserStore(path, clock=lambda: NOW)
    other = UserStore(tmp_path / "concurrent-users.db", clock=lambda: NOW)
    other.add("alice", password=PASSWORD)
    import cvebeacon.watch.users as users_module
    import sqlite3 as sqlite_module

    real_connect = sqlite_module.connect
    injected = []

    def creating_connect(database, *args, **kwargs):
        if not injected:
            injected.append(True)
            if not path.exists():
                os.close(
                    os.open(
                        path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                )
            # The second first-time opener finished creating the account file
            # after this opener checked for it but before SQLite opened it.
            shutil.copyfile(other.path, path)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(users_module.sqlite3, "connect", creating_connect)
    store.initialize()
    assert store.users()[0].username == "alice"


def test_concurrent_write_while_opening_an_existing_database_is_not_replacement(
    tmp_path, monkeypatch
):
    path = tmp_path / "users.db"
    store = UserStore(path, clock=lambda: NOW)
    store.initialize()
    import cvebeacon.watch.users as users_module
    import sqlite3 as sqlite_module

    real_connect = sqlite_module.connect
    injected = []

    def writing_connect(database, *args, **kwargs):
        if not injected:
            injected.append(True)
            with real_connect(path) as other:
                other.execute(
                    "INSERT INTO cb_user_meta(key,value) VALUES ('race','1')"
                )
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(users_module.sqlite3, "connect", writing_connect)
    assert store.users() == ()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file identity")
def test_same_store_id_replacement_cannot_recycle_the_validated_inode(
    tmp_path, monkeypatch
):
    import shutil
    from types import SimpleNamespace

    path = tmp_path / "users.db"
    store = UserStore(path, clock=lambda: NOW)
    store.initialize()
    original = path.stat()
    copy = tmp_path / "copy.db"
    shutil.copyfile(path, copy)
    copy.chmod(0o600)
    changed = UserStore(copy, clock=lambda: NOW)
    changed.add("replacement")
    assert changed._store_id == store._store_id

    real_open, real_stat = os.open, os.stat
    real_connect = sqlite3.connect
    validated = []
    recycled = []
    swapped = []

    def recording_open(candidate, *args, **kwargs):
        descriptor = real_open(candidate, *args, **kwargs)
        if Path(candidate) == path:
            validated.append(descriptor)
        return descriptor

    def swapping_connect(database, *args, **kwargs):
        if swapped:
            return real_connect(database, *args, **kwargs)
        swapped.append(True)
        try:
            os.fstat(validated[-1])
        except OSError:
            recycled.append(True)
        path.unlink()
        shutil.copyfile(copy, path)
        path.chmod(0o600)
        return real_connect(database, *args, **kwargs)

    def recycling_stat(candidate, *args, **kwargs):
        current = real_stat(candidate, *args, **kwargs)
        if Path(candidate) == path and recycled:
            recycled.pop()
            # The OS may reuse an unlinked inode only after its last open
            # descriptor closes. Model that reuse while keeping real metadata.
            return SimpleNamespace(
                st_dev=original.st_dev,
                st_ino=original.st_ino,
                st_mode=current.st_mode,
                st_size=current.st_size,
                st_mtime_ns=current.st_mtime_ns,
            )
        return current

    monkeypatch.setattr("cvebeacon.watch.users.os.open", recording_open)
    monkeypatch.setattr("cvebeacon.watch.users.os.stat", recycling_stat)
    monkeypatch.setattr("cvebeacon.watch.users.sqlite3.connect", swapping_connect)
    with pytest.raises(
        StateError, match="^CVEBeacon user database was replaced while opening$"
    ):
        store.users()


def test_foreign_read_only_ancestor_is_not_trusted(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX ownership model")
    child = tmp_path / "foreign"
    child.mkdir()
    child.chmod(0o555)
    real_euid = os.geteuid()
    monkeypatch.setattr(
        "cvebeacon.watch.users.os.geteuid", lambda: real_euid + 1
    )
    try:
        with pytest.raises(StateError) as caught:
            UserStore._trusted_directory_chain(child)
        assert str(child) in str(caught.value)
        assert "sticky-bit" in str(caught.value)
    finally:
        child.chmod(0o700)


def test_credential_version_revokes_proofs_without_clock_order(tmp_path):
    now = [NOW]
    store = UserStore(tmp_path / "users.db", clock=lambda: now[0])
    store.add("alice", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    store.add("bob", password=PASSWORD)
    self_proof = store.authenticate("bob", PASSWORD)
    admin = store.authenticate("alice", PASSWORD)

    now[0] = NOW - timedelta(seconds=5)
    reset = PASSWORD + " reset"
    store.set_password("bob", reset, authorization=admin)
    with pytest.raises(ConfigurationError, match="credential change"):
        store.set_password(
            "bob", PASSWORD + " stale", authorization=self_proof
        )

    self_proof = store.authenticate("bob", reset)
    now[0] = NOW - timedelta(seconds=10)
    store.disable("bob", authorization=admin)
    store.enable("bob", authorization=admin)
    with pytest.raises(ConfigurationError, match="credential change"):
        store.set_password(
            "bob", PASSWORD + " stale2", authorization=self_proof
        )


def test_replacement_with_identical_inode_and_timestamps_is_detected(
    tmp_path, monkeypatch
):
    import shutil

    path = tmp_path / "users.db"
    store = UserStore(path, clock=lambda: NOW)
    store.initialize()
    other = tmp_path / "other-users.db"
    UserStore(other, clock=lambda: NOW).initialize()
    original = path.stat()
    import sqlite3 as sqlite_module

    real_connect = sqlite_module.connect

    def swapping_connect(database, *args, **kwargs):
        path.unlink()
        shutil.copyfile(other, path)
        os.chmod(path, 0o600)
        return real_connect(database, *args, **kwargs)

    real_stat = os.stat

    def fake_stat(candidate, *args, **kwargs):
        if Path(candidate) == path:
            return original
        return real_stat(candidate, *args, **kwargs)

    monkeypatch.setattr("cvebeacon.watch.users.sqlite3.connect", swapping_connect)
    monkeypatch.setattr("cvebeacon.watch.users.os.stat", fake_stat)
    with pytest.raises(StateError, match="replaced"):
        store.users()


def test_existing_database_without_meta_gains_one_store_id(tmp_path):
    path = tmp_path / "users.db"
    old_user_database(path, "alice@example.com")
    store = UserStore(path, clock=lambda: NOW)
    store.initialize()
    with sqlite3.connect(path) as db:
        row = db.execute(
            "SELECT value FROM cb_user_meta WHERE key='store_id'"
        ).fetchone()
    assert row is not None and len(row[0]) == 64
    assert UserStore(path, clock=lambda: NOW).users()[0].username == "alice"
