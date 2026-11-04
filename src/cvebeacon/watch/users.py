"""CVEBeacon user accounts, authentication and the user-admin audit trail.

The account file is separate from the watch database so credentials can be
backed up and permissioned on their own, and so deleting or re-syncing the
public CVE history does not delete the people who use CVEBeacon.
"""

from __future__ import annotations

import os
import re
import sqlite3
import unicodedata
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..errors import ConfigurationError, StateError
from ..passwords import (
    DUMMY_HASH,
    hash_password_value,
    validate_password,
    verify_password,
)
from .chain import chain_hash, verify_chain
from .reported import checked_text, host_name, os_account

USERNAME_LIMIT = 64
DISPLAY_LIMIT = 100
EMAIL_LIMIT = 254
LOCKOUT_FAILURES = 5
LOCKOUT_MINUTES = 15
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9._@-]{1,64}\Z")
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+\Z")
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
_USER_COLUMNS = (
    "id,username,display_name,email,is_admin,disabled,created_at,updated_at,"
    "password_changed_at,failed_logins,locked_until"
)
AUDIT_CHAIN_FIELDS = ("id", "action", "username", "at", "os_account", "host")
_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS cb_user (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT,
        email TEXT COLLATE NOCASE,
        password_hash TEXT,
        is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
        disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        password_changed_at TEXT,
        failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS cb_user_email "
    "ON cb_user(email) WHERE email IS NOT NULL",
    """CREATE TABLE IF NOT EXISTS cb_user_audit (
        id INTEGER PRIMARY KEY,
        action TEXT NOT NULL,
        username TEXT NOT NULL,
        at TEXT NOT NULL,
        os_account TEXT,
        host TEXT,
        chain TEXT NOT NULL
    )""",
)


@dataclass(frozen=True, slots=True)
class User:
    """One account; deliberately carries no password hash."""

    id: int
    username: str
    display_name: str | None
    email: str | None
    is_admin: bool
    disabled: bool
    created_at: str
    updated_at: str
    password_changed_at: str | None
    failed_logins: int
    locked_until: str | None

    @property
    def identity(self) -> str:
        return self.display_name or self.username


@dataclass(frozen=True, slots=True)
class UserAuditEntry:
    id: int
    action: str
    username: str
    at: str
    os_account: str | None
    host: str | None
    chain: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def validate_username(value: object) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(
            "username must be 1–64 characters using letters, digits, dot, "
            "underscore, at sign, or hyphen"
        )
    text = checked_text(value, "username")
    if not USERNAME_PATTERN.fullmatch(text):
        raise ConfigurationError(
            "username must be 1–64 characters using letters, digits, dot, "
            "underscore, at sign, or hyphen"
        )
    return text


def validate_display_name(value: object | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError("display name must be text")
    text = checked_text(value, "display name").strip(" ")
    if not text:
        return None
    if len(text) > DISPLAY_LIMIT:
        raise ConfigurationError(
            f"display name must be at most {DISPLAY_LIMIT} characters"
        )
    return text


def validate_email(value: object | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError("email address is not valid")
    text = checked_text(value, "email address").strip(" ")
    if not text:
        return None
    if len(text) > EMAIL_LIMIT or not EMAIL_PATTERN.fullmatch(text):
        raise ConfigurationError("email address is not valid")
    return text


def audit_name(value: object) -> str:
    """Sanitise a typed login name before it enters the audit table."""
    text = "" if value is None else str(value)
    text = text.encode("utf-8", "replace").decode("utf-8")
    text = "".join(
        character
        for character in text
        if unicodedata.category(character) not in _FORBIDDEN_CATEGORIES
    ).strip(" ")
    return text[:DISPLAY_LIMIT] or "(blank)"


class UserStore:
    def __init__(
        self, path: str | Path, *, clock=_utc_now
    ) -> None:
        self.path = Path(path)
        self._clock = clock

    def _connect(self) -> sqlite3.Connection:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                descriptor = os.open(
                    self.path, os.O_RDWR | os.O_CREAT, 0o600
                )
                try:
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            return connection
        except (sqlite3.Error, OSError) as exc:
            raise StateError(
                f"cannot open CVEBeacon user database {self.path}: {exc}"
            ) from exc

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise StateError(f"user database transaction failed: {exc}") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with closing(self._connect()) as db:
            for statement in _SCHEMA:
                db.execute(statement)
            db.commit()

    @staticmethod
    def _user(row) -> User:
        return User(
            int(row["id"]),
            str(row["username"]),
            row["display_name"],
            row["email"],
            bool(row["is_admin"]),
            bool(row["disabled"]),
            str(row["created_at"]),
            str(row["updated_at"]),
            row["password_changed_at"],
            int(row["failed_logins"]),
            row["locked_until"],
        )

    @staticmethod
    def _find_identifier(db: sqlite3.Connection, identifier: object):
        if not isinstance(identifier, str) or not identifier or len(identifier) > EMAIL_LIMIT:
            return None
        row = db.execute(
            f"SELECT {_USER_COLUMNS},password_hash FROM cb_user "
            "WHERE username=? COLLATE NOCASE",
            (identifier,),
        ).fetchone()
        if row is None:
            row = db.execute(
                f"SELECT {_USER_COLUMNS},password_hash FROM cb_user "
                "WHERE email=? COLLATE NOCASE",
                (identifier,),
            ).fetchone()
        return row

    @staticmethod
    def _find_username(db: sqlite3.Connection, identifier: object):
        if not isinstance(identifier, str) or not identifier or len(identifier) > USERNAME_LIMIT:
            return None
        return db.execute(
            f"SELECT {_USER_COLUMNS},password_hash FROM cb_user "
            "WHERE username=? COLLATE NOCASE",
            (identifier,),
        ).fetchone()

    def find(self, username: object) -> User | None:
        self.initialize()
        with closing(self._connect()) as db:
            row = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE username=? COLLATE NOCASE",
                (str(username),),
            ).fetchone()
        return None if row is None else self._user(row)

    def resolve(self, identifier: object) -> User | None:
        """Find an account by username or email, enabled or disabled."""
        self.initialize()
        with closing(self._connect()) as db:
            row = self._find_identifier(db, identifier)
        return None if row is None else self._user(row)

    def resolve_enabled(self, identifier: object) -> User | None:
        user = self.resolve(identifier)
        if user is None or user.disabled:
            return None
        return user

    def users(self) -> tuple[User, ...]:
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user ORDER BY username COLLATE NOCASE"
            ).fetchall()
        return tuple(self._user(row) for row in rows)

    def add(
        self,
        username: object,
        *,
        password: object | None = None,
        display_name: object | None = None,
        email: object | None = None,
        is_admin: bool = False,
    ) -> User:
        name = validate_username(username)
        shown = validate_display_name(display_name)
        address = validate_email(email)
        self.initialize()
        if password is not None:
            password = validate_password(
                password, forbidden=(name, address)
            )
            encoded = hash_password_value(password)
        else:
            encoded = None
        now = _timestamp(self._clock())
        with self.transaction() as db:
            for value in (name, address):
                if value is None:
                    continue
                existing = db.execute(
                    "SELECT 1 FROM cb_user WHERE username=? COLLATE NOCASE "
                    "OR email=? COLLATE NOCASE",
                    (value, value),
                ).fetchone()
                if existing is not None:
                    raise ConfigurationError(
                        "username or email is already registered"
                    )
            try:
                cursor = db.execute(
                    "INSERT INTO cb_user(username,display_name,email,"
                    "password_hash,is_admin,disabled,created_at,updated_at,"
                    "password_changed_at,failed_logins,locked_until) "
                    "VALUES (?,?,?,?,?,0,?,?,?,0,NULL)",
                    (
                        name,
                        shown,
                        address,
                        encoded,
                        int(bool(is_admin)),
                        now,
                        now,
                        now if encoded is not None else None,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConfigurationError(
                    "username or email is already registered"
                ) from exc
            user_id = int(cursor.lastrowid)
            self._append_audit(db, "add", name, now)
            row = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user_id,)
            ).fetchone()
        return self._user(row)

    def set_password(self, username: object, password: object) -> User:
        self.initialize()
        with self.transaction() as db:
            row = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE username=? COLLATE NOCASE",
                (str(username),),
            ).fetchone()
            if row is None:
                raise ConfigurationError("user not found")
            user = self._user(row)
            password = validate_password(
                password, forbidden=(user.username, user.email)
            )
            now = _timestamp(self._clock())
            db.execute(
                "UPDATE cb_user SET password_hash=?,password_changed_at=?,"
                "updated_at=?,failed_logins=0,locked_until=NULL WHERE id=?",
                (hash_password_value(password), now, now, user.id),
            )
            self._append_audit(db, "passwd", user.username, now)
            updated = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user.id,)
            ).fetchone()
        return self._user(updated)

    def disable(self, username: object) -> User:
        return self._set_disabled(username, True, "disable")

    def enable(self, username: object) -> User:
        return self._set_disabled(username, False, "enable")

    def _set_disabled(self, username: object, value: bool, action: str) -> User:
        self.initialize()
        with self.transaction() as db:
            row = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE username=? COLLATE NOCASE",
                (str(username),),
            ).fetchone()
            if row is None:
                raise ConfigurationError("user not found")
            user = self._user(row)
            now = _timestamp(self._clock())
            db.execute(
                "UPDATE cb_user SET disabled=?,updated_at=? WHERE id=?",
                (int(value), now, user.id),
            )
            self._append_audit(db, action, user.username, now)
            updated = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user.id,)
            ).fetchone()
        return self._user(updated)

    def unlock(self, username: object) -> User:
        self.initialize()
        with self.transaction() as db:
            row = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE username=? COLLATE NOCASE",
                (str(username),),
            ).fetchone()
            if row is None:
                raise ConfigurationError("user not found")
            user = self._user(row)
            now = _timestamp(self._clock())
            db.execute(
                "UPDATE cb_user SET failed_logins=0,locked_until=NULL,"
                "updated_at=? WHERE id=?",
                (now, user.id),
            )
            self._append_audit(db, "unlock", user.username, now)
            updated = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user.id,)
            ).fetchone()
        return self._user(updated)

    @staticmethod
    def _locked(row, now: datetime) -> bool:
        raw = row["locked_until"]
        if not raw:
            return False
        try:
            parsed = datetime.fromisoformat(str(raw))
        except ValueError:
            # A corrupt lock timestamp fails closed until an admin unlocks it.
            return True
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc) > now

    def authenticate(
        self,
        identifier: object,
        password: object,
        *,
        os_account_value: str | None = None,
        host_value: str | None = None,
    ) -> User | None:
        """Verify one username login. Every failure looks the same to the caller.

        Email addresses are a lookup and notice detail, not a login identifier.
        """
        self.initialize()
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        now = now.astimezone(timezone.utc)
        stamp = _timestamp(now)
        account = os_account_value or os_account()
        host = host_value or host_name()
        typed = audit_name(identifier)
        with self.transaction() as db:
            row = self._find_username(db, identifier)
            if row is None:
                verify_password(DUMMY_HASH, password)
                self._append_audit(
                    db, "login_failed", typed, stamp, account, host
                )
                return None
            user = self._user(row)
            if self._locked(row, now):
                verify_password(DUMMY_HASH, password)
                self._append_audit(
                    db, "login_locked", typed, stamp, account, host
                )
                return None
            if user.disabled or row["password_hash"] is None:
                verify_password(DUMMY_HASH, password)
                accepted = False
            else:
                accepted = verify_password(row["password_hash"], password)
            if not accepted:
                failures = int(row["failed_logins"]) + 1
                locked_until = row["locked_until"]
                if failures >= LOCKOUT_FAILURES:
                    locked_until = _timestamp(
                        now + timedelta(minutes=LOCKOUT_MINUTES)
                    )
                db.execute(
                    "UPDATE cb_user SET failed_logins=?,locked_until=?,"
                    "updated_at=? WHERE id=?",
                    (failures, locked_until, stamp, user.id),
                )
                self._append_audit(
                    db, "login_failed", typed, stamp, account, host
                )
                return None
            db.execute(
                "UPDATE cb_user SET failed_logins=0,locked_until=NULL,"
                "updated_at=? WHERE id=?",
                (stamp, user.id),
            )
            self._append_audit(
                db, "login", user.username, stamp, account, host
            )
        return replace(user, failed_logins=0, locked_until=None, updated_at=stamp)

    def _append_audit(
        self,
        db: sqlite3.Connection,
        action: str,
        username: str,
        at: str,
        account: str | None = None,
        host: str | None = None,
    ) -> None:
        account = account or os_account()
        host = host or host_name()
        cursor = db.execute(
            "INSERT INTO cb_user_audit(action,username,at,os_account,host,chain) "
            "VALUES (?,?,?,?,?,'')",
            (action, username, at, account, host),
        )
        row_id = int(cursor.lastrowid)
        previous = db.execute(
            "SELECT chain FROM cb_user_audit WHERE id<? ORDER BY id DESC LIMIT 1",
            (row_id,),
        ).fetchone()
        values = {
            "id": row_id,
            "action": action,
            "username": username,
            "at": at,
            "os_account": account,
            "host": host,
        }
        db.execute(
            "UPDATE cb_user_audit SET chain=? WHERE id=?",
            (chain_hash(previous["chain"] if previous else "", values), row_id),
        )

    def audit_entries(self) -> tuple[UserAuditEntry, ...]:
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT id,action,username,at,os_account,host,chain "
                "FROM cb_user_audit ORDER BY id"
            ).fetchall()
        return tuple(
            UserAuditEntry(
                int(row["id"]),
                str(row["action"]),
                str(row["username"]),
                str(row["at"]),
                row["os_account"],
                row["host"],
                str(row["chain"]),
            )
            for row in rows
        )

    def verify_audit(self) -> UserAuditEntry | None:
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM cb_user_audit ORDER BY id").fetchall()
        broken = verify_chain((dict(row) for row in rows), AUDIT_CHAIN_FIELDS)
        if broken is None:
            return None
        return UserAuditEntry(
            int(broken["id"]),
            str(broken["action"]),
            str(broken["username"]),
            str(broken["at"]),
            broken["os_account"],
            broken["host"],
            str(broken["chain"]),
        )
