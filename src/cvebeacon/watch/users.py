"""CVEBeacon user accounts, authentication and the user-admin audit trail.

The account file is separate from the watch database so credentials can be
backed up and permissioned on their own, and so deleting or re-syncing the
public CVE history does not delete the people who use CVEBeacon.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
import unicodedata
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..errors import ConfigurationError, StateError
from ..passwords import (
    DUMMY_HASH,
    hash_password_value,
    validate_password,
    verify_password,
)
from .chain import chain_hash, decode_text, verify_chain
from .reported import checked_text, host_name, os_account

if TYPE_CHECKING:
    from .identity import ReportIdentity

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
        email_key TEXT,
        password_hash TEXT,
        is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
        disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        password_changed_at TEXT,
        failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS cb_user_audit (
        id INTEGER PRIMARY KEY,
        action TEXT NOT NULL,
        username TEXT NOT NULL,
        actor TEXT,
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
class AuthenticatedUser:
    """Proof of one successful password login, not a roster lookup."""

    user: User
    login_id: int

    @property
    def id(self) -> int:
        return self.user.id

    @property
    def username(self) -> str:
        return self.user.username

    @property
    def identity(self) -> str:
        return self.user.identity


@dataclass(frozen=True, slots=True)
class UserAuditEntry:
    id: int
    action: str
    username: str
    at: str
    os_account: str | None
    host: str | None
    chain: str
    actor: str | None = None


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


def email_lookup_key(value: str) -> str:
    """One Unicode-aware key for uniqueness and registered-mode lookup."""
    return unicodedata.normalize("NFC", value).casefold()


def audit_name(value: object) -> str:
    """Sanitise a typed login name before it enters the audit table.

    A value that is not a syntactically valid username is replaced with a
    fixed placeholder. This avoids retaining a password accidentally typed
    into the username field in the chained audit trail.
    """
    text = "" if value is None else str(value)
    text = text.encode("utf-8", "replace").decode("utf-8")
    text = "".join(
        character
        for character in text
        if unicodedata.category(character) not in _FORBIDDEN_CATEGORIES
    ).strip(" ")
    if not USERNAME_PATTERN.fullmatch(text):
        return "(invalid name)"
    return text


class UserStore:
    def __init__(
        self, path: str | Path, *, clock=_utc_now
    ) -> None:
        self.path = Path(path)
        self._clock = clock

    def _connect(self, *, create: bool = True) -> sqlite3.Connection:
        try:
            parent = self.path.parent
            if create:
                parent.mkdir(parents=True, exist_ok=True)
            resolved_parent = parent.resolve()
            path = resolved_parent / self.path.name
            connection = None
            if os.name == "posix":
                directory = resolved_parent.stat()
                directory_mode = stat.S_IMODE(directory.st_mode)
                if directory.st_uid not in {os.geteuid(), 0}:
                    raise StateError(
                        "CVEBeacon user database directory must be owned by "
                        "this account or root"
                    )
                if directory_mode & 0o022:
                    raise StateError(
                        "CVEBeacon user database directory must not be group "
                        "or other writable"
                    )
                parent_identity = (directory.st_dev, directory.st_ino)
                flags = (
                    os.O_RDWR if create else os.O_RDONLY
                ) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    if create:
                        descriptor = os.open(
                            path, flags | os.O_CREAT | os.O_EXCL, 0o600
                        )
                        created = True
                    else:
                        descriptor = os.open(path, flags)
                        created = False
                except FileExistsError:
                    descriptor = os.open(path, flags)
                    created = False
                except FileNotFoundError as exc:
                    raise StateError(
                        "CVEBeacon user database not found"
                    ) from exc
                try:
                    details = os.fstat(descriptor)
                    if not stat.S_ISREG(details.st_mode):
                        raise StateError(
                            "CVEBeacon user database must be a regular file"
                        )
                    if details.st_uid != os.geteuid():
                        raise StateError(
                            "CVEBeacon user database must be owned by this "
                            "account"
                        )
                    if created:
                        os.fchmod(descriptor, 0o600)
                    elif stat.S_IMODE(details.st_mode) & 0o077:
                        raise StateError(
                            "CVEBeacon user database must not be group or "
                            "other accessible"
                        )
                    expected = (details.st_dev, details.st_ino)
                finally:
                    os.close(descriptor)
                connection = sqlite3.connect(
                    f"{path.as_uri()}?mode={'rwc' if create else 'ro'}",
                    uri=True,
                    timeout=30,
                )
                try:
                    current = os.stat(path, follow_symlinks=False)
                except OSError as exc:
                    connection.close()
                    raise StateError(
                        "CVEBeacon user database was replaced while opening"
                    ) from exc
                current_parent = resolved_parent.stat()
                if (
                    not stat.S_ISREG(current.st_mode)
                    or (current.st_dev, current.st_ino) != expected
                    or (current_parent.st_dev, current_parent.st_ino)
                    != parent_identity
                ):
                    connection.close()
                    raise StateError(
                        "CVEBeacon user database was replaced while opening"
                    )
            else:
                if not create and not path.exists():
                    raise StateError("CVEBeacon user database not found")
                connection = sqlite3.connect(
                    str(path), timeout=30
                )
            connection.row_factory = sqlite3.Row
            return connection
        except StateError:
            raise
        except (sqlite3.Error, OSError, ValueError) as exc:
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

    def initialize(self, *, create: bool = True) -> None:
        with closing(self._connect(create=create)) as db:
            for statement in _SCHEMA:
                db.execute(statement)
            self._migrate_email_keys(db)
            self._migrate_audit_actor(db)
            db.commit()

    @staticmethod
    def _migrate_email_keys(db: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in db.execute("PRAGMA table_info(cb_user)")
        }
        if "email_key" not in columns:
            db.execute("ALTER TABLE cb_user ADD COLUMN email_key TEXT")
        rows = db.execute(
            "SELECT id,email FROM cb_user WHERE email IS NOT NULL"
        ).fetchall()
        for row in rows:
            key = email_lookup_key(str(row["email"]))
            db.execute(
                "UPDATE cb_user SET email_key=? WHERE id=?",
                (key, row["id"]),
            )
        db.execute("DROP INDEX IF EXISTS cb_user_email")
        username_keys: dict[str, str] = {}
        for row in db.execute("SELECT username FROM cb_user"):
            name = str(row["username"])
            key = email_lookup_key(name)
            if key in username_keys and username_keys[key] != name:
                raise StateError(
                    "CVEBeacon account usernames collide under Unicode case "
                    "folding; correct the account file"
                )
            username_keys[key] = name
        for row in db.execute(
            "SELECT username,email_key FROM cb_user "
            "WHERE email_key IS NOT NULL"
        ):
            username = str(row["username"])
            key = str(row["email_key"])
            owner = username_keys.get(key)
            if owner is not None and owner != username:
                raise StateError(
                    "CVEBeacon account usernames and emails collide under "
                    "Unicode case folding; correct the account file"
                )
        try:
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS cb_user_email_key "
                "ON cb_user(email_key) WHERE email_key IS NOT NULL"
            )
        except sqlite3.IntegrityError as exc:
            raise StateError(
                "CVEBeacon account emails collide under Unicode case "
                "folding; correct the account file"
            ) from exc

    @staticmethod
    def _migrate_audit_actor(db: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in db.execute("PRAGMA table_info(cb_user_audit)")
        }
        if "actor" not in columns:
            db.execute("ALTER TABLE cb_user_audit ADD COLUMN actor TEXT")

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
                "WHERE email_key=?",
                (email_lookup_key(identifier),),
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

    def has_admin(self) -> bool:
        self.initialize()
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT 1 FROM cb_user WHERE is_admin=1 LIMIT 1"
            ).fetchone()
        return row is not None

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
        actor: str | None = None,
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
        checks = [(name, email_lookup_key(name))]
        if address is not None:
            checks.append((address, email_lookup_key(address)))
        with self.transaction() as db:
            existing_usernames = {
                email_lookup_key(str(row["username"]))
                for row in db.execute("SELECT username FROM cb_user")
            }
            for value, key in checks:
                if key in existing_usernames:
                    raise ConfigurationError(
                        "username or email is already registered"
                    )
                existing = db.execute(
                    "SELECT 1 FROM cb_user WHERE username=? COLLATE NOCASE "
                    "OR email_key=?",
                    (value, key),
                ).fetchone()
                if existing is not None:
                    raise ConfigurationError(
                        "username or email is already registered"
                    )
            try:
                cursor = db.execute(
                    "INSERT INTO cb_user(username,display_name,email,email_key,"
                    "password_hash,is_admin,disabled,created_at,updated_at,"
                    "password_changed_at,failed_logins,locked_until) "
                    "VALUES (?,?,?,?,?,?,0,?,?,?,0,NULL)",
                    (
                        name,
                        shown,
                        address,
                        None if address is None else email_lookup_key(address),
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
            self._append_audit(db, "add", name, now, actor=actor)
            row = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user_id,)
            ).fetchone()
        return self._user(row)

    def set_password(
        self, username: object, password: object, *, actor: str | None = None
    ) -> User:
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
            self._append_audit(db, "passwd", user.username, now, actor=actor)
            updated = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user.id,)
            ).fetchone()
        return self._user(updated)

    def disable(self, username: object, *, actor: str | None = None) -> User:
        return self._set_disabled(username, True, "disable", actor=actor)

    def enable(self, username: object, *, actor: str | None = None) -> User:
        return self._set_disabled(username, False, "enable", actor=actor)

    def _set_disabled(
        self,
        username: object,
        value: bool,
        action: str,
        *,
        actor: str | None = None,
    ) -> User:
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
            self._append_audit(db, action, user.username, now, actor=actor)
            updated = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user.id,)
            ).fetchone()
        return self._user(updated)

    def unlock(self, username: object, *, actor: str | None = None) -> User:
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
            self._append_audit(db, "unlock", user.username, now, actor=actor)
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
    ) -> AuthenticatedUser | None:
        """Verify one username login. Every failure looks the same to the caller.

        Email addresses are a lookup and notice detail, not a login identifier.
        A successful result carries the login audit row that proves the
        password check; a roster lookup cannot produce this type.
        """
        self.initialize()
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        now = now.astimezone(timezone.utc)
        stamp = _timestamp(now)
        account = os_account()
        host = host_name()
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
                expired = bool(row["locked_until"]) and not self._locked(
                    row, now
                )
                failures = (
                    0 if expired else int(row["failed_logins"])
                ) + 1
                locked_until = None if expired else row["locked_until"]
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
            login_id = self._append_audit(
                db, "login", user.username, stamp, account, host
            )
        return AuthenticatedUser(
            replace(user, failed_logins=0, locked_until=None, updated_at=stamp),
            login_id,
        )

    def require_current(self, identity: "ReportIdentity") -> None:
        """Standalone re-check used by tests and non-atomic probes."""
        if identity.mode == "open":
            return
        self.initialize()
        with closing(self._connect(create=False)) as db:
            self.require_current_in(db, identity)

    def require_current_in(
        self, db: sqlite3.Connection, identity: "ReportIdentity"
    ) -> None:
        """Reject a deleted, renamed, disabled or unproven account.

        The caller may hold the user-database lock; ``ReportService`` keeps a
        ``transaction()`` open from this check through the report write so a
        concurrent disable cannot slip between them.
        """
        if identity.mode == "open":
            return
        if identity.user is None:
            raise ConfigurationError("the resolved CVEBeacon user is missing")
        row = db.execute(
            f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?",
            (identity.user.id,),
        ).fetchone()
        if row is None:
            raise ConfigurationError("the CVEBeacon user no longer exists")
        current = self._user(row)
        if current.username != identity.user.username:
            raise ConfigurationError(
                "the CVEBeacon user no longer matches the resolved identity"
            )
        if current.disabled:
            raise ConfigurationError("the CVEBeacon user is disabled")
        if identity.mode != "authenticated":
            return
        proof = identity.authenticated
        if (
            proof is None
            or proof.user.id != current.id
            or proof.user.username != current.username
        ):
            raise ConfigurationError(
                "authenticated identity proof does not match the user"
            )
        login = db.execute(
            "SELECT action,username,at FROM cb_user_audit WHERE id=?",
            (proof.login_id,),
        ).fetchone()
        if (
            login is None
            or login["action"] != "login"
            or login["username"] != current.username
        ):
            raise ConfigurationError(
                "authenticated identity proof is not a successful login"
            )
        changed = current.password_changed_at
        if changed:
            login_at = self._parse_time(login["at"])
            changed_at = self._parse_time(changed)
            if (
                login_at is None
                or changed_at is None
                or login_at < changed_at
            ):
                raise ConfigurationError(
                    "authenticated identity proof predates the password change"
                )

    @staticmethod
    def _parse_time(value: object) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _append_audit(
        self,
        db: sqlite3.Connection,
        action: str,
        username: str,
        at: str,
        account: str | None = None,
        host: str | None = None,
        actor: str | None = None,
    ) -> int:
        account = account or os_account()
        host = host or host_name()
        cursor = db.execute(
            "INSERT INTO cb_user_audit("
            "action,username,actor,at,os_account,host,chain) "
            "VALUES (?,?,?,?,?,?,'')",
            (action, username, actor, at, account, host),
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
        if actor is not None:
            values["actor"] = actor
        db.execute(
            "UPDATE cb_user_audit SET chain=? WHERE id=?",
            (chain_hash(previous["chain"] if previous else "", values), row_id),
        )
        return row_id

    def audit_entries(self) -> tuple[UserAuditEntry, ...]:
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT id,action,username,actor,at,os_account,host,chain "
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
                row["actor"],
            )
            for row in rows
        )

    def audit_count(self) -> int:
        if not self.path.is_file():
            raise StateError("CVEBeacon user database not found")
        with closing(self._connect(create=False)) as db:
            return int(
                db.execute("SELECT COUNT(*) FROM cb_user_audit").fetchone()[0]
            )

    def verify_audit(self) -> int | None:
        """Return the first broken user-audit row id, or ``None``.

        The check never creates a missing account file or table. It covers the
        user-admin audit log, not direct edits to the ``cb_user`` account rows.
        """
        if not self.path.is_file():
            raise StateError("CVEBeacon user database not found")
        with closing(self._connect(create=False)) as db:
            tables = {
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "cb_user" not in tables or "cb_user_audit" not in tables:
                raise StateError("CVEBeacon user audit trail is missing")
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(cb_user_audit)")
            }
            required = {
                "id", "action", "username", "at", "os_account", "host", "chain",
            }
            if not required <= columns:
                raise StateError("cb_user_audit is missing required columns")
            db.text_factory = decode_text
            rows = db.execute(
                "SELECT * FROM cb_user_audit ORDER BY id"
            ).fetchall()
        return verify_chain(
            rows, AUDIT_CHAIN_FIELDS, optional_fields=("actor",)
        )
