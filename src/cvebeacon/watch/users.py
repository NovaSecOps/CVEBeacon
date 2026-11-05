"""CVEBeacon user accounts, authentication and the user-admin audit trail.

The account file is separate from the watch database so credentials can be
backed up and permissioned on their own, and so deleting or re-syncing the
public CVE history does not delete the people who use CVEBeacon.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import stat
import threading
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
from .directories import ensure_private_directory
from .reported import checked_text, host_name, os_account
from .permissions import DEFAULT_ROLES, PERMISSIONS

if TYPE_CHECKING:
    from .identity import ReportIdentity

USERNAME_LIMIT = 64
DISPLAY_LIMIT = 100
EMAIL_LIMIT = 254
LOCKOUT_FAILURES = 5
LOCKOUT_MINUTES = 15
MAX_LOGIN_FAILURE_AUDITS = 10_000
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9._@-]{1,64}\Z")
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+\Z")
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
_USER_COLUMNS = (
    "id,username,display_name,email,is_admin,disabled,created_at,updated_at,"
    "password_changed_at,failed_logins,locked_until,credential_version"
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
        locked_until TEXT,
        credential_version INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS cb_user_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
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
    """CREATE TABLE IF NOT EXISTS cb_role (
        name TEXT PRIMARY KEY,
        permissions TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS cb_user_role (
        user_id INTEGER PRIMARY KEY,
        role TEXT NOT NULL
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
    credential_version: int = 0

    @property
    def identity(self) -> str:
        return self.display_name or self.username


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """Proof of one successful password login, not a roster lookup."""

    user: User
    login_id: int
    credential_version: int = 0

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
class BootstrapAuthorization:
    """The first administrator creation, checked inside the add transaction."""


BOOTSTRAP = BootstrapAuthorization()


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


# Closing any raw descriptor of a database can drop every POSIX record lock
# this process holds on it, including another instance's SQLite transaction.
# Reuse inode pins and leave cleanup to process exit, even after a failed open.
_DATABASE_PINS: dict[tuple[int, int], list[int]] = {}
_DATABASE_PINS_LOCK = threading.Lock()


def _pin_database(path: Path, *, create: bool) -> tuple[int, bool]:
    with _DATABASE_PINS_LOCK:
        try:
            current = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and stat.S_ISREG(current.st_mode):
            pins = _DATABASE_PINS.get((current.st_dev, current.st_ino))
            if pins:
                return pins[0], False

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
        details = os.fstat(descriptor)
        # A path swap between stat and open could select an already pinned
        # inode. Retain that extra descriptor too: closing it is unsafe.
        _DATABASE_PINS.setdefault(
            (details.st_dev, details.st_ino), []
        ).append(descriptor)
        return descriptor, created


def _retain_database_descriptor(
    descriptor: int,
    identity: tuple[int, int],
    target: tuple[int, int] | None,
) -> bool:
    """Keep a descriptor open when closing it could drop database locks.

    POSIX releases this process's record locks on a file when any descriptor
    for it closes. A descriptor that shares an inode with the target database
    or a pinned database therefore joins the registry instead of being closed.
    """
    with _DATABASE_PINS_LOCK:
        if identity not in _DATABASE_PINS and identity != target:
            return False
        _DATABASE_PINS.setdefault(identity, []).append(descriptor)
        return True


class UserStore:
    def __init__(
        self, path: str | Path, *, clock=_utc_now
    ) -> None:
        self.path = Path(path)
        self._clock = clock
        self._store_id: str | None = None

    @staticmethod
    def _trusted_directory_chain(directory: Path) -> tuple[tuple[int, int], ...]:
        """Validate every ancestor and return its device/inode identity."""
        euid = os.geteuid()
        identities: list[tuple[int, int]] = []
        current = directory
        while True:
            details = current.stat()
            if not stat.S_ISDIR(details.st_mode):
                raise StateError(
                    f"CVEBeacon user database path is not a directory: {current}"
                )
            mode = stat.S_IMODE(details.st_mode)
            if details.st_uid in {euid, 0}:
                if mode & 0o022 and not mode & stat.S_ISVTX:
                    raise StateError(
                        "CVEBeacon user database directory must not be group "
                        f"or other writable: {current}; chmod go-w {current}"
                    )
            elif not mode & stat.S_ISVTX:
                raise StateError(
                    "CVEBeacon user database directory must be owned by this "
                    f"account or root, or be sticky-bit protected: {current}"
                )
            identities.append((details.st_dev, details.st_ino))
            parent = current.parent
            if parent == current:
                break
            current = parent
        return tuple(identities)

    @staticmethod
    def _path_state(path: Path) -> tuple[bool, bool]:
        """Return whether the path exists and whether it is still empty.

        A final symlink counts as existing; the open path rejects it later.
        """
        try:
            details = os.lstat(path)
        except FileNotFoundError:
            return False, False
        return True, details.st_size == 0

    @contextmanager
    def _creation_lock(self, path: Path) -> Iterator[None]:
        """Serialize the first open that may create the account file.

        The lock file lives beside the database in the same protected
        directory. An advisory lock is released when the process exits, so a
        crash cannot leave a permanent lock. A creator that does not cooperate
        with the lock is still checked by the content verification below.
        """
        lock_path = path.with_name(path.name + ".lock")
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            try:
                descriptor = os.open(
                    lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600
                )
                created = True
            except FileExistsError:
                descriptor = os.open(lock_path, flags)
                created = False
        except OSError as exc:
            raise StateError(
                f"cannot open CVEBeacon user database lock {lock_path}: {exc}"
            ) from exc
        acquired = False
        retained = False
        identity: tuple[int, int] | None = None
        try:
            try:
                details = os.fstat(descriptor)
                identity = (details.st_dev, details.st_ino)
                try:
                    target_details = os.stat(path, follow_symlinks=False)
                except OSError:
                    target = None
                else:
                    target = (target_details.st_dev, target_details.st_ino)
                if _retain_database_descriptor(descriptor, identity, target):
                    retained = True
                    raise StateError(
                        "CVEBeacon user database lock must not be the account "
                        "database or a hardlink to it"
                    )
                if details.st_nlink != 1:
                    raise StateError(
                        "CVEBeacon user database lock must not be a hardlink"
                    )
                if not stat.S_ISREG(details.st_mode):
                    raise StateError(
                        "CVEBeacon user database lock must be a regular file"
                    )
                if os.name == "posix":
                    if details.st_uid != os.geteuid():
                        raise StateError(
                            "CVEBeacon user database lock must be owned by "
                            "this account"
                        )
                    if created:
                        os.fchmod(descriptor, 0o600)
                    elif stat.S_IMODE(details.st_mode) & 0o077:
                        raise StateError(
                            "CVEBeacon user database lock must not be group "
                            "or other accessible"
                        )
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                else:
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            except OSError as exc:
                raise StateError(
                    f"cannot lock CVEBeacon user database {path}: {exc}"
                ) from exc
            acquired = True
            yield
        finally:
            if acquired:
                if os.name == "posix":
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                else:
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            if (
                not retained
                and identity is not None
                and _retain_database_descriptor(descriptor, identity, None)
            ):
                retained = True
            if not retained:
                os.close(descriptor)

    def _connect(
        self,
        *,
        create: bool = True,
        _creation_locked: bool = False,
        _writable: bool = False,
    ) -> sqlite3.Connection:
        try:
            parent = self.path.parent
            if create:
                ensure_private_directory(parent)
            resolved_parent = parent.resolve()
            path = resolved_parent / self.path.name
            present, empty = self._path_state(path)
            directory_chain = None
            if os.name == "posix":
                directory_chain = self._trusted_directory_chain(
                    resolved_parent
                )
            if create and not _creation_locked and (not present or empty):
                with self._creation_lock(path):
                    return self._connect(
                        create=create,
                        _creation_locked=True,
                        _writable=_writable,
                    )
            mode = "rwc" if create else "rw" if _writable else "ro"
            connection = None
            if os.name == "posix":
                try:
                    descriptor, created = _pin_database(path, create=create)
                except FileNotFoundError as exc:
                    raise StateError(
                        "CVEBeacon user database not found"
                    ) from exc
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
                expected = (
                    details.st_dev,
                    details.st_ino,
                )
                # The process-lifetime pin prevents an unlinked inode from
                # being reused during SQLite and post-open identity checks.
                connection = sqlite3.connect(
                    f"{path.as_uri()}?mode={mode}",
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
                if (
                    not stat.S_ISREG(current.st_mode)
                    or (current.st_dev, current.st_ino) != expected
                    or self._trusted_directory_chain(resolved_parent)
                    != directory_chain
                ):
                    connection.close()
                    raise StateError(
                        "CVEBeacon user database was replaced while opening"
                    )
                # A size or timestamp change is either the creator still
                # initializing the file or a concurrent account write. The
                # read-only content check below proves it is still the same
                # store before the change is accepted.
            else:
                created = create and not path.exists()
                if not create and not path.exists():
                    raise StateError("CVEBeacon user database not found")
                connection = sqlite3.connect(
                    f"{path.as_uri()}?mode={mode}", uri=True, timeout=30
                )
            try:
                self._verify_store_content(
                    connection, created=created, allow_empty=create
                )
            except Exception:
                connection.close()
                raise
            connection.row_factory = sqlite3.Row
            return connection
        except StateError:
            raise
        except (sqlite3.Error, OSError, ValueError) as exc:
            raise StateError(
                f"cannot open CVEBeacon user database {self.path}: {exc}"
            ) from exc

    def _verify_store_content(
        self,
        connection: sqlite3.Connection,
        *,
        created: bool,
        allow_empty: bool = False,
    ) -> None:
        """Read-only identity check for the file SQLite actually opened."""
        connection.execute("BEGIN")
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "cb_user" not in tables:
                if (
                    self._store_id is None
                    and not tables
                    and (created or allow_empty)
                ):
                    return
                raise StateError(
                    "CVEBeacon user database was replaced while opening"
                )
            if "cb_user_meta" not in tables:
                if self._store_id is not None:
                    raise StateError(
                        "CVEBeacon user database was replaced while opening"
                    )
                return
            row = connection.execute(
                "SELECT value FROM cb_user_meta WHERE key='store_id'"
            ).fetchone()
            if row is None or not str(row[0]):
                if self._store_id is not None:
                    raise StateError(
                        "CVEBeacon user database was replaced while opening"
                    )
                return
            store_id = str(row[0])
            if self._store_id is not None and store_id != self._store_id:
                raise StateError(
                    "CVEBeacon user database was replaced while opening"
                )
            self._store_id = store_id
        except StateError:
            raise
        except sqlite3.Error as exc:
            raise StateError(
                "CVEBeacon user database was replaced while opening"
            ) from exc
        finally:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass

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
        if create:
            try:
                parent = self.path.parent
                ensure_private_directory(parent)
                resolved_parent = parent.resolve()
                if os.name == "posix":
                    self._trusted_directory_chain(resolved_parent)
                path = resolved_parent / self.path.name
                present, empty = self._path_state(path)
            except OSError as exc:
                raise StateError(
                    f"cannot open CVEBeacon user database {self.path}: {exc}"
                ) from exc
            if not present or empty or self._store_id is None:
                with self._creation_lock(path):
                    self._initialize(
                        create=create,
                        creation_locked=True,
                    )
                return
        self._initialize(create=create, creation_locked=False)

    def _initialize(
        self, *, create: bool, creation_locked: bool
    ) -> None:
        with closing(
            self._connect(
                create=create,
                _creation_locked=creation_locked,
                _writable=True,
            )
        ) as db:
            for statement in _SCHEMA:
                db.execute(statement)
            self._migrate_email_keys(db)
            self._migrate_audit_actor(db)
            self._migrate_credential_version(db)
            self._migrate_roles(db)
            self._ensure_store_id(db)
            db.commit()

    @staticmethod
    def _migrate_roles(db: sqlite3.Connection) -> None:
        # Seed once, so deleting an editable default does not resurrect it.
        if db.execute("SELECT 1 FROM cb_user_meta WHERE key='roles_initialized'").fetchone():
            return
        for name, permissions in DEFAULT_ROLES.items():
            db.execute("INSERT OR IGNORE INTO cb_role VALUES (?,?)",
                       (name, json.dumps(sorted(permissions))))
        db.execute("INSERT INTO cb_user_role SELECT id,'viewer' FROM cb_user")
        db.execute("INSERT INTO cb_user_meta VALUES ('roles_initialized','1')")

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

    def _ensure_store_id(self, db: sqlite3.Connection) -> None:
        row = db.execute(
            "SELECT value FROM cb_user_meta WHERE key='store_id'"
        ).fetchone()
        if row is not None and str(row[0]):
            self._store_id = str(row[0])
            return
        store_id = secrets.token_hex(32)
        db.execute(
            "INSERT OR IGNORE INTO cb_user_meta(key,value) "
            "VALUES ('store_id',?)",
            (store_id,),
        )
        row = db.execute(
            "SELECT value FROM cb_user_meta WHERE key='store_id'"
        ).fetchone()
        self._store_id = str(row[0])

    @staticmethod
    def _migrate_credential_version(db: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in db.execute("PRAGMA table_info(cb_user)")
        }
        if "credential_version" not in columns:
            db.execute(
                "ALTER TABLE cb_user ADD COLUMN "
                "credential_version INTEGER NOT NULL DEFAULT 0"
            )

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
            int(row["credential_version"]),
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
                "SELECT 1 FROM cb_user WHERE is_admin=1 AND disabled=0 LIMIT 1"
            ).fetchone()
        return row is not None

    def dashboard_accounts(self) -> bool:
        """Distinguish a fresh install from a lost or inaccessible account store.

        The persistent creation lock also records that this path was initialized.
        Never create a missing database while deciding authentication mode.
        """
        try:
            present, _ = self._path_state(self.path)
            initialized, _ = self._path_state(self.path.with_name(self.path.name + ".lock"))
            if not present:
                if initialized or self._store_id is not None:
                    raise StateError("account store unavailable; restore its database before starting the dashboard")
                return False
            if self._store_id is None:
                path = self.path.parent.resolve() / self.path.name
                if os.name == "posix":
                    self._trusted_directory_chain(path.parent)
                with self._creation_lock(path):
                    self._initialize(create=False, creation_locked=True)
            with closing(self._connect(create=False)) as db:
                return db.execute("SELECT 1 FROM cb_user LIMIT 1").fetchone() is not None
        except (OSError, sqlite3.Error) as exc:
            raise StateError("account store unavailable") from exc

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
        authorization: AuthenticatedUser | BootstrapAuthorization | None = None,
        role: str = "viewer",
        empty_store_only: bool = False,
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
            if empty_store_only and db.execute("SELECT 1 FROM cb_user LIMIT 1").fetchone():
                raise ConfigurationError("dashboard bootstrap requires an empty account store")
            if isinstance(authorization, BootstrapAuthorization):
                existing_admin = db.execute(
                    "SELECT 1 FROM cb_user WHERE is_admin=1 AND disabled=0 LIMIT 1"
                ).fetchone()
                if existing_admin is not None:
                    raise ConfigurationError(
                        "administrator login required; use --admin-user"
                    )
                actor = "(bootstrap)"
            elif authorization is not None:
                current = self.require_permission_in(db, authorization, "manage_users")
                self._authorize_assignment_in(db, current, "admin" if is_admin else role)
                actor = current.username
            else:
                actor = None
            if not is_admin:
                self._require_role_in(db, role)
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
            db.execute("INSERT INTO cb_user_role VALUES (?,?)", (user_id, role))
            self._append_audit(db, "add", name, now, actor=actor)
            row = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user_id,)
            ).fetchone()
        return self._user(row)

    def set_password(
        self,
        username: object,
        password: object,
        *,
        authorization: AuthenticatedUser | BootstrapAuthorization | None = None,
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
            if isinstance(authorization, BootstrapAuthorization):
                raise ConfigurationError(
                    "bootstrap is only valid for the first administrator"
                )
            if authorization is not None:
                current = self._validate_proof_in(db, authorization)
                if current.id != user.id:
                    self._authorize_target_in(db, authorization, user)
                actor = current.username
            else:
                actor = None
            password = validate_password(
                password, forbidden=(user.username, user.email)
            )
            now = _timestamp(self._clock())
            db.execute(
                "UPDATE cb_user SET password_hash=?,password_changed_at=?,"
                "updated_at=?,failed_logins=0,locked_until=NULL,"
                "credential_version=credential_version+1 WHERE id=?",
                (hash_password_value(password), now, now, user.id),
            )
            self._append_audit(db, "passwd", user.username, now, actor=actor)
            updated = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user.id,)
            ).fetchone()
        return self._user(updated)

    def disable(
        self,
        username: object,
        *,
        authorization: AuthenticatedUser | BootstrapAuthorization | None = None,
    ) -> User:
        return self._set_disabled(
            username, True, "disable", authorization=authorization
        )

    def enable(
        self,
        username: object,
        *,
        authorization: AuthenticatedUser | BootstrapAuthorization | None = None,
    ) -> User:
        return self._set_disabled(
            username, False, "enable", authorization=authorization
        )

    def _set_disabled(
        self,
        username: object,
        value: bool,
        action: str,
        *,
        authorization: AuthenticatedUser | BootstrapAuthorization | None = None,
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
            if isinstance(authorization, BootstrapAuthorization):
                raise ConfigurationError(
                    "bootstrap is only valid for the first administrator"
                )
            if authorization is not None:
                current = self._authorize_target_in(db, authorization, user)
                actor = current.username
            else:
                actor = None
            now = _timestamp(self._clock())
            if value and user.is_admin and not user.disabled:
                self._protect_last_admin_in(db, user.id)
            db.execute(
                "UPDATE cb_user SET disabled=?,updated_at=?,"
                "credential_version=credential_version+1 WHERE id=?",
                (int(value), now, user.id),
            )
            self._append_audit(db, action, user.username, now, actor=actor)
            updated = db.execute(
                f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user.id,)
            ).fetchone()
        return self._user(updated)

    def unlock(
        self,
        username: object,
        *,
        authorization: AuthenticatedUser | BootstrapAuthorization | None = None,
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
            if isinstance(authorization, BootstrapAuthorization):
                raise ConfigurationError(
                    "bootstrap is only valid for the first administrator"
                )
            if authorization is not None:
                current = self._authorize_target_in(db, authorization, user)
                actor = current.username
            else:
                actor = None
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
        if self._store_id is None:
            self.initialize()
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        now = now.astimezone(timezone.utc)
        stamp = _timestamp(now)
        account = os_account()
        host = host_name()
        typed = audit_name(identifier)
        # Snapshot before hashing; no writer reservation during expensive work.
        with closing(self._connect(create=False)) as db:
            snapshot = self._find_username(db, identifier)
        usable = (snapshot is not None and not snapshot["disabled"]
                  and snapshot["password_hash"] is not None and not self._locked(snapshot, now))
        accepted = verify_password(snapshot["password_hash"] if usable else DUMMY_HASH, password)
        with self.transaction() as db:
            row = self._find_username(db, identifier)
            if row is None:
                self._append_login_failure_in(db, "login_failed", typed, stamp, account, host)
                return None
            user = self._user(row)
            # A password, enabled-state, or role change during verification must
            # never produce a proof for the new account state. Lockout counters
            # are deliberately re-read here, serializing simultaneous failures.
            accepted = (accepted and usable and snapshot["id"] == row["id"]
                        and snapshot["password_hash"] == row["password_hash"]
                        and snapshot["credential_version"] == row["credential_version"]
                        and not user.disabled)
            now = self._clock()
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            now = now.astimezone(timezone.utc)
            stamp = _timestamp(now)
            if self._locked(row, now):
                self._append_login_failure_in(db, "login_locked", typed, stamp, account, host)
                return None
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
                self._append_login_failure_in(
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
            user.credential_version,
        )

    def require_current(self, identity: "ReportIdentity") -> None:
        """Standalone re-check used by tests and non-atomic probes."""
        if identity.mode == "open":
            return
        self.initialize()
        with closing(self._connect(create=False)) as db:
            self.require_current_in(db, identity)

    def _current_account(
        self, db: sqlite3.Connection, user_id: int, username: str
    ) -> User:
        row = db.execute(
            f"SELECT {_USER_COLUMNS} FROM cb_user WHERE id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise ConfigurationError("the CVEBeacon user no longer exists")
        current = self._user(row)
        if current.username != username:
            raise ConfigurationError(
                "the CVEBeacon user no longer matches the resolved identity"
            )
        if current.disabled:
            raise ConfigurationError("the CVEBeacon user is disabled")
        return current

    def _validate_proof_in(
        self, db: sqlite3.Connection, proof: AuthenticatedUser
    ) -> User:
        if not isinstance(proof, AuthenticatedUser):
            raise ConfigurationError("a successful login is required")
        current = self._current_account(
            db, proof.user.id, proof.user.username
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
        if current.credential_version != proof.credential_version:
            raise ConfigurationError(
                "authenticated identity proof predates a credential change"
            )
        return current

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
        if identity.mode == "authenticated":
            self._validate_proof_in(db, identity.authenticated)
            return
        self._current_account(
            db, identity.user.id, identity.user.username
        )

    def require_admin_in(
        self, db: sqlite3.Connection, proof: AuthenticatedUser
    ) -> User:
        current = self._validate_proof_in(db, proof)
        if not current.is_admin:
            raise ConfigurationError("administrator login required")
        return current

    def role_in(self, db: sqlite3.Connection, user: User) -> str:
        if user.is_admin:
            return "admin"
        row = db.execute("SELECT role FROM cb_user_role WHERE user_id=?", (user.id,)).fetchone()
        return str(row[0]) if row else ""

    def permissions_in(self, db: sqlite3.Connection, user: User) -> frozenset[str]:
        if user.is_admin:
            return PERMISSIONS
        row = db.execute("SELECT permissions FROM cb_role WHERE name=?", (self.role_in(db, user),)).fetchone()
        if row is None:
            return frozenset()
        try:
            values = json.loads(row[0])
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                return frozenset()
            return frozenset(values) & PERMISSIONS
        except (TypeError, ValueError):
            return frozenset()

    def require_permission_in(self, db, proof, permission) -> User:
        current = self._validate_proof_in(db, proof)
        if permission not in PERMISSIONS or permission not in self.permissions_in(db, current):
            raise ConfigurationError("permission required")
        return current

    def _authorize_target_in(self, db, proof, target):
        actor = self.require_permission_in(db, proof, "manage_users")
        if target.is_admin and not actor.is_admin:
            raise ConfigurationError("administrator login required")
        if not actor.is_admin and not self.permissions_in(db, target) <= self.permissions_in(db, actor):
            raise ConfigurationError("cannot manage an account with permissions you do not hold")
        return actor

    def _authorize_assignment_in(self, db, actor, role):
        if actor.is_admin:
            return
        if role == "admin":
            raise ConfigurationError("administrator login required")
        self._require_role_in(db, role)
        row = db.execute("SELECT permissions FROM cb_role WHERE name=?", (role,)).fetchone()
        if not frozenset(json.loads(row[0])) <= self.permissions_in(db, actor):
            raise ConfigurationError("cannot grant permissions you do not hold")

    def dashboard_identity(self, proof: AuthenticatedUser) -> tuple[User, frozenset[str]]:
        with closing(self._connect(create=False)) as db:
            db.execute("BEGIN")
            user = self._validate_proof_in(db, proof)
            return user, self.permissions_in(db, user)

    @staticmethod
    def _require_role_in(db, role):
        if role == "admin" or db.execute("SELECT 1 FROM cb_role WHERE name=?", (role,)).fetchone() is None:
            raise ConfigurationError("unknown role")

    @staticmethod
    def _protect_last_admin_in(db, user_id):
        if db.execute("SELECT 1 FROM cb_user WHERE is_admin=1 AND disabled=0 AND id<>? LIMIT 1", (user_id,)).fetchone() is None:
            raise ConfigurationError("cannot remove the last enabled administrator")

    def roles(self) -> dict[str, frozenset[str]]:
        self.initialize()
        with closing(self._connect()) as db:
            result = {str(row[0]): frozenset(json.loads(row[1])) for row in db.execute("SELECT name,permissions FROM cb_role ORDER BY name")}
        return {"admin": PERMISSIONS, **result}

    def user_roles(self) -> dict[int, str]:
        self.initialize()
        with closing(self._connect()) as db:
            rows = db.execute(f"SELECT {_USER_COLUMNS} FROM cb_user").fetchall()
            return {int(row["id"]): self.role_in(db, self._user(row)) for row in rows}

    def save_role(self, name, permissions, *, authorization: AuthenticatedUser) -> None:
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or name == "admin":
            raise ConfigurationError("role name must use 1–32 lowercase letters, digits, underscores or hyphens; admin is reserved")
        permissions = frozenset(permissions)
        if not permissions <= PERMISSIONS:
            raise ConfigurationError("unknown permission")
        self.initialize()
        with self.transaction() as db:
            actor = self.require_admin_in(db, authorization)
            db.execute("INSERT INTO cb_role VALUES (?,?) ON CONFLICT(name) DO UPDATE SET permissions=excluded.permissions",
                       (name, json.dumps(sorted(permissions))))
            self._append_audit(db, "role_save:" + name + ":" + ",".join(sorted(permissions)), actor.username,
                               _timestamp(self._clock()), actor=actor.username)

    def delete_role(self, name, *, authorization: AuthenticatedUser) -> None:
        self.initialize()
        with self.transaction() as db:
            actor = self.require_admin_in(db, authorization)
            self._require_role_in(db, name)
            if db.execute("SELECT 1 FROM cb_user_role r JOIN cb_user u ON u.id=r.user_id WHERE r.role=? AND u.is_admin=0", (name,)).fetchone():
                raise ConfigurationError("reassign users before deleting their role")
            db.execute("DELETE FROM cb_role WHERE name=?", (name,))
            self._append_audit(db, "role_delete:" + name, actor.username, _timestamp(self._clock()), actor=actor.username)

    def edit_user(self, username, *, role, disabled, display_name=None, email=None, authorization: AuthenticatedUser) -> None:
        shown, address = validate_display_name(display_name), validate_email(email)
        self.initialize()
        with self.transaction() as db:
            actor = self.require_permission_in(db, authorization, "manage_users")
            row = self._find_username(db, username)
            if row is None:
                raise ConfigurationError("user not found")
            user = self._user(row)
            self._authorize_target_in(db, authorization, user)
            if not actor.is_admin and actor.id == user.id and role != self.role_in(db, user):
                raise ConfigurationError("cannot change your own role")
            if role != self.role_in(db, user):
                self._authorize_assignment_in(db, actor, role)
            if role != "admin":
                self._require_role_in(db, role)
            if user.is_admin and not user.disabled and (role != "admin" or disabled):
                self._protect_last_admin_in(db, user.id)
            key = email_lookup_key(address) if address else None
            if key and any(email_lookup_key(str(r[0])) == key for r in db.execute("SELECT username FROM cb_user WHERE id<>?", (user.id,))):
                raise ConfigurationError("username or email is already registered")
            try:
                db.execute("UPDATE cb_user SET display_name=?,email=?,email_key=?,is_admin=?,disabled=?,updated_at=?,"
                           "credential_version=credential_version+1 WHERE id=?",
                           (shown, address, key, int(role == "admin"), int(disabled), _timestamp(self._clock()), user.id))
            except sqlite3.IntegrityError as exc:
                raise ConfigurationError("username or email is already registered") from exc
            db.execute("INSERT INTO cb_user_role VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET role=excluded.role", (user.id, role))
            self._append_audit(db, "user_edit:" + role + (":disabled" if disabled else ":enabled"), user.username,
                               _timestamp(self._clock()), actor=actor.username)

    def record_logout(self, proof: AuthenticatedUser, *, all_sessions=False) -> None:
        with self.transaction() as db:
            user = self._validate_proof_in(db, proof)
            if all_sessions:
                # Also invalidates sessions in other server processes.
                db.execute("UPDATE cb_user SET credential_version=credential_version+1 WHERE id=?", (user.id,))
            self._append_audit(db, "logout_all" if all_sessions else "logout", user.username,
                               _timestamp(self._clock()), actor=user.username)

    def require_self_in(
        self, db: sqlite3.Connection, proof: AuthenticatedUser, username: object
    ) -> User:
        current = self._validate_proof_in(db, proof)
        if current.username.casefold() != str(username).casefold():
            raise ConfigurationError(
                "the current password does not match the target account"
            )
        return current

    def _append_login_failure_in(self, db, action, username, stamp, account, host):
        # Preserve the chain and successful-login proofs: never prune old rows.
        # A bounded counter suppresses further failure entries after one final
        # chained notice. Upgraded stores count existing failures once.
        key = "failed_login_audits"
        row = db.execute("SELECT value FROM cb_user_meta WHERE key=?", (key,)).fetchone()
        if row is None:
            count = db.execute(
                "SELECT COUNT(*) FROM (SELECT 1 FROM cb_user_audit "
                "WHERE action IN ('login_failed','login_locked') LIMIT ?)",
                (MAX_LOGIN_FAILURE_AUDITS,),
            ).fetchone()[0]
        else:
            count = int(row[0])
        if count > MAX_LOGIN_FAILURE_AUDITS:
            return
        if count == MAX_LOGIN_FAILURE_AUDITS:
            action, username = "login_failures_suppressed", "(all accounts)"
        self._append_audit(db, action, username, stamp, account, host)
        db.execute("INSERT INTO cb_user_meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key, str(count + 1)))

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
