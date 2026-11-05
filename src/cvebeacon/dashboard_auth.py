"""Optional single-password authentication and bounded process-local state."""

from collections import OrderedDict
import getpass
import re
import secrets
from threading import Lock
import time
from dataclasses import dataclass

from werkzeug.security import check_password_hash

from .errors import ConfigurationError
from .passwords import hash_password_value, read_new_password


def password_hash(config):
    value = config.secret(config.dashboard.password_hash_env)
    if value is None:
        return None
    # Accept the maintained Werkzeug default, and reject plaintext/weak or
    # unbounded-work parameters before accepting any network requests.
    if not re.fullmatch(r"scrypt:32768:8:1\$[A-Za-z0-9]{16,64}\$[0-9a-f]{128}", value):
        raise ConfigurationError("invalid dashboard password hash; regenerate with dashboard hash-password")
    return value


def hash_password():
    # The shared helper converts the hidden-input warning into an error, so a
    # terminal without a usable hidden prompt never echoes the value.
    password = read_new_password(
        "Dashboard password (12–1024 characters): ", getpass_module=getpass
    )
    return hash_password_value(password)


class DashboardAuth:
    """One server process; never trust forwarded IP headers or client expiry."""

    def __init__(self, encoded, lifetime, *, clock=None):
        self.encoded = encoded
        self.lifetime = lifetime
        self.clock = clock or time.monotonic
        self.lock = Lock()
        self.attempts = {}
        self.sessions = OrderedDict()
        self.max_origins = 4096
        self.max_sessions = 256

    def login(self, origin, password):
        now = self.clock()
        with self.lock:
            self.attempts = {key: value for key, value in self.attempts.items() if value[2] > now}
            failures, next_try, _ = self.attempts.get(origin, (0, 0, 0))
            if now < next_try:
                return None
            if origin not in self.attempts and len(self.attempts) >= self.max_origins:
                # A full table must not lock out all unrelated clients for
                # fifteen minutes. Evict the least recently attempted origin.
                oldest = min(self.attempts, key=lambda key: self.attempts[key][2])
                self.attempts.pop(oldest)
            failures = min(failures + 1, 7)
            # Reserve before expensive hashing, so concurrent requests cannot
            # bypass the delay. No sleeps occupy the server's worker threads.
            self.attempts[origin] = (failures, now + min(2 ** (failures - 1), 60), now + 900)
        if not isinstance(password, str) or len(password) > 1024 or not check_password_hash(self.encoded, password):
            return None
        with self.lock:
            self.attempts.pop(origin, None)
            now = self.clock()
            self.sessions = OrderedDict((key, expiry) for key, expiry in self.sessions.items() if expiry > now)
            while len(self.sessions) >= self.max_sessions:
                self.sessions.popitem(last=False)
            identifier = secrets.token_hex(32)
            self.sessions[identifier] = now + self.lifetime
            return identifier

    def valid(self, identifier):
        with self.lock:
            expiry = self.sessions.get(identifier, 0)
            if expiry <= self.clock():
                self.sessions.pop(identifier, None)
                return False
            return True

    def logout(self, identifier):
        with self.lock:
            self.sessions.pop(identifier, None)


@dataclass
class AccountSession:
    proof: object
    csrf: str
    created: float
    touched: float


class AccountSessions:
    """Bounded, single-process sessions. The browser holds only an opaque id."""

    def __init__(self, lifetime, idle, *, clock=None):
        self.lifetime, self.idle = lifetime, idle
        self.clock = clock or time.monotonic
        self.sessions = OrderedDict()
        self.lock = Lock()
        self.max_sessions = 256

    def _prune(self, now):
        for key, value in list(self.sessions.items()):
            if now - value.created >= self.lifetime or now - value.touched >= self.idle:
                self.sessions.pop(key, None)

    def issue(self, proof=None):
        with self.lock:
            now = self.clock()
            self._prune(now)
            while len(self.sessions) >= self.max_sessions:
                self.sessions.popitem(last=False)
            identifier = secrets.token_hex(32)
            value = AccountSession(proof, secrets.token_hex(32), now, now)
            self.sessions[identifier] = value
            return identifier, value

    def get(self, identifier):
        with self.lock:
            self._prune(self.clock())
            value = self.sessions.get(identifier)
            if value:
                value.touched = self.clock()
            return value

    def logout(self, identifier):
        with self.lock:
            self.sessions.pop(identifier, None)

    def own(self, proof):
        with self.lock:
            self._prune(self.clock())
            # Never render bearer identifiers or CSRF values.
            return [(entry.created, entry.touched) for entry in self.sessions.values()
                    if entry.proof and entry.proof.id == proof.id
                    and entry.proof.credential_version == proof.credential_version]

    def logout_all(self, user_id):
        with self.lock:
            for key, value in list(self.sessions.items()):
                if value.proof and value.proof.id == user_id:
                    self.sessions.pop(key, None)
