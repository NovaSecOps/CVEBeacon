"""Optional single-password authentication and bounded process-local state."""

from collections import OrderedDict
import getpass
import re
import secrets
from threading import Lock
import time
import warnings

from werkzeug.security import check_password_hash, generate_password_hash

from .errors import ConfigurationError, CVEBeaconError


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
    # getpass otherwise falls back to an echoing stream on some terminals.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Dashboard password (12–1024 characters): ")
            confirmation = getpass.getpass("Confirm password: ")
    except (getpass.GetPassWarning, EOFError) as exc:
        raise CVEBeaconError("a terminal with hidden password input is required") from exc
    if not 12 <= len(password) <= 1024 or password.isspace():
        raise CVEBeaconError("password must contain 12–1024 characters and not be all whitespace")
    if not secrets.compare_digest(password.encode("utf-8"), confirmation.encode("utf-8")):
        raise CVEBeaconError("password confirmation does not match")
    return generate_password_hash(password)


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
            if now < next_try or (origin not in self.attempts and len(self.attempts) >= self.max_origins):
                return None
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
