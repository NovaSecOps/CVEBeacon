"""Shared password prompts, validation and hashing.

The dashboard and CVEBeacon user accounts deliberately use one scheme so a
future dashboard login can verify the same stored hashes.
"""

from __future__ import annotations

import getpass
import secrets
import warnings

from werkzeug.security import check_password_hash, generate_password_hash

from .errors import ConfigurationError

SCHEME = "scrypt:32768:8:1"
MIN_LENGTH = 12
MAX_LENGTH = 1024
CONFIRM_PROMPT = "Confirm password: "
# A fixed hash of an unguessable value. Unknown or unusable accounts verify
# against it so a missing username costs the same work as a wrong password.
DUMMY_HASH = (
    "scrypt:32768:8:1$E3YeEkz83E1rBQkt$"
    "01cfa7553fe7d60b86e13bd08b70b59245810f22913e24fcfe616d0c3e7e6afa"
    "5678791244fba4b44d1a35d91ea64faea758913edc713f8d13c249faa2dcf1c5"
)


def validate_password(password: object, *, forbidden: tuple[object, ...] = ()) -> str:
    if not isinstance(password, str) or not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        raise ConfigurationError(
            f"password must contain {MIN_LENGTH}–{MAX_LENGTH} characters "
            "and not be all whitespace"
        )
    if password.isspace():
        raise ConfigurationError(
            f"password must contain {MIN_LENGTH}–{MAX_LENGTH} characters "
            "and not be all whitespace"
        )
    for value in forbidden:
        if value is None or value == "":
            continue
        try:
            matched = secrets.compare_digest(
                password.casefold().encode("utf-8"),
                str(value).casefold().encode("utf-8"),
            )
        except UnicodeEncodeError:
            matched = False
        if matched:
            raise ConfigurationError(
                "password must not be the same as the username or email"
            )
    return password


def read_password(prompt: str, *, getpass_module=None) -> str:
    """Read one hidden value; never fall back to an echoing terminal."""
    module = getpass_module or getpass
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", module.GetPassWarning)
            return module.getpass(prompt)
    except (module.GetPassWarning, EOFError) as exc:
        raise ConfigurationError(
            "a terminal with hidden password input is required"
        ) from exc


def read_new_password(
    prompt: str,
    *,
    forbidden: tuple[object, ...] = (),
    getpass_module=None,
) -> str:
    """Read and confirm a new password, then apply the shared rules."""
    first = read_password(prompt, getpass_module=getpass_module)
    second = read_password(CONFIRM_PROMPT, getpass_module=getpass_module)
    try:
        matched = secrets.compare_digest(
            first.encode("utf-8"), second.encode("utf-8")
        )
    except UnicodeEncodeError:
        matched = False
    if not matched:
        raise ConfigurationError("password confirmation does not match")
    return validate_password(first, forbidden=forbidden)


def hash_password_value(password: str) -> str:
    return generate_password_hash(password, method=SCHEME)


def verify_password(encoded: object, password: object) -> bool:
    if not isinstance(encoded, str) or not encoded:
        return False
    if not isinstance(password, str) or len(password) > MAX_LENGTH:
        password = ""
    try:
        return check_password_hash(encoded, password)
    except (TypeError, ValueError):
        return False
