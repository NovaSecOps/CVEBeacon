"""The resolved identity attached to one report or withdrawal.

A report identity is produced by the reporting service, never by a front end
directly. Authenticated identities additionally carry the successful login
record returned by ``UserStore.authenticate``; a roster lookup returns only a
``User`` and cannot satisfy that field.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import ConfigurationError
from .reported import IDENTITY_MODES, validate_identity
from .users import (
    AuthenticatedUser,
    User,
    email_lookup_key,
    validate_email,
)


@dataclass(frozen=True, slots=True)
class ReportIdentity:
    mode: str
    display: str
    user: User | None = None
    authenticated: AuthenticatedUser | None = None
    email: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in IDENTITY_MODES:
            raise ConfigurationError(
                "watch.reporting.identity must be open, registered, or "
                "authenticated"
            )
        validate_identity(self.display)
        if self.mode == "open":
            if self.user is not None or self.authenticated is not None:
                raise ConfigurationError(
                    "open identity does not accept a resolved user"
                )
        elif self.mode == "registered":
            if self.user is None or self.authenticated is not None:
                raise ConfigurationError(
                    "registered identity requires a resolved user without "
                    "an authentication proof"
                )
        else:
            if self.user is None or self.authenticated is None:
                raise ConfigurationError(
                    "authenticated identity requires a successful login"
                )
            if self.authenticated.user != self.user:
                raise ConfigurationError(
                    "authenticated identity proof does not match the user"
                )
        if self.mode != "open":
            assert self.user is not None
            if self.display != self.user.identity:
                raise ConfigurationError(
                    "the display identity does not match the resolved account"
                )
            if self.email is not None:
                if (
                    self.user.email is None
                    or email_lookup_key(self.email)
                    != email_lookup_key(self.user.email)
                ):
                    raise ConfigurationError(
                        "the email identity does not match the resolved account"
                    )
        if self.email is not None:
            validate_email(self.email)

    @property
    def user_id(self) -> int | None:
        return None if self.user is None else self.user.id

    @property
    def username(self) -> str | None:
        return None if self.user is None else self.user.username
