"""The single report/unreport identity boundary.

Front ends provide user-visible arguments; this service binds them to the
configured identity policy and user store. ``WatchStore`` keeps only the raw
persistence methods behind it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

from ..errors import ConfigurationError
from .identity import ReportIdentity
from .reported import (
    default_identity,
    validate_identity,
    validate_identity_mode,
)
from .users import UserStore


class ReportService:
    def __init__(
        self,
        store,
        users_database: str | Path | None,
        mode: str,
    ) -> None:
        self.store = store
        self.mode = validate_identity_mode(mode)
        self._users_database = (
            None if users_database is None else Path(users_database)
        )
        if self.mode != "open" and self._users_database is None:
            raise ConfigurationError(
                "the configured identity mode requires a CVEBeacon user database"
            )
        self._users: UserStore | None = None

    @property
    def users(self) -> UserStore:
        if self._users is None:
            if self._users_database is None:
                raise ConfigurationError(
                    "the configured identity mode requires a CVEBeacon user "
                    "database"
                )
            self._users = UserStore(self._users_database)
        return self._users

    def _resolve(
        self,
        *,
        by: object | None,
        user: object | None,
        password: object | None,
        password_prompt: Callable[[str], str] | None,
    ) -> ReportIdentity:
        mode = self.mode
        if mode == "open":
            if user is not None or password is not None:
                raise ConfigurationError(
                    "--user is only available when watch.reporting.identity = "
                    "authenticated"
                )
            return ReportIdentity(
                "open",
                validate_identity(by if by is not None else default_identity()),
            )
        if mode == "registered":
            if user is not None or password is not None:
                raise ConfigurationError(
                    "--user is only available when watch.reporting.identity = "
                    "authenticated"
                )
            if by is None:
                raise ConfigurationError(
                    "reported by is required; name an enabled CVEBeacon user "
                    "with --by"
                )
            roster = self.users.resolve_enabled(by)
            if roster is None:
                raise ConfigurationError(
                    "reported by must name an enabled CVEBeacon user"
                )
            return ReportIdentity(
                "registered",
                validate_identity(roster.identity),
                user=roster,
                email=roster.email,
            )
        if by is not None:
            raise ConfigurationError(
                "--by is not available when watch.reporting.identity = "
                "authenticated; use --user"
            )
        if user is None:
            raise ConfigurationError(
                "--user is required when watch.reporting.identity = "
                "authenticated"
            )
        if password is None:
            if password_prompt is None:
                raise ConfigurationError(
                    "a password is required for authenticated mode"
                )
            password = password_prompt(str(user))
        proof = self.users.authenticate(user, password)
        if proof is None:
            raise ConfigurationError("invalid username or password")
        return ReportIdentity(
            "authenticated",
            validate_identity(proof.user.identity),
            user=proof.user,
            authenticated=proof,
            email=proof.user.email,
        )

    def _recheck(self, identity: ReportIdentity) -> Callable[[], None]:
        if identity.mode == "open":
            return lambda: None
        return lambda: self.users.require_current(identity)

    def report_cve(
        self,
        cve_id: object,
        *,
        by: object | None = None,
        user: object | None = None,
        password: object | None = None,
        password_prompt: Callable[[str], str] | None = None,
        note: object | None = None,
        force: bool = False,
        notify_channels: Iterable[str] = (),
    ):
        identity = self._resolve(
            by=by,
            user=user,
            password=password,
            password_prompt=password_prompt,
        )
        return self.store._report_cve(
            cve_id,
            identity=identity,
            recheck=self._recheck(identity),
            note=note,
            force=force,
            notify_channels=notify_channels,
        )

    def unreport_cve(
        self,
        cve_id: object,
        *,
        by: object | None = None,
        user: object | None = None,
        password: object | None = None,
        password_prompt: Callable[[str], str] | None = None,
        note: object | None = None,
        notify_channels: Iterable[str] = (),
    ):
        identity = self._resolve(
            by=by,
            user=user,
            password=password,
            password_prompt=password_prompt,
        )
        return self.store._unreport_cve(
            cve_id,
            identity=identity,
            recheck=self._recheck(identity),
            note=note,
            notify_channels=notify_channels,
        )
