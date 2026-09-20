"""Application error types."""

from __future__ import annotations

from dataclasses import dataclass


class CVEBeaconError(Exception):
    """Base class for expected operational failures."""


class ConfigurationError(CVEBeaconError):
    """Configuration is missing, invalid, or unsafe."""


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    message: str
    location: str | None = None

    def __str__(self) -> str:
        return f"{self.location}: {self.message}" if self.location else self.message


class InventoryValidationError(CVEBeaconError):
    """One or more inventory records failed validation."""

    def __init__(self, issues: list[ValidationIssue]):
        self.issues = tuple(issues)
        super().__init__("; ".join(str(issue) for issue in issues))


class SourceError(CVEBeaconError):
    """An external source failed or returned an invalid response."""

    def __init__(self, source: str, message: str, *, retryable: bool = False):
        self.source = source
        self.retryable = retryable
        super().__init__(f"{source}: {message}")


class StateError(CVEBeaconError):
    """Local state could not be read or committed safely."""


class NotificationError(CVEBeaconError):
    """A notification channel did not accept a message."""


class ReportingError(CVEBeaconError):
    """A requested report could not be written safely."""


class SchedulingError(CVEBeaconError):
    """A native schedule operation was unsafe or unsuccessful."""
