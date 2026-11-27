"""CVEBeacon public package."""

from .models import Applicability, Asset, Finding, QueryResult

__all__ = ["Applicability", "Asset", "Finding", "QueryResult"]
__version__ = "0.2.8"
