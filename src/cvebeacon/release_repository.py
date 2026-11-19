"""One bounded owner/repository validation rule for release URLs."""
import re


def valid_repository(value):
    if not isinstance(value, str) or len(value) > 201:
        return False
    match = re.fullmatch(r"[A-Za-z0-9_-]+/([A-Za-z0-9_.-]+)", value)
    return match is not None and match[1] not in {".", ".."}
