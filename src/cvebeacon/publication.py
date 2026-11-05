"""Atomic publication with a bounded wait for brief Windows readers."""

import os
import time


class PublicationTimeout(PermissionError):
    """An atomic replacement stayed blocked beyond its bounded wait."""

    def __init__(self):
        super().__init__(
            "Atomic publication could not complete within 2 seconds; "
            "close open readers and retry"
        )


def replace_file(source, destination):
    # Python's Windows replace does not use POSIX rename semantics even when
    # a reader shares deletion. Wait briefly for readers to close their handles.
    deadline = time.monotonic() + 2.0
    while True:
        try:
            os.replace(source, destination)
            return
        except PermissionError as exc:
            if os.name != "nt":
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PublicationTimeout() from exc
            time.sleep(min(0.05, remaining))
