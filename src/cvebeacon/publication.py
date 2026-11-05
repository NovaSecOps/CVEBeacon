"""Atomic publication with a bounded wait for brief Windows readers."""

import os
import time


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
                raise PermissionError(
                    "Web publication could not complete within 2 seconds; "
                    "close open readers and retry"
                ) from exc
            time.sleep(min(0.05, remaining))
