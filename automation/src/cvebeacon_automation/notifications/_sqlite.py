"""Finite SQLite work with a fresh deadline for each statement."""

import sqlite3
import time


SQL_TIMEOUT_SECONDS = 5


class BoundedConnection(sqlite3.Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._restart_deadline()
        self.set_trace_callback(self._restart_deadline)
        self.set_progress_handler(self._expired, 1000)

    def _restart_deadline(self, *_):
        self._deadline = time.monotonic() + SQL_TIMEOUT_SECONDS

    def _expired(self):
        return int(time.monotonic() >= self._deadline)

    def execute(self, *args, **kwargs):
        self._restart_deadline()
        return super().execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        self._restart_deadline()
        return super().executemany(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        self._restart_deadline()
        return super().executescript(*args, **kwargs)
