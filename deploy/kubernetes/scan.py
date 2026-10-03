"""Linux deployment serialization around one core scan, not a scheduler."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import sys

from cvebeacon.cli import main as core


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--accept-degraded", action="store_true",
                        help="treat recorded core exit 4 as completed execution, retaining coverage warnings")
    args = parser.parse_args()
    terminated = False

    def terminate(signum, frame):
        nonlocal terminated
        terminated = True
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    root = Path("/persistent")
    descriptor = os.open(root / ".cvebeacon.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("invalid lock file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("another cooperating scan holds the state lock", file=sys.stderr)
            return 75
        (root / "reports").mkdir(exist_ok=True)
        code = core(["--config", "/config/cvebeacon.toml", "scan", "--report", "json"])
        if terminated:
            return 143
        # This is execution metadata only. The report and SQLite retain actual
        # findings/coverage; accepting degraded execution never makes it clean.
        (root / "last-execution.json").write_text(json.dumps({"core_exit_code": code}) + "\n", encoding="utf-8")
        if code == 4 and args.accept_degraded:
            print("scan recorded with coverage warnings (core exit 4); explicit degraded-execution policy")
            return 0
        return code
    except KeyboardInterrupt:
        return 143 if terminated else 130
    except OSError:
        print("state or lock filesystem operation failed", file=sys.stderr)
        return 2
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
