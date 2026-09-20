"""Exercise narrowly owned native schedules on disposable GitHub-hosted runners."""

import os
from pathlib import Path
import platform
import subprocess
import tempfile
import uuid

from cvebeacon import scheduling
from smoke import prepare


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, check=False, **kwargs)


def windows(config: Path, token: str) -> None:
    scheduling.WINDOWS_TASK = f"CVEBeacon CI {token}"
    before = command(["schtasks", "/Query", "/FO", "CSV", "/NH"])
    assert before.returncode == 0, before.stderr
    assert scheduling.status() == "not installed"
    try:
        scheduling.install(scheduling.make_plan(config, 24))
        assert scheduling.WINDOWS_TASK in scheduling.status()
    finally:
        scheduling.remove()
    assert scheduling.status() == "not installed"
    after = command(["schtasks", "/Query", "/FO", "CSV", "/NH"])
    assert after.returncode == 0, after.stderr
    # Status and next-run fields can change while the test is running.
    import csv
    def names(text):
        return {row[0] for row in csv.reader(text.splitlines()) if row}
    assert names(before.stdout) == names(after.stdout), "unrelated task names changed"


def linux(config: Path, token: str) -> None:
    scheduling.CRON_BEGIN = f"# BEGIN CVEBEACON CI {token}"
    scheduling.CRON_END = f"# END CVEBEACON CI {token}"
    original = scheduling._read_crontab()
    sentinel = f"0 0 1 1 * : # unrelated CI sentinel {token}"
    baseline = original.rstrip() + "\n" + sentinel + "\n"
    assert command(["crontab", "-"], input=baseline).returncode == 0
    try:
        assert scheduling.status() == "not installed"
        scheduling.install(scheduling.make_plan(config, 24))
        assert scheduling.CRON_BEGIN in scheduling.status()
        assert sentinel in scheduling._read_crontab()
        assert scheduling.remove()
        assert scheduling.status() == "not installed"
        assert scheduling._read_crontab() == baseline
    finally:
        scheduling.remove()
        current = scheduling._read_crontab()
        if current == baseline:
            cleaned = original
        else:
            cleaned = "\n".join(line for line in current.splitlines() if line != sentinel) + "\n"
        assert command(["crontab", "-"], input=cleaned).returncode == 0
    assert scheduling._read_crontab() == original


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Native mutation checks require a disposable GitHub-hosted runner")
    with tempfile.TemporaryDirectory(prefix="cvebeacon-scheduler-") as temp:
        config = prepare(Path(temp))
        (windows if platform.system() == "Windows" else linux)(config, uuid.uuid4().hex)
    print("PASS native schedule install/status/remove and unrelated entry preservation")
