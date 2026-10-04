"""Translate container termination while the CLI cleans up its child processes."""

import signal

from cvebeacon_automation.cli import main

terminated = False


def terminate(signum, frame):
    global terminated
    terminated = True
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, terminate)
code = main()
raise SystemExit(143 if terminated else code)
