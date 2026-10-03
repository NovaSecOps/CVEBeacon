"""Container signal adapter; the application runs directly as PID 1."""

import signal

from cvebeacon.cli import main

terminated = False


def stop(signum, frame):
    global terminated
    terminated = True
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, stop)
result = main()
raise SystemExit(143 if terminated else result)
