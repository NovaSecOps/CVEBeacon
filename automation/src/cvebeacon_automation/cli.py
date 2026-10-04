"""Explicit commands; no dynamic Python plugins or embedded scheduler."""

import argparse
import json
from pathlib import Path
import sys

from cvebeacon_extensions.contract import ExtensionError
from .common import AutomationError


def parser():
    result = argparse.ArgumentParser(prog="cvebeacon-auto")
    result.add_argument("--config", default="cvebeacon-automation.toml")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="one-shot collection, merge, core scan and notification pipeline")
    for name in ("status", "doctor"):
        child = commands.add_parser(name, help="separate operational health JSON")
        child.add_argument("--json", action="store_true", help="JSON is also the default")
    notify = commands.add_parser("notify", help="independent additional delivery channels")
    notify_commands = notify.add_subparsers(dest="notify_command", required=True)
    notify_commands.add_parser("run")
    notify_commands.add_parser("status")
    test = notify_commands.add_parser("test", help="send an explicitly labelled test")
    test.add_argument("channel")
    ingest = commands.add_parser("ingest", help="isolated receiver and verified HTTPS snapshot push")
    ingest_commands = ingest.add_subparsers(dest="ingest_command", required=True)
    ingest_commands.add_parser("serve", help="use a receiver-only configuration")
    push = ingest_commands.add_parser("push")
    push.add_argument("snapshot", type=Path)
    push.add_argument("--endpoint", required=True)
    credentials = push.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--secret-env")
    credentials.add_argument("--secret-file", type=Path)
    push.add_argument("--ca-file", type=Path)
    push.add_argument("--timeout", type=int, default=15)
    push.add_argument("--max-age-seconds", type=int, default=86400)
    discovery = commands.add_parser("discover", help="run explicitly authorized low-trust discovery jobs")
    discovery.add_argument("--json", action="store_true")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "ingest":
            if args.ingest_command == "serve":
                from .ingest.server import load_ingest_config, serve
                serve(load_ingest_config(args.config))
                return 0
            from .ingest.client import push
            from .common import Secret
            reference = {"env": args.secret_env} if args.secret_env else {"file": str(args.secret_file)}
            result = push(args.snapshot, args.endpoint, Secret.parse(reference, Path.cwd()), ca_file=args.ca_file,
                          timeout=args.timeout, max_age_seconds=args.max_age_seconds)
            print(json.dumps(result, sort_keys=True))
            return 0
        from .config import load_config
        config = load_config(args.config)
        if args.command in {"notify", "discover"}:
            from .common import lock
            with lock(config.state_dir / "automation.lock"):
                if args.command == "discover":
                    from .discovery.nmap import run_jobs
                    result = run_jobs(config)
                    code = 0 if all(item["status"] == "success" for item in result.values()) else 5
                else:
                    from .notifications import service
                    if args.notify_command == "status":
                        result, code = service.delivery_status(config), 0
                    elif args.notify_command == "test":
                        result = service.test_channel(config, args.channel)
                        code = 0 if not result.get("unhealthy", False) else 5
                    else:
                        from cvebeacon.config import load_config as load_core
                        result = service.dispatch(config, load_core(config.core_config).database_path)
                        code = 0 if not result["unhealthy"] else 5
                print(json.dumps(result, sort_keys=True, indent=2))
                return code
        if args.command == "run":
            from .pipeline import run_pipeline
            return run_pipeline(config)
        from .health import status
        value = status(config.state_dir)
        print(json.dumps(value, sort_keys=True, indent=2))
        return 0 if value["status"] == "operational" else 4
    except AutomationError as exc:
        print("automation error: " + exc.category, file=sys.stderr)
        return 75 if exc.category == "locked" else 2
    except (ExtensionError, OSError, ValueError):
        # External strings, secret values, URLs and absolute paths never cross this boundary.
        print("automation error: configuration, state or operation rejected", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("automation cancelled", file=sys.stderr)
        return 130
