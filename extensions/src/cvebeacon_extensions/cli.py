"""Explicit one-shot commands; no dynamic plugins or automatic uploads."""

import argparse
from pathlib import Path
import sys

from cvebeacon.errors import CVEBeaconError

from .contract import ExtensionError, read_snapshot
from .merge import merge_snapshots


def parser():
    root = argparse.ArgumentParser(prog="cvebeacon-ext")
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate a snapshot and its manifest")
    validate.add_argument("snapshot", type=Path)
    validate.add_argument("--max-age-seconds", type=int, default=86400)
    validate.add_argument("--allow-partial", action="store_true")
    merge = commands.add_parser("merge", help="merge fresh snapshots through core validation")
    merge.add_argument("snapshots", nargs="+", type=Path)
    merge.add_argument("--output", required=True, type=Path)
    merge.add_argument("--source-id", required=True)
    merge.add_argument("--expected-source", action="append", default=[])
    merge.add_argument("--max-age-seconds", type=int, default=86400)
    merge.add_argument("--allow-partial", action="store_true")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            snapshot = read_snapshot(args.snapshot, max_age_seconds=args.max_age_seconds, allow_partial=args.allow_partial)
            print(f"valid: {len(snapshot.records)} records; status={snapshot.manifest['status']}")
        elif args.command == "merge":
            manifest = merge_snapshots(args.snapshots, args.output, source_id=args.source_id,
                                       expected_sources=args.expected_source, max_age_seconds=args.max_age_seconds,
                                       allow_partial=args.allow_partial)
            print(f"wrote {manifest['record_count']} records; status={manifest['status']}")
        return 0
    except (ExtensionError, CVEBeaconError, OSError) as exc:
        # OS errors may include private filesystem paths; don't echo them.
        message = "filesystem operation failed" if isinstance(exc, OSError) else str(exc)
        print(f"error: {message}", file=sys.stderr)
        return 2
