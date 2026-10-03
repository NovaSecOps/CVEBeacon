"""Reference init-container pipeline; never mounts or opens monitoring state."""

import argparse

from cvebeacon_extensions.cli import main as extensions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()
    partial = ["--allow-partial"] if args.allow_partial else []
    commands = [
        ["collect", "kubernetes", "--namespace", args.namespace, "--source-id", args.source_id,
         "--sbom-map", "/sboms/map.json", "--output", "/inventory/collected.json"],
        ["merge", "/inventory/collected.json", "--output", "/inventory/inventory.json",
         "--source-id", "kubernetes-merged", "--expected-source", args.source_id,
         "--max-age-seconds", "300", *partial],
        ["validate", "/inventory/inventory.json", "--max-age-seconds", "300", *partial],
    ]
    for command in commands:
        code = extensions(command)
        if code:
            return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
