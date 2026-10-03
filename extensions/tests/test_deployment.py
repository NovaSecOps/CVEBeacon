from pathlib import Path

import yaml


def test_compose_tmpfs_options_are_one_mount_not_yaml_items():
    root = Path(__file__).parents[2]
    compose = yaml.safe_load((root / "deploy/container/compose.yml").read_text())
    for service in compose["services"].values():
        # An unquoted comma-delimited flow item becomes five independent
        # mounts, dropping the size/security options from /tmp.
        assert len(service["tmpfs"]) == 1
        target, options = service["tmpfs"][0].split(":", 1)
        assert target == "/tmp"
        assert {"noexec", "nosuid", "size=64m"} <= set(options.split(","))
