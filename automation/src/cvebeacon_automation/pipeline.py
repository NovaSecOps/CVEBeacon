"""One-shot fail-closed orchestration through unchanged lower-layer boundaries."""

from __future__ import annotations

from datetime import datetime, timezone
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile

from cvebeacon.config import load_config as load_core
from cvebeacon.errors import CVEBeaconError
from cvebeacon.inventory import load_inventory
from cvebeacon_extensions.contract import ExtensionError, manifest_path, read_bytes, read_snapshot
from cvebeacon_extensions.merge import merge_snapshots

from .common import AutomationError, atomic, directory, lock, now, publish_pair, regular
from .config import Config, input_paths
from .health import save, status
from .process import run
from .staging import current_snapshot, publish


def collect(config, source):
    if source.kind == "ssh":
        from .remote.ssh import collect_ssh
        return collect_ssh(config, source)
    elif source.kind in {"registry", "kubernetes"}:
        from .registry.acquire import collect_source
        return collect_source(config, source)


def core_scan(config: Config) -> int:
    code, _ = run([sys.executable, "-I", "-m", "cvebeacon", "--config", str(config.core_config), "scan"],
                  timeout=config.core_timeout, limit=1024 * 1024, extra_env=config.core_env, cwd=config.state_dir)
    return code


def run_pipeline(config: Config, *, scanner=None) -> int:
    directory(config.state_dir)
    with lock(config.state_dir / "automation.lock"), ExitStack() as resources:
        previous = status(config.state_dir)
        state = dict(version=1, status="running", started_at=now(), ended_at=None, core_exit=None,
                     sources={}, failures=[], consecutive_failures=previous.get("consecutive_failures", 0))
        save(config.state_dir, state)
        code = 2
        try:
            core = load_core(config.core_config)
            output_pair = {config.inventory_path, manifest_path(config.inventory_path)}
            protected = input_paths(config) | {core.database_path}
            if output_pair & protected:
                raise AutomationError("pipeline_path_collision")
            # Different configs/state directories must still serialize shared outputs/DBs.
            for resource in sorted({config.inventory_path.resolve(), core.database_path.resolve()}, key=str):
                resources.enter_context(lock(resource.with_name(resource.name + ".automation.lock")))
            # Core configuration is explicit; never patch its identity/config semantics.
            if core.inventory.path != config.inventory_path or core.inventory.format not in {"auto", "json"}:
                raise AutomationError("core_inventory_configuration_mismatch")
            owned_state = {config.state_dir / name for name in ("health.json", "notification-ledger.sqlite3", "automation.lock", "notifications.lock")}
            if core.database_path in output_pair | input_paths(config) | owned_state or core.database_path.is_relative_to(config.staging_dir):
                raise AutomationError("core_state_path_collision")
            for destination in (config.inventory_path, manifest_path(config.inventory_path)):
                if destination.exists() or destination.is_symlink():
                    regular(destination)
            accepted = []
            required_failed = False
            for source in config.sources:
                entry = dict(required=source.required, status="pending")
                prior = previous.get("sources", {}).get(source.id, {})
                if "last_collection_success" in prior:
                    entry["last_collection_success"] = prior["last_collection_success"]
                acquisition_failed = False
                try:
                    outcome = collect(config, source)
                    if source.kind in {"ssh", "registry", "kubernetes"}:
                        entry["last_collection_success"] = now()
                        entry["collection"] = "success"
                        if isinstance(outcome, dict):
                            entry.update((key, outcome[key]) for key in ("generation", "images") if key in outcome)
                except (AutomationError, ExtensionError, OSError):
                    acquisition_failed = True
                    entry["collection"] = "failed"
                    state["failures"].append("collection_failure:" + source.id)
                    if source.required:
                        required_failed = True
                try:
                    filename = source.snapshot if source.kind == "snapshot" else current_snapshot(config.staging_dir, source.id)
                    snapshot = read_snapshot(filename, max_age_seconds=source.max_age_seconds, allow_partial=source.allow_partial)
                    if snapshot.manifest["source_id"] != source.id:
                        raise AutomationError("source_identity_mismatch")
                    entry.update(status="using_previous" if acquisition_failed else snapshot.manifest["status"],
                                 observed_at=snapshot.manifest["observed_at"], generated_at=snapshot.manifest["generated_at"])
                    # Private copies prevent a concurrent upload/replacement changing merge inputs.
                    accepted.append((filename, source))
                except (AutomationError, ExtensionError, OSError) as exc:
                    category = "source_missing" if isinstance(exc, FileNotFoundError) else "source_stale_or_future" if str(exc) == "snapshot is stale or has invalid future timestamps" else "source_invalid"
                    entry["status"] = "stale_missing_or_invalid"
                    entry["failure_category"] = category
                    state["failures"].append(category + ":" + source.id)
                    required_failed |= source.required
                state["sources"][source.id] = entry
            if required_failed or not accepted:
                raise AutomationError("required_inventory_unavailable")
            directory(config.inventory_path.parent)
            with tempfile.TemporaryDirectory(prefix=".pipeline-", dir=config.state_dir) as scratch:
                inputs = []
                for index, (filename, source) in enumerate(accepted):
                    private = Path(scratch) / f"source-{index}.json"
                    atomic(private, read_bytes(filename))
                    atomic(manifest_path(private), read_bytes(manifest_path(filename), 65536))
                    # Same freshness/source policy after copy; altered pairs fail before publication.
                    copied = read_snapshot(private, max_age_seconds=source.max_age_seconds, allow_partial=source.allow_partial)
                    if copied.manifest["source_id"] != source.id:
                        raise AutomationError("source_identity_mismatch")
                    inputs.append(private)
                candidate = Path(scratch) / "merged.json"
                missing = [source.id for source in config.sources if state["sources"][source.id]["status"] == "stale_missing_or_invalid"]
                merge_snapshots(inputs, candidate, source_id="automation-merged", expected_sources=[source.id for source in config.sources],
                    max_age_seconds=max(source.max_age_seconds for _, source in accepted), allow_partial=True)
                from dataclasses import replace
                load_inventory(replace(core.inventory, path=candidate))
                # Candidate fully validated before replacing previous good inventory.
                publish_pair(config.inventory_path, read_bytes(candidate), read_bytes(manifest_path(candidate), 65536))
            code = (scanner or core_scan)(config)
            state["core_exit"] = code
            if code != 0:
                state["failures"].append("core_scan_coverage_warning" if code == 4 else "core_scan_failure")
            if config.notifications:
                from .notifications.service import dispatch
                result = dispatch(config, core.database_path)
                state["notifications"] = result
                if result["unhealthy"]:
                    state["failures"].append("notification_failure")
            if config.discovery:
                from .discovery.nmap import run_jobs
                state["discovery"] = run_jobs(config)
                if any(item["status"] not in {"success", "disabled"} for item in state["discovery"].values()):
                    state["failures"].append("discovery_failure")
            if code == 0 and state["failures"]:
                code = 5
            state["status"] = "operational" if code == 0 else "coverage_warning" if code == 4 else "degraded" if code == 5 else "failed"
        except (AutomationError, ExtensionError, CVEBeaconError, OSError, ValueError) as exc:
            state["status"] = "skipped_locked" if isinstance(exc, AutomationError) and exc.category == "locked" else "failed"
            state["failures"].append(exc.category if isinstance(exc, AutomationError) else "pipeline_validation_failure")
            code = 75 if isinstance(exc, AutomationError) and exc.category == "locked" else 2
        except BaseException:
            state["status"] = "interrupted"
            state["failures"].append("pipeline_interrupted")
            code = 130
            raise
        finally:
            state["ended_at"] = now()
            state["consecutive_failures"] = 0 if code == 0 else state["consecutive_failures"] + 1
            save(config.state_dir, state)
        if config.operations.get("enabled") and config.notifications and state["status"] in {"operational", "coverage_warning", "degraded", "failed"}:
            from .notifications.service import operational
            try:
                state["operations"] = operational(config, state, previous)
                if state["operations"].get("unhealthy", False):
                    state["failures"].append("operational_notification_failure")
            except (AutomationError, OSError, ValueError):
                state["operations"] = {"version": 1, "unhealthy": True, "error": "operational_notification_failure"}
                state["failures"].append("operational_notification_failure")
            if code == 0 and state["operations"]["unhealthy"]:
                code, state["status"] = 5, "degraded"
            state["consecutive_failures"] = 0 if code == 0 else previous.get("consecutive_failures", 0) + 1
            save(config.state_dir, state)
        return code
