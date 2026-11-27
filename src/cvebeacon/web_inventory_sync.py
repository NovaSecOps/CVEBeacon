"""Reconcile client inventory against completed, saved web observations."""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from pathlib import Path
import re

from . import web_assets
from . import web_inventory_actions as actions
from .applicability import exact_cpe_version
from .config import WEB_SYNC_MODES, AppConfig
from .dashboard_inventory import _commit_change, _publish, inventory_lock
from .errors import CVEBeaconError, ConfigurationError
from .identity import normalize_asset, parse_purl, purl_string
from .inventory import MAX_CONTRACT_ROWS
from .inventory_journal import recover, remove_file
from .managed_inventory import client_key
from .models import Asset
from .private_storage import private_directory
from .sources.nvd import split_cpe23
from .web_inventory import MAX_BYTES, WEB_ASSET_ID, _timestamp, decode_json, read_bytes, web_asset_id

LOG = logging.getLogger("cvebeacon")
MISSES_REQUIRED = 2
MODE_CHOICES = ("default", *WEB_SYNC_MODES)
REMOVAL_CHOICES = ("default", "off", "on")
STATE_WARNING = "Web inventory sync state could not be read. No sync changes were made."
SETTINGS_WARNING = "The client’s web inventory sync setting could not be read. No sync changes were made."
RESULTS_WARNING = "Web inventory sync could not read the latest detection. No sync changes were made."
WRITE_WARNING = "Web inventory sync could not finish. Check storage and try again."
WAITING = "Run detection to check for inventory changes using the current web assets."
STALE = "The proposed change is no longer available. Review the latest inventory changes."
_RUN_ID = re.compile(r"[a-f0-9]{32}")
_DIGEST = re.compile(r"[a-f0-9]{64}")
# Match the detector's display-only labels, such as GA4, which are not versions.
_DISPLAY_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9]{0,15}")


def _now():
    return datetime.now(timezone.utc)


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def mode_path(allowlist):
    return allowlist.with_suffix(".sync-mode")


@dataclass(frozen=True)
class Settings:
    mode_override: str
    removal_override: str
    mode: str
    auto_remove: bool


def mode(config, allowlist):
    try:
        saved = decode_json(read_bytes(mode_path(allowlist), 128))
    except FileNotFoundError:
        saved = {}
    except (CVEBeaconError, OSError, ValueError):
        raise ConfigurationError(SETTINGS_WARNING) from None
    if (not isinstance(saved, dict) or set(saved) - {"mode", "auto_remove"}
            or saved.get("mode", "off") not in WEB_SYNC_MODES
            or type(saved.get("auto_remove", False)) is not bool):
        raise ConfigurationError(SETTINGS_WARNING)
    active = saved.get("mode", config.web.inventory_sync)
    remove = saved.get("auto_remove", config.web.inventory_auto_remove)
    return Settings(saved.get("mode", "default"),
                    ("on" if remove else "off") if "auto_remove" in saved else "default",
                    active, active == "auto" and remove)


def save_mode(config, allowlist, client, value, removal, users, proof):
    if value not in MODE_CHOICES or removal not in REMOVAL_CHOICES:
        raise ConfigurationError("Select a valid sync mode and automatic removal setting.")
    path = mode_path(allowlist)
    old = mode(config, allowlist)
    if (old.mode_override, old.removal_override) == (value, removal):
        return
    def write(mode_value, removal_value):
        document = {}
        if mode_value != "default":
            document["mode"] = mode_value
        if removal_value != "default":
            document["auto_remove"] = removal_value == "on"
        if document:
            web_assets.replace_bytes(path, json.dumps(document).encode("ascii"))
        else:
            remove_file(path)

    changed = False
    try:
        with users.transaction() as db:
            try:
                actor = users.require_permission_in(db, proof, "manage_inventory")
                users.require_permission_in(db, proof, "view")
            except ConfigurationError as exc:
                raise PermissionError from exc
            detail = json.dumps({"client": client, "mode": value, "auto_remove": removal}, ensure_ascii=True)
            users._append_audit(db, "web_inventory_sync_mode:" + detail, actor.username,
                                _now().isoformat(), actor=actor.username)
            changed = True
            write(value, removal)
    except BaseException:
        if changed:
            write(old.mode_override, old.removal_override)
        raise


def state_path(config, client):
    return config.inventory_directory / f"{client_key(client)}.web-sync"


def _empty_state(client):
    return {"client": web_assets.client_key(client), "run": "", "blocked": "",
            "applied": False, "entries": {}, "summary": None}


def _empty_entry(site):
    return {"site": site, "misses": 0, "since": None, "decision": "", "signature": ""}


def _read_state(path, client):
    initial = _empty_state(client)
    try:
        state = decode_json(read_bytes(path), max_items=MAX_CONTRACT_ROWS * 7 + 32)
        if (not isinstance(state, dict) or set(state) != set(initial)
                or state["client"] != initial["client"] or type(state["applied"]) is not bool
                or any(state[key] != "" and not _matches(_RUN_ID, state[key])
                       for key in ("run", "blocked"))
                or not isinstance(state["entries"], dict) or len(state["entries"]) > MAX_CONTRACT_ROWS):
            raise ValueError
        for identity, entry in state["entries"].items():
            if (not _matches(WEB_ASSET_ID, identity) or not isinstance(entry, dict)
                    or set(entry) != set(_empty_entry(""))
                    or not _matches(WEB_ASSET_ID, entry["site"])
                    or type(entry["misses"]) is not int or not 0 <= entry["misses"] <= MISSES_REQUIRED
                    or entry["decision"] not in ("", "ignore", "keep-version", "keep-removal")
                    or (entry["decision"] in ("ignore", "keep-version")
                        and not _matches(_DIGEST, entry["signature"]))
                    or (entry["decision"] in ("", "keep-removal") and entry["signature"] != "")
                    or (entry["since"] is None
                        and (entry["misses"] == MISSES_REQUIRED or entry["decision"] == "keep-removal"))):
                raise ValueError
            if entry["since"] is not None:
                _timestamp(entry["since"])
        summary = state["summary"]
        if summary is not None:
            if (not isinstance(summary, dict) or set(summary) != {"at", "added", "updated", "removed"}
                    or any(type(summary[key]) is not int or not 0 <= summary[key] <= MAX_CONTRACT_ROWS
                           for key in ("added", "updated", "removed"))):
                raise ValueError
            _timestamp(summary["at"])
        return state
    except FileNotFoundError:
        return initial
    except (CVEBeaconError, OSError, ValueError):
        raise ConfigurationError(STATE_WARNING) from None


def _encoded(state):
    data = json.dumps(state, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_BYTES or len(state["entries"]) > MAX_CONTRACT_ROWS:
        raise ConfigurationError("Web inventory sync reached its storage limit.")
    return data


@dataclass(frozen=True)
class Observation:
    id: str
    previous: str
    sites: dict
    products: dict
    failed: bool

    @property
    def complete(self):
        return not self.failed and all(site[-1] for site in self.sites.values())


def _observation(output, client, allowlist_revision, asset_count):
    from .dashboard_web import _review_metadata

    review_file = output.with_name(output.name + ".review.json")
    try:
        detail = decode_json(read_bytes(review_file))
        products, _, run = _review_metadata(detail, client)
        metadata = run and run.get("inventory_sync")
        if metadata is None or (run and run.get("review_truncated")):
            return None
        if (not isinstance(metadata, dict) or set(metadata) != {"id", "previous", "allowlist", "sites"}
                or not _matches(_RUN_ID, metadata["id"])
                or (metadata["previous"] != "" and not _matches(_RUN_ID, metadata["previous"]))
                or metadata["previous"] == metadata["id"] or not _matches(_DIGEST, metadata["allowlist"])
                or not isinstance(metadata["sites"], dict) or not 1 <= len(metadata["sites"]) <= 1000):
            raise ValueError
        if metadata["allowlist"] != allowlist_revision:
            return None
        sites = metadata["sites"]
        if (asset_count != len(sites) or run.get("asset_count") != asset_count
                or run.get("products_recognized") != len(products)):
            raise ValueError
        for identity, endpoint in sites.items():
            if (not isinstance(endpoint, list) or len(endpoint) != 5
                    or endpoint[0] not in ("http", "https")
                    or not isinstance(endpoint[1], str) or not 0 < len(endpoint[1]) <= 253
                    or type(endpoint[2]) is not int or not 1 <= endpoint[2] <= 65535
                    or not isinstance(endpoint[3], str) or not endpoint[3].startswith("/")
                    or len(endpoint[3]) > 2048 or type(endpoint[4]) is not bool
                    or identity != web_asset_id(client, *endpoint[:4])):
                raise ValueError
        failed = run["status"] == "failed"
        complete_count = sum(site[-1] for site in sites.values())
        if (complete_count > min(run["fetched_count"], asset_count - run.get("analysis_stopped", 0),
                                 asset_count - run.get("fingerprint_stopped", 0))
                or (complete_count and failed)
                or (complete_count == asset_count and run.get("fingerprint_error"))):
            raise ValueError
        by_id = {}
        for item in products:
            identity, site = item.get("asset_id"), item.get("site_id")
            if (not _matches(WEB_ASSET_ID, identity) or not _matches(WEB_ASSET_ID, site)
                    or identity == site or identity in by_id or site not in sites
                    or item.get("hostname") != sites[site][1] or type(item.get("inventory")) is not bool):
                raise ValueError
            item["in_inventory"] = item["inventory"]
            by_id[identity] = item
        return Observation(metadata["id"], metadata["previous"], sites, by_id, failed)
    except FileNotFoundError:
        return None
    except (CVEBeaconError, OSError, ValueError, KeyError):
        raise ConfigurationError(RESULTS_WARNING) from None


def _legacy_site(client, identity, row, endpoints):
    # Old managed rows saved the hostname only. Recompute the full product ID
    # before treating any of those rows as belonging to a particular endpoint.
    vendors = {row.vendor}
    if row.vendor == row.product:
        vendors.update(actions.GENERIC_VENDORS)
    for site, endpoint in endpoints.get(row.system_id, ()):
        if any(identity == web_asset_id(client, *endpoint[:4], vendor, row.product) for vendor in vendors):
            return site
    return None


def _web_rows(assets):
    return {base: row for row in assets
            if row.asset_id.endswith(actions.MANUAL_SUFFIX)
            and _matches(WEB_ASSET_ID, base := row.asset_id[:-len(actions.MANUAL_SUFFIX)])}


def _advance(state, observation, client, web_rows, applied_at):
    if observation.id == state["run"]:
        # An operator may have added one of this run's products after viewing it.
        for identity in (web_rows.keys() & observation.products.keys()) - state["entries"].keys():
            item = observation.products[identity]
            if item["hostname"] == web_rows[identity].system_id:
                state["entries"][identity] = _empty_entry(item["site_id"])
        return
    endpoints = {}
    for site, endpoint in observation.sites.items():
        endpoints.setdefault(endpoint[1], []).append((site, endpoint))
    entries = state["entries"]
    continuity = observation.previous == state["run"]
    for identity in entries.keys() | web_rows.keys():
        entry = entries.get(identity)
        item = observation.products.get(identity)
        row = web_rows.get(identity)
        if item is not None:
            site = item["site_id"]
            if entry is None or entry["site"] != site or entry["since"] is not None:
                entries[identity] = _empty_entry(site)
            else:
                entry["misses"] = 0
            continue
        if row is None:
            if entry["site"] in observation.sites and observation.sites[entry["site"]][-1]:
                entries.pop(identity)  # Forget an Ignore after a complete absence.
            continue
        site = entry["site"] if entry else _legacy_site(client, identity, row, endpoints)
        if site is None:
            continue
        if entry is None:
            entry = entries[identity] = _empty_entry(site)
        if not observation.failed and site in observation.sites and observation.sites[site][-1]:
            misses = entry["misses"] if continuity else 0
            entry["misses"] = min(MISSES_REQUIRED, misses + 1)
            if entry["misses"] == MISSES_REQUIRED and entry["since"] is None:
                entry["since"] = applied_at.isoformat()
        else:
            entry["misses"] = 0
    state.update(run=observation.id, blocked="", applied=False)


@dataclass(frozen=True)
class Proposal:
    kind: str
    product: str
    site: str
    old: Asset | None
    new: Asset | None
    site_id: str
    signature: str
    token: str
    since: datetime | None = None
    due: datetime | None = None
    kept: bool = False
    can_remove: bool = False


def _proposal(run_id, kind, identity, site_id, product, site, old=None, new=None, *,
              since=None, due=None, kept=False, can_remove=False):
    signature = actions.digest([asset for asset in (old, new) if asset is not None])
    token = hashlib.sha256(json.dumps(
        [run_id, kind, identity, signature, str(due), kept, can_remove],
        separators=(",", ":")).encode("ascii")).hexdigest()
    return Proposal(kind, product, site, old, new, site_id, signature, token, since, due, kept, can_remove)


def _version_update(item, old):
    versions = set(actions.detected_versions(item))
    if len(versions) != 1:
        return None
    version = versions.pop()
    if version == old.version or _DISPLAY_LABEL.fullmatch(version):
        return None
    try:
        version = actions.typed_version(version)
        purl = purl_string(parse_purl(old.purl)._replace(version=version)) if old.purl else ""
        cpe = old.cpe
        if cpe and split_cpe23(cpe)[3] not in {"*", "-"}:
            cpe = exact_cpe_version(cpe, version)
        return normalize_asset(replace(old, version=version, purl=purl, cpe=cpe))
    except ValueError:
        return None


def _addition(observation, identity, item, client, managed, snapshots_on):
    if actions.classify(item, snapshots_on=snapshots_on, managed=managed)[0] != "ready":
        return None
    try:
        new = actions.build_row(item, client, actions.ready_version(item))
    except actions.RowRefused:
        return None
    return _proposal(observation.id, "add", identity, item["site_id"],
                     item.get("name") or item["product"], item["hostname"], new=new)


def _product_changes(observation, entries, profile, assets, web_rows, snapshots_on):
    if observation.failed:
        return {}
    proposals = {}
    managed = actions.ManagedIndex(assets)
    for identity, item in observation.products.items():
        row = web_rows.get(identity)
        name = item.get("name") or item.get("product") or identity
        if row is not None:
            if row.system_id != item["hostname"]:
                continue
            updated = _version_update(item, row)
            if updated is None:
                entry = entries.get(identity)
                if entry is not None and entry["decision"] == "keep-version":
                    entry.update(decision="", signature="")
                continue
            proposal = _proposal(observation.id, "update", identity, item["site_id"],
                                 name, item["hostname"], row, updated)
            decision = "keep-version"
        else:
            proposal = _addition(observation, identity, item, profile["name"], managed, snapshots_on)
            if proposal is None:
                entry = entries.get(identity)
                if entry is not None and entry["decision"] == "ignore" and observation.sites[item["site_id"]][-1]:
                    entry.update(decision="", signature="")
                continue
            decision = "ignore"
        entry = entries.get(identity)
        if entry is not None and (entry["decision"], entry["signature"]) != (decision, proposal.signature):
            entry.update(decision="", signature="")
        if entry is None or not entry["decision"]:
            proposals[identity] = proposal
    return proposals


def _missing_products(observation, state, web_rows, grace):
    proposals = {}
    for identity, row in web_rows.items():
        entry = state["entries"].get(identity)
        if entry is None or entry["since"] is None or (observation and identity in observation.products):
            continue
        site = entry["site"]
        endpoint = observation.sites.get(site) if observation else None
        kept = entry["decision"] == "keep-removal"
        can_remove = bool(endpoint and endpoint[1] == row.system_id and observation.complete
                          and entry["misses"] == MISSES_REQUIRED)
        since = _timestamp(entry["since"])
        proposals[identity] = _proposal(
            state["run"], "remove", identity, site, row.product, row.system_id, old=row,
            since=since, due=since + timedelta(days=grace),
            kept=kept, can_remove=can_remove)
    return proposals


@dataclass
class Session:
    config: AppConfig
    settings: Settings
    path: Path
    profile: dict
    previous: bytes | None
    assets: list[Asset]
    state: dict
    evidence: Observation | None
    proposals: dict
    before: bytes
    now: datetime

    @property
    def state_file(self):
        return self.path.with_suffix(".web-sync")

    def save_observations(self):
        data = _encoded(self.state)
        if data != self.before:
            private_directory(self.path.parent, owner_only=True)
            web_assets.replace_bytes(self.state_file, data)

    def require(self, identity, token):
        proposal = self.proposals.get(identity)
        if proposal is None or proposal.token != token:
            raise ConfigurationError(STALE)
        return proposal

    def commit(self, selected, operation, *, automatic=False):
        """Publish selected inventory changes and their state in the same journal."""
        current = {asset.asset_id: asset for asset in self.assets}
        counts = {"added": 0, "updated": 0, "removed": 0}
        for identity, change in selected.items():
            if change.kind == "remove":
                current.pop(change.old.asset_id)
                self.state["entries"].pop(identity)
                counts["removed"] += 1
            else:
                current[change.new.asset_id] = change.new
                self.state["entries"][identity] = _empty_entry(change.site_id)
                counts["added" if change.kind == "add" else "updated"] += 1
        if len(current) > MAX_CONTRACT_ROWS:
            raise ConfigurationError("This inventory would exceed 100,000 rows. Select fewer products.")
        detail = {"sync": counts} if automatic else {"asset_id": next(iter(selected))}
        if automatic:
            self.state["summary"] = {"at": self.now.isoformat(), **counts}
        private_directory(self.path.parent, owner_only=True)
        _publish(self.config, self.path, self.profile, self.previous, list(current.values()), operation,
                 sync=(self.state_file, _encoded(self.state)), detail=detail, system=automatic)

    def removal_due(self, change):
        return (self.settings.auto_remove and change.kind == "remove" and change.can_remove
                and not change.kept and change.due <= self.now)


    def apply_auto(self):
        if self.evidence is None or not self.evidence.complete:
            self.save_observations()
            return
        selected = {identity: change for identity, change in self.proposals.items()
                    if self.removal_due(change) or (change.kind == "update" and not self.state["applied"])}
        if selected or not self.state["applied"]:
            self.select_additions(selected)
        self.state["applied"] = True
        if selected:
            self.commit(selected, "web-sync-auto", automatic=True)
            for identity in selected:
                self.proposals.pop(identity, None)
        else:
            self.save_observations()


    def select_additions(self, selected):
        projected = {asset.asset_id: asset for asset in self.assets}
        for change in selected.values():
            if change.kind == "remove":
                projected.pop(change.old.asset_id)
            else:
                projected[change.new.asset_id] = change.new
        managed = actions.ManagedIndex(projected.values())
        previous = actions.ManagedIndex(self.assets) if self.state["applied"] else None
        snapshots_on = self.config.inventory is not None and self.config.inventory.web_snapshots
        for identity, item in self.evidence.products.items():
            if previous is not None and not previous.covering(item):
                continue  # This run already applied additions unrelated to the due removals.
            proposal = _addition(self.evidence, identity, item, self.profile["name"], managed, snapshots_on)
            entry = self.state["entries"].get(identity)
            if proposal and (entry is None or (entry["decision"], entry["signature"])
                             != ("ignore", proposal.signature)):
                selected[identity] = proposal

    def decide(self, identity, token, action):
        proposal = self.require(identity, token)
        if action == "keep-removal":
            allowed = proposal.kind == "remove" and not proposal.kept
        elif action == "reconsider":
            allowed = proposal.kind == "remove" and proposal.kept
        elif action == "remove":
            allowed = proposal.kind == "remove" and proposal.can_remove
        else:
            allowed = self.settings.mode == "review" and (proposal.kind, action) in {
                ("add", "ignore"), ("update", "keep-version"), ("update", "update"),
            }
        if not allowed:
            raise ConfigurationError(STALE)
        if action in {"update", "remove"}:
            self.commit({identity: proposal}, "web-sync-" + action)
            return
        entry = self.state["entries"].setdefault(identity, _empty_entry(proposal.site_id))
        entry.update(decision="" if action == "reconsider" else action,
                     signature=proposal.signature if action in {"ignore", "keep-version"} else "")
        private_directory(self.path.parent, owner_only=True)
        _commit_change(self.config, "web_inventory_sync_" + action.replace("-", "_"), self.path.stem,
                       {"client": self.profile["name"], "asset_id": identity},
                       {"sync": (self.state_file, _encoded(self.state))})


def session(config, client):
    """Read and reconcile under the caller's inventory operation lock."""
    from .dashboard_web import _client_profile, _read_managed

    allowlist, output = web_assets.paths(config, client)
    document, revision = web_assets.read_allowlist(allowlist, client)
    client = document["client"]
    settings = mode(config, allowlist)
    if not config.managed_inventory:
        return None
    path = config.inventory_directory / f"{client_key(client)}.json"
    if config.inventory is not None and path == config.inventory.path:
        raise ConfigurationError("Inventory sync is unavailable for a configured inventory file.")
    profile = _client_profile(config, client)
    previous, assets = _read_managed(config, profile["name"])
    if assets and assets[0].client != profile["name"]:
        raise ConfigurationError("The saved inventory belongs to a different client. No sync changes were made.")
    state = _read_state(state_path(config, client), client)
    before = _encoded(state)
    observation = _observation(output, client, revision, len(document["assets"]))
    now = _now()
    proposals = {}
    web_rows = _web_rows(assets)
    if observation is not None and observation.id == state["blocked"]:
        observation = None
    if observation is not None:
        _advance(state, observation, client, web_rows, now)
        snapshots_on = config.inventory is not None and config.inventory.web_snapshots
        if settings.mode in {"review", "auto"}:
            proposals = _product_changes(observation, state["entries"], profile, assets, web_rows, snapshots_on)
    proposals.update(_missing_products(observation, state, web_rows, config.web.removal_grace_days))
    return Session(config, settings, path, profile, previous, assets, state, observation, proposals, before, now)


def inspect(config, client):
    lock = inventory_lock(config)
    try:
        current = session(config, client)
        if current is not None:
            if current.settings.mode == "auto":
                current.apply_auto()
            else:
                current.save_observations()
        return current
    finally:
        lock.release()


def detection_started(config, client, allowlist, output, revision, asset_count):
    """Prevent an interrupted detection from making an older review actionable."""
    try:
        if not config.managed_inventory:
            return
        mode(config, allowlist)
        recover(config.inventory_directory, config.watch.users_database)
        path = state_path(config, client)
        state = _read_state(path, client)
        latest = _observation(output, client, revision, asset_count)
        if state["blocked"]:
            for entry in state["entries"].values():
                entry["misses"] = 0
        state["blocked"] = latest.id if latest is not None else state["run"]
        if state["blocked"]:
            private_directory(path.parent, owner_only=True)
            web_assets.replace_bytes(path, _encoded(state))
    except (CVEBeaconError, OSError, ValueError):
        LOG.warning(WRITE_WARNING)


def detection_finished(config, client):
    """The detection command already holds the shared inventory operation lock."""
    try:
        if not config.managed_inventory:
            return
        recover(config.inventory_directory, config.watch.users_database)
        current = session(config, client)
        if current is not None:
            if current.settings.mode == "auto":
                current.apply_auto()
            else:
                current.save_observations()
    except (CVEBeaconError, OSError, ValueError):
        LOG.warning(WRITE_WARNING)
