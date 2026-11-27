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
from .identity import identity_conflict, normalize_asset, package_name, parse_purl, purl_string
from .inventory import MAX_CONTRACT_ROWS
from .inventory_journal import pending_exists, recover, remove_file
from .managed_inventory import client_key
from .models import Asset
from .private_storage import private_directory
from .sources.nvd import split_cpe23
from .web_endpoints import canonical_endpoint
from .web_inventory import (MAX_BYTES, UNSAFE_ID_TEXT, WEB_ASSET_ID, WEB_SYNC_SCHEMA, _timestamp,
                            decode_json, read_bytes, read_web_snapshot, sync_identity_matches,
                            valid_npm_name, valid_sync_identity, web_asset_id, web_cpe_fields,
                            web_product_key)

LOG = logging.getLogger("cvebeacon")
MISSES_REQUIRED = 2
MODE_CHOICES = ("default", *WEB_SYNC_MODES)
REMOVAL_CHOICES = ("default", "off", "on")
STATE_WARNING = "Web inventory sync state could not be read. No sync changes were made."
SETTINGS_WARNING = "The client’s web inventory sync setting could not be read. No sync changes were made."
COVERAGE_WARNING = "Automatic removal is waiting for confirmed coverage of detected products."
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
    return config.inventory_directory / f"{client_key(client)}.{web_assets.client_key(client)}.web-sync"


def _empty_state(client):
    return {"client": web_assets.client_key(client), "run": "", "blocked": "",
            "detecting": False, "confirmed": "", "applied": False, "entries": {}, "summary": None}


def _empty_entry(site, identity=None):
    return {"site": site, "identity": identity, "misses": 0, "since": None,
            "decision": "", "signature": ""}


def _read_state(path, client, *, legacy=False):
    initial = _empty_state(client)
    try:
        state = decode_json(read_bytes(path), max_items=MAX_CONTRACT_ROWS * 10 + 32)
        if legacy and isinstance(state, dict) and _matches(_DIGEST, state.get("client")):
            if state["client"] != initial["client"]:
                return None
        if isinstance(state, dict) and set(state) in (
                set(initial) - {"confirmed"}, set(initial) - {"confirmed", "detecting"}):
            state.setdefault("detecting", False)
            state["confirmed"] = ""
        if (not isinstance(state, dict) or set(state) != set(initial)
                or state["client"] != initial["client"] or type(state["applied"]) is not bool
                or type(state["detecting"]) is not bool
                or any(state[key] != "" and not _matches(_RUN_ID, state[key])
                       for key in ("run", "blocked", "confirmed"))
                or not isinstance(state["entries"], dict) or len(state["entries"]) > MAX_CONTRACT_ROWS):
            raise ValueError
        for identity, entry in state["entries"].items():
            older_entry = isinstance(entry, dict) and set(entry) == set(_empty_entry("")) - {"identity"}
            if older_entry:
                entry["identity"] = None
            if (not _matches(WEB_ASSET_ID, identity) or not isinstance(entry, dict)
                    or set(entry) != set(_empty_entry(""))
                    or not _matches(WEB_ASSET_ID, entry["site"])
                    or (entry["identity"] is not None and not valid_sync_identity(entry["identity"]))
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
            if older_entry:
                # Retain the flag and decision while establishing a fresh streak.
                entry["misses"] = 0
        summary = state["summary"]
        if summary is not None:
            if (not isinstance(summary, dict) or set(summary) != {"at", "added", "updated", "removed"}
                    or any(type(summary[key]) is not int or not 0 <= summary[key] <= MAX_CONTRACT_ROWS
                           for key in ("added", "updated", "removed"))):
                raise ValueError
            _timestamp(summary["at"])
        return state
    except FileNotFoundError:
        return None
    except (CVEBeaconError, OSError, ValueError):
        raise ConfigurationError(STATE_WARNING) from None


def _load_state(path, client):
    state = _read_state(path, client)
    if state is not None:
        return state, None
    old_path = path.parent / f"{client_key(client)}.web-sync"
    state = _read_state(old_path, client, legacy=True)
    return (_empty_state(client), None) if state is None else (state, old_path)


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


def _observation(output, client, allowlist_revision, allowlisted):
    from .dashboard_web import _review_metadata

    review_file = output.with_name(output.name + ".review.json")
    try:
        detail = decode_json(read_bytes(review_file))
        products, _, run = _review_metadata(detail, client)
        metadata = run and run.get("inventory_sync")
        if metadata is None or (run and run.get("review_truncated")):
            return None
        if isinstance(metadata, dict) and ("schema" not in metadata
                                          or type(metadata["schema"]) is int and metadata["schema"] == 1):
            return None  # Earlier producers could mark incomplete pages complete.
        if (not isinstance(metadata, dict)
                or set(metadata) != {"schema", "id", "previous", "allowlist", "sites"}
                or type(metadata["schema"]) is not int or metadata["schema"] != WEB_SYNC_SCHEMA
                or not _matches(_RUN_ID, metadata["id"])
                or (metadata["previous"] != "" and not _matches(_RUN_ID, metadata["previous"]))
                or metadata["previous"] == metadata["id"] or not _matches(_DIGEST, metadata["allowlist"])
                or not isinstance(metadata["sites"], dict) or not 1 <= len(metadata["sites"]) <= 1000):
            raise ValueError
        if metadata["allowlist"] != allowlist_revision:
            return None
        sites = metadata["sites"]
        asset_count = len(allowlisted)
        if (asset_count != len(sites) or run.get("asset_count") != asset_count
                or run.get("products_recognized") != len(products)):
            raise ValueError
        for identity, endpoint in sites.items():
            if (not isinstance(endpoint, list) or len(endpoint) != 5
                    or endpoint[0] not in ("http", "https")
                    or not isinstance(endpoint[1], str) or not 0 < len(endpoint[1]) <= 253
                    or UNSAFE_ID_TEXT.search(endpoint[1])
                    or type(endpoint[2]) is not int or not 1 <= endpoint[2] <= 65535
                    or not isinstance(endpoint[3], str) or not endpoint[3].startswith("/")
                    or len(endpoint[3]) > 2048 or UNSAFE_ID_TEXT.search(endpoint[3])
                    or type(endpoint[4]) is not bool
                    or identity != web_asset_id(client, *endpoint[:4])):
                raise ValueError
        if {tuple(endpoint[:4]) for endpoint in sites.values()} != {
                canonical_endpoint(entry) for entry in allowlisted}:
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
            inputs = item.get("sync_identity")
            if (not _matches(WEB_ASSET_ID, identity) or not _matches(WEB_ASSET_ID, site)
                    or identity == site or identity in by_id or site not in sites
                    or item.get("hostname") != sites[site][1] or type(item.get("inventory")) is not bool
                    or not isinstance(item.get("vendor"), str) or not item["vendor"]
                    or not isinstance(item.get("product"), str)
                    or not sync_identity_matches(inputs, item)
                    or identity != web_asset_id(client, *sites[site][:4], *inputs)):
                raise ValueError
            item["in_inventory"] = item["inventory"]
            by_id[identity] = item
        return Observation(metadata["id"], metadata["previous"], sites, by_id, failed)
    except FileNotFoundError:
        return None
    except (CVEBeaconError, OSError, ValueError, KeyError):
        raise ConfigurationError(RESULTS_WARNING) from None


def _legacy_association(client, identity, row, endpoints):
    # Old managed rows saved the hostname only. Recompute the full product ID
    # before treating any of those rows as belonging to a particular endpoint.
    vendors = {row.vendor}
    if row.vendor == row.product:
        vendors.update(actions.GENERIC_VENDORS)
    for site, endpoint in endpoints.get(row.system_id, ()):
        for vendor in vendors:
            inputs = [vendor, row.product]
            if valid_sync_identity(inputs) and identity == web_asset_id(client, *endpoint[:4], *inputs):
                return site, inputs
    return None


def _verified_association(client, identity, row, entry, endpoint):
    inputs = entry["identity"]
    return (endpoint is not None and endpoint[1] == row.system_id and inputs is not None
            and identity == web_asset_id(client, *endpoint[:4], *inputs))


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
                state["entries"][identity] = _empty_entry(item["site_id"], item["sync_identity"])
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
            if row is not None and item["hostname"] != row.system_id:
                continue
            if entry is None or entry["site"] != site or entry["since"] is not None:
                entries[identity] = _empty_entry(site, item["sync_identity"])
            else:
                entry.update(identity=item["sync_identity"], misses=0)
            continue
        if row is None:
            if entry["site"] in observation.sites and observation.sites[entry["site"]][-1]:
                entries.pop(identity)  # Forget an Ignore after a complete absence.
            continue
        if entry is None or entry["identity"] is None:
            association = _legacy_association(client, identity, row, endpoints)
            if association is None or (entry is not None and entry["site"] != association[0]):
                continue
            site, inputs = association
            entry = entries.setdefault(identity, _empty_entry(site))
            entry.update(identity=inputs, misses=0)
        endpoint = observation.sites.get(entry["site"])
        if (not observation.failed and _verified_association(client, identity, row, entry, endpoint)
                and endpoint[-1]):
            misses = entry["misses"] if continuity else 0
            entry["misses"] = min(MISSES_REQUIRED, misses + 1)
            if entry["misses"] == MISSES_REQUIRED and entry["since"] is None:
                entry["since"] = applied_at.isoformat()
        else:
            entry["misses"] = 0
    state.update(run=observation.id, blocked="", confirmed="", applied=False)


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
    # Readiness follows the saved review's snapshot prediction; removals separately confirm
    # coverage against the readable snapshot (defer_uncovered_removals).
    predicted = {item["asset_id"]} if item.get("in_inventory") and item.get("asset_id") else set()
    if actions.classify(item, snapshots_on=snapshots_on, snapshot_ids=predicted,
                        managed=managed)[0] != "ready":
        return None
    try:
        new = actions.build_row(item, client, actions.ready_version(item))
    except actions.RowRefused:
        return None
    return _proposal(observation.id, "add", identity, item["site_id"],
                     item.get("name") or item["product"], item["hostname"], new=new)


def _coverage_identity(vendor, product, *, cpe="", ecosystem="", package=""):
    if ecosystem or package:
        if ecosystem == "npm" and valid_npm_name(package) and not cpe:
            return "npm", package
        return None
    if cpe:
        if web_cpe_fields(cpe):
            # Even an unqualified application CPE must match a CPE here.
            return "cpe", *web_product_key(vendor, product, cpe=cpe)
        return None
    if vendor and product:
        return web_product_key(vendor, product)
    return None


def _row_coverage(asset):
    if identity_conflict(asset) or asset.commit:
        return None
    if asset.purl:
        purl = parse_purl(asset.purl)
        identity = _coverage_identity("", "", ecosystem=purl.type, package=package_name(purl))
    else:
        identity = _coverage_identity(asset.vendor, asset.product, cpe=asset.cpe,
                                      ecosystem=asset.ecosystem,
                                      package=asset.product if asset.ecosystem else "")
    return (asset.version, identity) if identity is not None else None


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


def _missing_products(observation, state, web_rows, grace, client):
    proposals = {}
    for identity, row in web_rows.items():
        entry = state["entries"].get(identity)
        if entry is None or entry["since"] is None or (observation and identity in observation.products):
            continue
        site = entry["site"]
        endpoint = observation.sites.get(site) if observation else None
        kept = entry["decision"] == "keep-removal"
        can_remove = bool(_verified_association(client, identity, row, entry, endpoint) and observation.complete
                          and entry["misses"] == MISSES_REQUIRED)
        since = _timestamp(entry["since"])
        try:
            due = since + timedelta(days=grace)
        except OverflowError:
            raise ConfigurationError(STATE_WARNING) from None
        proposals[identity] = _proposal(
            state["run"], "remove", identity, site, row.product, row.system_id, old=row,
            since=since, due=due,
            kept=kept, can_remove=can_remove)
    return proposals


@dataclass
class Session:
    config: AppConfig
    settings: Settings
    client: str
    path: Path
    state_file: Path
    legacy_path: Path | None
    profile: dict
    previous: bytes | None
    assets: list[Asset]
    state: dict
    evidence: Observation | None
    proposals: dict
    before: bytes
    now: datetime
    removal_deferred: bool = False

    def save_observations(self):
        data = _encoded(self.state)
        if data != self.before or self.legacy_path is not None:
            private_directory(self.path.parent, owner_only=True)
            web_assets.replace_bytes(self.state_file, data)
            self.finish_migration()

    def finish_migration(self):
        if self.legacy_path is not None:
            remove_file(self.legacy_path)

    def removal_due(self, change):
        return (self.settings.auto_remove and change.kind == "remove" and change.can_remove
                and not change.kept and change.due <= self.now)

    def needs_write(self):
        return (self.legacy_path is not None or self.before != _encoded(self.state)
                or (self.settings.mode == "auto" and self.evidence is not None and self.evidence.complete
                    and (not self.state["applied"] or any(map(self.removal_due, self.proposals.values())))))

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
                item = self.evidence.products[identity]
                self.state["entries"][identity] = _empty_entry(change.site_id, item["sync_identity"])
                counts["added" if change.kind == "add" else "updated"] += 1
        if len(current) > MAX_CONTRACT_ROWS:
            raise ConfigurationError("This inventory would exceed 100,000 rows. Select fewer products.")
        detail = {"sync": counts} if automatic else {"asset_id": next(iter(selected))}
        if automatic:
            self.state["summary"] = {"at": self.now.isoformat(), **counts}
        private_directory(self.path.parent, owner_only=True)
        _publish(self.config, self.path, self.profile, self.previous, list(current.values()), operation,
                 sync=(self.state_file, _encoded(self.state)), sync_client=self.client,
                 detail=detail, system=automatic)
        self.finish_migration()

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
        if snapshots_on and any(change.kind == "remove" for change in selected.values()):
            self.defer_uncovered_removals(selected, projected)

    def defer_uncovered_removals(self, selected, projected):
        for change in selected.values():
            if change.kind == "add":
                projected[change.new.asset_id] = change.new
        managed_coverage = {_row_coverage(asset) for asset in projected.values()}
        _, output = web_assets.paths(self.config, self.client)
        try:
            rows, _ = read_web_snapshot(output)
        except (CVEBeaconError, OSError, ValueError):
            rows = []
        snapshot = {asset.asset_id: asset for asset in rows if asset.client == self.client}
        for identity, item in self.evidence.products.items():
            if not item["in_inventory"]:
                continue
            version = actions.ready_version(item)
            key = _coverage_identity(item["vendor"], item["product"], cpe=item.get("cpe", ""),
                                     ecosystem=item.get("ecosystem", ""), package=item.get("package", ""))
            asset = snapshot.get(identity)
            if version is not None and key is not None and (
                    (version, key) in managed_coverage
                    or (asset is not None and _row_coverage(asset) == (version, key))):
                continue
            # Keep the old rows when a detected replacement would lose coverage.
            for removal in [key for key, change in selected.items() if change.kind == "remove"]:
                selected.pop(removal)
            self.removal_deferred = True
            return

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
        item = self.evidence.products.get(identity) if self.evidence is not None else None
        entry = self.state["entries"].setdefault(
            identity, _empty_entry(proposal.site_id, item["sync_identity"] if item else None))
        entry.update(decision="" if action == "reconsider" else action,
                     signature=proposal.signature if action in {"ignore", "keep-version"} else "")
        private_directory(self.path.parent, owner_only=True)
        _commit_change(self.config, "web_inventory_sync_" + action.replace("-", "_"), self.path.stem,
                       {"client": self.profile["name"], "asset_id": identity},
                       {"sync": (self.state_file, _encoded(self.state))}, sync_client=self.client)
        self.finish_migration()


def session(config, client):
    """Build a view of saved evidence. Publishing it requires the operation lock."""
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
    state_file = state_path(config, client)
    state, legacy_path = _load_state(state_file, client)
    before = _encoded(state)
    observation = None
    if not state["detecting"]:
        observation = _observation(output, client, revision, document["assets"])
    now = _now()
    proposals = {}
    web_rows = _web_rows(assets)
    if observation is not None and (observation.id == state["blocked"]
                                    or (state["confirmed"] and observation.id != state["confirmed"])):
        observation = None
    if observation is not None:
        _advance(state, observation, client, web_rows, now)
        snapshots_on = config.inventory is not None and config.inventory.web_snapshots
        if settings.mode in {"review", "auto"}:
            proposals = _product_changes(observation, state["entries"], profile, assets, web_rows, snapshots_on)
    proposals.update(_missing_products(observation, state, web_rows, config.web.removal_grace_days, client))
    return Session(config, settings, client, path, state_file, legacy_path, profile, previous, assets,
                   state, observation, proposals, before, now)


def inspect(config, client):
    if not pending_exists(config.inventory_directory):
        current = session(config, client)
        if current is None or not current.needs_write():
            return current
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


def detection_started(config, client, run_id):
    """Prevent an interrupted detection from making an older review actionable."""
    try:
        recover(config.inventory_directory, config.watch.users_database)
        path = state_path(config, client)
        state, legacy_path = _load_state(path, client)
        if state["detecting"] or state["blocked"] or state["confirmed"]:
            for entry in state["entries"].values():
                entry["misses"] = 0
        state.update(detecting=True, blocked=run_id, confirmed="")
        private_directory(path.parent, owner_only=True)
        web_assets.replace_bytes(path, _encoded(state))
        if legacy_path is not None:
            remove_file(legacy_path)
    except (CVEBeaconError, OSError, ValueError):
        raise ConfigurationError(WRITE_WARNING) from None


def detection_finished(config, client, run_id):
    """The detection command already holds the shared inventory operation lock."""
    try:
        recover(config.inventory_directory, config.watch.users_database)
        allowlist, output = web_assets.paths(config, client)
        document, revision = web_assets.read_allowlist(allowlist, client)
        observation = _observation(output, client, revision, document["assets"])
        path = state_path(config, client)
        state, _ = _load_state(path, client)
        if not (state["detecting"] and state["blocked"] == run_id
                and observation is not None and observation.id == run_id):
            raise ConfigurationError(RESULTS_WARNING)
        # Save the parent-confirmed review before attempting the separate inventory transaction.
        state.update(detecting=False, blocked="", confirmed=run_id)
        web_assets.replace_bytes(path, _encoded(state))
        current = session(config, client)
        if current is not None:
            if current.settings.mode == "auto":
                current.apply_auto()
            else:
                current.save_observations()
    except (CVEBeaconError, OSError, ValueError):
        LOG.warning(WRITE_WARNING)
