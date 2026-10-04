"""One-shot delivery, operational messages and safe independent ledger health."""

from __future__ import annotations

from contextlib import ExitStack
import math
import random
import time
import uuid

from ..common import AutomationError, digest, lock
from ..http import HTTPS
from .adapters import Outcome, bind, split_message, validate_channels
from .ledger import check_paths, claim, destination, due, enforce_replay_scope, finish, ledger, next_due, prepare, recover, summary
from .reader import core_reader, event_batch, render_event


MAX_ATTEMPTS_PER_RUN = 32
RUN_BUDGET_SECONDS = 30


def _channels(config):
    return validate_channels(config.notifications, config.config_path.parent)


def _timestamp(clock):
    value = clock()
    if type(value) not in (int, float) or not 0 <= value <= 10**12 or not math.isfinite(value):
        raise AutomationError("invalid_notification_clock")
    return float(value)


def _send_due(connection, targets, *, transport_factory, clock, sleeper, random_value, event_key=None, purpose=None):
    """Round-robin isolation, finite time/attempts, durable provider pacing."""
    attempts = dict.fromkeys((item.channel.id for item in targets), 0)
    deadline = time.monotonic() + RUN_BUDGET_SECONDS
    count = 0
    ordered = list(targets)
    while count < MAX_ATTEMPTS_PER_RUN and time.monotonic() < deadline:
        progressed = False
        for bound in ordered:
            if count >= MAX_ATTEMPTS_PER_RUN or time.monotonic() >= deadline:
                break
            if attempts[bound.channel.id] >= bound.channel.batch_size:
                continue
            timestamp = _timestamp(clock)
            row = due(connection, bound, timestamp, event_key, purpose)
            if row is None:
                continue
            if row["attempts"] >= bound.channel.max_attempts:
                with connection:
                    connection.execute("UPDATE deliveries SET state='ambiguous',error='attempts_exhausted',updated_at=? WHERE rowid=?",
                                       (timestamp, row["rowid"]))
                progressed = True
                continue
            claim(connection, row, timestamp)  # Commit before entering credential-bearing transport.
            try:
                outcome = bound.send(row["text"], row["transaction_id"], transport_factory=transport_factory,
                                     timestamp=timestamp, timeout=max(1, min(bound.channel.timeout, int(deadline - time.monotonic()))))
            except Exception:
                # No exception text/provider data may cross this boundary. Unknown send phase fails closed.
                outcome = Outcome("retryable" if bound.channel.provider == "matrix" else "ambiguous", "adapter_failure")
            jitter = random_value()
            if type(jitter) not in (int, float) or not 0 <= jitter <= 1:
                jitter = 0.5
            finish(connection, bound, row, outcome, _timestamp(clock), jitter)
            count += 1
            attempts[bound.channel.id] += 1
            progressed = True
        if progressed:
            ordered = ordered[1:] + ordered[:1]
            continue
        timestamp = _timestamp(clock)
        future = [value for target in targets if attempts[target.channel.id] < target.channel.batch_size
                  if (value := next_due(connection, target, event_key, purpose)) is not None]
        if not future:
            break
        wait = max(0, min(future) - timestamp)
        left = deadline - time.monotonic()
        # Waiting for a distant backoff/429 belongs to the next scheduler run.
        if wait > min(3, left) or wait <= 0:
            break
        sleeper(wait)
    return count


def _deliver(config, *, core_db=None, messages=(), selected=None, only_event=None, transport_factory=HTTPS,
             clock=time.time, sleeper=time.sleep, random_value=random.random):
    channels = _channels(config)
    check_paths(config, core_db)
    if selected is not None:
        channels = tuple(item for item in channels if item.id == selected)
        if not channels:
            raise AutomationError("notification_channel_not_found")
        if not channels[0].enabled:
            raise AutomationError("notification_channel_disabled")
    errors, targets, seen = {}, [], set()
    for channel in channels:
        if not channel.enabled:
            continue
        try:
            bound = bind(channel)
            identity = (channel.provider, bound.destination)
            if identity in seen:
                raise AutomationError("duplicate_notification_destination")
            seen.add(identity)
            targets.append(bound)
        except (AutomationError, OSError, ValueError, TypeError):
            errors[channel.id] = "channel_unavailable"
    with lock(config.state_dir / "notifications.lock"):
        with ledger(config, core_db=core_db) as connection:
            recover(connection, _timestamp(clock))
            prepared = []
            try:
                with ExitStack() as resources:
                    reader = resources.enter_context(core_reader(core_db)) if core_db is not None else None
                    for target in targets:
                        cursor = destination(connection, target)
                        enforce_replay_scope(connection, target, _timestamp(clock))
                        try:
                            if reader is not None:
                                rows = event_batch(reader, cursor["cursor_id"], cursor["cursor_run"], target.channel.batch_size)
                                for row in rows:
                                    event_key, text = render_event(row)
                                    prepare(connection, target, event_key, split_message(text, target.channel), _timestamp(clock),
                                            cursor=(row["event_id"], row["run_id"]))
                            for event_key, text in messages:
                                prepare(connection, target, event_key, split_message(text, target.channel), _timestamp(clock),
                                        purpose="test" if selected is not None else "operational")
                            prepared.append(target)
                        except (AutomationError, OSError, ValueError, TypeError):
                            errors[target.channel.id] = "event_preparation_failed"
            except (AutomationError, OSError, ValueError, TypeError):
                # The shared read snapshot is an integrity gate for every alert channel.
                errors.update((target.channel.id, "event_preparation_failed") for target in targets)
                prepared = []
            sent = _send_due(connection, prepared, transport_factory=transport_factory, clock=clock,
                             sleeper=sleeper, random_value=random_value, event_key=only_event,
                             purpose="event" if core_db is not None else "test" if selected is not None else "operational")
            result = summary(connection, channels)
            result.update(attempted=sent, errors=errors)
            result["unhealthy"] |= bool(errors)
            return result


def dispatch(config, core_db, *, transport_factory=HTTPS, clock=time.time, sleeper=time.sleep, random_value=random.random):
    return _deliver(config, core_db=core_db, transport_factory=transport_factory, clock=clock,
                    sleeper=sleeper, random_value=random_value)


def delivery_status(config):
    channels = _channels(config)
    with ledger(config, readonly=True) as connection:
        return summary(connection, channels)


def test_channel(config, channel_id, *, transport_factory=HTTPS, clock=time.time, sleeper=time.sleep, random_value=random.random):
    key = digest(("notification-test:" + str(uuid.uuid4())).encode("ascii"))
    text = "CVEBeacon notification TEST\nThis is an explicitly requested test message. No vulnerability assertion is made."
    return _deliver(config, selected=channel_id, only_event=key, messages=((key, text),), transport_factory=transport_factory,
                    clock=clock, sleeper=sleeper, random_value=random_value)


def operational(config, state, previous, *, transport_factory=HTTPS, clock=time.time,
                sleeper=time.sleep, random_value=random.random):
    if not config.operations.get("enabled", False):
        return {"version": 1, "channels": {}, "unhealthy": False, "attempted": 0}
    if not isinstance(state, dict) or not isinstance(previous, dict):
        raise AutomationError("invalid_operational_state")
    timestamp = _timestamp(clock)
    interval = config.operations.get("interval_seconds", 86400)
    if type(interval) is not int or not 60 <= interval <= 604800:
        raise AutomationError("invalid_operational_interval")
    status = state.get("status")
    allowed = {"operational", "degraded", "failed", "coverage_warning"}
    if status not in allowed:
        raise AutomationError("invalid_operational_status")
    # Only fixed operational status and aggregate counts cross the privacy boundary.
    sources = state.get("sources", {})
    total = min(len(sources), 128) if isinstance(sources, dict) else 0
    core_exit = state.get("core_exit")
    core_status = "coverage warning" if core_exit == 4 else "completed" if core_exit == 0 else "not successful"
    text = ("CVEBeacon Automation operational digest / heartbeat\nPipeline: " + status
            + "\nConfigured sources reported: " + str(total) + "\nCore scan: " + core_status
            + "\nPipeline operational does not mean vulnerability-free. Review Core findings separately.")
    messages = [(digest(f"operation:interval:{int(timestamp // interval)}:{interval}".encode("ascii")), text)]
    was_bad = previous.get("status") in allowed - {"operational"}
    bad = status != "operational"
    transition = "failure" if bad and not was_bad and config.operations.get("failures", False) else (
                 "recovery" if not bad and was_bad and config.operations.get("recovery", False) else None)
    if transition:
        stamp = state.get("started_at", state.get("ended_at", ""))
        if not isinstance(stamp, str) or len(stamp) > 64:
            raise AutomationError("invalid_operational_timestamp")
        messages.append((digest(("operation:" + transition + ":" + stamp).encode("utf-8")),
                         "CVEBeacon Automation operational " + transition.upper() + "\n" + text))
    if config.operations.get("discovery", False) and isinstance(state.get("discovery"), dict):
        changes, changed_jobs, scope_changes = 0, 0, 0
        for item in list(state["discovery"].values())[:16]:
            if not isinstance(item, dict) or item.get("status") != "success" or item.get("changed") is not True:
                continue
            count = sum(min(value, 10000) for key in ("added", "not_observed", "service_changes")
                        if type(value := item.get(key)) is int and 0 <= value <= 10**12)
            changes = min(10000, changes + count)
            changed_jobs += 1
            scope_changes += item.get("scope_changed") is True
        if changed_jobs:
            key = digest(("operation:discovery:" + str(int(timestamp // interval)) + ":"
                          + str(changes) + ":" + str(changed_jobs) + ":" + str(scope_changes)).encode("ascii"))
            messages.append((key, "CVEBeacon Automation DISCOVERY observation changes: " + str(changes)
                             + "\nChanged jobs: " + str(changed_jobs) + "; changed scopes: " + str(scope_changes)
                             + "\nObservations require review; they are not authoritative vulnerability inventory."))
    return _deliver(config, messages=tuple(messages), transport_factory=transport_factory, clock=clock,
                    sleeper=sleeper, random_value=random_value)
