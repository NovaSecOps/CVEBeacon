"""Recover pending inventory changes according to the durable audit decision."""

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from cvebeacon import inventory_journal as journal, snapshot as primitives
from cvebeacon.inventory import load_inventory
from cvebeacon.managed_inventory import client_key, encode_records, profiles
from cvebeacon.models import Asset
from cvebeacon.private_storage import private_directory, private_file
from test_dashboard import setup
from test_dashboard_accounts import PASSWORD, accounts as account_fixture


@pytest.fixture
def storage(account_fixture):
    config, users, _, _ = account_fixture
    config = replace(config, inventory=None)
    directory = config.inventory_directory
    private_directory(directory, owner_only=True)
    actor = users.authenticate("admin", PASSWORD)
    name = "Sample client"
    key = client_key(name)
    return config, directory, users, actor, name, key


def _stage(storage, changes, *, commit=True, event="inventory_saved"):
    _, directory, users, actor, label, key = storage
    with users.transaction() as db:
        journal.stage_change(directory, db, users, actor, event, key,
                             {"client": label, "row_count": 1, "mode": "replace"}, changes)
        if not commit:
            db.rollback()


def _data(asset_id, label):
    return encode_records([Asset(asset_id, "Vendor", "Product", "1", client=label)])


def test_rolled_back_profile_and_inventory_never_become_visible(storage):
    config, directory, users, _, label, key = storage
    current = directory / f"{key}.json"
    profile = directory / f"{key}.client"
    _stage(storage, {
        "current": (current, _data("new", label)),
        "profile": (profile, b'{"name":"Sample client","notes":"","contact":""}'),
    }, commit=False)
    assert journal.pending_exists(directory)
    assert config.effective_inventory is None
    assert not current.exists() and not profile.exists() and not journal.pending_exists(directory)
    assert all(not entry.action.startswith("inventory_saved:") for entry in users.audit_entries())


@pytest.mark.parametrize("interrupt", ("archive", "current"))
def test_committed_change_is_replayed_after_interrupted_publication(storage, monkeypatch, interrupt):
    config, directory, users, _, label, key = storage
    current = directory / f"{key}.json"
    archived = directory / f"{key}.20261119T120000000000Z.json"
    previous = _data("before", label)
    journal.replace_bytes(current, previous)
    _stage(storage, {"archive": (archived, previous), "current": (current, _data("after", label))})
    real_replace = journal.replace_bytes

    def fail_after_replacement(path: Path, data: bytes):
        real_replace(path, data)
        if path == (archived if interrupt == "archive" else current):
            raise OSError("simulated interrupted directory sync")

    with monkeypatch.context() as failure:
        failure.setattr(journal, "replace_bytes", fail_after_replacement)
        with pytest.raises(OSError):
            load_inventory(config.effective_inventory)
    assert journal.pending_exists(directory)
    assert [asset.asset_id for asset in load_inventory(config.effective_inventory)] == ["after"]
    assert archived.read_bytes() == previous and not journal.pending_exists(directory)
    assert sum(entry.action.startswith("inventory_saved:") for entry in users.audit_entries()) == 1


def test_new_profile_and_removal_finish_after_commit(storage):
    config, directory, _, _, label, key = storage
    profile = directory / f"{key}.client"
    _stage(storage, {"profile": (profile, b'{"name":"Sample client","notes":"","contact":""}')},
           event="client_added")
    assert not profile.exists()
    assert profiles(directory, config.watch.users_database)[0]["name"] == label
    current = directory / f"{key}.json"
    archived = directory / f"{key}.20261119T120000000000Z.json"
    previous = _data("existing", label)
    journal.replace_bytes(current, previous)
    _stage(storage, {"archive": (archived, previous), "current": (current, None)}, event="inventory_removed")
    assert current.exists()
    assert config.effective_inventory is None
    assert archived.read_bytes() == previous and not current.exists()


@pytest.mark.parametrize("without_unix_flags", (False, True), ids=("native", "without-unix-flags"))
def test_update_snapshot_restores_managed_files_and_audit_together(
    storage, tmp_path, monkeypatch, without_unix_flags,
):
    from cvebeacon import update_state

    if without_unix_flags:
        class WindowsFileAPI:
            name = "nt"

            def __getattr__(self, name):
                if name in {"O_DIRECTORY", "O_NOFOLLOW", "fchmod"}:
                    raise AttributeError(name)
                return getattr(os, name)

        monkeypatch.setattr(primitives, "os", WindowsFileAPI())
        monkeypatch.setattr(update_state, "os", WindowsFileAPI())

    config, directory, users, _, label, key = storage
    current = directory / f"{key}.json"
    profile = directory / f"{key}.client"
    history = directory / f"{key}.20261119T120000000000Z.json"
    previous = _data("before", label)
    _stage(storage, {
        "current": (current, previous), "archive": (history, previous),
        "profile": (profile, b'{"name":"Sample client","notes":"","contact":""}'),
    })
    snapshot = tmp_path / "snapshots" / "one"
    private_directory(snapshot, owner_only=True)
    update_state.backup(config, config.config_path.parent, snapshot)
    for entry in snapshot.iterdir():
        os.close(private_file(entry, readonly=True))
    before = users.audit_entries()
    _stage(storage, {"current": (current, _data("after", label))})
    assert config.effective_inventory is not None
    other = directory / f"{client_key('New client')}.json"
    journal.replace_bytes(other, _data("new", "New client"))
    unrelated = directory / "notes.json"
    unrelated.write_text("Nota do operador — privada", encoding="utf-8")
    history.unlink()

    update_state.restore(config, config.config_path.parent, snapshot)
    update_state.verify_restore(config, config.config_path.parent, snapshot)
    assert users.audit_entries() == before
    assert current.read_bytes() == history.read_bytes() == previous
    assert profile.exists() and not other.exists()
    assert unrelated.read_text(encoding="utf-8") == "Nota do operador — privada"
    for path in (current, history, profile, config.config_path, config.watch.users_database):
        os.close(private_file(path, readonly=True))


@pytest.mark.parametrize("platform", ("nt", "posix"))
def test_directory_sync_works_without_unix_open_flags(tmp_path, monkeypatch, platform):
    from types import SimpleNamespace

    calls = []
    monkeypatch.setattr(primitives, "os", SimpleNamespace(
        name=platform, O_RDONLY=0, open=lambda *args: 7,
        fsync=lambda fd: calls.append(("sync", fd)), close=lambda fd: calls.append(("close", fd)),
    ))
    journal.sync_directory(tmp_path)
    assert calls == ([] if platform == "nt" else [("sync", 7), ("close", 7)])


def test_recovery_removes_staging_files_left_before_the_marker(storage):
    config, directory, users, _, label, _ = storage
    orphan = directory / journal.PARTS["current"]
    journal.replace_bytes(orphan, _data("orphan", label))
    assert not journal.pending_exists(directory)
    assert config.effective_inventory is None
    assert not orphan.exists()
    assert all(not entry.action.startswith("inventory_saved:") for entry in users.audit_entries())


@pytest.mark.parametrize("entry", ([], "text", {}, {"name": "missing-fields"}, {"sha256": None}))
def test_malformed_inventory_snapshot_has_a_clean_error(storage, tmp_path, entry):
    from cvebeacon import update_state

    config, *_ = storage
    with pytest.raises(update_state.SnapshotError, match="invalid managed inventory snapshot"):
        update_state._managed_entries(config, tmp_path, {"managed_inventories": [entry]})


def test_snapshot_refuses_too_many_entries_before_copying(storage, tmp_path, monkeypatch):
    from cvebeacon import update_state

    config, directory, _, _, label, key = storage
    journal.replace_bytes(directory / f"{key}.json", _data("sample", label))
    monkeypatch.setattr(update_state, "MAX_MANAGED_FILES", 0, raising=False)
    with pytest.raises(update_state.SnapshotError, match="managed inventory snapshot"):
        update_state._managed_snapshot(config, tmp_path)
    assert not list(tmp_path.glob("inventory-*.copy"))


def test_unsafe_orphan_staging_path_does_not_block_current_inventory(storage, caplog):
    config, directory, _, _, label, key = storage
    current = directory / f"{key}.json"
    journal.replace_bytes(current, _data("active", label))
    orphan = directory / journal.PARTS["current"]
    orphan.mkdir()
    sentinel = orphan / "operator-note"
    sentinel.write_text("private content", encoding="utf-8")

    assert [asset.asset_id for asset in load_inventory(config.effective_inventory)] == ["active"]
    assert sentinel.read_text(encoding="utf-8") == "private content"
    assert "Skipping an unsafe orphaned inventory staging file" in caplog.text
    assert "private content" not in caplog.text


def test_unassigned_journal_recovery_after_interrupted_publish(storage, monkeypatch):
    config, directory, users, actor, _, _ = storage
    current = directory / "unassigned.json"
    archived = directory / "unassigned.20261119T120000000000Z.json"
    previous = _data("before", "")
    journal.replace_bytes(current, previous)
    with users.transaction() as db:
        journal.stage_change(
            directory, db, users, actor, "inventory_saved", "unassigned",
            {"client": "", "row_count": 1, "mode": "replace"},
            {"archive": (archived, previous), "current": (current, _data("after", ""))},
        )
    real_replace = journal.replace_bytes

    def fail_after_current(path: Path, data: bytes):
        real_replace(path, data)
        if path == current:
            raise OSError("simulated interrupted directory sync")

    with monkeypatch.context() as failure:
        failure.setattr(journal, "replace_bytes", fail_after_current)
        with pytest.raises(OSError):
            load_inventory(config.inventory_for_management())
    assert journal.pending_exists(directory)
    assert [asset.asset_id for asset in load_inventory(config.inventory_for_management())] == ["after"]
    assert archived.read_bytes() == previous
    assert not journal.pending_exists(directory)
    assert sum(entry.action.startswith('inventory_saved:{"client":""') for entry in users.audit_entries()) == 1


def test_unassigned_journal_accepts_current_but_rejects_profile_target(storage):
    from cvebeacon.errors import StateError

    _, directory, users, actor, _, _ = storage
    current = directory / "unassigned.json"
    with users.transaction() as db:
        journal.stage_change(
            directory, db, users, actor, "inventory_saved", "unassigned",
            {"client": "", "row_count": 1, "mode": "replace"},
            {"current": (current, _data("reserved", ""))},
        )
    assert journal.pending_exists(directory)
    journal.recover(directory, users.path)
    assert current.read_bytes() == _data("reserved", "")

    with users.transaction() as db:
        with pytest.raises(StateError, match="Invalid inventory change target"):
            journal.stage_change(
                directory, db, users, actor, "inventory_saved", "unassigned",
                {"client": "", "row_count": 1, "mode": "replace"},
                {"profile": (directory / "unassigned.client", b"{}")},
            )


def test_reserved_publisher_add_revision_archive_and_restore(storage):
    from cvebeacon.errors import ConfigurationError
    from cvebeacon.managed_inventory import (
        HISTORY_LIMIT, publish_unassigned_inventory, prune, read_unassigned_inventory, versions,
    )

    config, directory, users, actor, _, _ = storage
    current = directory / "unassigned.json"
    before = Asset("before", "Vendor", "Product", "1")
    publish_unassigned_inventory(
        config, [before], expected_revision="empty", users=users, proof=actor, mode="replace",
    )
    first_revision = hashlib.sha256(current.read_bytes()).hexdigest()
    added = Asset("added", "Vendor", "Product", "1")
    publish_unassigned_inventory(
        config, [added], expected_revision=first_revision, users=users, proof=actor, mode="add",
    )
    assert [asset.asset_id for asset in read_unassigned_inventory(current.read_bytes())] == ["before", "added"]
    history = versions(current)
    assert len(history) == 1
    assert [asset.asset_id for asset in read_unassigned_inventory(history[0].read_bytes())] == ["before"]

    after_revision = hashlib.sha256(current.read_bytes()).hexdigest()
    with pytest.raises(ConfigurationError, match="changed"):
        publish_unassigned_inventory(
            config, [Asset("stale", "Vendor", "Product", "1")], expected_revision=first_revision,
            users=users, proof=actor, mode="replace",
        )
    publish_unassigned_inventory(
        config, read_unassigned_inventory(history[0].read_bytes()), expected_revision=after_revision,
        users=users, proof=actor, mode="restore",
    )
    assert [asset.asset_id for asset in read_unassigned_inventory(current.read_bytes())] == ["before"]
    assert len(versions(current)) == 2
    for index in range(HISTORY_LIMIT + 2):
        archived = directory / f"unassigned.20261119T120000{index:06d}Z.json"
        journal.replace_bytes(archived, _data(f"history-{index}", ""))
    prune(current)
    assert len(versions(current)) == HISTORY_LIMIT
