"""Recover pending inventory changes according to the durable audit decision."""

from pathlib import Path

import pytest

from cvebeacon import inventory_journal as journal
from cvebeacon.inventory import load_inventory
from cvebeacon.managed_inventory import client_key, encode_records, profiles
from cvebeacon.models import Asset
from cvebeacon.watch.users import BOOTSTRAP, UserStore
from test_dashboard_watch import PASSWORD
from watch_support import write_config


@pytest.fixture
def storage(tmp_path):
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    config = write_config(data, inventory=False)
    directory = config.inventory_directory
    directory.mkdir(mode=0o700)
    users = UserStore(config.watch.users_database)
    users.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
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


def test_update_snapshot_restores_managed_files_and_audit_together(storage, tmp_path):
    from cvebeacon import update_state

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
    snapshot.mkdir(parents=True)
    update_state.backup(config, config.config_path.parent, snapshot)
    before = users.audit_entries()
    _stage(storage, {"current": (current, _data("after", label))})
    assert config.effective_inventory is not None
    other = directory / f"{client_key('New client')}.json"
    journal.replace_bytes(other, _data("new", "New client"))
    unrelated = directory / "notes.json"
    unrelated.write_text("operator file")
    history.unlink()

    update_state.restore(config, config.config_path.parent, snapshot)
    update_state.verify_restore(config, config.config_path.parent, snapshot)
    assert users.audit_entries() == before
    assert current.read_bytes() == history.read_bytes() == previous
    assert profile.exists() and not other.exists() and unrelated.read_text() == "operator file"
