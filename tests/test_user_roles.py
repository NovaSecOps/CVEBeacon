"""Transactional role administration and administrator preservation."""

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from cvebeacon.errors import ConfigurationError
from cvebeacon.watch.users import BOOTSTRAP, UserStore

PASSWORD = "Synthetic account password 123"


@pytest.fixture
def users(tmp_path):
    store = UserStore(tmp_path / "users.db")
    store.add("admin", password=PASSWORD, is_admin=True, authorization=BOOTSTRAP)
    store.add("reader", password=PASSWORD)
    return store


def test_last_admin_cannot_be_disabled_or_demoted(users):
    proof = users.authenticate("admin", PASSWORD)
    with pytest.raises(ConfigurationError, match="last enabled administrator"):
        users.disable("admin", authorization=proof)
    with pytest.raises(ConfigurationError, match="last enabled administrator"):
        users.edit_user("admin", role="viewer", disabled=False, authorization=proof)


def test_role_changes_require_current_authorization(users):
    proof = users.authenticate("reader", PASSWORD)
    with pytest.raises(ConfigurationError):
        users.save_role("custom", {"manage_users"}, authorization=proof)


@pytest.mark.parametrize("action", ["disable", "demote"])
def test_concurrent_admin_removal_is_serialized(users, action):
    users.add("backup", password=PASSWORD, is_admin=True)
    barrier = threading.Barrier(2)

    def remove(name):
        store = UserStore(users.path)
        proof = store.authenticate(name, PASSWORD)
        barrier.wait(timeout=10)
        try:
            if action == "disable":
                store.disable(name, authorization=proof)
            else:
                store.edit_user(name, role="viewer", disabled=False, authorization=proof)
            return True
        except ConfigurationError as exc:
            assert "last enabled administrator" in str(exc)
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(remove, ["admin", "backup"]))
    assert sorted(outcomes) == [False, True]
    assert sum(u.is_admin and not u.disabled for u in users.users()) == 1


def test_stale_management_proof_cannot_mutate(users):
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("manager", {"manage_users"}, authorization=admin)
    users.edit_user("reader", role="manager", disabled=False, authorization=admin)
    proof = users.authenticate("reader", PASSWORD)
    users.save_role("manager", set(), authorization=admin)
    operations = [lambda: users.add("extra", password=PASSWORD, authorization=proof),
                  lambda: users.save_role("other", {"view"}, authorization=proof),
                  lambda: users.delete_role("operator", authorization=proof),
                  lambda: users.edit_user("admin", role="viewer", disabled=False, authorization=proof),
                  lambda: users.set_password("admin", PASSWORD + " changed", authorization=proof),
                  lambda: users.disable("admin", authorization=proof),
                  lambda: users.unlock("admin", authorization=proof)]
    for operation in operations:
        with pytest.raises(ConfigurationError):
            operation()
    assert users.find("extra") is None


def test_migration_assigns_viewer_and_does_not_resurrect_roles(users):
    with users.transaction() as db:
        db.execute("DROP TABLE cb_role")
        db.execute("DROP TABLE cb_user_role")
        db.execute("DELETE FROM cb_user_meta WHERE key='roles_initialized'")
    migrated = UserStore(users.path)
    migrated.initialize()
    assert migrated.user_roles() == {users.find("admin").id: "admin", users.find("reader").id: "viewer"}
    proof = migrated.authenticate("admin", PASSWORD)
    migrated.delete_role("operator", authorization=proof)
    assert "operator" not in UserStore(users.path).roles()

