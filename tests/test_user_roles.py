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


def test_password_verification_does_not_hold_writer_lock(users, monkeypatch):
    from cvebeacon.watch import users as module
    proof = users.authenticate("admin", PASSWORD)
    entered, release = threading.Event(), threading.Event()
    original = module.verify_password

    def verify(encoded, password):
        entered.set()
        assert release.wait(10)
        return original(encoded, password)

    monkeypatch.setattr(module, "verify_password", verify)
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempt = pool.submit(users.authenticate, "reader", PASSWORD)
        assert entered.wait(5)
        try:
            identity = pool.submit(users.dashboard_identity, proof)
            assert identity.result(timeout=1)[0].username == "admin"
            with UserStore(users.path).transaction() as db:
                db.execute("UPDATE cb_user SET credential_version=credential_version+1 WHERE username='reader'")
        finally:
            release.set()
        assert attempt.result(timeout=5) is None


def test_identity_reads_do_not_require_writer_lock(users):
    proof = users.authenticate("admin", PASSWORD)
    with users.transaction():
        assert users.dashboard_identity(proof)[0].username == "admin"


@pytest.mark.parametrize("operation", [
    "promote", "self_role", "admin_edit", "admin_password", "admin_disable",
    "admin_enable", "admin_unlock", "create_admin", "grant_stronger", "assign_stronger",
    "create_role", "edit_role", "delete_role",
])
def test_delegated_manager_cannot_escalate(users, operation):
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("manager", {"manage_users"}, authorization=admin)
    users.edit_user("reader", role="manager", disabled=False, authorization=admin)
    users.add("target", password=PASSWORD)
    manager = users.authenticate("reader", PASSWORD)
    actions = {
        "promote": lambda: users.edit_user("target", role="admin", disabled=False, authorization=manager),
        "self_role": lambda: users.edit_user("reader", role="viewer", disabled=False, authorization=manager),
        "admin_edit": lambda: users.edit_user("admin", role="admin", disabled=False, display_name="changed", authorization=manager),
        "admin_password": lambda: users.set_password("admin", PASSWORD + " changed", authorization=manager),
        "admin_disable": lambda: users.disable("admin", authorization=manager),
        "admin_enable": lambda: users.enable("admin", authorization=manager),
        "admin_unlock": lambda: users.unlock("admin", authorization=manager),
        "create_admin": lambda: users.add("extra", password=PASSWORD, is_admin=True, authorization=manager),
        "grant_stronger": lambda: users.add("extra", password=PASSWORD, role="viewer", authorization=manager),
        "assign_stronger": lambda: users.edit_user("target", role="operator", disabled=False, authorization=manager),
        "create_role": lambda: users.save_role("newrole", {"manage_users"}, authorization=manager),
        "edit_role": lambda: users.save_role("manager", {"manage_users", "view"}, authorization=manager),
        "delete_role": lambda: users.delete_role("operator", authorization=manager),
    }
    before = users.users(), users.roles(), users.user_roles(), users.audit_entries()
    with pytest.raises(ConfigurationError):
        actions[operation]()
    assert (users.users(), users.roles(), users.user_roles(), users.audit_entries()) == before


def test_delegated_manager_can_manage_subset_roles(users):
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("manager", {"manage_users", "view"}, authorization=admin)
    users.edit_user("reader", role="manager", disabled=False, authorization=admin)
    manager = users.authenticate("reader", PASSWORD)
    users.add("target", password=PASSWORD, role="viewer", authorization=manager)
    users.edit_user("target", role="viewer", disabled=False, display_name="Changed", authorization=manager)
    users.set_password("target", PASSWORD + " changed", authorization=manager)
    users.disable("target", authorization=manager)
    users.enable("target", authorization=manager)
    users.unlock("target", authorization=manager)
    assert users.find("target").display_name == "Changed"


def test_delegated_manager_cannot_take_over_a_more_privileged_member(users):
    admin = users.authenticate("admin", PASSWORD)
    users.save_role("manager", {"manage_users"}, authorization=admin)
    users.edit_user("reader", role="manager", disabled=False, authorization=admin)
    users.add("operator", password=PASSWORD, role="operator")
    proof = users.authenticate("reader", PASSWORD)
    with pytest.raises(ConfigurationError):
        users.set_password("operator", PASSWORD + " changed", authorization=proof)
