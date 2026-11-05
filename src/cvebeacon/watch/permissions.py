"""Fixed dashboard capabilities; stored roles may select only these names."""

PERMISSIONS = frozenset({
    "view", "report", "statement", "run", "retry", "test_channel",
    "edit_rules", "edit_channels", "edit_sources", "edit_watch",
    "edit_reporting", "edit_dashboard", "edit_inventory", "edit_http", "edit_system", "manage_schedule",
    "manage_users", "view_audit",
})

DEFAULT_ROLES = {
    "viewer": frozenset({"view"}),
    "operator": frozenset({"view", "report", "statement", "run", "retry", "test_channel"}),
}
