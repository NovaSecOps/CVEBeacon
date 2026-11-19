# Upgrading

## Optional Teams bot channel

Back up the watch database before upgrading. The first write-capable watch
operation migrates schema 8 to 9 in a transaction, preserving existing event,
delivery and reporting history. The new tables store Teams bot conversation
references, frozen message batches and per-recipient results. Bot migration
checks actual tables and columns even if an earlier build already wrote the
version number. Upgrades from schema 7 run the preceding provider migration
first when both features are installed. Read-only views
of an older database may require a watch operation to migrate it first.

Existing configuration files and the Teams Workflow webhook channel require no
changes. The new `teams_bot` channel is opt-in and requires the Azure registration
and Teams app installation described in [Teams bot setup](TEAMS.md). No schedules
or notifications are created by the upgrade itself.

After schema migration, older binaries will reject the newer schema. To roll
back, stop all processes using the watch database and restore its pre-upgrade
backup together with the previous configuration and application version. A
restore also restores the delivery ledger, so review notifications sent since
the backup before resuming delivery.
