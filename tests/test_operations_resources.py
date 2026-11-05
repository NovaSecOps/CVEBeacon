"""Coordinate each mutable storage location and classify lock failures."""

from dataclasses import replace
import errno
from pathlib import Path

import pytest

from cvebeacon import cli, dashboard_jobs as jobs
from cvebeacon.errors import CVEBeaconError
from cvebeacon.locking import LOCK_NAME, RunLock, run_lock_path
from test_dashboard_operations import fake_job, make_config, new_accounts
from test_dashboard_watch import seeded, login as watch_login, csrf as watch_csrf


@pytest.mark.parametrize('command', ['scan', 'run'])
def test_shared_inventory_with_distinct_watch_storage_contends(tmp_path, monkeypatch, capsys, command):
    config = make_config(tmp_path)
    config = replace(config, watch=replace(config.watch, database=tmp_path / 'watch-other' / 'watch.db'))
    monkeypatch.setattr(cli, 'load_config', lambda _: config)
    monkeypatch.setattr(cli, '_run_scan', lambda *a, **k: 17)
    monkeypatch.setattr(cli, '_run_all', lambda *a, **k: 17)
    with RunLock(Path(config.database_path).resolve().parent / LOCK_NAME):
        assert cli.run(cli._parser().parse_args([command])) == 2
    assert 'another run is in progress' in capsys.readouterr().err



def test_scan_does_not_lock_unrelated_watch_storage(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    config = replace(config, watch=replace(config.watch, database=tmp_path / 'other' / 'watch.db'))
    monkeypatch.setattr(cli, 'load_config', lambda _: config)
    monkeypatch.setattr(cli, '_run_scan', lambda *a, **k: 17)
    with RunLock(run_lock_path(config)):
        assert cli.run(cli._parser().parse_args(['scan'])) == 17



@pytest.mark.parametrize('method', ['acquire', 'probe'])
def test_non_contention_lock_errors_are_operational_errors(tmp_path, monkeypatch, method):
    lock = RunLock(tmp_path / 'run.lock')
    def fail(_):
        raise OSError(errno.ENOLCK, 'synthetic unavailable lock service')
    monkeypatch.setattr(lock, '_lock', fail)
    with pytest.raises(CVEBeaconError, match='lock'):
        getattr(lock, method)()



@pytest.mark.parametrize('action,identifier', [('report', 'CVE-2026-0002'), ('unreport', 'CVE-2026-0001')])
def test_dashboard_report_actions_take_watch_lock(tmp_path, action, identifier):
    config, _, store, _, client = seeded(tmp_path)
    watch_login(client, 'ops')
    token = watch_csrf(client, '/watch/cve/' + identifier)
    before = store.report_trail(identifier)
    with RunLock(run_lock_path(config)):
        response = client.post(f'/watch/cve/{identifier}/{action}', data={'csrf': token})
    assert response.status_code == 409
    assert 'another run is in progress' in response.text
    assert store.report_trail(identifier) == before



@pytest.mark.parametrize('command', ['watch-sync', 'watch-evaluate', 'watch-run', 'watch-notify', 'watch-report', 'watch-unreport'])
def test_watch_commands_ignore_unrelated_inventory_lock(tmp_path, monkeypatch, command):
    config = make_config(tmp_path)
    config = replace(config, watch=replace(config.watch, database=tmp_path / 'watch' / 'watch.db'))
    monkeypatch.setattr(cli, 'load_config', lambda _: config)
    monkeypatch.setattr(cli, '_run_watch', lambda *a, **k: 17)
    arguments = command.split('-')
    if arguments[-1] == 'evaluate':
        arguments.append('--all')
    if command in {'watch-report', 'watch-unreport'}:
        arguments.append('CVE-2026-0001')
    with RunLock(Path(config.database_path).resolve().parent / LOCK_NAME):
        assert cli.run(cli._parser().parse_args(arguments)) == 17



def test_dashboard_job_probes_shared_inventory_storage(tmp_path):
    config = make_config(tmp_path)
    config = replace(config, watch=replace(config.watch, database=tmp_path / 'other' / 'watch.db'))
    manager = jobs.JobManager(config, new_accounts(config))
    with RunLock(Path(config.database_path).resolve().parent / LOCK_NAME):
        with pytest.raises(CVEBeaconError, match='another run'):
            manager.submit('scan', started_by='admin', argv=fake_job('pass'))
    assert manager.store.recent() == ()



def test_dual_locks_sort_deduplicate_and_release_partial_acquisition(tmp_path):
    from cvebeacon.locking import OperationLock, operation_lock_paths

    config = make_config(tmp_path)
    # Identical locations take one lock rather than contending with themselves.
    assert len(operation_lock_paths(config, 'run')) == 1
    with_watch_elsewhere = replace(config, watch=replace(config.watch, database=tmp_path / 'z-watch' / 'watch.db'))
    paths = operation_lock_paths(with_watch_elsewhere, 'run')
    assert len(paths) == 2
    assert paths == tuple(sorted(paths))
    with RunLock(paths[1]):
        combined = OperationLock(with_watch_elsewhere, 'run')
        assert not combined.acquire()
        with RunLock(paths[0]):
            pass  # First acquisition was released after the second failed.
    assert combined.acquire()
    combined.release()
    disabled = replace(with_watch_elsewhere, watch=replace(with_watch_elsewhere.watch, enabled=False))
    assert operation_lock_paths(disabled, 'run') == (paths[0],)
    watch_only = replace(with_watch_elsewhere, inventory=None)
    assert operation_lock_paths(watch_only, 'run') == (paths[1],)
