"""Recover background jobs and child supervision from storage failures."""

import sqlite3
import subprocess
import threading

import pytest

from cvebeacon import dashboard_jobs as jobs
from cvebeacon.errors import StateError
from test_dashboard_operations import fake_job, make_config, new_accounts, wait_for


@pytest.mark.parametrize('source', ['idle', 'audit'])
def test_transient_idle_or_raw_audit_failure_recovers(tmp_path, monkeypatch, source):
    config = make_config(tmp_path)
    manager = jobs.JobManager(config, new_accounts(config))
    entered = threading.Event()
    resume = threading.Event()
    if source == 'idle':
        original = manager.store.pending_audits
        calls = 0
        def flaky():
            nonlocal calls
            calls += 1
            if calls == 2:
                entered.set()
                resume.wait(3)
                raise StateError('synthetic idle failure')
            return original()
        monkeypatch.setattr(manager.store, 'pending_audits', flaky)
    else:
        manager.store.queue_action('schedule_removed', 'admin', 'synthetic')
        original = manager.users.record_action
        def flaky(action, **kwargs):
            if action == 'schedule_removed' and not entered.is_set():
                entered.set()
                resume.wait(3)
                raise sqlite3.OperationalError('synthetic audit timeout')
            return original(action, **kwargs)
        monkeypatch.setattr(manager.users, 'record_action', flaky)
    try:
        manager.start_thread()
        assert entered.wait(3)
        worker = manager._thread
        resume.set()
        # Allow the pre-fix worker to exit before the next admission attempt.
        worker.join(timeout=0.8)
        job = manager.submit('notify-test', started_by='admin', argv=fake_job('pass'))
        assert manager.wait(job.id, timeout=4).status == 'succeeded'
        wait_for(lambda: not manager.store.pending_actions())
    finally:
        resume.set()
        manager.shutdown()



@pytest.mark.parametrize('error', [StateError, sqlite3.OperationalError])
def test_shutdown_bookkeeping_failure_still_reaps_child(tmp_path, monkeypatch, error):
    config = make_config(tmp_path)
    manager = jobs.JobManager(config, new_accounts(config))
    marker = tmp_path / 'cleanup'
    job = manager.submit('notify-test', started_by='admin', argv=fake_job('''
        import signal, pathlib, sys, time
        def stop(*args):
            pathlib.Path(sys.argv[1]).write_text('cleaned')
            raise SystemExit(130)
        signal.signal(signal.SIGINT, stop)
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, stop)
        print('ready', flush=True)
        time.sleep(30)
    ''', marker))
    wait_for(lambda: 'ready' in manager.store.log_tail(manager.store.get(job.id)))
    process = manager._process
    queued = manager.submit('notify-test', started_by='admin', argv=fake_job('pass'))
    def fail(*args, **kwargs):
        raise error('synthetic cancellation failure')
    monkeypatch.setattr(manager.store, 'cancel_queued', fail)
    try:
        # The same registered callback runs at normal interpreter exit.
        callback = manager.shutdown
        callback()
        assert process.poll() is not None
        assert marker.read_text() == 'cleaned'
        assert manager._queue == []
        assert manager.store.get(queued.id).status == 'queued'
        # Failed bookkeeping remains durable for restart recovery.
        jobs.JobManager(config, manager.users).shutdown()
        assert manager.store.get(queued.id).status == 'failed'
    finally:
        monkeypatch.undo()
        manager.shutdown()
        if process.poll() is None:
            process.kill()
            process.wait()



def test_raw_audit_write_errors_are_controlled(tmp_path, monkeypatch):
    users = new_accounts(make_config(tmp_path))
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError('synthetic audit failure')
    monkeypatch.setattr(users, '_append_audit', fail)
    with pytest.raises(StateError, match='audit'):
        users.record_action('schedule_removed', username='admin')



def test_raw_job_query_errors_are_controlled(tmp_path, monkeypatch):
    store = jobs.JobStore(tmp_path / 'jobs.db')
    class BrokenConnection:
        def execute(self, *args):
            raise sqlite3.OperationalError('synthetic read failure')
        def close(self):
            pass
    monkeypatch.setattr(store, '_connect', BrokenConnection)
    with pytest.raises(StateError):
        store.pending_audits()



@pytest.mark.skipif(__import__('os').name != 'posix', reason='POSIX process exit and signal check')
def test_actual_exit_hook_reaps_child_when_store_and_worker_are_unavailable(tmp_path):
    import os
    import signal
    import sys
    import textwrap

    config = make_config(tmp_path)
    new_accounts(config)
    marker = tmp_path / 'exit-cleanup'
    child = fake_job('''
        import signal, pathlib, sys, time
        def stop(*args):
            pathlib.Path(sys.argv[1]).write_text('cleaned')
            raise SystemExit(130)
        signal.signal(signal.SIGINT, stop)
        print('ready', flush=True)
        time.sleep(30)
    ''', marker)
    script = textwrap.dedent(f'''
        import threading, time
        from cvebeacon.config import load_config
        from cvebeacon import dashboard_jobs as jobs
        from cvebeacon.errors import StateError
        from cvebeacon.watch.users import UserStore
        jobs.CANCEL_GRACE_SECONDS = 0.15
        jobs.TERMINATE_GRACE_SECONDS = 0.15
        config = load_config({str(config.config_path)!r})
        manager = jobs.JobManager(config, UserStore(config.watch.users_database))
        job = manager.submit('notify-test', started_by='admin', argv={child!r})
        deadline = time.monotonic() + 5
        while 'ready' not in manager.store.log_tail(manager.store.get(job.id)):
            assert time.monotonic() < deadline
            time.sleep(0.02)
        manager.submit('notify-test', started_by='admin', argv={fake_job('pass')!r})
        print(manager._process.pid, flush=True)
        original = manager.store.get
        blocked = threading.Event()
        def unavailable(job_id):
            if threading.current_thread() is manager._thread:
                blocked.set()
                time.sleep(30)
            return original(job_id)
        manager.store.get = unavailable
        def fail(*args, **kwargs):
            raise StateError('synthetic queued write failure')
        manager.store.cancel_queued = fail
        assert blocked.wait(3)
        # Normal interpreter return invokes the registered shutdown callback.
    ''')
    parent = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pid = None
    try:
        stdout, stderr = parent.communicate(timeout=12)
        assert parent.returncode == 0, stderr
        pid = int(stdout.strip())
        assert marker.read_text() == 'cleaned'
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.communicate()
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass



def test_pending_audit_failure_does_not_skip_other_rows(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    manager = jobs.JobManager(config, new_accounts(config))
    manager.store.queue_action('schedule_removed', 'admin', 'first')
    manager.store.queue_action('schedule_removed', 'admin', 'second')
    original = manager.users.record_action
    def fail_first(action, **kwargs):
        if kwargs.get('detail') == 'first':
            raise sqlite3.OperationalError('synthetic first-row failure')
        return original(action, **kwargs)
    monkeypatch.setattr(manager.users, 'record_action', fail_first)
    manager.retry_audits()
    assert [row['detail'] for row in manager.store.pending_actions()] == ['first']
    monkeypatch.setattr(manager.users, 'record_action', original)
    manager.retry_audits()
    assert manager.store.pending_actions() == []



def test_worker_start_replaces_a_dead_thread_reference(tmp_path):
    config = make_config(tmp_path)
    manager = jobs.JobManager(config, new_accounts(config))
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    manager._thread = dead
    try:
        job = manager.submit('notify-test', started_by='admin', argv=fake_job('pass'))
        assert manager.wait(job.id, timeout=3).status == 'succeeded'
    finally:
        manager.shutdown()



def test_active_cancellation_storage_failure_still_runs_child_cleanup(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    manager = jobs.JobManager(config, new_accounts(config))
    marker = tmp_path / 'cancel-cleanup'
    job = manager.submit('notify-test', started_by='admin', argv=fake_job('''
        import signal, pathlib, sys, time
        def stop(*args):
            pathlib.Path(sys.argv[1]).write_text('cleaned')
            raise SystemExit(130)
        signal.signal(signal.SIGINT, stop)
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, stop)
        print('ready', flush=True)
        time.sleep(30)
    ''', marker))
    wait_for(lambda: 'ready' in manager.store.log_tail(manager.store.get(job.id)))
    process = manager._process
    def fail(*args, **kwargs):
        raise StateError('synthetic cancellation storage failure')
    monkeypatch.setattr(manager.store, 'request_cancel', fail)
    try:
        with pytest.raises(StateError):
            manager.cancel(job.id, actor='runner')
        assert process.poll() is not None
        assert marker.read_text() == 'cleaned'
    finally:
        manager.shutdown()
        if process.poll() is None:
            process.kill()
            process.wait()
