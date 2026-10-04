"""Independent adversarial cases for notification event preservation and scheduling."""
from contextlib import closing
from dataclasses import replace
from pathlib import Path
import sqlite3

import pytest

from cvebeacon_automation.common import AutomationError
from cvebeacon_automation.http import Response, TransportError
from cvebeacon_automation.notifications import service
from cvebeacon_automation.notifications.ledger import ledger
from test_automation_notifications import Clock, Wire, channel, config, core, dispatch, secrets


@pytest.fixture(autouse=True)
def exact_audit_source():
    assert Path(service.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1] / 'src')


def change_delivery_primary_key(cfg):
    with ledger(cfg):
        pass
    filename = cfg.state_dir / 'notification-ledger.sqlite3'
    with closing(sqlite3.connect(filename)) as db:
        sql = db.execute("SELECT sql FROM sqlite_master WHERE name='deliveries'").fetchone()[0]
        assert 'PRIMARY KEY(event_key,channel,destination,part)' in sql
        db.execute('DROP INDEX due_deliveries')
        db.execute('DROP TABLE deliveries')
        db.execute(sql.replace('PRIMARY KEY(event_key,channel,destination,part)', 'PRIMARY KEY(channel,destination,part)'))
        db.execute('CREATE INDEX due_deliveries ON deliveries(channel,destination,state,next_retry,updated_at)')
        db.commit()
    return filename


def test_changed_ledger_primary_key_rejected_before_cursor_or_network(tmp_path, secrets):
    cfg, clock, wire = config(tmp_path, ('slack',)), Clock(), Wire()
    filename = core(tmp_path, count=2)
    path = change_delivery_primary_key(cfg)
    before = path.read_bytes()
    with pytest.raises(AutomationError, match='unsupported_notification_ledger'):
        dispatch(cfg, filename, wire, clock)
    assert not wire.calls and path.read_bytes() == before


@pytest.mark.parametrize('provider', ['telegram', 'matrix'])
def test_slow_first_provider_cannot_starve_later_providers(tmp_path, secrets, monkeypatch, provider):
    elapsed = [0.0]
    monkeypatch.setattr(service.time, 'monotonic', lambda: elapsed[0])
    cfg = config(tmp_path, (provider, 'discord', 'slack'))
    cfg = replace(cfg, notifications=tuple({**c, 'timeout_seconds': 30} for c in cfg.notifications))
    clock, filename = Clock(), core(tmp_path)

    class SlowFirst(Wire):
        def factory(self, url, **bounds):
            self.current_timeout = bounds['timeout']
            return super().factory(url, **bounds)

        def request(self, method, url, **kwargs):
            if ('telegram.org' in url if provider == 'telegram' else 'matrix.example.invalid' in url):
                self.calls.append((method, url, kwargs.get('headers', {}), kwargs.get('body', b'')))
                elapsed[0] += self.current_timeout
                clock.value += self.current_timeout
                raise TransportError('synthetic_timeout', False)
            return super().request(method, url, **kwargs)

    wire = SlowFirst()
    result = dispatch(cfg, filename, wire, clock)
    assert result['channels']['discord']['states']['accepted'] == 1
    assert result['channels']['slack']['states']['accepted'] == 1
    assert elapsed[0] <= service.RUN_BUDGET_SECONDS


def test_matrix_check_and_send_share_one_timeout_budget(tmp_path, secrets, monkeypatch):
    elapsed = [0.0]
    monkeypatch.setattr(service.time, 'monotonic', lambda: elapsed[0])
    from cvebeacon_automation.notifications.adapters import bind, validate_channels
    bound = bind(validate_channels((channel('matrix', timeout_seconds=10),), tmp_path)[0])
    budgets = []

    class SlowMatrix(Wire):
        def factory(self, url, **bounds):
            self.timeout = bounds['timeout']
            budgets.append(self.timeout)
            return self

        def request(self, method, url, **kwargs):
            # Each HTTPS request currently receives a new deadline.
            if method == 'GET':
                elapsed[0] += 8
                return super().request(method, url, **kwargs)
            elapsed[0] += self.timeout
            raise TransportError('synthetic_timeout', True)

    wire = SlowMatrix()
    outcome = bound.send('synthetic alert', 'fixed-transaction', transport_factory=wire.factory, timeout=10)
    assert outcome.state == 'retryable'
    assert elapsed[0] <= 10

@pytest.mark.parametrize('change', ['default', 'check', 'index_unique', 'index_columns'])
def test_changed_ledger_defaults_constraints_and_indexes_rejected(tmp_path, change):
    cfg = config(tmp_path)
    with ledger(cfg):
        pass
    path = cfg.state_dir / 'notification-ledger.sqlite3'
    with closing(sqlite3.connect(path)) as db:
        if change in {'default', 'check'}:
            sql = db.execute("SELECT sql FROM sqlite_master WHERE name='deliveries'").fetchone()[0]
            if change == 'default':
                sql = sql.replace('attempts INTEGER NOT NULL DEFAULT 0', 'attempts INTEGER NOT NULL DEFAULT 99')
            else:
                sql = sql.replace("CHECK(purpose IN ('event','operational','test'))", "CHECK(purpose IN ('event','operational','test','other'))")
            db.execute('DROP INDEX due_deliveries')
            db.execute('DROP TABLE deliveries')
            db.execute(sql)
            db.execute('CREATE INDEX due_deliveries ON deliveries(channel,destination,state,next_retry,updated_at)')
        else:
            db.execute('DROP INDEX due_deliveries')
            db.execute('CREATE ' + ('UNIQUE ' if change == 'index_unique' else '') + 'INDEX due_deliveries ON deliveries(' + ('channel' if change == 'index_columns' else 'channel,destination,state,next_retry,updated_at') + ')')
        db.commit()
    before = path.read_bytes()
    with pytest.raises(AutomationError, match='unsupported_notification_ledger'):
        with ledger(cfg):
            pytest.fail('altered ledger schema was accepted')
    assert path.read_bytes() == before
