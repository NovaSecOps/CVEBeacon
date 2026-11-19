"""Pre-release recovery and compatibility with existing read/CLI entry points."""
import json
import sqlite3

import pytest

from cvebeacon.errors import StateError
from cvebeacon.watch.records import WatchRecord
from cvebeacon.watch.store import WatchStore
from test_cve_explorer import official
from test_cve_fix1 import schema_seven
from watch_support import NOW, write_config

ID = 'CVE-2026-10001'


def prerelease_eight(path, *, corrupt=False):
    from cvebeacon.watch.store import _nvd_content
    store=WatchStore(path)
    record=WatchRecord(ID,'rejected',description='original NVD')
    store.upsert_nvd([record])
    store.upsert_cve_list([official(description='CNA text')])
    with sqlite3.connect(path) as db:
        db.execute("UPDATE watch_meta SET value='8' WHERE key='schema_version'")
        db.execute("DELETE FROM watch_meta WHERE key='provider_storage'")
        for name in ('insert','delete','update'):
            db.execute('DROP TRIGGER IF EXISTS watch_search_'+name)
        db.execute('DROP TABLE watch_fts')
        db.execute('DROP TABLE watch_search')
        db.execute('CREATE TABLE watch_search(cve_id TEXT PRIMARY KEY,text TEXT NOT NULL)')
        db.execute('INSERT INTO watch_search VALUES (?,?)',(ID,'mixed old preview'))
        content=json.dumps(_nvd_content(record))
        db.execute("INSERT INTO watch_provider VALUES (?,'nvd',?,?,?,?)",(ID,'not-json' if corrupt else content,content,record.last_modified,NOW.isoformat()))
        db.execute("UPDATE watch_cve SET status='published',description='mixed old preview'")
    return store


def test_prerelease_eight_restores_nvd_and_rebuilds_provider_search(tmp_path):
    store=prerelease_eight(tmp_path/'watch.db')
    store.initialize()
    assert store.view(ID).status=='rejected'
    assert store.view(ID).description=='original NVD'
    assert store.search(query='CNA text').total==1
    with store.read() as db:
        assert db.execute("SELECT count(*) FROM watch_provider WHERE source='nvd'").fetchone()[0]==0
    assert store.metadata()['provider_storage']=='sparse-v1'


def test_prerelease_corruption_names_cve_and_rolls_back(tmp_path):
    store=prerelease_eight(tmp_path/'watch.db',corrupt=True)
    with pytest.raises(StateError,match=ID):
        store.initialize()
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM watch_provider WHERE source='nvd'").fetchone()[0]==1
        assert db.execute('SELECT description FROM watch_cve').fetchone()[0]=='mixed old preview'
        assert db.execute("SELECT value FROM watch_meta WHERE key='provider_storage'").fetchone() is None


def test_schema_seven_dashboard_browse_does_not_migrate(tmp_path):
    from cvebeacon import dashboard
    config=write_config(tmp_path,sources=('nvd',))
    schema_seven(config.watch.database)
    app=dashboard.create_app(config)
    try:
        client=app.test_client()
        assert client.get('/watch/cves?q=retained').status_code==200
        assert client.get('/watch/cve/'+ID).status_code==200
        with sqlite3.connect(config.watch.database) as db:
            assert db.execute("SELECT value FROM watch_meta WHERE key='schema_version'").fetchone()[0]=='7'
    finally:
        app.extensions['dashboard_jobs'].shutdown()


@pytest.mark.parametrize('command',['sync','run'])
def test_cli_forwards_confirmed_provider_initial_choice(tmp_path,monkeypatch,command):
    from cvebeacon import cli
    from cvebeacon.watch.sync import SyncReport
    config=write_config(tmp_path,sources=('nvd','cve_list'))
    observed=[]
    def sync(config,http,**kwargs):
        observed.append(kwargs)
        return SyncReport()
    monkeypatch.setattr('cvebeacon.watch.sync.sync_watch',sync)
    assert cli.main(['--config',str(config.config_path),'watch',command,'--cve-list-initial','full','--yes']) in (0,4)
    assert observed[0]['cve_list_initial']=='full'
    assert observed[0]['assume_yes']


def test_read_snapshot_precedes_schema_inspection(tmp_path,monkeypatch):
    path=tmp_path/'watch.db'
    schema_seven(path)
    store=WatchStore(path)
    class SnapshotGuard(sqlite3.Connection):
        def execute(self,sql,*args,**kwargs):
            if 'FROM sqlite_master' in sql:
                assert self.in_transaction, 'schema inspected before pinning snapshot'
            return super().execute(sql,*args,**kwargs)
    monkeypatch.setattr(store,'_connect_readonly',lambda:sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,factory=SnapshotGuard))
    assert store.view(ID).description=='retained'
