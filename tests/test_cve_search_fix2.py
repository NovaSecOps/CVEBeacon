"""Preserve the original FTS5 search behavior without copying legacy text."""
import sqlite3

import pytest

from cvebeacon.watch.records import WatchRecord
from cvebeacon.watch.store import WatchStore
from test_cve_explorer import official
from test_cve_fix1 import schema_seven

ID = 'CVE-2026-10001'


@pytest.mark.parametrize('migrate',[False,True])
@pytest.mark.parametrize('query,expected', [('Spring execution',1), ('execution spr',1), ('ring',0), ('cafe',1), ('foo_bar',1), ('absent',0)])
def test_legacy_nvd_search_preserves_fts_tokens(tmp_path,query,expected,migrate):
    path=tmp_path/'watch.db'
    schema_seven(path)
    with sqlite3.connect(path) as db:
        db.execute('UPDATE watch_cve SET description=?',('Spring Framework remote code execution café foo_bar',))
    store=WatchStore(path)
    if migrate:
        store.initialize()
    assert store.search(query=query).total == expected
    assert store.metadata()['schema_version'] == ('11' if migrate else '7')


def test_search_terms_can_span_enabled_providers(tmp_path):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published',description='Spring Framework')])
    store.upsert_cve_list([official(description='remote execution')])
    assert store.search(query='Spring execution').total == 1
    assert store.search(query='Spring execution',catalogs=('nvd',)).total == 0


@pytest.mark.parametrize('text,query',[('foo bar','foo_bar'),('cafe','café'),('foo barista','foo_bar'),('CAFÉ noir','cafe')])
def test_nvd_search_uses_exact_sqlite_tokenization(tmp_path,text,query):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published',description=text)])
    assert store.search(query=query).total==1
