"""Measure schema-7 upgrade time and disk growth using synthetic local data."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Event, Thread
from time import perf_counter

from cvebeacon.watch.store import WatchStore


def benchmark(rows=430_000):
    with tempfile.TemporaryDirectory(prefix='cve-migration-benchmark-') as temporary:
        path = Path(temporary) / 'watch.db'
        schema = Path(__file__).resolve().parents[1] / 'tests/fixtures/watch_schema_v7.sql'
        description = 'Synthetic description. ' + 'x' * 968
        metric = '[{"provider":"nvd","source":"nvd","version":"3.1","score":9.8}]'
        products = '[{"vendor":"example","product":"widget"}]'
        references = '[{"url":"https://example.com/advisory","tags":["Patch"]}]'
        with sqlite3.connect(path) as db:
            db.execute('PRAGMA journal_mode=OFF')
            db.executescript(schema.read_text())
            db.execute('ALTER TABLE watch_cve ADD COLUMN legacy_extra TEXT')
            for start in range(0, rows, 5000):
                db.executemany('INSERT INTO watch_cve(cve_id,status,published,last_modified,description,source_identifier,cvss_json,cwes_json,products_json,references_json,first_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                    ((f'CVE-2026-{index:07d}', 'published','2026-11-01','2026-11-02',description,'Example CNA',metric,'["CWE-79"]',products,references,'2026-11-01','2026-11-02') for index in range(start,min(rows,start+5000))))
                db.commit()
            for index in range(min(rows,5000)):
                identifier = f'CVE-2026-{index:07d}'
                euvd_id = f'EUVD-2026-{index}'
                db.execute('INSERT INTO watch_euvd_item VALUES (?,?,?,?,?,?,?,?,?)', (euvd_id,json.dumps([identifier]),'2026-11-02',7.5,'3.1',None,None,products,'2026-11-02'))
                db.execute('INSERT INTO watch_euvd_alias VALUES (?,?)', (identifier,euvd_id))
            db.commit()
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        def size():
            return sum(file.stat().st_size for file in path.parent.iterdir() if file.name.startswith('watch.db'))
        before = size()
        peak = [before]
        stop = Event()
        def sample():
            while not stop.wait(0.005):
                try:
                    peak[0] = max(peak[0],size())
                except FileNotFoundError:
                    pass
        sampler = Thread(target=sample,daemon=True)
        sampler.start()
        started = perf_counter()
        store = WatchStore(path)
        store.initialize()
        elapsed = perf_counter() - started
        peak[0] = max(peak[0],size())
        stop.set()
        sampler.join(timeout=2)
        with sqlite3.connect(path) as db:
            db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            counts = {name:db.execute(f'SELECT count(*) FROM {name}').fetchone()[0] for name in ('watch_cve','watch_euvd_item','watch_provider','watch_search')}
            assert counts['watch_cve'] == rows
            assert counts['watch_euvd_item'] == min(rows,5000)
            assert counts['watch_provider'] == counts['watch_search'] == 0
        after = size()
        assert after - before < 2 * 1024 * 1024
        return {'rows':rows,'before_mib':round(before/2**20,3),'after_mib':round(after/2**20,3),
                'growth_mib':round((after-before)/2**20,3),'peak_sampled_mib':round(peak[0]/2**20,3),
                'migration_seconds':round(elapsed,4),'table_rows':counts}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--rows',type=int,default=430_000)
    arguments = parser.parse_args()
    print(json.dumps(benchmark(arguments.rows),indent=2))
