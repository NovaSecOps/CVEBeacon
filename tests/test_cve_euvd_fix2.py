"""Freshness and alias removal when global EUVD follows targeted refresh."""
import pytest

from cvebeacon.watch.records import CVSSEntry, EUVDUpdate, WatchRecord
from cvebeacon.watch.store import WatchStore

ID = 'CVE-2026-10001'
OTHER = 'CVE-2026-10002'


def update(aliases,date,score):
    return EUVDUpdate(tuple(aliases),'EUVD-1',None,CVSSEntry('euvd','euvd','3.1',score),date)


@pytest.mark.parametrize('global_date', ['2026-11-01','2026-11-10'])
def test_global_euvd_cannot_drop_newer_targeted_observation(tmp_path,global_date):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published')])
    store.replace_euvd_items([update([ID],'2026-11-01',4.0)])
    store.upsert_euvd_cve(ID,[update([ID],'2026-11-19',9.8)])
    store.replace_euvd_items([update([ID],global_date,4.0)])
    assert store.view(ID,catalogs=('euvd',)).cvss[0].score == 9.8


def test_newer_global_alias_removal_reconciles_targeted_evidence(tmp_path):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published'),WatchRecord(OTHER,'published')])
    store.replace_euvd_items([update([ID,OTHER],'2026-11-01',4.0)])
    store.upsert_euvd_cve(ID,[update([ID,OTHER],'2026-11-19',9.8)])
    store.replace_euvd_items([update([OTHER],'2026-11-20',4.0)])
    assert not store.view(ID,catalogs=('euvd',)).cvss
    assert ID in store.pending_evaluations()


def test_unversioned_global_change_cannot_clear_targeted_evidence(tmp_path):
    store=WatchStore(tmp_path/'watch.db')
    store.upsert_nvd([WatchRecord(ID,'published')])
    store.replace_euvd_items([update([ID],None,4.0)])
    store.upsert_euvd_cve(ID,[update([ID],None,9.8)])
    store.replace_euvd_items([update([ID,OTHER],None,4.0)])
    assert store.view(ID,catalogs=('euvd',)).cvss[0].score==9.8
