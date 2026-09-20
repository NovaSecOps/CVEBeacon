from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from cvebeacon.engine import QueryEngine
from cvebeacon.errors import SourceError
from cvebeacon.config import ProductMapping
from cvebeacon.models import Applicability, Asset, QueryResult
from cvebeacon.sources.nvd import CPECandidate


def test_scan_deduplicates_identical_targets():
    engine = object.__new__(QueryEngine)
    calls = []
    def query(asset):
        calls.append(asset.target_key)
        return QueryResult(asset, (), (), Applicability.COVERAGE_UNKNOWN, "test")
    engine.query_asset = query
    assets = [Asset("a1", "Acme", "Widget", "1"), Asset("a2", "Acme", "Widget", "1")]
    results = engine.scan(assets)
    assert len(calls) == 1
    assert [x.asset.asset_id for x in results] == ["a1", "a2"]


def test_source_failure_cannot_become_clean():
    engine = object.__new__(QueryEngine)
    engine.config = SimpleNamespace(sources=SimpleNamespace(
        nvd_enabled=True, euvd_enabled=True, cve_enabled=False,
        cisa_kev_enabled=False, eu_kev_enabled=False, epss_enabled=False,
    ))
    engine._resolve_cpe = lambda asset: (_ for _ in ()).throw(SourceError("nvd", "offline"))
    engine.euvd = SimpleNamespace(search=lambda vendor, product: [])
    result = engine.query_asset(Asset("a1", "Acme", "Widget", "1"))
    assert result.coverage == Applicability.COVERAGE_UNKNOWN
    assert any(item.source == "nvd" and item.status.value == "failed" for item in result.source_health)


def test_cpe_resolution_supports_hardware_and_deduplicates_versions():
    engine = object.__new__(QueryEngine)
    engine.config = SimpleNamespace(product_mappings=())
    engine.nvd = SimpleNamespace(resolve_cpes=lambda asset: [
        CPECandidate("cpe:2.3:h:acme:device:1:*:*:*:*:*:*:*", "", "h", "acme", "device"),
        CPECandidate("cpe:2.3:h:acme:device:2:*:*:*:*:*:*:*", "", "h", "acme", "device"),
    ])
    cpe, reason = engine._resolve_cpe(Asset("a", "Acme", "Device", "3"))
    assert cpe.startswith("cpe:2.3:h:acme:device:3:")
    assert "unique" in reason


def test_cross_part_cpe_ambiguity_requires_mapping():
    engine = object.__new__(QueryEngine)
    engine.config = SimpleNamespace(product_mappings=())
    engine.nvd = SimpleNamespace(resolve_cpes=lambda asset: [
        CPECandidate("cpe:2.3:a:acme:device:*:*:*:*:*:*:*:*", "", "a", "acme", "device"),
        CPECandidate("cpe:2.3:o:acme:device:*:*:*:*:*:*:*:*", "", "o", "acme", "device"),
    ])
    cpe, reason = engine._resolve_cpe(Asset("a", "Acme", "Device", "3"))
    assert cpe is None and "multiple" in reason
