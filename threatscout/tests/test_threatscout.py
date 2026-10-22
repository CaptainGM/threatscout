import pytest
from fastapi.testclient import TestClient

from threatscout.config import Settings
from threatscout.db import Store
from threatscout.engine import RiskScorer, SQLiteCache, ThreatScoutEngine
from threatscout.models import EnrichmentReport, IOCType, ProviderResult, detect_ioc_type
from threatscout.providers import BaseProvider


class MockProvider(BaseProvider):
    name = "virustotal"

    async def analyze_ip(self, ip):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 65}}}}

    async def analyze_domain(self, d):
        return await self.analyze_ip(d)

    async def analyze_url(self, u):
        return await self.analyze_ip(u)

    async def analyze_hash(self, h):
        return await self.analyze_ip(h)

    def normalize(self, raw, ioc_type):
        stats = raw["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": stats["malicious"], "total_engines": sum(stats.values())}


@pytest.fixture
def engine(tmp_path):
    cache = SQLiteCache(str(tmp_path / "cache.db"))
    store = Store(str(tmp_path / "app.db"))
    return ThreatScoutEngine(
        settings=Settings(virustotal_api_key="x", sqlite_path=str(tmp_path / "app.db")),
        providers=[MockProvider("x")],
        cache=cache,
        store=store,
    )


@pytest.mark.asyncio
async def test_enrich(engine):
    report = await engine.enrich("8.8.8.8", ioc_type=IOCType.IP)
    assert report.providers[0].success
    assert report.threat_score > 0
    assert report.id is not None
    await engine.close()


@pytest.mark.asyncio
async def test_cache(engine):
    await engine.enrich("1.1.1.1", ioc_type=IOCType.IP)
    r2 = await engine.enrich("1.1.1.1", ioc_type=IOCType.IP)
    assert r2.providers[0].cached
    await engine.close()


def test_ioc_detection():
    assert detect_ioc_type("8.8.8.8") == IOCType.IP
    assert detect_ioc_type("evil.com") == IOCType.DOMAIN
    assert detect_ioc_type("a" * 64) == IOCType.HASH
    assert detect_ioc_type("user@evil.com") == IOCType.EMAIL


def test_risk_scorer():
    scorer = RiskScorer()
    report = EnrichmentReport(
        ioc="x",
        ioc_type=IOCType.IP,
        providers=[
            ProviderResult(
                provider="virustotal",
                success=True,
                normalized={"malicious": 35, "total_engines": 70},
            )
        ],
    )
    result = scorer.enrich_report(report)
    assert result.threat_score == 50.0


def test_greynoise_score():
    scorer = RiskScorer()
    report = EnrichmentReport(
        ioc="1.2.3.4",
        ioc_type=IOCType.IP,
        providers=[
            ProviderResult(
                provider="greynoise",
                success=True,
                normalized={"classification": "malicious", "noise": True},
            )
        ],
    )
    result = scorer.enrich_report(report)
    assert result.threat_score == 90.0


def test_api_keys_and_history(tmp_path):
    store = Store(str(tmp_path / "app.db"))
    raw = store.create_api_key("test")
    assert raw.startswith("ts_")
    assert store.valid_api_key(raw)
    assert not store.valid_api_key("wrong")
    report = EnrichmentReport(ioc="8.8.8.8", ioc_type=IOCType.IP, threat_score=1)
    scan_id = store.save_scan(report)
    assert store.get_scan(scan_id)["ioc"] == "8.8.8.8"


def test_health_open():
    from threatscout.api import app
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"
        assert client.get("/api/v1/history").status_code == 401
        assert client.get("/").status_code == 200
