import pytest
from fastapi.testclient import TestClient

from threatscout import api
from threatscout.models import RiskLevel
from threatscout.providers import BaseProvider


class FakeVirusTotal(BaseProvider):
    # Ağ çağrısı yapmayan sahte VirusTotal: 5 motor zararlı, toplam 70
    name = "virustotal"

    def __init__(self):
        super().__init__("anahtar")

    async def analyze_ip(self, ip):
        return {"ok": True}

    async def analyze_domain(self, domain):
        return {"ok": True}

    async def analyze_url(self, url):
        return {"ok": True}

    async def analyze_hash(self, file_hash):
        return {"ok": True}

    def normalize(self, raw, ioc_type):
        return {"malicious": 5, "total_engines": 70}


class FailingShodan(BaseProvider):
    # Her zaman hata veren sahte Shodan
    name = "shodan"

    def __init__(self):
        super().__init__("anahtar")

    async def analyze_ip(self, ip):
        raise RuntimeError("zaman aşımı")

    async def analyze_domain(self, domain):
        raise RuntimeError("zaman aşımı")

    async def analyze_url(self, url):
        raise RuntimeError("zaman aşımı")

    async def analyze_hash(self, file_hash):
        raise RuntimeError("zaman aşımı")

    def normalize(self, raw, ioc_type):
        return {}


async def test_stream_gives_each_provider_then_the_report(make_engine):
    engine = make_engine(providers=[FakeVirusTotal(), FailingShodan()])
    events = [
        event
        async for event in engine.enrich_stream("8.8.8.8", use_cache=False, persist=False, notify=False)
    ]
    kinds = [kind for kind, _ in events]
    assert kinds.count("provider") == 2
    assert kinds[-1] == "report"

    report = events[-1][1]
    # Rapordaki sıra, kaynakların tanımlandığı sıradır (cevap sırası değil)
    assert [p.provider for p in report.providers] == ["virustotal", "shodan"]
    # Sahte VirusTotal 5 motor işaretledi: 5 * 3 = 15 puan
    assert report.threat_score == pytest.approx(15.0)
    assert report.risk_level == RiskLevel.LOW


async def test_enrich_returns_the_same_report_as_the_stream(make_engine):
    engine = make_engine(providers=[FakeVirusTotal(), FailingShodan()])
    report = await engine.enrich("8.8.8.8", use_cache=False, persist=False, notify=False)
    assert report.risk_level == RiskLevel.LOW
    assert len(report.providers) == 2


async def test_stream_for_unknown_input_is_unknown(make_engine):
    engine = make_engine(providers=[FakeVirusTotal()])
    events = [event async for event in engine.enrich_stream("bu bir ioc değil", persist=False)]
    assert events == [("report", events[0][1])]
    assert events[0][1].risk_level == RiskLevel.UNKNOWN


def test_scan_stream_sends_provider_and_report_events(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine(providers=[FakeVirusTotal()]))
    client = TestClient(api.app)
    response = client.post("/scan/stream", data={"ioc": "8.8.8.8"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "event: provider" in response.text
    assert "VirusTotal" in response.text
    assert "event: report" in response.text


def test_scan_stream_rejects_invalid_input(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine(providers=[FakeVirusTotal()]))
    client = TestClient(api.app)
    response = client.post("/scan/stream", data={"ioc": "bu bir ioc değil"})
    assert response.status_code == 400
    assert "Gecersiz IOC" in response.text
