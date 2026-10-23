from fastapi.testclient import TestClient

from threatscout import api
from threatscout.models import EnrichmentReport, IOCType, ProviderResult, RiskLevel


def test_scan_without_sources_shows_unknown(make_engine, monkeypatch):
    # Hic kaynak yokken sonuc TEMIZ degil, YETERSIZ VERI olmali
    monkeypatch.setattr(api, "engine", make_engine())
    client = TestClient(api.app)
    response = client.post("/scan", data={"ioc": "8.8.8.8"})
    assert response.status_code == 200
    assert "YETERSİZ VERİ" in response.text


def test_invalid_scan_shows_error(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    client = TestClient(api.app)
    response = client.post("/scan", data={"ioc": "bu bir ioc degil"})
    assert response.status_code == 400
    assert "Gecersiz IOC" in response.text


def test_history_pages_show_unknown_scan(make_engine, monkeypatch):
    engine = make_engine()
    scan_id = engine.store.save_scan(
        EnrichmentReport(
            ioc="user@example.com",
            ioc_type=IOCType.EMAIL,
            risk_level=RiskLevel.UNKNOWN,
        )
    )
    monkeypatch.setattr(api, "engine", engine)
    client = TestClient(api.app)
    assert client.get("/history").status_code == 200
    detail = client.get(f"/history/{scan_id}")
    assert detail.status_code == 200
    assert "YETERSİZ VERİ" in detail.text


def test_detail_column_shows_provider_data(make_engine, monkeypatch):
    # Detay sutunu eskiden hep "—" gosteriyordu, artik VirusTotal sayilarini gostermeli
    engine = make_engine()
    scan_id = engine.store.save_scan(
        EnrichmentReport(
            ioc="8.8.8.8",
            ioc_type=IOCType.IP,
            threat_score=5,
            risk_level=RiskLevel.LOW,
            providers=[
                ProviderResult(
                    provider="virustotal",
                    success=True,
                    normalized={"malicious": 3, "total_engines": 70},
                )
            ],
        )
    )
    monkeypatch.setattr(api, "engine", engine)
    client = TestClient(api.app)
    detail = client.get(f"/history/{scan_id}")
    assert "3 / 70 motor zararlı dedi" in detail.text
