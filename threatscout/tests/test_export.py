from fastapi.testclient import TestClient

from threatscout import api
from threatscout.export import history_csv, misp_event, stix_bundle, stix_pattern
from threatscout.models import EnrichmentReport, IOCType, RiskLevel


def sample(ioc="8.8.8.8", ioc_type="ip", score=0.0, risk="CLEAN"):
    return {
        "id": 7,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "threat_score": score,
        "risk_level": risk,
        "created_at": "2026-10-22T10:00:00+00:00",
    }


def test_stix_bundle_has_one_indicator():
    bundle = stix_bundle(sample())
    assert bundle["type"] == "bundle"
    indicator = bundle["objects"][0]
    assert indicator["type"] == "indicator"
    assert indicator["spec_version"] == "2.1"
    assert indicator["pattern"] == "[ipv4-addr:value = '8.8.8.8']"
    assert indicator["indicator_types"] == ["benign"]


def test_stix_patterns_for_hash_and_url():
    assert stix_pattern("44d88612fea8a8f36de82e1278abb02f", "hash") == (
        "[file:hashes.'MD5' = '44d88612fea8a8f36de82e1278abb02f']"
    )
    assert stix_pattern("https://example.com/a'b", "url") == "[url:value = 'https://example.com/a\\'b']"


def test_stix_is_empty_for_unknown_type():
    assert stix_bundle(sample(ioc="bu bir ioc", ioc_type="unknown"))["objects"] == []


def test_stix_indicator_id_is_the_same_every_time():
    first = stix_bundle(sample())["objects"][0]["id"]
    second = stix_bundle(sample())["objects"][0]["id"]
    assert first == second


def test_misp_event_marks_high_scores_for_ids():
    event = misp_event(sample(ioc="evil.example", ioc_type="domain", score=90, risk="CRITICAL"))["Event"]
    attribute = event["Attribute"][0]
    assert attribute["type"] == "domain"
    assert attribute["to_ids"] is True
    assert event["threat_level_id"] == 1


def test_history_csv_has_header_and_row():
    text = history_csv([
        {"id": 1, "ioc": "8.8.8.8", "ioc_type": "ip", "threat_score": 0, "risk_level": "CLEAN", "created_at": "2026-10-22"}
    ])
    lines = text.strip().splitlines()
    assert lines[0] == "id,deger,tur,puan,risk,tarih"
    assert lines[1].startswith("1,8.8.8.8,ip,0,CLEAN")


def test_export_routes_need_the_api_key(make_engine, monkeypatch):
    engine = make_engine()
    scan_id = engine.store.save_scan(
        EnrichmentReport(ioc="8.8.8.8", ioc_type=IOCType.IP, threat_score=0, risk_level=RiskLevel.CLEAN)
    )
    monkeypatch.setattr(api, "engine", engine)
    monkeypatch.setattr(api.settings, "app_api_key", "test-key")
    client = TestClient(api.app)

    assert client.get(f"/api/v1/history/{scan_id}/stix").status_code == 401
    stix = client.get(f"/api/v1/history/{scan_id}/stix", headers={"X-API-Key": "test-key"})
    assert stix.status_code == 200
    assert stix.json()["type"] == "bundle"

    csv_response = client.get("/api/v1/history.csv", headers={"X-API-Key": "test-key"})
    assert csv_response.status_code == 200
    assert "8.8.8.8" in csv_response.text
