from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from threatscout import api, watch
from threatscout.models import EnrichmentReport, IOCType, RiskLevel
from threatscout.report import panel_view


def make_item(**changes):
    item = {
        "id": 1,
        "ioc": "8.8.8.8",
        "ioc_type": "ip",
        "interval_hours": 24,
        "enabled": 1,
        "last_score": None,
        "last_risk": None,
        "last_checked": None,
    }
    item.update(changes)
    return item


def test_stats_counts_levels_and_recent_days(make_engine):
    store = make_engine().store
    store.save_scan(EnrichmentReport(ioc="1.1.1.1", ioc_type=IOCType.IP, threat_score=0, risk_level=RiskLevel.CLEAN))
    store.save_scan(
        EnrichmentReport(ioc="evil.example", ioc_type=IOCType.DOMAIN, threat_score=90, risk_level=RiskLevel.CRITICAL)
    )
    stats = store.stats(days=30)
    assert stats["total"] == 2
    assert stats["levels"] == {"CLEAN": 1, "CRITICAL": 1}
    assert sum(stats["daily"].values()) == 2
    assert stats["top"][0]["ioc"] == "evil.example"


def test_panel_view_has_thirty_bars(make_engine):
    view = panel_view(make_engine().store.stats(days=30))
    assert len(view["bars"]) == 30
    assert view["levels"][0]["code"] == "CRITICAL"
    assert view["total"] == 0


def test_new_item_is_due_and_checked_item_is_not():
    now = datetime.now(timezone.utc)
    assert watch.is_due(make_item(), now)
    assert not watch.is_due(make_item(last_checked=now.isoformat()), now)


def test_score_or_risk_change_is_detected():
    item = make_item(last_score=10, last_risk="LOW")
    assert watch.changed(item, 25, "LOW")
    assert watch.changed(item, 10, "MEDIUM")
    assert not watch.changed(item, 12, "LOW")
    assert not watch.changed(make_item(), 50, "HIGH")


async def test_run_due_reports_a_change(make_engine, monkeypatch):
    engine = make_engine()
    watch_id = engine.store.add_watch("8.8.8.8", "ip", 24)
    reports = [
        EnrichmentReport(ioc="8.8.8.8", ioc_type=IOCType.IP, threat_score=5, risk_level=RiskLevel.LOW),
        EnrichmentReport(ioc="8.8.8.8", ioc_type=IOCType.IP, threat_score=70, risk_level=RiskLevel.HIGH),
    ]

    async def fake_enrich(*args, **kwargs):
        return reports.pop(0)

    sent = []

    async def fake_notify(eng, change):
        sent.append(change)

    monkeypatch.setattr(engine, "enrich", fake_enrich)
    monkeypatch.setattr(watch, "notify_change", fake_notify)

    # İlk kontrol sonucu kaydeder, karşılaştıracak bir şey olmadığı için haber vermez
    assert await watch.run_due(engine) == []
    assert engine.store.get_watch(watch_id)["last_risk"] == "LOW"

    # 25 saat sonra tekrar kontrol: risk yükseldi, haber verilmeli
    long_ago = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    engine.store.update_watch(watch_id, 5, "LOW", long_ago)
    changes = await watch.run_due(engine)
    assert len(changes) == 1
    assert changes[0]["new_risk"] == "HIGH"
    assert sent == changes


def test_watchlist_add_show_and_delete(make_engine, monkeypatch):
    engine = make_engine()
    monkeypatch.setattr(api, "engine", engine)
    client = TestClient(api.app)

    added = client.post("/watchlist", data={"ioc": "8.8.8.8", "interval_hours": "6"}, follow_redirects=False)
    assert added.status_code == 303
    page = client.get("/watchlist")
    assert page.status_code == 200
    assert "8.8.8.8" in page.text

    item_id = engine.store.list_watch()[0]["id"]
    removed = client.post(f"/watchlist/{item_id}/delete", follow_redirects=False)
    assert removed.status_code == 303
    assert engine.store.list_watch() == []


def test_watchlist_rejects_invalid_value(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    client = TestClient(api.app)
    response = client.post(
        "/watchlist", data={"ioc": "bu bir ioc değil", "interval_hours": "24"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "error=" in response.headers["location"]


def test_panel_page_renders(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    client = TestClient(api.app)
    response = client.get("/panel")
    assert response.status_code == 200
    assert "Son 30 gün" in response.text
