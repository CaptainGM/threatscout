"""İzleme listesi: seçilen değerler belli aralıklarla yeniden taranır.

Puan belirgin biçimde değişirse ya da risk seviyesi değişirse, ayarlarda tanımlı
webhook'lara haber gönderilir.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from threatscout.models import IOCType
from threatscout.webhooks import dispatch_webhook

log = logging.getLogger("threatscout.watch")

# Bu kadar puan oynarsa (ya da risk seviyesi değişirse) haber verilir
SCORE_CHANGE_LIMIT = 10.0

RISK_LABELS = {
    "CRITICAL": "Kritik",
    "HIGH": "Yüksek",
    "MEDIUM": "Orta",
    "LOW": "Düşük",
    "CLEAN": "Temiz",
    "UNKNOWN": "Yetersiz veri",
}


def is_due(item: dict[str, Any], now: datetime) -> bool:
    if not item.get("last_checked"):
        return True
    last = datetime.fromisoformat(item["last_checked"])
    return now - last >= timedelta(hours=int(item["interval_hours"]))


def changed(item: dict[str, Any], new_score: float, new_risk: str) -> bool:
    # İlk kontrolde karşılaştıracak eski bir sonuç yoktur
    if not item.get("last_risk"):
        return False
    old_score = float(item.get("last_score") or 0)
    return new_risk != item["last_risk"] or abs(new_score - old_score) >= SCORE_CHANGE_LIMIT


async def notify_change(engine, change: dict[str, Any]) -> None:
    hooks = await asyncio.to_thread(engine.store.enabled_webhooks)
    for hook in hooks:
        try:
            await dispatch_webhook(
                hook["kind"], hook["url"], hook["token"], {"event": "watch_change", **change}
            )
        except Exception as exc:  # Bir alıcının hatası diğerlerini durdurmasın
            log.warning("izleme bildirimi gönderilemedi: %s", exc)


async def check_item(engine, item: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    report = await engine.enrich(
        item["ioc"],
        ioc_type=IOCType(item["ioc_type"]),
        use_cache=False,
        persist=True,
        notify=False,
    )
    change = None
    if changed(item, report.threat_score, report.risk_level.value):
        change = {
            "ioc": item["ioc"],
            "old_risk": item["last_risk"],
            "new_risk": report.risk_level.value,
            "old_score": item["last_score"],
            "new_score": report.threat_score,
            "scan_id": report.id,
        }
        await notify_change(engine, change)
    engine.store.update_watch(item["id"], report.threat_score, report.risk_level.value, now.isoformat())
    return change


async def run_due(engine, now: datetime | None = None) -> list[dict[str, Any]]:
    # Süresi gelmiş tüm değerleri sırayla tarar (API limitlerini zorlamamak için tek tek)
    now = now or datetime.now(timezone.utc)
    changes = []
    for item in await asyncio.to_thread(engine.store.list_watch):
        if item["enabled"] and is_due(item, now):
            change = await check_item(engine, item, now)
            if change:
                changes.append(change)
    return changes


async def watch_loop(engine, every_seconds: int = 900) -> None:
    while True:
        try:
            await run_due(engine)
        except Exception as exc:
            log.warning("izleme döngüsünde hata: %s", exc)
        await asyncio.sleep(every_seconds)


def watch_view(item: dict[str, Any]) -> dict[str, Any]:
    checked = item.get("last_checked")
    return {
        "id": item["id"],
        "ioc": item["ioc"],
        "ioc_type": str(item["ioc_type"]).upper(),
        "interval_hours": item["interval_hours"],
        "score": item.get("last_score"),
        "risk": item.get("last_risk"),
        "risk_label": RISK_LABELS.get(item.get("last_risk") or "", "Henüz taranmadı"),
        "checked": datetime.fromisoformat(checked).strftime("%Y-%m-%d %H:%M") if checked else "—",
    }
