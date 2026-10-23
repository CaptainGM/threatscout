"""Sonuçları başka araçların okuyabileceği biçimlere çevirir: STIX 2.1, MISP ve CSV.

Girdi olarak EnrichmentReport.to_dict() çıktısı (veya geçmişten gelen aynı yapı) kullanılır.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone
from typing import Any

# STIX 2.1 kalıbında IOC türüne karşılık gelen nesne yolu
STIX_PATHS = {
    "ip": "ipv4-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "email": "email-addr:value",
}

# Hash uzunluğuna göre (karakter sayısı): STIX yolu ve MISP türü
HASH_FORMS = {
    32: ("file:hashes.'MD5'", "md5"),
    40: ("file:hashes.'SHA-1'", "sha1"),
    64: ("file:hashes.'SHA-256'", "sha256"),
}

# MISP öznitelik türleri (ağ tabanlı olanlar)
MISP_TYPES = {"ip": "ip-dst", "domain": "domain", "url": "url", "email": "email-src"}

# STIX indicator_types sözlüğü: risk seviyesine göre
STIX_INDICATOR_TYPES = {
    "CRITICAL": "malicious-activity",
    "HIGH": "malicious-activity",
    "MEDIUM": "anomalous-activity",
    "LOW": "anomalous-activity",
    "CLEAN": "benign",
    "UNKNOWN": "unknown",
}

# MISP threat_level_id: 1 yüksek, 2 orta, 3 düşük, 4 belirsiz
MISP_THREAT_LEVELS = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4, "UNKNOWN": 4}


def _escape(value: str) -> str:
    # STIX kalıbında ters eğik çizgi ve tek tırnak kaçırılmalı
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_pattern(ioc: str, ioc_type: str) -> str | None:
    if ioc_type == "hash":
        form = HASH_FORMS.get(len(ioc))
        return f"[{form[0]} = '{_escape(ioc)}']" if form else None
    path = STIX_PATHS.get(ioc_type)
    return f"[{path} = '{_escape(ioc)}']" if path else None


def stix_bundle(report: dict[str, Any]) -> dict[str, Any]:
    """Tek bir göstergeyi (indicator) içeren STIX 2.1 paketi üretir."""
    now = _utc_now()
    objects = []
    pattern = stix_pattern(report["ioc"], report["ioc_type"])
    if pattern:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            # Aynı değer her seferinde aynı kimliği alır, böylece tekrar içe aktarmada çoğalmaz
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, report['ioc_type'] + ':' + report['ioc'])}",
            "created": now,
            "modified": now,
            "name": report["ioc"],
            "description": (
                f"ThreatScout risk puanı {report['threat_score']} "
                f"({report['risk_level']}). Kaynak sayısı ve ayrıntılar taramada kayıtlı."
            ),
            "indicator_types": [STIX_INDICATOR_TYPES.get(report["risk_level"], "unknown")],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(round(float(report["threat_score"]))),
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def misp_event(report: dict[str, Any]) -> dict[str, Any]:
    """MISP'in JSON olay biçimi: tek bir öznitelik içerir."""
    attributes = []
    ioc_type = report["ioc_type"]
    attr_type = MISP_TYPES.get(ioc_type)
    category = "Network activity"
    if ioc_type == "hash":
        form = HASH_FORMS.get(len(report["ioc"]))
        attr_type = form[1] if form else None
        category = "Payload delivery"
    if attr_type:
        attributes.append({
            "type": attr_type,
            "category": category,
            "value": report["ioc"],
            "to_ids": float(report["threat_score"]) >= 60,
            "comment": f"ThreatScout: {report['risk_level']} ({report['threat_score']})",
        })
    return {
        "Event": {
            "info": f"ThreatScout taraması: {report['ioc']}",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "distribution": 0,
            "threat_level_id": MISP_THREAT_LEVELS.get(report["risk_level"], 4),
            "analysis": 2,
            "Attribute": attributes,
        }
    }


def history_csv(rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "deger", "tur", "puan", "risk", "tarih"])
    for row in rows:
        writer.writerow([
            row["id"],
            row["ioc"],
            row["ioc_type"],
            row["threat_score"],
            row["risk_level"],
            row["created_at"],
        ])
    return buffer.getvalue()
