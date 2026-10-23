from __future__ import annotations

import json
import math
from datetime import date, timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from threatscout.models import DISABLED_ERROR, EnrichmentReport, ProviderResult, RiskLevel

TEMPLATE_DIR = Path(__file__).parent / "templates"

RISK_COLORS = {
    RiskLevel.CRITICAL: "#dc2626",
    RiskLevel.HIGH: "#ea580c",
    RiskLevel.MEDIUM: "#ca8a04",
    RiskLevel.LOW: "#2563eb",
    RiskLevel.CLEAN: "#16a34a",
    RiskLevel.UNKNOWN: "#64748b",
}

SCORE_FIELDS = (
    "virustotal",
    "abuseipdb",
    "shodan",
    "otx",
    "greynoise",
    "urlhaus",
    "misp",
)

PROVIDER_TITLES = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "shodan": "Shodan",
    "otx": "AlienVault OTX",
    "greynoise": "GreyNoise",
    "urlhaus": "URLhaus",
    "misp": "MISP",
    "whois": "WHOIS / RDAP",
}

# Gösterge yarım çemberinin uzunluğu: yarıçap 80 için pi * 80
GAUGE_LENGTH = round(math.pi * 80, 2)

# İlişki grafiğinin merkezi, yarıçapı ve düğüm türleri (SVG koordinatları)
GRAPH_CENTER = (160.0, 135.0)
GRAPH_RADIUS = 95.0
GRAPH_KIND_LABELS = {
    "isp": "ISP / konum",
    "ns": "Ad sunucusu",
    "mail": "E-posta",
    "cve": "CVE",
    "tag": "Etiket",
}
GRAPH_KIND_LETTERS = {"isp": "ISP", "ns": "NS", "mail": "@", "cve": "CVE", "tag": "#"}

# Panelde gösterilen risk seviyeleri, sırası ve renkleri
PANEL_LEVELS = [
    ("CRITICAL", "Kritik", "#fb7185"),
    ("HIGH", "Yüksek", "#f97316"),
    ("MEDIUM", "Orta", "#fbbf24"),
    ("LOW", "Düşük", "#38bdf8"),
    ("CLEAN", "Temiz", "#34d399"),
    ("UNKNOWN", "Yetersiz veri", "#64748b"),
]


def to_json(report: EnrichmentReport, pretty: bool = True) -> str:
    return json.dumps(report.to_dict(), indent=2 if pretty else None, ensure_ascii=False)


def save_json(report: EnrichmentReport, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(to_json(report), encoding="utf-8")
    return p


def breakdown_rows(report: EnrichmentReport) -> list[dict]:
    scores = {k: getattr(report.risk_breakdown, k, 0) for k in SCORE_FIELDS}
    return [
        {"name": k.title(), "score": scores.get(k, 0), "weight": w}
        for k, w in report.risk_breakdown.weights_applied.items()
    ]


def render_html(report: EnrichmentReport) -> str:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    return env.get_template("report.html").render(
        report=report,
        breakdown_rows=breakdown_rows(report),
        risk_color=RISK_COLORS.get(report.risk_level, "#6b7280"),
    )


def save_html(report: EnrichmentReport, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_html(report), encoding="utf-8")
    return p


def provider_detail(result: ProviderResult) -> str:
    """Bir kaynağın sonucunu tek satırlık, insanın okuyabileceği metne çevirir."""
    if not result.success:
        return result.error or "Hata"
    n = result.normalized or {}
    if not n:
        return "Veri yok"
    name = result.provider
    if name == "virustotal":
        return f"{n.get('malicious', 0)} / {n.get('total_engines', 0)} motor zararlı dedi"
    if name == "abuseipdb":
        return f"Kötüye kullanım skoru %{n.get('abuse_confidence', 0)} ({n.get('total_reports', 0)} şikayet)"
    if name == "shodan":
        ports = n.get("open_ports") or []
        return "Açık portlar: " + (", ".join(str(p) for p in ports[:8]) if ports else "yok")
    if name == "otx":
        return f"{n.get('pulse_count', 0)} tehdit raporunda geçiyor"
    if name == "greynoise":
        return f"Sınıf: {n.get('classification', 'bilinmiyor')}"
    if name == "urlhaus":
        return "Zararlı listesinde" if n.get("listed") else "Listede yok"
    if name == "misp":
        return f"{n.get('event_count', 0)} olay bulundu"
    if name == "whois":
        return "Kayıt: " + str(n.get("name") or n.get("handle") or "bilgi alındı")
    return "Veri alındı"


def provider_row(result: ProviderResult) -> dict:
    """Şablonda ve canlı akışta kullanılan düz sözlük."""
    if result.success:
        state = "ok"
    elif result.error == DISABLED_ERROR:
        state = "off"
    else:
        state = "fail"
    return {
        "provider": result.provider,
        "title": PROVIDER_TITLES.get(result.provider, result.provider.title()),
        "ok": result.success,
        "state": state,
        "cached": result.cached,
        "error": result.error or "",
        "detail": provider_detail(result),
    }


def coverage(rows: list[dict]) -> dict:
    """Her kaynak için bir parça: veri alındı, anahtar yok veya hata."""
    segments = []
    for row in rows:
        if row["ok"]:
            state, label = "ok", "veri alındı"
        elif row["error"] == DISABLED_ERROR:
            state, label = "off", "anahtar yok"
        else:
            state, label = "fail", row["error"] or "hata"
        segments.append({"state": state, "title": f"{row['title']}: {label}"})
    return {
        "segments": segments,
        "answered": sum(1 for row in rows if row["ok"]),
        "total": len(rows),
    }


def gauge(report: EnrichmentReport) -> dict:
    """Yarım daire göstergenin çizgi uzunluğu ve doluluk ofseti."""
    unknown = report.risk_level == RiskLevel.UNKNOWN
    score = 0.0 if unknown else min(max(float(report.threat_score), 0.0), 100.0)
    return {
        "length": GAUGE_LENGTH,
        "offset": round(GAUGE_LENGTH * (1 - score / 100), 2),
        "unknown": unknown,
    }


def _shorten(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def graph(report: EnrichmentReport) -> dict | None:
    """Merkezde IOC, çevresinde ISP, ad sunucusu, e-posta, CVE ve etiketler."""
    geo = report.geo or {}
    related = report.related or {}
    items: list[tuple[str, str]] = []
    isp = geo.get("isp") or geo.get("country")
    if isp:
        items.append(("isp", str(isp)))
    for ns in related.get("nameservers", [])[:2]:
        items.append(("ns", str(ns)))
    for mail in related.get("emails", [])[:2]:
        items.append(("mail", str(mail)))
    for cve in (report.cves or [])[:3]:
        items.append(("cve", str(cve.get("id", ""))))
    for tag in (report.tags or [])[:2]:
        items.append(("tag", str(tag)))
    if not items:
        return None

    cx, cy = GRAPH_CENTER
    nodes = []
    for index, (kind, value) in enumerate(items):
        angle = -math.pi / 2 + 2 * math.pi * index / len(items)
        nodes.append({
            "kind": kind,
            "kind_label": GRAPH_KIND_LABELS[kind],
            "letter": GRAPH_KIND_LETTERS[kind],
            "caption": _shorten(value, 24),
            "x": round(cx + GRAPH_RADIUS * math.cos(angle), 1),
            "y": round(cy + GRAPH_RADIUS * math.sin(angle), 1),
        })
    return {"cx": cx, "cy": cy, "center": _shorten(report.ioc, 18), "nodes": nodes}


def map_point(report: EnrichmentReport) -> dict | None:
    geo = report.geo or {}
    lat, lon = geo.get("latitude"), geo.get("longitude")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        return {"lat": float(lat), "lon": float(lon)}
    return None


def result_context(report: EnrichmentReport, error: str | None = None) -> dict:
    """Sonuç kartının (result.html) ihtiyaç duyduğu tüm değerler."""
    rows = [provider_row(p) for p in report.providers]
    return {
        "report": report,
        "error": error,
        "risk_color": RISK_COLORS.get(report.risk_level, "#6b7280"),
        "breakdown_rows": breakdown_rows(report),
        "rows": rows,
        "coverage": coverage(rows),
        "gauge": gauge(report),
        "graph": graph(report),
        "map": map_point(report),
    }


def panel_view(stats: dict) -> dict:
    """Panel sayfasının çizdireceği değerler: son 30 günün çubukları ve risk dağılımı."""
    since = date.fromisoformat(stats["since"])
    days = [(since + timedelta(days=i)).isoformat() for i in range(30)]
    counts = [stats["daily"].get(day, 0) for day in days]
    peak = max(counts) or 1
    slot = 600 / 30
    bars = []
    for index, (day, count) in enumerate(zip(days, counts)):
        height = round(count / peak * 130, 1)
        bars.append({
            "day": day,
            "count": count,
            "x": round(index * slot + 3, 1),
            "w": round(slot - 6, 1),
            "y": round(150 - height, 1),
            "h": height,
        })
    levels_map = stats["levels"]
    total = sum(levels_map.values()) or 1
    levels = [
        {
            "code": code,
            "label": label,
            "color": color,
            "count": levels_map.get(code, 0),
            "pct": round(levels_map.get(code, 0) / total * 100, 1),
        }
        for code, label, color in PANEL_LEVELS
    ]
    return {
        "total": stats["total"],
        "last30": sum(counts),
        "risky": levels_map.get("CRITICAL", 0) + levels_map.get("HIGH", 0),
        "unknown": levels_map.get("UNKNOWN", 0),
        "peak": peak,
        "bars": bars,
        "levels": levels,
        "top": stats["top"],
        "most": stats["most"],
    }
