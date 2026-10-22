from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from threatscout.models import EnrichmentReport, RiskLevel

TEMPLATE_DIR = Path(__file__).parent / "templates"

RISK_COLORS = {
    RiskLevel.CRITICAL: "#dc2626",
    RiskLevel.HIGH: "#ea580c",
    RiskLevel.MEDIUM: "#ca8a04",
    RiskLevel.LOW: "#2563eb",
    RiskLevel.CLEAN: "#16a34a",
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
