from __future__ import annotations

from fpdf import FPDF

from threatscout.models import EnrichmentReport


def render_pdf(report: EnrichmentReport) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "ThreatScout Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=11)
    pdf.cell(0, 8, f"IOC: {_safe(report.ioc)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Type: {report.ioc_type.value}  Score: {report.threat_score}  Risk: {report.risk_level.value}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Analyzed: {report.analyzed_at.isoformat()}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Providers", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    for p in report.providers:
        status = "OK" if p.success else _safe(p.error or "error")
        pdf.cell(0, 6, f"- {p.provider}: {status}  cache={p.cached}", new_x="LMARGIN", new_y="NEXT")
    if report.tags:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Tags", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(0, 6, _safe(", ".join(report.tags[:40])))
    if report.cves:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "CVEs", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        for cve in report.cves:
            line = f"{cve.get('id','')} score={cve.get('score','-')} {cve.get('severity','')}"
            pdf.cell(0, 6, _safe(line), new_x="LMARGIN", new_y="NEXT")
            if cve.get("summary"):
                pdf.multi_cell(0, 5, _safe(str(cve["summary"])[:500]))
    if report.whois:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "WHOIS / RDAP", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        for key in ("name", "handle", "registrar", "country", "mailbox_domain"):
            if report.whois.get(key):
                pdf.cell(0, 6, _safe(f"{key}: {report.whois[key]}"), new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())


def _safe(text: str) -> str:
    return str(text).encode("latin-1", "replace").decode("latin-1")
