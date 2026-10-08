"""Deterministic PDF: same scan -> same bytes, so the SHA-256 is stable and anchorable."""
import io, time
from xml.sax.saxutils import escape as e
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, PageBreak

SEVC = {"Critical": "#e5384f", "High": "#e8890c", "Medium": "#2b8fd6", "Low": "#1fa97a"}

def build_pdf(scan: dict) -> bytes:
    buf = io.BytesIO(); ss = getSampleStyleSheet()
    H = ParagraphStyle("H", parent=ss["Heading2"], spaceBefore=14, textColor=colors.HexColor("#2a1f6b"))
    S = ParagraphStyle("S", parent=ss["BodyText"], fontSize=9.5, leading=13)
    M = ParagraphStyle("M", parent=S, fontName="Courier", fontSize=8)
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm, invariant=1,
                            title=f"AuditLens report - {scan['name']}", author="AuditLens")
    st = [Paragraph("AuditLens security and compliance report", ss["Title"]),
          Paragraph(f"Contract: <b>{e(scan['name'])}</b> &nbsp; Scan ID: {scan['id']} &nbsp; Generated (UTC): {time.strftime('%Y-%m-%d %H:%M', time.gmtime(scan['created']))}", S),
          Paragraph(f"Source SHA-256: {scan['source_sha256']}", M),
          Paragraph(f"Analysis: {'Slither static analysis' if scan['engine']['slither'] else 'Slither unavailable'}{' + AI logic audit' if scan['engine'].get('ai_audit') else ''}; explanations: {'AI-assisted (' + str(scan['engine']['llm_info']) + ')' if scan['engine']['llm'] else 'built-in knowledge base'}.", S),
          Spacer(1, 8), Paragraph("Summary", H),
          Paragraph(f"Security posture <b>{scan['score']}/100</b>. Governance score <b>{scan['governance']['score'] if scan['governance']['score'] is not None else 'n/a'}/100</b>. Findings: " +
                    ", ".join(f"{v} {k}" for k, v in scan["counts"].items()) + ".", S), Paragraph("Compliance coverage", H)]
    t = Table([["Framework", "Coverage", "Failing controls"]] + [[c["name"], f"{c['pct']}%", Paragraph(e(", ".join(c["failing"]) or "none"), S)] for c in scan["coverage"].values()], colWidths=[55 * mm, 22 * mm, 95 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ebe7ff")), ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#b9b2e6")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 9)]))
    st += [t, Paragraph("Findings", H)]
    for f in scan["findings"]:
        st += [Paragraph(f"<font color='{SEVC[f['severity']]}'><b>[{f['severity']}]</b></font> {f['id']} - {e(f['title'])} <font size=8>({e(f['file'])}:{f['line']}, risk {f['likelihood']}x{f['impact']}={f['risk']}, {f['engine']})</font>", ss["Heading4"]),
               Preformatted(f["code"][:110], M), Paragraph(e(f["explanation"]), S), Paragraph(f"<b>Business risk:</b> {e(f['risk_statement'])}", S),
               Paragraph(f"<b>Fix:</b> {e(f['fix'])}", S)]
        if f["fix_code"]: st.append(Preformatted(f["fix_code"][:600], M))
        if f.get("exploit"): st += [Paragraph("<b>Exploit scenario (AI-written, not executed):</b>", S)] + [Paragraph(f"{n}. {e(x)}", S) for n, x in enumerate(f["exploit"], 1)]
        st += [Paragraph(f"<b>Controls:</b> {e(f['owasp'])}; {e('; '.join(f['iso']))}; {e('; '.join(f['soc2']))}. <b>Owner:</b> {e(f['owner'])}", S), Spacer(1, 6)]
    st.append(Paragraph("Governance review", H))
    for g in scan["governance"]["items"] or [{"severity": "Low", "title": "No governance issues found by the checks that ran", "detail": [], "why": " ".join(scan["governance"].get("notes", [])), "fix": ""}]:
        st += [Paragraph(f"<b>[{g['severity']}]</b> {e(g['title'])} <font size=8>({g.get('source', '')})</font>", S)] + [Paragraph("- " + e(d), M) for d in g["detail"]] + [Paragraph(e(g["why"] + " " + g["fix"]), S)]
    st += [Spacer(1, 10), Paragraph("Limitations: automated analysis finds known bug classes only and is not a substitute for a manual audit. Control IDs come from a fixed catalog (AI-selected where noted, otherwise a reference table) and should be reviewed by your GRC owner.", S)]
    doc.build(st); return buf.getvalue()
