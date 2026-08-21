"""PDF from the scan dict. Only fields that exist in results/."""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

AUTHOR = "Harsha Nandhan Reddy Gajulapalli"
EMAIL = "harshanandhanreddy820@gmail.com"


class ReportGenerator:
    def __init__(self, results: dict):
        self.results = results
        self.styles = getSampleStyleSheet()
        self.styles.add(
            ParagraphStyle(name="H", parent=self.styles["Heading2"], spaceBefore=12, spaceAfter=8)
        )

    def generate_pdf(self, filename: str) -> str:
        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(path), pagesize=letter)
        story = []
        r = self.results
        story.append(Paragraph("Host security scan", self.styles["Title"]))
        story.append(Paragraph(f"{AUTHOR} · {EMAIL}", self.styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))
        story.append(
            Paragraph(
                f"Target: {r.get('target')} &nbsp; Date: {r.get('scan_date')} &nbsp; "
                f"Authorized lab target only.",
                self.styles["Normal"],
            )
        )
        story.append(Paragraph("Open ports", self.styles["H"]))
        rows = [["Port", "Service", "Banner"]]
        for p in r.get("ports", []):
            rows.append([str(p["port"]), p.get("service", ""), (p.get("banner") or "")[:60]])
        if len(rows) == 1:
            rows.append(["—", "none", ""])
        story.append(self._table(rows))

        story.append(Paragraph("Web checks", self.styles["H"]))
        wrows = [["Test", "Flagged", "Note"]]
        for f in r.get("web_findings", []):
            wrows.append(
                [
                    f.get("test", ""),
                    "yes" if f.get("vulnerable") else "no",
                    (f.get("note") or "")[:80],
                ]
            )
        if len(wrows) == 1:
            wrows.append(["—", "skipped", ""])
        story.append(self._table(wrows))

        ssl = r.get("ssl")
        if ssl:
            story.append(Paragraph("TLS", self.styles["H"]))
            if ssl.get("error"):
                story.append(Paragraph(f"TLS error: {ssl['error']}", self.styles["Normal"]))
            else:
                story.append(
                    Paragraph(
                        f"Protocol {ssl.get('protocol')} cipher {ssl.get('cipher')} "
                        f"expires {ssl.get('not_after')}",
                        self.styles["Normal"],
                    )
                )
        story.append(Spacer(1, 0.3 * inch))
        story.append(
            Paragraph(
                "This is a lab tool: TCP connect scan, banner grab, a few GET tests, TLS peek. "
                "It is not a penetration test and it does not query a CVE database.",
                self.styles["Normal"],
            )
        )
        doc.build(story)
        return str(path)

    @staticmethod
    def _table(data):
        t = Table(data, colWidths=[1.6 * inch, 1.6 * inch, 3.4 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94a3b8")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return t
