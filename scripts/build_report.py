"""Build the readable progress report from versioned Markdown documents.

Optional authoring dependency: reportlab. It is not required for running search.
"""
import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, LongTable, TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]


def main():
    # Override these two paths when authoring on another operating system.
    font_root = Path("/System/Library/Fonts/Supplemental")
    pdfmetrics.registerFont(TTFont("Report", str(font_root / "Arial.ttf")))
    pdfmetrics.registerFont(TTFont("ReportBold", str(font_root / "Arial Bold.ttf")))
    pdfmetrics.registerFontFamily("Report", normal="Report", bold="ReportBold")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("BodyTR", fontName="Report", fontSize=10.5, leading=15,
                              spaceAfter=8, textColor=colors.HexColor("#243041")))
    styles.add(ParagraphStyle("TitleTR", fontName="ReportBold", fontSize=26, leading=33,
                              spaceAfter=20, textColor=colors.HexColor("#12324B")))
    styles.add(ParagraphStyle("H1TR", fontName="ReportBold", fontSize=19, leading=24,
                              spaceAfter=18, textColor=colors.HexColor("#12324B")))
    styles.add(ParagraphStyle("H2TR", fontName="ReportBold", fontSize=12.5, leading=17,
                              spaceBefore=12, spaceAfter=7, keepWithNext=True))
    styles.add(ParagraphStyle("CellTR", fontName="Report", fontSize=9, leading=12,
                              spaceAfter=0, alignment=TA_LEFT))

    def markup(text):
        text = text.replace("–", "-").replace("—", "-")
        text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)
        text = html.escape(text.replace("`", ""))
        return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)

    def p(text, kind="BodyTR"):
        return Paragraph(markup(text), styles[kind])

    story = [Spacer(1, 56), p("MITRE-RAG", "TitleTR"),
             p("İlk 7 haftanın araştırma ve teknik çıktıları", "H1TR"),
             p("Bernanur Kalkan<br/>Ankara Üniversitesi - Bilgisayar Mühendisliği".replace("<br/>", " / ")),
             p("5 Kasım 2026"), Spacer(1, 24),
             p("Kapsam: danışmanın onayladığı 14 haftalık planın 1-7. haftaları."),
             p("697 aktif ATT&CK kaydı, 1.993 metin parçası ve 384 boyutlu embedding indeksi hazır. "
               "Dört gerçek sorgu demosu ve 9 otomatik test başarıyla çalıştı."),
             p("Bu rapor bir ilerleme teslimidir. Dört demo, bağımsız etiketli test kümesi "
               "üzerinde yapılmış genel başarı değerlendirmesi değildir."),
             Spacer(1, 18), p("Kod ve kanıtlar: https://github.com/bernakalkann/mitre_rag_final")]

    def table(rows):
        width = A4[0] - 96
        count = len(rows[0])
        fractions = {2: [.28, .72], 3: [.20, .43, .37], 4: [.12, .28, .30, .30]}[count]
        if rows[0][0] == "Kod":
            fractions = [.08, .50, .42]
        elif rows[0][0] == "Olay":
            fractions = [.45, .20, .35]
        elif rows[0][0] == "Alan":
            fractions = [.25, .18, .57]
        cells = [[p(cell, "CellTR") for cell in row] for row in rows]
        t = LongTable(cells, colWidths=[width * f for f in fractions], repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9F0F4")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LINEBELOW", (0, 0), (-1, 0), .6, colors.HexColor("#A8BBC7")),
            ("LINEBELOW", (0, 1), (-1, -1), .3, colors.HexColor("#DCE4EA")),
        ]))
        story.extend([t, Spacer(1, 12)])

    documents = sorted((ROOT / "docs").glob("0[1-7]_*.md"))
    for source in documents:
        story.append(PageBreak())
        lines = source.read_text(encoding="utf-8").splitlines()
        pending, rows, code, code_kind = [], [], False, ""

        def flush():
            if pending:
                story.append(p(" ".join(pending)))
                pending.clear()
            if rows:
                table(rows.copy())
                rows.clear()

        for line in lines:
            if line.startswith("```"):
                flush()
                if not code:
                    code_kind = line[3:]
                code = not code
                continue
            if code:
                if code_kind != "mermaid":
                    story.append(p(line, "CellTR"))
                continue
            if line.startswith("|"):
                if pending:
                    story.append(p(" ".join(pending)))
                    pending.clear()
                row = [c.strip() for c in line.strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-+:?", c) for c in row):
                    rows.append(row)
            elif line.startswith("# "):
                flush()
                story.append(p(line[2:], "H1TR"))
            elif line.startswith("## "):
                flush()
                story.append(p(line[3:], "H2TR"))
            elif not line.strip():
                flush()
            elif re.match(r"(?:- |\d+\. )", line):
                flush()
                story.append(p(line))
            else:
                if rows:
                    table(rows.copy())
                    rows.clear()
                pending.append(line)
        flush()

    def page(canvas, doc):
        canvas.setFont("Report", 8)
        canvas.setFillColor(colors.HexColor("#677787"))
        canvas.drawString(48, 28, "MITRE-RAG / İlk 7 hafta / Bernanur Kalkan")
        canvas.drawRightString(A4[0] - 48, 28, str(doc.page))

    output = ROOT / "docs/MITRE_RAG_Hafta_01_07_Rapor.pdf"
    SimpleDocTemplate(str(output), pagesize=A4, leftMargin=48, rightMargin=48,
                      topMargin=48, bottomMargin=48,
                      title="MITRE-RAG - İlk 7 Haftanın Çıktıları", author="Bernanur Kalkan").build(
                          story, onFirstPage=page, onLaterPages=page)
    print(output)


if __name__ == "__main__":
    main()
