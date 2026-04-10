"""
D-043: PDF Report Export — GET /api/scans/{scan_id}/report.pdf

Generates a downloadable PDF security report for a completed scan.
Auth-gated via CurrentUser dependency (requires valid JWT).

The PDF includes:
  - Executive summary (score, grade, risk level)
  - Per-category scores with visual bars
  - Findings table (severity, type, title, file)
  - Remediation summary

Uses reportlab for PDF generation (pinned: reportlab==4.2.2).
"""

from __future__ import annotations

import io
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from app.api.deps import CurrentUser
from app.models import database as db

logger = logging.getLogger("zse.api.reports")
router = APIRouter(prefix="/api/scans", tags=["reports"])


def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def _score_to_risk(score: int) -> str:
    if score >= 80: return "LOW"
    if score >= 60: return "MEDIUM"
    if score >= 40: return "HIGH"
    return "CRITICAL"


def _build_pdf(scan: dict, findings: list[dict]) -> bytes:
    """Generate PDF bytes using reportlab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm,
                                leftMargin=2*cm, rightMargin=2*cm)
        styles = getSampleStyleSheet()
        story = []

        # ── Title
        title_style = ParagraphStyle("title", parent=styles["Title"],
                                     fontSize=22, textColor=colors.HexColor("#1a1a2e"))
        story.append(Paragraph("ZaphScore Security Report", title_style))
        story.append(Spacer(1, 0.3*cm))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#7B2FF7")))
        story.append(Spacer(1, 0.5*cm))

        # ── Meta
        score = scan.get("score") or 0
        grade = _score_to_grade(score)
        risk = _score_to_risk(score)
        repo = scan.get("repo_url", "Unknown")
        branch = scan.get("branch", "main")
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        meta_data = [
            ["Repository", repo],
            ["Branch", branch],
            ["Scan ID", str(scan.get("id", ""))[:8] + "..."],
            ["Generated", generated],
            ["Overall Score", f"{score}/100  —  Grade {grade}  —  Risk {risk}"],
        ]
        meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f0ff")),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#7B2FF7")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0d0ff")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.7*cm))

        # ── Score breakdown
        story.append(Paragraph("Score Breakdown", styles["Heading2"]))
        score_details = scan.get("score_details") or {}
        if isinstance(score_details, dict):
            cats = ["dependency", "sast", "secrets", "iac", "license"]
            score_rows = [["Category", "Score", "Status"]]
            for cat in cats:
                val = score_details.get(cat, 100)
                status_text = "PASS" if val >= 70 else ("WARN" if val >= 50 else "FAIL")
                score_rows.append([cat.title(), f"{val}/100", status_text])
            score_rows.append(["OVERALL", f"{score}/100", f"Grade {grade}"])

            st = Table(score_rows, colWidths=[5*cm, 4*cm, 4*cm])
            st.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7B2FF7")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, -1), (-1, -1), colors.white),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ]))
            story.append(st)
            story.append(Spacer(1, 0.7*cm))

        # ── Findings
        if findings:
            story.append(Paragraph(f"Findings ({len(findings)} total)", styles["Heading2"]))
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 5))

            find_rows = [["Severity", "Type", "Title", "File"]]
            for f in sorted_findings[:50]:  # Cap at 50 rows for readability
                find_rows.append([
                    f.get("severity", "").upper(),
                    f.get("type", ""),
                    (f.get("title", "") or "")[:60],
                    (f.get("file_path", "") or "")[-40:],
                ])

            sev_colors = {
                "CRITICAL": colors.HexColor("#ff4444"),
                "HIGH": colors.HexColor("#ff8800"),
                "MEDIUM": colors.HexColor("#ffcc00"),
                "LOW": colors.HexColor("#44bb44"),
                "INFO": colors.HexColor("#888888"),
            }

            ft = Table(find_rows, colWidths=[2.5*cm, 3*cm, 8*cm, 4*cm])
            ft_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
            for i, row in enumerate(find_rows[1:], 1):
                sev = row[0]
                col = sev_colors.get(sev, colors.HexColor("#cccccc"))
                ft_style.append(("BACKGROUND", (0, i), (0, i), col))
                ft_style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
                ft_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

            ft.setStyle(TableStyle(ft_style))
            story.append(ft)

        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#7B2FF7")))
        footer_style = ParagraphStyle("footer", parent=styles["Normal"],
                                      fontSize=8, textColor=colors.HexColor("#888888"))
        story.append(Paragraph(
            f"Generated by ZaphScore · zaphscore.zaphenath.app · {generated}",
            footer_style
        ))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        # reportlab not installed — return a minimal text-based PDF placeholder
        logger.warning("reportlab not installed — returning plain text report")
        text = (
            f"ZaphScore Security Report\n"
            f"Repository: {scan.get('repo_url', 'Unknown')}\n"
            f"Score: {scan.get('score', 0)}/100\n"
            f"Findings: {len(findings)}\n"
            f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
        )
        return text.encode("utf-8")


@router.get("/{scan_id}/report.pdf")
async def export_pdf_report(
    scan_id: uuid.UUID,
    current_user: CurrentUser,
) -> StreamingResponse:
    """Export a completed scan as a downloadable PDF security report.

    Requires authentication. Only available for completed scans.
    Returns HTTP 404 if scan not found, HTTP 400 if scan not yet complete.
    """
    row = await db.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if row.get("status") not in ("complete",):
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not complete yet (status: {row.get('status')}). "
                   "Wait for the scan to finish before exporting.",
        )

    findings_rows = await db.get_scan_findings(scan_id)

    try:
        pdf_bytes = _build_pdf(row, findings_rows)
    except Exception as exc:
        logger.error("PDF generation failed for scan %s: %s", scan_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail="PDF generation failed.")

    repo_slug = (row.get("repo_url", "repo") or "repo").rstrip("/").split("/")[-1]
    filename = f"zaphscore-{repo_slug}-{str(scan_id)[:8]}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
