"""
Zorynex — Audit Report PDF Generator
=======================================
Generates a professional PDF audit report from verification records.

Each report includes:
  - Cover page: tenant, date range, summary statistics
  - Verification summary table: result, instance, sequence, key, timestamp
  - Compliance attestation section (SR 11-7 / EU AI Act / CFPB)
  - Appendix: Merkle root of all included proofs

Usage:
    from provable_ai.audit_report import generate_audit_report

    pdf_bytes = generate_audit_report(
        tenant_id="bank_abc",
        entries=audit_log.query("bank_abc", from_date="2026-01-01T00:00:00Z").entries,
        merkle_root="a3f8...",
        compliance_pack=build_compliance_pack(entries),
    )

The output is a bytes object — write to file or stream to HTTP response.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .audit_log import VerificationAuditEntry


# ── Colour palette — Zorynex brand ────────────────────────────────────────────

_ACCENT  = colors.HexColor("#00d4aa")   # Zorynex green
_DARK    = colors.HexColor("#0a0c0f")   # near-black
_SURFACE = colors.HexColor("#f4f7fa")   # light grey row background
_TEXT    = colors.HexColor("#1a2536")   # dark text
_MUTED   = colors.HexColor("#6b7f96")   # secondary text
_RED     = colors.HexColor("#e63946")   # invalid
_GREEN   = colors.HexColor("#00d4aa")   # valid


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Normal"],
            fontSize=26, fontName="Helvetica-Bold",
            textColor=_DARK, spaceAfter=4, leading=32,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"],
            fontSize=11, fontName="Helvetica",
            textColor=_MUTED, spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Normal"],
            fontSize=14, fontName="Helvetica-Bold",
            textColor=_DARK, spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"],
            fontSize=9, fontName="Helvetica",
            textColor=_TEXT, spaceAfter=4, leading=14,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Normal"],
            fontSize=8, fontName="Courier",
            textColor=_TEXT, spaceAfter=2,
        ),
        "label": ParagraphStyle(
            "label", parent=base["Normal"],
            fontSize=8, fontName="Helvetica-Bold",
            textColor=_MUTED, spaceAfter=2, leading=12,
        ),
        "center": ParagraphStyle(
            "center", parent=base["Normal"],
            fontSize=9, fontName="Helvetica",
            textColor=_TEXT, alignment=TA_CENTER,
        ),
        "footer": ParagraphStyle(
            "footer", parent=base["Normal"],
            fontSize=7, fontName="Helvetica",
            textColor=_MUTED, alignment=TA_CENTER,
        ),
    }


# ── Page template ─────────────────────────────────────────────────────────────

def _on_page(canvas, doc) -> None:
    """Draw header line + footer on every page."""
    w, h = A4
    canvas.saveState()

    # Top accent bar
    canvas.setFillColor(_ACCENT)
    canvas.rect(0, h - 8 * mm, w, 8 * mm, fill=1, stroke=0)

    # Logo text in bar
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(15 * mm, h - 5.5 * mm, "ZORYNEX")

    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 15 * mm, h - 5.5 * mm, "Provable AI Infrastructure")

    # Footer
    canvas.setFillColor(_MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(15 * mm, 8 * mm, "CONFIDENTIAL — Zorynex Verification Audit Report")
    canvas.drawRightString(
        w - 15 * mm, 8 * mm,
        f"Page {doc.page}"
    )
    canvas.line(15 * mm, 12 * mm, w - 15 * mm, 12 * mm)

    canvas.restoreState()


# ── Main generator ────────────────────────────────────────────────────────────

def generate_audit_report(
    tenant_id:       str,
    entries:         list[VerificationAuditEntry],
    merkle_root:     str,
    compliance_pack: dict[str, Any],
    from_date:       str | None = None,
    to_date:         str | None = None,
    generated_by:    str        = "Zorynex Automated Audit System",
) -> bytes:
    """
    Generate a PDF audit report.

    Args:
        tenant_id:       The tenant this report covers
        entries:         Verification audit entries (from VerificationAuditLog.query)
        merkle_root:     Merkle root of all included proof hashes
        compliance_pack: Output of build_compliance_pack()
        from_date:       Report start date (ISO-8601 UTC)
        to_date:         Report end date (ISO-8601 UTC)
        generated_by:    Author attribution string

    Returns:
        PDF as bytes — write to file or stream as HTTP response.
    """
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=20 * mm, bottomMargin=20 * mm,
        title=f"Zorynex Audit Report — {tenant_id}",
        author="Zorynex",
        subject="Proof Verification Audit Report",
    )

    st      = _styles()
    story   = []
    w       = A4[0] - 30 * mm   # usable width

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Cover page ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 24 * mm))
    story.append(Paragraph("Verification Audit Report", st["title"]))
    story.append(Paragraph(f"Tenant: {tenant_id}", st["subtitle"]))

    date_range = ""
    if from_date or to_date:
        date_range = f"{from_date or '—'} → {to_date or '—'}"
    else:
        date_range = "All records"
    story.append(Paragraph(f"Period: {date_range}", st["subtitle"]))
    story.append(Paragraph(f"Generated: {generated_at}", st["subtitle"]))
    story.append(Paragraph(f"By: {generated_by}", st["subtitle"]))
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width=w, color=_ACCENT, thickness=2))
    story.append(Spacer(1, 6 * mm))

    # Summary stats
    total   = len(entries)
    valid   = sum(1 for e in entries if e.result == "valid")
    invalid = total - valid
    rate    = f"{valid / total * 100:.1f}%" if total > 0 else "N/A"

    summary_data = [
        ["Total Verifications", "Valid", "Invalid", "Valid Rate"],
        [str(total), str(valid), str(invalid), rate],
    ]
    summary_table = Table(summary_data, colWidths=[w / 4] * 4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  _DARK),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  9),
        ("BACKGROUND",   (0, 1), (-1, 1),  _SURFACE),
        ("FONTNAME",     (0, 1), (-1, 1),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 1), (-1, 1),  16),
        ("TEXTCOLOR",    (2, 1), (2, 1),   _RED if invalid > 0 else _GREEN),
        ("TEXTCOLOR",    (0, 1), (1, 1),   _GREEN),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_DARK, _SURFACE]),
        ("ROWHEIGHT",    (0, 0), (0, 0), 10 * mm),
        ("ROWHEIGHT",    (0, 1), (0, 1), 18 * mm),
        ("BOX",          (0, 0), (-1, -1), 0.5, _MUTED),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 6 * mm))

    # Merkle root
    story.append(Paragraph("Merkle Root (all included proofs)", st["label"]))
    story.append(Paragraph(merkle_root, st["mono"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "The Merkle root cryptographically commits to every proof verification "
        "in this report. Any modification to any entry changes this value.",
        st["body"],
    ))

    story.append(PageBreak())

    # ── Verification table ────────────────────────────────────────────────────
    story.append(Paragraph("Verification Records", st["h2"]))
    story.append(HRFlowable(width=w, color=_ACCENT, thickness=1))
    story.append(Spacer(1, 3 * mm))

    if not entries:
        story.append(Paragraph("No verification records in this period.", st["body"]))
    else:
        col_w   = [18 * mm, 38 * mm, 22 * mm, 18 * mm, 30 * mm, 24 * mm]
        headers = ["Result", "Instance ID", "Proof ID", "Seq", "Key ID", "Verified At"]

        rows    = [headers]
        for e in entries[:500]:   # cap at 500 rows to prevent enormous PDFs
            rows.append([
                e.result.upper(),
                (e.instance_id or "—")[:28],
                (e.proof_id[:12] + "…" if e.proof_id else "—"),
                str(e.sequence_id) if e.sequence_id is not None else "—",
                (e.key_id or "—")[:20],
                (e.verified_at or "—")[:19],
            ])

        tbl = Table(rows, colWidths=col_w, repeatRows=1)
        row_styles = [
            ("BACKGROUND",  (0, 0), (-1, 0),  _DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7),
            ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("ROWHEIGHT",   (0, 0), (-1, -1), 7 * mm),
            ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#dde4ed")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _SURFACE]),
        ]
        # Colour result column
        for i, e in enumerate(entries[:500], start=1):
            color = _GREEN if e.result == "valid" else _RED
            row_styles.append(("TEXTCOLOR", (0, i), (0, i), color))
            row_styles.append(("FONTNAME",  (0, i), (0, i), "Helvetica-Bold"))

        tbl.setStyle(TableStyle(row_styles))
        story.append(tbl)

        if total > 500:
            story.append(Spacer(1, 3 * mm))
            story.append(Paragraph(
                f"⚠ Report truncated to 500 entries. Total records: {total}. "
                f"Use the /audit/export endpoint for the full dataset.",
                st["body"],
            ))

    story.append(PageBreak())

    # ── Compliance attestation ────────────────────────────────────────────────
    story.append(Paragraph("Regulatory Compliance Attestation", st["h2"]))
    story.append(HRFlowable(width=w, color=_ACCENT, thickness=1))
    story.append(Spacer(1, 3 * mm))

    for framework, details in compliance_pack.items():
        story.append(Paragraph(details["name"], st["h2"]))
        story.append(Paragraph(details["status"], st["body"]))
        for point in details.get("evidence", []):
            story.append(Paragraph(f"• {point}", st["body"]))
        story.append(Spacer(1, 3 * mm))

    story.append(PageBreak())

    # ── Appendix ──────────────────────────────────────────────────────────────
    story.append(Paragraph("Appendix — Technical Details", st["h2"]))
    story.append(HRFlowable(width=w, color=_ACCENT, thickness=1))
    story.append(Spacer(1, 3 * mm))

    tech_rows = [
        ["Property", "Value"],
        ["Report Version",      "1.0"],
        ["Signing Algorithm",   "Ed25519"],
        ["Hash Algorithm",      "SHA-256"],
        ["Canonical JSON",      "sort_keys=True, separators=(',', ':'), ensure_ascii=False"],
        ["Chain Verification",  "SHA-256 hash chain — each proof links to prior"],
        ["Merkle Tree",         "Binary SHA-256 Merkle tree over proof_id list"],
        ["Tenant Isolation",    "UNIQUE(tenant_id, instance_id, sequence_id) at DB level"],
        ["Governance Verified", "false — record authenticity proven, not decision correctness"],
        ["Report Generated",    generated_at],
        ["Tenant ID",           tenant_id],
        ["Total Records",       str(total)],
        ["Merkle Root",         merkle_root],
    ]
    tech_tbl = Table(tech_rows, colWidths=[60 * mm, w - 60 * mm])
    tech_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  _DARK),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),
        ("FONTNAME",    (0, 1), (0, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",   (0, 1), (0, -1),  _MUTED),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHT",   (0, 0), (-1, -1), 7 * mm),
        ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#dde4ed")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _SURFACE]),
        ("FONTNAME",    (1, -1), (1, -1), "Courier"),
        ("FONTSIZE",    (1, -1), (1, -1), 7),
    ]))
    story.append(tech_tbl)

    # Build PDF
    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    buf.seek(0)
    return buf.read()