#!/usr/bin/env python3
"""repeatability.py — cross-run CV table + Jaccard overlap for the report."""
from __future__ import annotations

from .base import esc, fmt_ratio, fmt_value, verdict_badge, section, card, table, note, run_headers


def _kpi(value: str, label: str, sub: str = "") -> str:
    sub_html = f'<div class="kpi-sub">{sub}</div>' if sub else ""
    return f"""<div class="kpi">
  <div class="kpi-val">{value}</div>
  <div class="kpi-label">{label}</div>
  {sub_html}
</div>"""


def _cv_row(row: dict) -> str:
    fmt = row.get("format", "num")
    values = row.get("values") or []
    cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
    mean_cell = f'<td class="num">{fmt_value(row.get("mean"), fmt)}</td>'
    stdev_cell = f'<td class="num">{fmt_value(row.get("stdev"), fmt)}</td>'
    cv_cell = f'<td class="num">{fmt_ratio(row.get("cv"))}</td>'
    badge_cell = f'<td>{verdict_badge(row.get("verdict"))}</td>'
    return (f'<tr><td class="rowlabel">{esc(row.get("label"))}</td>'
            f"{cells}{mean_cell}{stdev_cell}{cv_cell}{badge_cell}</tr>")


def _jaccard_cls(v) -> str:
    if v is None:
        return "cons-none"
    if v >= 0.5:
        return "cons-all"
    if v >= 0.2:
        return "cons-partial"
    return "cons-none"


def _jaccard_cell(v) -> str:
    return f'<td class="ctr"><span class="badge {_jaccard_cls(v)}">{fmt_ratio(v)}</span></td>'


def render(data: dict) -> str:
    repro = data.get("reproducibility")
    if not repro or not repro.get("rows"):
        return ""

    meta = data.get("meta") or {}
    # Repeatability needs at least two runs to mean anything; with one run the
    # CV is undefined and every finding is trivially "in all runs".
    if (meta.get("run_count") or 0) < 2:
        return ""

    labels = list(meta.get("run_labels") or [])
    jaccard = repro.get("jaccard") or {}
    matrix = jaccard.get("matrix") or []
    findings = data.get("findings") or {}

    # ── headline KPIs ──────────────────────────────────────────────────────
    cv_kpi = _kpi(fmt_ratio(repro.get("overall_cv")), "Overall CV",
                  verdict_badge(repro.get("overall_verdict")))
    jacc_sub = (f'{fmt_value(jaccard.get("common_count"), "int")} common of '
                f'{fmt_value(jaccard.get("union_count"), "int")} union findings')
    jacc_kpi = _kpi(fmt_ratio(jaccard.get("mean")), "Mean Jaccard Similarity", jacc_sub)
    headline = card(f'<div class="kpi-grid">{cv_kpi}{jacc_kpi}</div>')

    # ── CV table ───────────────────────────────────────────────────────────
    headers = ["Metric"] + run_headers(meta, ["Mean", "Stdev", "CV", "Verdict"])
    cv_rows_html = "".join(_cv_row(r) for r in repro.get("rows", []))
    cv_table = card(table(headers, cv_rows_html), "Per-Metric Coefficient of Variation")

    # ── Jaccard matrix ─────────────────────────────────────────────────────
    jm_html = ""
    if matrix:
        jm_headers = [""] + [esc(l) for l in labels]
        rows_html = ""
        for i, row_vals in enumerate(matrix):
            row_label = labels[i] if i < len(labels) else f"Run {i + 1}"
            cells = "".join(_jaccard_cell(v) for v in row_vals)
            rows_html += f'<tr><td class="rowlabel">{esc(row_label)}</td>{cells}</tr>'
        jm_html = card(table(jm_headers, rows_html), "Finding Overlap (Jaccard Index)")

    # ── interpretation ─────────────────────────────────────────────────────
    interp_parts = [
        "CV below 0.05 is treated as <strong>consistent</strong>, 0.05&ndash;0.20 as "
        "<strong>variable</strong>, and above 0.20 as <strong>unstable</strong> run-to-run behaviour."
    ]
    if findings.get("available"):
        interp_parts.append(
            f'Of {fmt_value(findings.get("total_unique"), "int")} unique findings across all runs, '
            f'{fmt_value(findings.get("shared_count"), "int")} appeared in every run, '
            f'{fmt_value(findings.get("partial_count"), "int")} appeared in some but not all runs, and '
            f'{fmt_value(findings.get("unique_count"), "int")} appeared in only one run.'
        )
    interpretation = note(" ".join(interp_parts))

    body = headline + cv_table + jm_html + interpretation
    subtitle = ("Findings are matched across runs by CWE plus normalised endpoint, not by title text "
                "— the model reworks finding titles between repeat runs, so title matching would "
                "understate overlap. The Jaccard index below measures overlap of these matched findings.")
    return section("repeatability", "Repeatability Analysis", body, subtitle)
