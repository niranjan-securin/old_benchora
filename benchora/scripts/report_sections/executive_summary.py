#!/usr/bin/env python3
"""executive_summary.py — KPI grid + per-run comparison table for the report."""
from __future__ import annotations

from .base import esc, fmt_value, verdict_badge, section, table, run_headers


def _kpi_card(row: dict) -> str:
    label = esc(row.get("label"))
    fmt = row.get("format", "num")
    mean_val = fmt_value(row.get("mean"), fmt)
    values = row.get("values") or []
    vals_str = " / ".join(fmt_value(v, fmt) for v in values)
    badge = verdict_badge(row.get("verdict"))
    return f"""<div class="kpi">
  <div class="kpi-val">{mean_val}</div>
  <div class="kpi-label">{label}</div>
  <div class="kpi-sub">{vals_str} &middot; {badge}</div>
</div>"""


def _table_row(row: dict) -> str:
    fmt = row.get("format", "num")
    values = row.get("values") or []
    cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
    mean_cell = f'<td class="num">{fmt_value(row.get("mean"), fmt)}</td>'
    stdev_cell = f'<td class="num">{fmt_value(row.get("stdev"), fmt)}</td>'
    cv_cell = f'<td class="num">{fmt_value(row.get("cv"), "ratio")}</td>'
    badge_cell = f'<td>{verdict_badge(row.get("verdict"))}</td>'
    return (f'<tr><td class="rowlabel">{esc(row.get("label"))}</td>'
            f"{cells}{mean_cell}{stdev_cell}{cv_cell}{badge_cell}</tr>")


def render(data: dict) -> str:
    kpis = data.get("kpis")
    meta = data.get("meta") or {}
    if not kpis:
        return ""

    grid = '<div class="kpi-grid">' + "".join(_kpi_card(k) for k in kpis) + "</div>"

    headers = ["KPI"] + run_headers(meta, ["Mean", "Stdev", "CV", "Verdict"])
    rows_html = "".join(_table_row(k) for k in kpis)
    comparison_table = table(headers, rows_html)

    body = grid + comparison_table
    subtitle = (f"Mean across {meta.get('run_count', len(kpis and kpis[0].get('values') or []))} "
                f"repeat runs, with per-run spread and repeatability verdict.")
    return section("summary", "Executive Summary", body, subtitle)
