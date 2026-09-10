#!/usr/bin/env python3
"""metrics_table.py — metric group comparison table + area score table."""
from __future__ import annotations

from .base import esc, fmt_value, verdict_badge, section, table, run_headers

GROUP_ORDER = [
    "endpoint_coverage", "finding_accuracy", "exploitation",
    "reliability", "efficiency", "dedup",
]


def _stat_row(row: dict, ncols: int) -> str:
    fmt = row.get("format", "num")
    values = row.get("values") or []
    cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
    mean_cell = f'<td class="num">{fmt_value(row.get("mean"), fmt)}</td>'
    stdev_cell = f'<td class="num">{fmt_value(row.get("stdev"), fmt)}</td>'
    cv_cell = f'<td class="num">{fmt_value(row.get("cv"), "ratio")}</td>'
    badge_cell = f'<td>{verdict_badge(row.get("verdict"))}</td>'
    note = row.get("note")
    title_attr = f' title="{esc(note)}"' if note else ""
    note_html = f'<br><span class="note">{esc(note)}</span>' if note else ""
    label_cell = (f'<td class="rowlabel"{title_attr}>{esc(row.get("label"))}'
                  f"{note_html}</td>")
    return f"<tr>{label_cell}{cells}{mean_cell}{stdev_cell}{cv_cell}{badge_cell}</tr>"


def _group_row(label: str, area: str, ncols: int) -> str:
    text = esc(label)
    if area:
        text += f" &middot; {esc(area)}"
    return f'<tr class="group-row"><td colspan="{ncols}">{text}</td></tr>'


def _metrics_table(metrics: dict, meta: dict) -> str:
    headers = ["Metric"] + run_headers(meta, ["Mean", "Stdev", "CV", "Consistency"])
    ncols = len(headers)
    rows_html = ""
    for key in GROUP_ORDER:
        group = metrics.get(key)
        if not group:
            continue
        rows = group.get("rows") or []
        if not rows:
            continue
        rows_html += _group_row(group.get("label", key), group.get("area", ""), ncols)
        for row in rows:
            rows_html += _stat_row(row, ncols)
    return table(headers, rows_html)


def _area_row(row: dict, ncols: int) -> str:
    num = row.get("num", "")
    label = f'{esc(num)}. {esc(row.get("label"))}' if num else esc(row.get("label"))
    if row.get("inverse"):
        label += ' <span class="note">(cost, lower is better)</span>'
    fmt = row.get("format", "ratio")
    values = row.get("values") or []
    cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
    mean_cell = f'<td class="num">{fmt_value(row.get("mean"), fmt)}</td>'
    cv_cell = f'<td class="num">{fmt_value(row.get("cv"), "ratio")}</td>'
    method_cell = f'<td>{esc(row.get("method"))}</td>'
    return f"<tr><td class=\"rowlabel\">{label}</td>{cells}{mean_cell}{cv_cell}{method_cell}</tr>"


def _area_table(area_scores: dict, meta: dict) -> str:
    headers = ["Area"] + run_headers(meta, ["Mean", "CV", "Method"])
    ncols = len(headers)
    rows = area_scores.get("rows") or []
    rows_html = "".join(_area_row(r, ncols) for r in rows)
    return table(headers, rows_html)


def render(data: dict) -> str:
    metrics = data.get("metrics")
    area_scores = data.get("area_scores")
    meta = data.get("meta") or {}
    if not metrics and not area_scores:
        return ""

    parts = []
    if metrics:
        parts.append(_metrics_table(metrics, meta))
    if area_scores and area_scores.get("rows"):
        parts.append('<h3 class="card-title">Area Scores</h3>')
        parts.append(_area_table(area_scores, meta))

    body = "\n".join(parts)
    subtitle = ("Per-metric values across repeat runs, grouped by scoring area, "
                "with mean, spread and repeatability verdict; area-level scores follow.")
    return section("metrics", "Metrics Comparison", body, subtitle)
