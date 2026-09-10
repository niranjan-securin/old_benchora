#!/usr/bin/env python3
"""severity.py — Severity Distribution section.

Renders one stacked bar per run (critical..info), a legend, and a counts
table (Severity x Run x Mean x Total).
"""
from __future__ import annotations

from .base import (
    esc, fmt_int, fmt_num, pct_of, severity_badge, section, note, table, card,
    SEV_ORDER,
)


def _bar(run: dict, max_total: float) -> str:
    total = run.get("total") or 0
    segs = "".join(
        f'<span class="s-{sev}" style="width:{pct_of(run.get(sev, 0), max_total):.2f}%"></span>'
        for sev in SEV_ORDER
    )
    title = f'{run.get("label")} · {fmt_int(total)} findings'
    return card(f'<div class="sbar">{segs}</div>', title=title)


def _legend() -> str:
    items = "".join(
        f'<span><i style="background:var(--sev-{sev})"></i>{sev.title()}</span>'
        for sev in SEV_ORDER
    )
    return f'<div class="legend">{items}</div>'


def _counts_table(runs: list) -> str:
    n = len(runs)
    rows = []
    col_totals = [0] * n
    for sev in SEV_ORDER:
        counts = [int(r.get(sev, 0) or 0) for r in runs]
        for i, c in enumerate(counts):
            col_totals[i] += c
        mean = sum(counts) / n if n else 0.0
        total = sum(counts)
        cells = "".join(f'<td class="num">{fmt_int(c)}</td>' for c in counts)
        rows.append(
            f"<tr><td>{severity_badge(sev)}</td>{cells}"
            f'<td class="num">{fmt_num(mean, 1)}</td>'
            f'<td class="num">{fmt_int(total)}</td></tr>'
        )
    grand_total = sum(col_totals)
    total_cells = "".join(f'<td class="num">{fmt_int(c)}</td>' for c in col_totals)
    grand_mean = grand_total / n if n else 0.0
    rows.append(
        f'<tr class="total-row"><td>Total</td>{total_cells}'
        f'<td class="num">{fmt_num(grand_mean, 1)}</td>'
        f'<td class="num">{fmt_int(grand_total)}</td></tr>'
    )
    headers = ["Severity"] + [esc(r.get("label")) for r in runs] + ["Mean", "Total"]
    return table(headers, "".join(rows))


def render(data: dict) -> str:
    sev_data = data.get("severity") or {}
    runs = sev_data.get("runs") or []
    if not runs or not any((r.get("total") or 0) > 0 for r in runs):
        return ""

    max_total = sev_data.get("max_total") or max((r.get("total") or 0) for r in runs)

    bars = "".join(_bar(r, max_total) for r in runs)
    body = (
        f"{bars}"
        f"{_legend()}"
        f'{note("Bar widths are scaled against the highest single-run total "
                "(max_total) across all runs, so runs are directly comparable "
                "by length &mdash; a run with fewer findings renders a "
                "visibly shorter bar rather than always filling its row.")}'
        f"{_counts_table(runs)}"
    )
    return section("severity", "Severity Distribution", body,
                    "Findings by severity, per run, scaled for cross-run comparison.")
