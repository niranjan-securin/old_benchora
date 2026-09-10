#!/usr/bin/env python3
"""cost_tokens.py — cost summary, per-component cost (when available), pricing,
token consumption and runtime for the comparison report."""
from __future__ import annotations

from .base import (
    esc, fmt_value, fmt_usd, fmt_pct, fmt_min, verdict_badge,
    section, card, table, run_headers,
)


def _cost_summary(cost: dict, meta: dict) -> str:
    totals = cost.get("totals") or {}
    fmt = totals.get("format", "usd")
    sources = cost.get("sources") or []
    src_text = ", ".join(sorted(set(esc(s) for s in sources))) if sources else "&mdash;"
    values = totals.get("values") or []
    lo = min(values) if values else None
    hi = max(values) if values else None
    grid = f"""<div class="meta-grid">
      <div><b>Mean Total Cost</b>{fmt_value(totals.get('mean'), fmt)}</div>
      <div><b>Min</b>{fmt_value(lo, fmt)}</div>
      <div><b>Max</b>{fmt_value(hi, fmt)}</div>
      <div><b>CV</b>{fmt_value(totals.get('cv'), 'ratio')} {verdict_badge(totals.get('verdict'))}</div>
      <div><b>Cost Source(s)</b>{src_text}</div>
    </div>"""
    return card(grid, "Cost Summary")


def _per_run_cost_table(cost: dict, meta: dict) -> str:
    totals = cost.get("totals") or {}
    fmt = totals.get("format", "usd")
    values = totals.get("values") or []
    headers = ["Metric"] + run_headers(meta, ["Mean", "Stdev", "CV"])
    cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
    row = (f'<tr><td class="rowlabel">{esc(totals.get("label", "Total Cost"))}</td>{cells}'
           f'<td class="num">{fmt_value(totals.get("mean"), fmt)}</td>'
           f'<td class="num">{fmt_value(totals.get("stdev"), fmt)}</td>'
           f'<td class="num">{fmt_value(totals.get("cv"), "ratio")}</td></tr>')
    return table(headers, row)


def _component_block(cost: dict, meta: dict) -> str:
    if not cost.get("breakdown_available"):
        warn = (f'<p class="tone-warn">{esc(cost.get("breakdown_note") or "")}</p>')
        return card(warn, "Per-Component Cost")
    by_component = cost.get("by_component") or []
    headers = ["Component"] + run_headers(meta, ["Mean", "Share"])
    rows_html = ""
    for row in by_component:
        fmt = row.get("format", "usd")
        values = row.get("values") or []
        cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
        rows_html += (f'<tr><td class="rowlabel">{esc(row.get("label"))}</td>{cells}'
                       f'<td class="num">{fmt_value(row.get("mean"), fmt)}</td>'
                       f'<td class="num">{fmt_pct(row.get("share"))}</td></tr>')
    return table(headers, rows_html)


def _pricing_table(prices: dict) -> str:
    if prices is None:
        return ""
    labels = [
        ("input_per_million", "Input / M tokens"),
        ("output_per_million", "Output / M tokens"),
        ("cache_write_per_million", "Cache Write / M tokens"),
        ("cache_read_per_million", "Cache Read / M tokens"),
    ]
    rows_html = ""
    for key, label in labels:
        if key.startswith("_"):
            continue
        rows_html += (f'<tr><td class="rowlabel">{esc(label)}</td>'
                       f'<td class="num">{fmt_usd(prices.get(key))}</td></tr>')
    return card(table(["Rate", "Price"], rows_html), "Pricing")


def _token_table(tokens: dict, meta: dict) -> str:
    headers = ["Token Type"] + run_headers(meta, ["Mean"])
    rows_html = ""
    for row in tokens.get("rows") or []:
        fmt = row.get("format", "int")
        values = row.get("values") or []
        cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
        rows_html += (f'<tr><td class="rowlabel">{esc(row.get("label"))}</td>{cells}'
                       f'<td class="num">{fmt_value(row.get("mean"), fmt)}</td></tr>')
    totals = tokens.get("totals") or {}
    if totals:
        fmt = totals.get("format", "int")
        values = totals.get("values") or []
        cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
        rows_html += (f'<tr class="total-row"><td class="rowlabel">{esc(totals.get("label", "Total Tokens"))}</td>'
                       f'{cells}<td class="num">{fmt_value(totals.get("mean"), fmt)}</td></tr>')
    turns = tokens.get("turns") or {}
    if turns:
        fmt = turns.get("format", "int")
        values = turns.get("values") or []
        cells = "".join(f'<td class="num">{fmt_value(v, fmt)}</td>' for v in values)
        rows_html += (f'<tr><td class="rowlabel">{esc(turns.get("label", "Total Turns"))}</td>'
                       f'{cells}<td class="num">{fmt_value(turns.get("mean"), fmt)}</td></tr>')
    return table(headers, rows_html)


def _runtime_block(runtime: dict, meta: dict) -> str:
    if not runtime or not runtime.get("available"):
        return ""
    total = runtime.get("total") or {}
    values = total.get("values") or []
    headers = ["Metric"] + run_headers(meta, ["Mean"])
    cells = "".join(f'<td class="num">{fmt_min(v)}</td>' for v in values)
    row = (f'<tr><td class="rowlabel">{esc(total.get("label", "Runtime (min)"))}</td>{cells}'
           f'<td class="num">{fmt_min(total.get("mean"))}</td></tr>')
    return card(table(headers, row), "Runtime")


def render(data: dict) -> str:
    cost = data.get("cost") or {}
    tokens = data.get("tokens") or {}
    runtime = data.get("runtime") or {}
    meta = data.get("meta") or {}
    if not cost and not tokens:
        return ""

    parts = []
    if cost:
        parts.append(_cost_summary(cost, meta))
        parts.append(card(_per_run_cost_table(cost, meta), "Cost by Run"))
        parts.append(_component_block(cost, meta))
        pricing = _pricing_table(cost.get("prices"))
        if pricing:
            parts.append(pricing)
    if tokens:
        parts.append(card(_token_table(tokens, meta), "Token Consumption"))
    rt = _runtime_block(runtime, meta)
    if rt:
        parts.append(rt)

    body = "\n".join(p for p in parts if p)
    subtitle = ("Run cost, token consumption and wall-clock runtime across repeat runs.")
    return section("cost", "Cost & Token Consumption", body, subtitle)
