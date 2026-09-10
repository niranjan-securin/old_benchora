#!/usr/bin/env python3
"""components.py — gate status grid + runtime-by-component table."""
from __future__ import annotations

from .base import (
    esc, fmt_min, pct_of, bool_mark, consistency_badge, section, card,
    table, note, run_headers, DASH,
)


def _status_cell(status) -> str:
    if status is None:
        return f'<td class="ctr st-absent">{DASH}</td>'
    s = str(status).upper()
    if s == "PASS":
        cls = "cons-all"
    elif s in ("FAIL", "ERROR"):
        cls = "cons-none"
    else:
        cls = "cons-partial"
    return f'<td class="ctr"><span class="badge {cls}">{esc(s)}</span></td>'


def _gate_row(row: dict, run_count: int) -> str:
    cells = "".join(_status_cell(s) for s in (row.get("status") or []))
    badge = consistency_badge(row.get("pass_count"), run_count)
    label_cell = f'<td class="rowlabel">{esc(row.get("label"))}</td>'
    return f"<tr>{label_cell}{cells}<td class=\"ctr\">{badge}</td></tr>"


def _produced_row(row: dict) -> str:
    marks = "".join(
        f'<td class="ctr">{bool_mark(p)}</td>' for p in (row.get("produced_output") or [])
    )
    label_cell = f'<td class="rowlabel">{esc(row.get("label"))}</td>'
    produced = row.get("produced_count")
    summary = f'<td class="ctr num">{DASH if produced is None else produced}</td>'
    return f"<tr>{label_cell}{marks}{summary}</tr>"


def _gate_table(rows: list, meta: dict) -> str:
    run_count = len(meta.get("run_labels") or [])
    headers = ["Component"] + run_headers(meta, ["Gates Passed"])
    ordered = sorted(rows, key=lambda r: r.get("all_pass", True))
    rows_html = "".join(_gate_row(r, run_count) for r in ordered)
    return table(headers, rows_html)


def _produced_table(rows: list, meta: dict) -> str:
    headers = ["Component"] + run_headers(meta, ["Produced (of runs)"])
    ordered = sorted(rows, key=lambda r: r.get("all_pass", True))
    rows_html = "".join(_produced_row(r) for r in ordered)
    return table(headers, rows_html)


def _runtime_row(row: dict, max_mean: float) -> str:
    label_cell = f'<td class="rowlabel">{esc(row.get("label"))}</td>'
    cells = "".join(f'<td class="num">{fmt_min(v)}</td>' for v in (row.get("values") or []))
    mean = row.get("mean")
    width = pct_of(mean, max_mean)
    bar = f'<div class="bar"><span style="width:{width:.1f}%"></span></div>'
    mean_cell = f'<td class="num">{fmt_min(mean)}<br>{bar}</td>'
    return f"<tr>{label_cell}{cells}{mean_cell}</tr>"


def _runtime_table(runtime: dict, meta: dict) -> str:
    by_component = runtime.get("by_component") or []
    means = [r.get("mean") for r in by_component if r.get("mean") is not None]
    max_mean = max(means) if means else 0
    headers = ["Component"] + run_headers(meta, ["Mean (min)"])
    rows_html = "".join(_runtime_row(r, max_mean) for r in by_component)
    return table(headers, rows_html)


def render(data: dict) -> str:
    components = data.get("components") or {}
    if not components.get("available"):
        return ""

    meta = data.get("meta") or {}
    rows = components.get("rows") or []
    runtime = data.get("runtime") or {}

    parts = []

    gate_body = _gate_table(rows, meta)
    parts.append(card(
        gate_body,
        title="Gate Status by Run",
    ))
    parts.append(note(
        "Components that did not pass their gate in every run are listed first, "
        "so the interesting cases surface at the top; components passing 3/3 "
        "follow beneath them."
    ))

    produced_body = _produced_table(rows, meta)
    parts.append(card(
        produced_body,
        title="Produced Output vs. Gate Passed",
    ))
    parts.append(note(
        "A gate can PASS in a run even when the component produced no usable output "
        "for it (see api_testing and cross_app above): the gate checks that the "
        "component ran and exited cleanly, not that its output was non-empty. "
        "“Produced” counts the runs with actual output, independent of gate status."
    ))

    if runtime.get("available"):
        runtime_body = _runtime_table(runtime, meta)
        parts.append(card(runtime_body, title="Runtime by Component"))
        parts.append(note(
            "The orchestrator row is the wall-clock duration of the entire run, not a "
            "discrete pipeline phase — it spans and overlaps every component below it, "
            "so it should not be summed with the others as if it were additive."
        ))

    ignored = components.get("ignored_gate_keys") or []
    if ignored:
        keys = ", ".join(f"<code>{esc(k)}</code>" for k in ignored)
        parts.append(note(
            f"Excluded from this table: {keys} — these are progress-marker files "
            "written by the orchestrator, not gates for a pipeline component."
        ))

    body = "\n".join(parts)
    subtitle = ("Per-component gate outcomes across repeat runs, whether each run "
                "produced usable output, and per-component runtime.")
    return section("components", "Component Pipeline", body, subtitle)
