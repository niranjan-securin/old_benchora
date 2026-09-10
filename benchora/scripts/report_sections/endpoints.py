#!/usr/bin/env python3
"""endpoints.py — endpoint coverage: ground truth hits + unmatched discoveries."""
from __future__ import annotations

from .base import (
    esc, fmt_int, fmt_value, bool_mark, consistency_badge, section, card,
    table, note, run_headers,
)

_SORT_KEY = {"none": 0, "partial": 1, "all": 2}
UNMATCHED_COLLAPSE_THRESHOLD = 60


def _find_recall_mean(metrics: dict):
    rows = ((metrics or {}).get("endpoint_coverage") or {}).get("rows") or []
    for row in rows:
        if row.get("key") == "recall":
            return fmt_value(row.get("mean"), row.get("format", "pct"))
    return None


def _summary_card(ep: dict, metrics: dict) -> str:
    recall = _find_recall_mean(metrics)
    cells = [
        ("Ground Truth Endpoints", fmt_int(ep.get("gt_total"))),
        ("Found In All Runs", fmt_int(ep.get("all_found_count"))),
        ("Never Found", fmt_int(ep.get("never_found_count"))),
        ("Recall (Mean)", recall if recall is not None else fmt_int(None)),
    ]
    divs = "".join(f"<div><b>{esc(l)}</b>{v}</div>" for l, v in cells)
    return card(f'<div class="meta-grid">{divs}</div>', title="Coverage Summary")


def _gt_table(ep: dict, meta: dict) -> str:
    rows = list(ep.get("gt_rows") or [])
    run_count = len(meta.get("run_labels") or []) or (
        len(rows[0].get("hits") or []) if rows else 0)
    rows.sort(key=lambda r: _SORT_KEY.get(r.get("classification"), 1))

    headers = ["Endpoint"] + run_headers(meta, ["Consistency"])
    rows_html = ""
    for r in rows:
        hits = r.get("hits") or []
        ep_cell = f'<td><code>{esc(r.get("endpoint"))}</code></td>'
        run_cells = "".join(
            f'<td class="ctr">{bool_mark(h)}</td>' for h in hits)
        cons_cell = (f'<td>{consistency_badge(r.get("hit_count"), run_count)}'
                     f'</td>')
        rows_html += f"<tr>{ep_cell}{run_cells}{cons_cell}</tr>"

    tbl = table(headers, rows_html)
    sort_note = note(
        "Sorted worst-first: endpoints never found, then partially found, "
        "then endpoints found in every run.")
    return tbl + sort_note


def _unmatched_table(ep: dict, meta: dict) -> str:
    rows = ep.get("unmatched_rows") or []
    if not rows:
        return ""
    run_count = len(meta.get("run_labels") or []) or (
        len(rows[0].get("present") or []) if rows else 0)

    headers = ["Endpoint"] + run_headers(meta, ["Seen In"])
    rows_html = ""
    for r in rows:
        present = r.get("present") or []
        ep_cell = f'<td><code>{esc(r.get("endpoint"))}</code></td>'
        run_cells = "".join(
            f'<td class="ctr">{bool_mark(p)}</td>' for p in present)
        seen_cell = (f'<td>{consistency_badge(r.get("hit_count"), run_count)}'
                     f'</td>')
        rows_html += f"<tr>{ep_cell}{run_cells}{seen_cell}</tr>"

    intro = note(
        "These endpoints were discovered by the crawler but do not appear in "
        "the ground-truth inventory. Their status is <strong>unknown</strong> "
        "&mdash; they are not confirmed false positives, and may simply be "
        "missing from ground truth.")
    tbl = table(headers, rows_html)

    if len(rows) > UNMATCHED_COLLAPSE_THRESHOLD:
        return (intro + f'<details><summary>Show {len(rows)} unmatched '
                f'endpoints</summary><div class="detail-body">{tbl}</div>'
                f'</details>')
    return intro + tbl


def render(data: dict) -> str:
    ep = (data or {}).get("endpoints") or {}
    if ep.get("available") is False:
        return ""

    meta = data.get("meta") or {}
    metrics = data.get("metrics") or {}

    parts = [_summary_card(ep, metrics), _gt_table(ep, meta)]
    unmatched = _unmatched_table(ep, meta)
    if unmatched:
        parts.append('<h3 class="card-title">Unmatched Discoveries</h3>')
        parts.append(unmatched)

    body = "\n".join(parts)
    subtitle = ("Ground-truth endpoint hits per run, plus endpoints "
                "discovered that fall outside the ground-truth inventory.")
    return section("endpoints", "Endpoint Coverage", body, subtitle)
