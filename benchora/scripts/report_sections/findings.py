#!/usr/bin/env python3
"""findings.py — Vulnerability Findings section.

Per-run summary cards, classification counts, the main findings table
(one row per finding, status per run, agreement badge), expandable detail
blocks per finding, and a "missed vulnerabilities" table.
"""
from __future__ import annotations

from .base import (
    esc, fmt_int, fmt_num, fmt_pct, fmt_ratio, severity_badge, status_cell,
    consistency_badge, bool_mark, section, card, table, note, DASH,
)

TITLE_MAX = 90


def _truncate(s, n=TITLE_MAX) -> str:
    s = str(s or "")
    if len(s) <= n:
        return s
    return s[: n - 1].rstrip() + "…"


def _run_cards(per_run: list) -> str:
    cells = []
    for r in per_run:
        body = f"""<div class="meta-grid">
          <div><b>TP</b>{fmt_int(r.get("tp"))}</div>
          <div><b>Unmatched</b>{fmt_int(r.get("unmatched"))}</div>
          <div><b>FN</b>{fmt_int(r.get("fn"))}</div>
          <div><b>Precision</b>{fmt_pct(r.get("precision"))}</div>
          <div><b>Recall</b>{fmt_pct(r.get("recall"))}</div>
          <div><b>F1</b>{fmt_ratio(r.get("f1"))}</div>
        </div>"""
        cells.append(card(body, title=esc(r.get("label"))))
    return f'<div class="kpi-grid">{"".join(cells)}</div>'


def _classification_line(fdata: dict) -> str:
    items = [
        ("Shared", fdata.get("shared_count")),
        ("Partial", fdata.get("partial_count")),
        ("Unique", fdata.get("unique_count")),
        ("Total Unique", fdata.get("total_unique")),
    ]
    kpis = "".join(
        f'<div class="kpi"><div class="kpi-val">{fmt_int(v)}</div>'
        f'<div class="kpi-label">{esc(label)}</div></div>'
        for label, v in items
    )
    return card(f'<div class="kpi-grid">{kpis}</div>',
                title="Finding Classification")


def _main_table(rows: list, run_labels: list) -> str:
    n_runs = len(run_labels)
    headers = (["Severity", "CWE", "Endpoint", "Title"]
               + list(run_labels) + ["Agreement"])
    body_rows = []
    for row in rows:
        status = row.get("status") or []
        status_cells = "".join(
            status_cell(status[i] if i < len(status) else None)
            for i in range(n_runs)
        )
        present = row.get("present_count")
        agreement = consistency_badge(present, n_runs) if present is not None else DASH
        body_rows.append(
            f"<tr>"
            f"<td>{severity_badge(row.get('severity'))}</td>"
            f"<td>{esc(row.get('cwe'))}</td>"
            f"<td><code>{esc(row.get('endpoint'))}</code></td>"
            f"<td>{esc(_truncate(row.get('title')))}</td>"
            f"{status_cells}"
            f"<td>{agreement}</td>"
            f"</tr>"
        )
    return table(headers, "".join(body_rows))


def _detail_block(row: dict, run_labels: list) -> str:
    variants_html = ""
    if (row.get("title_variants") or 0) > 1:
        titles = row.get("titles_per_run") or []
        items = "".join(
            f"<div><b>{esc(run_labels[i] if i < len(run_labels) else f'Run {i + 1}')}</b>"
            f"{esc(titles[i])}</div>"
            for i in range(len(titles))
        )
        variants_html = (
            f'{note("The model reworded the same underlying vulnerability "
                     "differently across runs; per-run titles are shown below.")}'
            f'<div class="meta-grid">{items}</div>'
        )
    meta = f"""<div class="meta-grid">
      <div><b>Endpoint (raw)</b><code>{esc(row.get("endpoint_raw"))}</code></div>
      <div><b>CWE</b>{esc(row.get("cwe"))}</div>
      <div><b>Severity</b>{severity_badge(row.get("severity"))}</div>
      <div><b>CVSS</b>{fmt_num(row.get("cvss"), 1)}</div>
      <div><b>Finding ID</b><code>{esc(row.get("finding_id"))}</code></div>
    </div>"""
    summary = esc(_truncate(row.get("title"), 140))
    return f"""<details>
      <summary>{summary}</summary>
      <div class="detail-body">
        <p>{esc(row.get("title"))}</p>
        {meta}
        {variants_html}
      </div>
    </details>"""


def _missed_table(missed: list, run_labels: list) -> str:
    n_runs = len(run_labels)
    headers = (["GT ID", "Severity", "CWE", "Endpoint", "Title"]
               + [f"Missed in {esc(l)}" for l in run_labels] + ["Consistency"])
    body_rows = []
    for m in missed:
        missed_by = m.get("missed_by") or []
        mark_cells = "".join(
            f'<td class="ctr">{bool_mark(missed_by[i] if i < len(missed_by) else False)}</td>'
            for i in range(n_runs)
        )
        body_rows.append(
            f"<tr>"
            f"<td>{esc(m.get('id'))}</td>"
            f"<td>{severity_badge(m.get('severity'))}</td>"
            f"<td>{esc(m.get('cwe'))}</td>"
            f"<td><code>{esc(m.get('endpoint'))}</code></td>"
            f"<td>{esc(_truncate(m.get('title')))}</td>"
            f"{mark_cells}"
            f"<td>{esc(m.get('consistency'))}</td>"
            f"</tr>"
        )
    return table(headers, "".join(body_rows))


def render(data: dict) -> str:
    fdata = (data or {}).get("findings") or {}
    if fdata.get("available") is False:
        return ""

    meta = (data or {}).get("meta") or {}
    run_labels = meta.get("run_labels") or []
    rows = fdata.get("rows") or []
    missed = fdata.get("missed") or []
    per_run = fdata.get("per_run") or []

    parts = []
    if per_run:
        parts.append(_run_cards(per_run))
    parts.append(_classification_line(fdata))

    if rows:
        parts.append(f'<h3 class="card-title">All Findings ({fmt_int(len(rows))})</h3>')
        parts.append(_main_table(rows, run_labels))
        details = "".join(_detail_block(r, run_labels) for r in rows)
        parts.append(f'<h3 class="card-title">Finding Details</h3>{details}')

    if missed:
        parts.append(
            f'<h3 class="card-title">Missed Vulnerabilities ({fmt_int(len(missed))})</h3>'
        )
        parts.append(_missed_table(missed, run_labels))

    body = "".join(parts)
    return section("findings", "Vulnerability Findings", body,
                    "Per-finding agreement across runs, matched against ground truth; "
                    "expand a row for full detail, including reworded titles.")
