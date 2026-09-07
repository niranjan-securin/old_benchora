#!/usr/bin/env python3
"""render_combined_report.py — generate a combined multi-run HTML benchmark report.

Reads multiple benchora_score.json files and produces a single report showing
all runs side-by-side with mean/stdev, reproducibility analysis, and full details.

Usage:
    python render_combined_report.py --scores run1.json run2.json run3.json \
        [--prices model_prices.json] [--output combined.html] [--model-display "Claude Opus 4.7"]
"""
from __future__ import annotations

import argparse
import html
import json
import math
import os
import sys
from datetime import datetime
from statistics import mean, stdev

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from render_benchmark_report import (
    _render_css, _clean_component_name, _esc, _fmt_num, _fmt_pct, _fmt_usd,
    _severity_badge, _render_progress_bar,
    _render_advisory_data, _render_advisory_overlay,
)


def _read_json(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _safe_mean(vals):
    nums = [v for v in vals if v is not None]
    return mean(nums) if nums else None


def _safe_stdev(vals):
    nums = [v for v in vals if v is not None]
    return stdev(nums) if len(nums) >= 2 else None


def _cv(vals):
    m = _safe_mean(vals)
    s = _safe_stdev(vals)
    if m and s and m != 0:
        return s / abs(m)
    return None


def _fmt_cv(vals):
    c = _cv(vals)
    if c is None:
        return "—"
    return f"{c:.3f}"


def _fmt_price(v):
    """Format a per-million token price. Models without prompt caching have null rates."""
    if v is None:
        return "n/a"
    return f"${v:.2f}"


def _get_nested(d, *keys, default=None):
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d


def render_combined(scores: list[dict], prices: dict | None = None, model_display: str = None) -> str:
    n = len(scores)
    model_raw = scores[0].get("model", "Unknown")
    model_name = model_display or model_raw
    target = scores[0].get("target", "Unknown")
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    merged_advisory_html: dict[str, str] = {}
    for s in scores:
        ah = s.get("advisory_html", {})
        for fid, content in ah.items():
            if fid not in merged_advisory_html:
                merged_advisory_html[fid] = content
    advisory_ids = set(merged_advisory_html.keys()) if merged_advisory_html else None

    parts = []
    parts.append(_render_css())
    parts.append(_header(model_name, target, n, now, [s.get("run_id", "") for s in scores]))
    parts.append(_kpi_summary(scores))
    parts.append(_summary_table(scores))
    parts.append(_area_scores_table(scores))
    parts.append(_reproducibility(scores))
    parts.append(_endpoint_details(scores))
    parts.append(_endpoint_cross_comparison(scores))
    parts.append(_finding_details(scores, advisory_ids))
    parts.append(_vuln_cross_comparison(scores, advisory_ids))
    parts.append(_cost_comparison(scores, prices))
    parts.append(_token_comparison(scores))
    if merged_advisory_html:
        parts.append(_render_advisory_data(merged_advisory_html))
        parts.append(_render_advisory_overlay())
    parts.append(_footer(now))

    return "\n".join(parts)


def _header(model_name, target, n, now, run_ids) -> str:
    ids_html = " &middot; ".join(f"<code>{_esc(r)}</code>" for r in run_ids)
    return f"""
<div class="report-header">
  <div class="container">
    <div class="eyebrow">Securin &middot; Application Penetration Testing &middot; AEGIS Programme &middot; Benchmark Round 1</div>
    <h1>{_esc(model_name)} &mdash; Benchmark Summary ({n} Runs)</h1>
    <div class="sub">Cross-run analysis with reproducibility metrics and full source-of-truth</div>
    <div class="meta-row">
      <span><strong>Model:</strong> <code>{_esc(model_name)}</code></span>
      <span><strong>Target:</strong> <code>{_esc(target)}</code></span>
      <span><strong>Runs:</strong> {n}</span>
      <span><strong>Generated:</strong> {_esc(now)}</span>
    </div>
    <div style="margin-top:8px;font-size:0.8rem;opacity:0.85">{ids_html}</div>
  </div>
</div>"""


def _kpi_summary(scores) -> str:
    recalls = [_get_nested(s, "accuracy", "endpoint_coverage", "recall") for s in scores]
    f1s = [_get_nested(s, "accuracy", "finding_accuracy", "f1") for s in scores]
    exploit_rates = [_get_nested(s, "accuracy", "exploitation", "exploit_rate") for s in scores]
    costs = [_get_nested(s, "cost", "full_run_usd") for s in scores]
    refusals = [_get_nested(s, "refusals", "total_refusals", default=0) for s in scores]

    kpis = [
        (_fmt_pct(_safe_mean(recalls)), "Mean Endpoint Recall"),
        (_fmt_pct(_safe_mean(f1s)), "Mean Finding F1"),
        (_fmt_pct(_safe_mean(exploit_rates)), "Mean Exploit Rate"),
        (_fmt_usd(_safe_mean(costs)), "Mean Cost"),
        (str(sum(r or 0 for r in refusals)), "Total Refusals"),
        (_fmt_cv(f1s), "CV (Finding F1)"),
        (_fmt_cv(costs), "CV (Cost)"),
    ]
    cards = "\n".join(
        f'<div class="kpi-card"><div class="kpi-val">{v}</div><div class="kpi-label">{l}</div></div>'
        for v, l in kpis
    )
    return f'<div class="container"><div class="kpi-strip" style="margin-top:-28px;position:relative;z-index:1">{cards}</div></div>'


def _summary_table(scores) -> str:
    n = len(scores)

    def _row(label, extractor, fmt_fn=None):
        if fmt_fn is None:
            fmt_fn = lambda x: _fmt_num(x, 4) if isinstance(x, float) else _fmt_num(x)
        vals = [extractor(s) for s in scores]
        m = _safe_mean(vals)
        sd = _safe_stdev(vals)
        cells = "".join(f"<td class='mono'>{fmt_fn(v)}</td>" for v in vals)
        mean_cell = f"<td class='mono' style='font-weight:600'>{fmt_fn(m)}</td>"
        sd_cell = f"<td class='mono'>{fmt_fn(sd) if sd is not None else '—'}</td>"
        return f"<tr><td style='font-weight:500'>{label}</td>{cells}{mean_cell}{sd_cell}</tr>"

    headers = "".join(f"<th>Run {i+1}</th>" for i in range(n))

    rows = []
    rows.append("<tr><td colspan='100%' style='background:var(--accent-bg);font-weight:600;color:var(--accent)'>Endpoint Coverage (Area 1)</td></tr>")
    rows.append(_row("TP", lambda s: _get_nested(s, "accuracy", "endpoint_coverage", "tp"), _fmt_num))
    rows.append(_row("Unmatched", lambda s: _get_nested(s, "accuracy", "endpoint_coverage", "unmatched"), _fmt_num))
    rows.append(_row("FN", lambda s: _get_nested(s, "accuracy", "endpoint_coverage", "fn"), _fmt_num))
    rows.append(_row("Precision", lambda s: _get_nested(s, "accuracy", "endpoint_coverage", "precision"), _fmt_pct))
    rows.append(_row("Recall", lambda s: _get_nested(s, "accuracy", "endpoint_coverage", "recall"), _fmt_pct))
    rows.append(_row("F1", lambda s: _get_nested(s, "accuracy", "endpoint_coverage", "f1")))

    rows.append("<tr><td colspan='100%' style='background:var(--accent-bg);font-weight:600;color:var(--accent)'>Vulnerability Analysis (Area 4)</td></tr>")
    rows.append(_row("TP", lambda s: _get_nested(s, "accuracy", "finding_accuracy", "tp"), _fmt_num))
    rows.append(_row("Unmatched", lambda s: _get_nested(s, "accuracy", "finding_accuracy", "unmatched"), _fmt_num))
    rows.append(_row("FN", lambda s: _get_nested(s, "accuracy", "finding_accuracy", "fn"), _fmt_num))
    rows.append(_row("Precision", lambda s: _get_nested(s, "accuracy", "finding_accuracy", "precision"), _fmt_pct))
    rows.append(_row("Recall", lambda s: _get_nested(s, "accuracy", "finding_accuracy", "recall"), _fmt_pct))
    rows.append(_row("F1", lambda s: _get_nested(s, "accuracy", "finding_accuracy", "f1")))
    rows.append(_row("OWASP Breadth", lambda s: _get_nested(s, "accuracy", "finding_accuracy", "owasp_breadth"), _fmt_num))
    rows.append(_row("Severity Accuracy", lambda s: _get_nested(s, "accuracy", "finding_accuracy", "severity_accuracy"), _fmt_pct))

    rows.append("<tr><td colspan='100%' style='background:var(--accent-bg);font-weight:600;color:var(--accent)'>Exploitation (Area 5)</td></tr>")
    rows.append(_row("Exploit Rate", lambda s: _get_nested(s, "accuracy", "exploitation", "exploit_rate"), _fmt_pct))
    rows.append(_row("Reproduced", lambda s: _get_nested(s, "accuracy", "exploitation", "reproduced"), _fmt_num))
    rows.append(_row("GT Exploitable", lambda s: _get_nested(s, "accuracy", "exploitation", "gt_exploitable"), _fmt_num))

    rows.append("<tr><td colspan='100%' style='background:var(--accent-bg);font-weight:600;color:var(--accent)'>Refusals</td></tr>")
    rows.append(_row("Total Refusals", lambda s: _get_nested(s, "refusals", "total_refusals", default=0), _fmt_num))
    rows.append(_row("Guardrail Rate", lambda s: _get_nested(s, "refusals", "guardrail_rate", default=0), _fmt_pct))

    rows.append("<tr><td colspan='100%' style='background:var(--accent-bg);font-weight:600;color:var(--accent)'>Reliability (Area 9)</td></tr>")
    rows.append(_row("Schema Pass Rate", lambda s: _get_nested(s, "reliability", "schema_pass_rate"), _fmt_pct))
    rows.append(_row("Gates Passed", lambda s: _get_nested(s, "reliability", "gates_passed"), _fmt_num))
    rows.append(_row("Gates Failed", lambda s: _get_nested(s, "reliability", "gates_failed"), _fmt_num))

    rows.append("<tr><td colspan='100%' style='background:var(--accent-bg);font-weight:600;color:var(--accent)'>Cost & Efficiency (Area 10)</td></tr>")
    rows.append(_row("Total Cost", lambda s: _get_nested(s, "cost", "full_run_usd"), _fmt_usd))
    rows.append(_row("Total Turns", lambda s: _get_nested(s, "transcripts", "total_turns"), _fmt_num))

    runtime_vals = [_get_nested(s, "cwe_cve", "runtime", "total_minutes") for s in scores]
    if any(v is not None for v in runtime_vals):
        rows.append(_row("Runtime (min)", lambda s: _get_nested(s, "cwe_cve", "runtime", "total_minutes"),
                         lambda x: f"{x:.1f}" if x is not None else "—"))

    body = "\n".join(rows)
    return f"""<div class="container">
<h2>Metrics Summary</h2>
<div class="card">
  <div class="tbl-wrap"><table>
    <thead><tr><th>Metric</th>{headers}<th>Mean</th><th>Stdev</th></tr></thead>
    <tbody>{body}</tbody>
  </table></div>
</div>
</div>"""


def _area_scores_table(scores) -> str:
    n = len(scores)
    area_names = {
        "1_recon": "Reconnaissance", "2_interaction": "Interactive Discovery",
        "3_sast": "SAST", "4_vuln_analysis": "Vulnerability Analysis",
        "5_exploitation": "Exploitation", "6_attack_path": "Attack Path",
        "7_business_logic": "Business Logic", "8_reporting": "Reporting",
        "9_reliability": "Reliability", "10_cost": "Cost Efficiency",
        "11_reproducibility": "Reproducibility",
    }

    headers = "".join(f"<th>Run {i+1}</th>" for i in range(n))
    rows = ""

    area_keys = sorted(scores[0].get("area_scores", {}).keys(),
                       key=lambda x: int(x.split("_")[0]))

    for ak in area_keys:
        name = area_names.get(ak, ak)
        num = ak.split("_")[0]
        vals = []
        cells = ""
        for s in scores:
            area = _get_nested(s, "area_scores", ak, default={})
            score_val = area.get("score")
            is_inverse = area.get("inverse", False)
            if score_val is None:
                cells += "<td class='mono' style='color:var(--text-secondary)'>—</td>"
            elif is_inverse:
                cells += f"<td class='mono'>{_fmt_usd(score_val)}</td>"
            else:
                cells += f"<td class='mono'>{score_val:.4f}</td>"
            vals.append(score_val)

        m = _safe_mean(vals)
        is_inv = any(_get_nested(s, "area_scores", ak, "inverse") for s in scores)
        if m is None:
            mean_cell = "<td class='mono' style='color:var(--text-secondary)'>—</td>"
        elif is_inv:
            mean_cell = f"<td class='mono' style='font-weight:600'>{_fmt_usd(m)}</td>"
        else:
            mean_cell = f"<td class='mono' style='font-weight:600'>{m:.4f}</td>"

        cv_val = _cv(vals)
        cv_cell = f"<td class='mono'>{cv_val:.3f}</td>" if cv_val is not None else "<td class='mono'>—</td>"

        rows += f"<tr><td><span class='area-num' style='display:inline'>{num}</span> {_esc(name)}</td>{cells}{mean_cell}{cv_cell}</tr>\n"

    return f"""<div class="container">
<h2>Area Scores Comparison</h2>
<div class="card">
  <div class="tbl-wrap"><table>
    <thead><tr><th>Area</th>{headers}<th>Mean</th><th>CV</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
  <p style="font-size:0.8rem;color:var(--text-secondary);margin-top:8px">
    CV = Coefficient of Variation (stdev / mean). Lower CV = more reproducible.
    Cost is inverse-scored (lower is better). Deferred areas show —.
  </p>
</div>
</div>"""


def _reproducibility(scores) -> str:
    metrics = {
        "Endpoint Recall": [_get_nested(s, "accuracy", "endpoint_coverage", "recall") for s in scores],
        "Endpoint F1": [_get_nested(s, "accuracy", "endpoint_coverage", "f1") for s in scores],
        "Finding Precision": [_get_nested(s, "accuracy", "finding_accuracy", "precision") for s in scores],
        "Finding Recall": [_get_nested(s, "accuracy", "finding_accuracy", "recall") for s in scores],
        "Finding F1": [_get_nested(s, "accuracy", "finding_accuracy", "f1") for s in scores],
        "Exploit Rate": [_get_nested(s, "accuracy", "exploitation", "exploit_rate") for s in scores],
        "Total Cost ($)": [_get_nested(s, "cost", "full_run_usd") for s in scores],
        "Guardrail Rate": [_get_nested(s, "refusals", "guardrail_rate", default=0) for s in scores],
        "Schema Pass Rate": [_get_nested(s, "reliability", "schema_pass_rate") for s in scores],
        "Reliability Score": [_get_nested(s, "area_scores", "9_reliability", "score") for s in scores],
    }

    rows = ""
    for name, vals in metrics.items():
        m = _safe_mean(vals)
        sd = _safe_stdev(vals)
        cv_val = _cv(vals)
        val_cells = "".join(
            f"<td class='mono'>{v:.4f}</td>" if v is not None and isinstance(v, float)
            else f"<td class='mono'>{_fmt_num(v)}</td>" if v is not None
            else "<td class='mono'>—</td>"
            for v in vals
        )

        cv_color = ""
        if cv_val is not None:
            if cv_val < 0.05:
                cv_color = "color:var(--green)"
            elif cv_val > 0.2:
                cv_color = "color:var(--red)"

        rows += f"""<tr>
  <td style='font-weight:500'>{_esc(name)}</td>
  {val_cells}
  <td class='mono'>{f'{m:.4f}' if m is not None and isinstance(m, float) else _fmt_num(m)}</td>
  <td class='mono'>{f'{sd:.4f}' if sd is not None else '—'}</td>
  <td class='mono' style='{cv_color}'>{f'{cv_val:.3f}' if cv_val is not None else '—'}</td>
</tr>"""

    n = len(scores)
    headers = "".join(f"<th>Run {i+1}</th>" for i in range(n))

    # Jaccard similarity of findings
    jaccard_html = _jaccard_analysis(scores)

    return f"""<div class="container">
<h2>Reproducibility Analysis</h2>
<div class="card">
  <h3>Coefficient of Variation (CV) Across Runs</h3>
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:12px">
    CV = stdev / mean. <span style="color:var(--green)">CV &lt; 0.05 = highly reproducible</span>.
    <span style="color:var(--red)">CV &gt; 0.20 = high variance</span>.
  </p>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Metric</th>{headers}<th>Mean</th><th>Stdev</th><th>CV</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
  {jaccard_html}
</div>
</div>"""


def _jaccard_analysis(scores) -> str:
    """Compute Jaccard similarity of TP findings between runs."""
    tp_sets = []
    for s in scores:
        tp_findings = _get_nested(s, "accuracy", "finding_accuracy", "tp_findings", default=[])
        keys = set()
        for f in tp_findings:
            cwe = f.get("cwe", "")
            title = (f.get("title", "") or "")[:60].strip().lower()
            keys.add(f"{cwe}|{title}")
        tp_sets.append(keys)

    if not any(tp_sets):
        return "<h3>Jaccard Similarity (TP Findings)</h3><p style='color:var(--text-secondary)'>TP finding details not available in score data.</p>"

    n = len(scores)
    rows = ""
    similarities = []
    for i in range(n):
        cells = ""
        for j in range(n):
            if i == j:
                cells += "<td class='mono' style='background:var(--accent-bg)'>1.000</td>"
            else:
                intersection = len(tp_sets[i] & tp_sets[j])
                union = len(tp_sets[i] | tp_sets[j])
                jac = intersection / union if union > 0 else 0
                similarities.append(jac)
                color = "color:var(--green)" if jac >= 0.5 else "color:var(--red)" if jac < 0.2 else ""
                cells += f"<td class='mono' style='{color}'>{jac:.3f}</td>"
        rows += f"<tr><td style='font-weight:500'>Run {i+1}</td>{cells}</tr>\n"

    headers = "".join(f"<th>Run {i+1}</th>" for i in range(n))
    mean_jac = mean(similarities) if similarities else 0

    # Also show what findings are shared across all runs
    if all(tp_sets):
        common = tp_sets[0]
        for s in tp_sets[1:]:
            common = common & s
        all_union = tp_sets[0]
        for s in tp_sets[1:]:
            all_union = all_union | s

        common_list = ""
        if common:
            common_items = sorted(common)
            common_list = "<br>".join(f"<code style='font-size:0.8rem'>{_esc(c)}</code>" for c in common_items[:20])
            common_list = f"""<details>
  <summary>Findings found in ALL runs ({len(common)}/{len(all_union)} unique)</summary>
  <div class="detail-body">{common_list}</div>
</details>"""
    else:
        common_list = ""

    return f"""<h3>Jaccard Similarity (TP Findings)</h3>
<p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:8px">
  Pairwise Jaccard index of TP findings (CWE + title first 60 chars). Mean = {mean_jac:.3f}.
</p>
<div class="tbl-wrap" style="max-width:400px"><table>
  <thead><tr><th></th>{headers}</tr></thead>
  <tbody>{rows}</tbody>
</table></div>
{common_list}"""


def _endpoint_details(scores) -> str:
    n = len(scores)
    sections = ""
    for i, s in enumerate(scores):
        ep = _get_nested(s, "accuracy", "endpoint_coverage", default={})
        tp_eps = ep.get("tp_endpoints", [])
        unmatched_eps = ep.get("unmatched_endpoints", [])
        fn_eps = ep.get("missed", [])
        mismatch = ep.get("method_mismatch_credited", [])

        def _ep_list(endpoints, label):
            if not endpoints:
                return ""
            items = "\n".join(
                f'<div class="ep-item"><span class="ep-method">{_esc(e.split(" ")[0])}</span> {_esc(" ".join(e.split(" ")[1:]))}</div>'
                if " " in e else f'<div class="ep-item">{_esc(e)}</div>'
                for e in endpoints
            )
            return f"""<details>
  <summary>{label} ({len(endpoints)})</summary>
  <div class="detail-body ep-list">{items}</div>
</details>"""

        run_id = s.get("run_id", f"Run {i+1}")
        tp_count = ep.get("tp", 0)
        unmatched_count = ep.get("unmatched", 0)
        fn_count = ep.get("fn", 0)

        sections += f"""<details>
  <summary>Run {i+1}: {_esc(run_id)} — TP={tp_count} Unmatched={unmatched_count} FN={fn_count}</summary>
  <div class="detail-body">
    {_ep_list(tp_eps, "✓ True Positive Endpoints")}
    {_ep_list(unmatched_eps, "? Unmatched Endpoints")}
    {_ep_list(fn_eps, "✗ False Negative (Missed) Endpoints")}
    {_ep_list(mismatch, "↔ Method Mismatch Credited")}
  </div>
</details>"""

    return f"""<div class="container">
<h2>Endpoint Coverage Details</h2>
<div class="card">
  <button class="expand-all tag" style="cursor:pointer;margin-bottom:12px">Expand all</button>
  {sections}
</div>
</div>"""


def _finding_details(scores, advisory_ids: set | None = None) -> str:
    n = len(scores)
    has_advisories = bool(advisory_ids)
    sections = ""
    for i, s in enumerate(scores):
        fa = _get_nested(s, "accuracy", "finding_accuracy", default={})
        tp_list = fa.get("tp_findings", [])
        unmatched_list = fa.get("unmatched_findings", [])
        fn_list = fa.get("missed_vulns", [])

        def _finding_table(findings, label):
            if not findings:
                return ""
            rows = ""
            for f in findings:
                ep = f.get("endpoint", "")
                if isinstance(ep, list):
                    ep = ep[0] if ep else ""
                cwe = f.get("cwe", "")
                if isinstance(cwe, list):
                    cwe = ", ".join(str(c) for c in cwe)
                sev = f.get("severity", "")
                title = f.get("title", "")
                cvss = f.get("cvss_score")
                fid = f.get("finding_id") or f.get("id") or ""
                adv_col = ""
                if has_advisories:
                    if fid and fid in advisory_ids:
                        adv_col = f"<td><button class='adv-btn' onclick=\"showAdvisory('{_esc(fid)}')\">View Advisory</button></td>"
                    else:
                        adv_col = "<td></td>"
                rows += f"<tr><td><code>{_esc(ep)}</code></td><td>{_esc(title)}</td><td><code>{_esc(cwe)}</code></td><td>{_severity_badge(sev)}</td><td class='mono'>{_fmt_num(cvss, 1) if cvss else '—'}</td>{adv_col}</tr>\n"
            adv_header = "<th>Advisory</th>" if has_advisories else ""
            return f"""<details>
  <summary>{label} ({len(findings)})</summary>
  <div class="detail-body">
    <div class="tbl-wrap"><table>
      <thead><tr><th>Endpoint</th><th>Title</th><th>CWE</th><th>Severity</th><th>CVSS</th>{adv_header}</tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
  </div>
</details>"""

        run_id = s.get("run_id", f"Run {i+1}")
        tp_count = fa.get("tp", 0)
        unmatched_count = fa.get("unmatched", 0)
        fn_count = fa.get("fn", 0)

        sections += f"""<details>
  <summary>Run {i+1}: {_esc(run_id)} — TP={tp_count} Unmatched={unmatched_count} FN={fn_count}, F1={fa.get('f1', 0):.4f}</summary>
  <div class="detail-body">
    {_finding_table(tp_list, "✓ True Positive Findings")}
    {_finding_table(unmatched_list, "? Unmatched Findings")}
    {_finding_table(fn_list, "✗ False Negative (Missed) Vulnerabilities")}
  </div>
</details>"""

    return f"""<div class="container">
<h2>Vulnerability Analysis Details</h2>
<div class="card">
  <button class="expand-all tag" style="cursor:pointer;margin-bottom:12px">Expand all</button>
  {sections}
</div>
</div>"""


def _endpoint_cross_comparison(scores) -> str:
    """Cross-run endpoint matrix: each GT endpoint as a row, runs as columns."""
    n = len(scores)
    gt_endpoints = set()
    run_tp = []
    run_unmatched = []
    for s in scores:
        ep = _get_nested(s, "accuracy", "endpoint_coverage", default={})
        if not ep.get("has_ground_truth"):
            return ""
        tp_eps = set(ep.get("tp_endpoints", []))
        unmatched_eps = set(ep.get("unmatched_endpoints", []))
        fn_eps = set(ep.get("missed", []))
        gt_endpoints |= tp_eps | fn_eps
        run_tp.append(tp_eps)
        run_unmatched.append(unmatched_eps)

    if not gt_endpoints:
        return ""

    headers = "".join(f"<th>Run {i+1}</th>" for i in range(n))
    rows = ""
    for ep in sorted(gt_endpoints):
        cells = ""
        for i in range(n):
            if ep in run_tp[i]:
                cells += "<td style='text-align:center;color:var(--green);font-weight:600'>&#10003;</td>"
            else:
                cells += "<td style='text-align:center;color:var(--red);font-weight:600'>&#10007;</td>"
        hit_count = sum(1 for i in range(n) if ep in run_tp[i])
        consistency = f"{hit_count}/{n}"
        rows += f"<tr><td><code style='font-size:0.8rem'>{_esc(ep)}</code></td>{cells}<td class='mono' style='text-align:center'>{consistency}</td></tr>\n"

    # Unmatched endpoints (not in GT)
    all_unmatched = set()
    for um_set in run_unmatched:
        all_unmatched |= um_set
    unmatched_only = all_unmatched - gt_endpoints
    unmatched_rows = ""
    for ep in sorted(unmatched_only):
        cells = ""
        for i in range(n):
            if ep in run_unmatched[i]:
                cells += "<td style='text-align:center;color:var(--orange);font-size:0.8rem'>Unmatched</td>"
            else:
                cells += "<td style='text-align:center'>—</td>"
        unmatched_rows += f"<tr style='background:var(--bg-muted)'><td><code style='font-size:0.8rem'>{_esc(ep)}</code></td>{cells}<td></td></tr>\n"

    return f"""<div class="container">
<h2>Endpoint Cross-Run Matrix</h2>
<div class="card">
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:12px">
    Each row = one GT endpoint. &#10003; = found (TP), &#10007; = missed (FN).
    {f'<span style="color:var(--orange)">Unmatched</span> rows are findings not in ground truth.' if unmatched_only else ''}
  </p>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Endpoint</th>{headers}<th>Consistency</th></tr></thead>
    <tbody>{rows}{unmatched_rows}</tbody>
  </table></div>
</div>
</div>"""


def _vuln_cross_comparison(scores, advisory_ids: set | None = None) -> str:
    """Cross-run vulnerability matrix: each finding keyed by CWE+title, runs as columns."""
    n = len(scores)
    has_advisories = bool(advisory_ids)

    all_vulns = {}
    run_tp_keys = []
    run_um_keys = []
    for i, s in enumerate(scores):
        fa = _get_nested(s, "accuracy", "finding_accuracy", default={})
        if not fa.get("has_ground_truth"):
            return ""
        tp_map = {}
        for f in fa.get("tp_findings", []):
            cwe = str(f.get("cwe", ""))
            title = (f.get("title", "") or "")[:60].strip()
            key = f"{cwe}|{title}".lower()
            tp_map[key] = f
            if key not in all_vulns:
                all_vulns[key] = f
        um_map = {}
        for f in fa.get("unmatched_findings", []):
            cwe = str(f.get("cwe", ""))
            title = (f.get("title", "") or "")[:60].strip()
            key = f"{cwe}|{title}".lower()
            um_map[key] = f
            if key not in all_vulns:
                all_vulns[key] = f
        for f in fa.get("missed_vulns", []):
            cwe = str(f.get("cwe", ""))
            title = (f.get("title", "") or "")[:60].strip()
            key = f"{cwe}|{title}".lower()
            if key not in all_vulns:
                all_vulns[key] = f
        run_tp_keys.append(tp_map)
        run_um_keys.append(um_map)

    if not all_vulns:
        return ""

    headers = "".join(f"<th>Run {i+1}</th>" for i in range(n))
    adv_header = "<th>Advisory</th>" if has_advisories else ""
    rows = ""
    for key in sorted(all_vulns.keys()):
        f = all_vulns[key]
        cwe = str(f.get("cwe", ""))
        title = (f.get("title", "") or "")[:60].strip()
        sev = f.get("severity", "")
        cells = ""
        any_fid = ""
        for i in range(n):
            if key in run_tp_keys[i]:
                cells += "<td style='text-align:center;color:var(--green);font-weight:600'>TP</td>"
                fid = run_tp_keys[i][key].get("finding_id") or run_tp_keys[i][key].get("id") or ""
                if fid:
                    any_fid = fid
            elif key in run_um_keys[i]:
                cells += "<td style='text-align:center;color:var(--orange);font-weight:600'>Unmatched</td>"
                fid = run_um_keys[i][key].get("finding_id") or run_um_keys[i][key].get("id") or ""
                if fid:
                    any_fid = fid
            else:
                cells += "<td style='text-align:center;color:var(--red)'>FN</td>"
        tp_count = sum(1 for i in range(n) if key in run_tp_keys[i])
        adv_col = ""
        if has_advisories:
            if any_fid and any_fid in advisory_ids:
                adv_col = f"<td><button class='adv-btn' onclick=\"showAdvisory('{_esc(any_fid)}')\">View</button></td>"
            else:
                adv_col = "<td></td>"
        rows += f"<tr><td><code>{_esc(cwe)}</code></td><td style='font-size:0.82rem'>{_esc(title)}</td><td>{_severity_badge(sev)}</td>{cells}<td class='mono' style='text-align:center'>{tp_count}/{n}</td>{adv_col}</tr>\n"

    return f"""<div class="container">
<h2>Vulnerability Cross-Run Matrix</h2>
<div class="card">
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:12px">
    Each row = one unique finding (CWE + title). Shows TP/Unmatched/FN status per run.
  </p>
  <div class="tbl-wrap"><table>
    <thead><tr><th>CWE</th><th>Title</th><th>Severity</th>{headers}<th>TP Rate</th>{adv_header}</tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</div>
</div>"""


def _cost_comparison(scores, prices) -> str:
    n = len(scores)

    # Collect all component names across all runs
    all_comps = set()
    for s in scores:
        by_comp = _get_nested(s, "cost", "by_component", default={})
        all_comps.update(by_comp.keys())

    headers = "".join(f"<th>Run {i+1}</th>" for i in range(n))
    rows = ""

    # Total row
    totals = [_get_nested(s, "cost", "full_run_usd", default=0) for s in scores]
    total_cells = "".join(f"<td class='mono' style='font-weight:600'>{_fmt_usd(t)}</td>" for t in totals)
    m = _safe_mean(totals)
    rows += f"<tr style='background:var(--accent-bg)'><td style='font-weight:700'>Total</td>{total_cells}<td class='mono' style='font-weight:700'>{_fmt_usd(m)}</td></tr>\n"

    for comp in sorted(all_comps):
        name = _clean_component_name(comp)
        vals = [_get_nested(s, "cost", "by_component", comp, default=0) for s in scores]
        cells = "".join(f"<td class='mono'>{_fmt_usd(v)}</td>" for v in vals)
        m = _safe_mean(vals)
        rows += f"<tr><td>{_esc(name)}</td>{cells}<td class='mono'>{_fmt_usd(m)}</td></tr>\n"

    # Price info
    price_html = ""
    if prices:
        p_in = prices.get("input_per_million") or 0
        p_out = prices.get("output_per_million") or 0
        p_cw = prices.get("cache_write_per_million") or 0
        p_cr = prices.get("cache_read_per_million") or 0
        price_html = f"""<h3>Pricing (per million tokens)</h3>
<div class="metric-grid">
  <div class="metric-box"><div class="val">{_fmt_price(prices.get("input_per_million"))}</div><div class="label">Input</div></div>
  <div class="metric-box"><div class="val">{_fmt_price(prices.get("output_per_million"))}</div><div class="label">Output</div></div>
  <div class="metric-box"><div class="val">{_fmt_price(prices.get("cache_write_per_million"))}</div><div class="label">Cache Write</div></div>
  <div class="metric-box"><div class="val">{_fmt_price(prices.get("cache_read_per_million"))}</div><div class="label">Cache Read</div></div>
</div>"""

    # Cost derivation for each run
    derivation = ""
    if prices:
        p_in = prices.get("input_per_million") or 0
        p_out = prices.get("output_per_million") or 0
        p_cw = prices.get("cache_write_per_million") or 0
        p_cr = prices.get("cache_read_per_million") or 0
        for i, s in enumerate(scores):
            t = _get_nested(s, "transcripts", "total_tokens", default={})
            ti = t.get("input", 0)
            to = t.get("output", 0)
            tcw = t.get("cache_write", 0)
            tcr = t.get("cache_read", 0)
            c_in = ti * p_in / 1e6
            c_out = to * p_out / 1e6
            c_cw = tcw * p_cw / 1e6
            c_cr = tcr * p_cr / 1e6
            total = c_in + c_out + c_cw + c_cr
            derivation += f"""<details>
  <summary>Run {i+1} Cost Derivation — {_fmt_usd(total)}</summary>
  <div class="detail-body">
    <div class="formula">Input:       {ti:>14,} × ${p_in}/M = ${c_in:>10,.2f}
Output:      {to:>14,} × ${p_out}/M = ${c_out:>10,.2f}
Cache Write: {tcw:>14,} × ${p_cw}/M = ${c_cw:>10,.2f}
Cache Read:  {tcr:>14,} × ${p_cr}/M = ${c_cr:>10,.2f}
{'─' * 52}
Total:       {ti+to+tcw+tcr:>14,}          = ${total:>10,.2f}</div>
  </div>
</details>"""

    return f"""<div class="container">
<h2>Cost Comparison</h2>
<div class="card">
  {price_html}
  <h3>By Component</h3>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Component</th>{headers}<th>Mean</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
  {derivation}
</div>
</div>"""


def _token_comparison(scores) -> str:
    n = len(scores)
    headers = "".join(f"<th>Run {i+1}</th>" for i in range(n))

    token_types = ["input", "output", "cache_write", "cache_read"]
    labels = {"input": "Input", "output": "Output", "cache_write": "Cache Write", "cache_read": "Cache Read"}

    rows = ""
    for tt in token_types:
        vals = [_get_nested(s, "transcripts", "total_tokens", tt, default=0) for s in scores]
        cells = "".join(f"<td class='mono'>{v:,}</td>" for v in vals)
        m = _safe_mean(vals)
        rows += f"<tr><td>{labels[tt]}</td>{cells}<td class='mono' style='font-weight:600'>{int(m):,}</td></tr>\n"

    # Total
    totals = []
    for s in scores:
        t = _get_nested(s, "transcripts", "total_tokens", default={})
        totals.append(sum(t.get(k, 0) for k in token_types))
    total_cells = "".join(f"<td class='mono' style='font-weight:600'>{v:,}</td>" for v in totals)
    m_total = _safe_mean(totals)
    rows += f"<tr style='background:var(--accent-bg)'><td style='font-weight:700'>Total</td>{total_cells}<td class='mono' style='font-weight:700'>{int(m_total):,}</td></tr>\n"

    # Turns
    turns = [_get_nested(s, "transcripts", "total_turns", default=0) for s in scores]
    turn_cells = "".join(f"<td class='mono'>{v:,}</td>" for v in turns)
    m_turns = _safe_mean(turns)
    rows += f"<tr><td>Total Turns</td>{turn_cells}<td class='mono'>{int(m_turns):,}</td></tr>\n"

    return f"""<div class="container">
<h2>Token Consumption</h2>
<div class="card">
  <div class="tbl-wrap"><table>
    <thead><tr><th>Token Type</th>{headers}<th>Mean</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</div>
</div>"""


def _footer(now) -> str:
    return f"""<div class="report-footer">
  <div class="container">
    <strong>Securin</strong> &middot; Internal &middot; Confidential &middot; v1.0<br>
    AEGIS Programme &middot; Benchmark Round 1<br>
    Generated by <code>render_combined_report.py</code> on {_esc(now)}
  </div>
</div>"""


def main():
    ap = argparse.ArgumentParser(description="Generate combined multi-run benchmark report")
    ap.add_argument("--scores", nargs="+", required=True, help="Paths to benchora_score.json files")
    ap.add_argument("--prices", default=None, help="Path to model_prices.json")
    ap.add_argument("--output", default=None, help="Output HTML path")
    ap.add_argument("--model-display", default=None, help="Display name for model (e.g. 'Claude Opus 4.7')")
    args = ap.parse_args()

    scores = []
    for p in args.scores:
        s = _read_json(p)
        if not s:
            print(f"ERROR: Cannot read {p}", file=sys.stderr)
            sys.exit(1)
        scores.append(s)

    prices = None
    if args.prices:
        all_prices = _read_json(args.prices)
        if all_prices:
            model = scores[0].get("model", "")
            prices = all_prices.get(model) or all_prices.get(f"anthropic/{model}")

    html_content = render_combined(scores, prices, args.model_display)

    output = args.output
    if not output:
        output = os.path.join(os.path.dirname(args.scores[0]), "combined_report.html")

    with open(output, "w", encoding="utf-8", newline="") as f:
        f.write("<!doctype html>\n<html lang='en'>\n<head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>\n")
        f.write(html_content.split("</style>")[0] + "</style>\n</head>\n<body>\n<!--email_off-->\n")
        f.write(html_content.split("</style>", 1)[1])
        f.write("\n<!--/email_off-->\n</body>\n</html>")

    print(f"Combined report written to {output}")
    print(f"  Runs: {len(scores)}")
    print(f"  Model: {scores[0].get('model', '?')}")


if __name__ == "__main__":
    main()
