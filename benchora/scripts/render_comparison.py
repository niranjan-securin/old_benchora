#!/usr/bin/env python3
"""render_comparison.py — render comparison.json to Markdown + premium HTML report.

Generates:
  - comparison.md   — Results Card + per-area detail + cross-model summary
  - comparison.html — standalone styled HTML with Chart.js charts, heatmap,
                      radar diagrams, severity bars, CWE coverage, runtime

Usage:
    render_comparison.py --comparison <path> [--output-dir <dir>]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

RATING_COLORS = {
    "Leading": "#22c55e", "Strong": "#3b82f6", "Adequate": "#f59e0b",
    "Weak": "#f97316", "Not viable": "#ef4444",
}
RATING_COLORS_DARK = {
    "Leading": "#4ade80", "Strong": "#60a5fa", "Adequate": "#fbbf24",
    "Weak": "#fb923c", "Not viable": "#f87171",
}
RATING_BG = {
    "Leading": "#dcfce7", "Strong": "#dbeafe", "Adequate": "#fef3c7",
    "Weak": "#ffedd5", "Not viable": "#fee2e2",
}
RATING_BG_DARK = {
    "Leading": "#14532d", "Strong": "#1e3a5f", "Adequate": "#78350f",
    "Weak": "#7c2d12", "Not viable": "#7f1d1d",
}

AREA_NAMES = {
    "1_recon": "Recon & Surface", "2_interaction": "Interaction",
    "3_sast": "SAST", "4_vuln_analysis": "Vuln Analysis",
    "5_exploitation": "Exploitation", "6_attack_path": "Attack Path",
    "7_business_logic": "Business Logic", "8_reporting": "Reporting",
    "9_reliability": "Reliability", "10_cost": "Cost", "11_reproducibility": "Reproducibility",
}

AREA_NAMES_FULL = {
    "1_recon": "Recon & Attack Surface", "2_interaction": "Live Application Interaction",
    "3_sast": "SAST", "4_vuln_analysis": "Vulnerability Analysis",
    "5_exploitation": "Exploitation & PoC", "6_attack_path": "Attack Path",
    "7_business_logic": "Business Logic & Research", "8_reporting": "Reporting & Evidence",
    "9_reliability": "Operational Reliability", "10_cost": "Cost Efficiency",
    "11_reproducibility": "Reproducibility",
}

MODEL_COLORS = [
    "#3b82f6", "#ef4444", "#22c55e", "#f59e0b", "#8b5cf6",
    "#ec4899", "#06b6d4", "#f97316", "#84cc16", "#6366f1",
]
MODEL_COLORS_ALPHA = [c + "33" for c in MODEL_COLORS]



def _um(d, default=None):
    """Unmatched count, accepting the legacy "fp" key."""
    if not isinstance(d, dict):
        return default
    for k in ("unmatched", "fp"):
        if d.get(k) is not None:
            return d[k]
    return default


def _um_eps(d):
    if not isinstance(d, dict):
        return []
    for k in ("unmatched_endpoints", "false_positives"):
        if d.get(k) is not None:
            return d[k]
    return []


def _um_finds(d):
    if not isinstance(d, dict):
        return []
    for k in ("unmatched_findings", "fp_findings"):
        if d.get(k) is not None:
            return d[k]
    return []


def _short(model_id: str) -> str:
    parts = model_id.split("/")
    return parts[-1] if len(parts) > 1 else model_id


def _fmt(val, area_key: str = "") -> str:
    if val is None: return "N/A"
    if area_key == "10_cost": return f"${val:.2f}"
    if isinstance(val, float): return f"{val:.3f}"
    return str(val)


# ─── Markdown ──────────────────────────────────────────────────────────────────

def render_markdown(data: dict) -> str:
    lines = []
    lines.append(f"# AEGIS Model Benchmark — {data['target']}")
    lines.append(f"\n**Compared:** {data['compared_at'][:10]}  \n**Models:** {data['model_count']}\n")

    v = data.get("verdict", {})
    lines.append("## Verdict\n")
    if v.get("recommended"): lines.append(f"**Recommended:** {_short(v['recommended'])}  ")
    if v.get("runner_up"): lines.append(f"**Runner-up:** {_short(v['runner_up'])}  ")
    if v.get("cost_leader"): lines.append(f"**Cost leader:** {_short(v['cost_leader'])}  ")

    lines.append("\n## Overall Ranking\n\n| Rank | Model | Score |\n|------|-------|-------|")
    for mid, d in sorted(data.get("overall", {}).items(), key=lambda x: x[1]["rank"]):
        lines.append(f"| #{d['rank']} | {_short(mid)} | {d['overall_score']:.4f} |")

    ar = data.get("area_ratings", {})
    models = data.get("models", [])
    lines.append("\n## Per-Area Ratings\n")
    lines.append("| Area | " + " | ".join(_short(m) for m in models) + " |")
    lines.append("|------|" + "|".join("------" for _ in models) + "|")
    for ak in sorted(ar.keys()):
        cells = []
        for m in models:
            d = ar[ak].get(m, {})
            cells.append(f"{d.get('rating','N/A')} ({_fmt(d.get('mean'), ak)})")
        lines.append(f"| {AREA_NAMES_FULL.get(ak, ak)} | " + " | ".join(cells) + " |")

    lines.append("\n## Area Detail\n")
    for ak in sorted(ar.keys()):
        leader = data.get("area_leaders", {}).get(ak, "?")
        lines.append(f"### {AREA_NAMES_FULL.get(ak, ak)}\n**Leader:** {_short(leader)}\n")
        lines.append("| Rank | Model | Rating | Mean | Stdev |\n|------|-------|--------|------|-------|")
        for mid, d in sorted(ar[ak].items(), key=lambda x: x[1].get("rank", 99)):
            lines.append(f"| #{d.get('rank','?')} | {_short(mid)} | {d.get('rating','N/A')} "
                         f"| {_fmt(d.get('mean'), ak)} | {_fmt(d.get('stdev'))} |")
        lines.append("")

    md = data.get("model_details", {})
    if any(md[m].get("cwe_count", 0) > 0 for m in md):
        lines.append("## CWE Coverage\n")
        lines.append("| Model | Unique CWEs | OWASP Coverage | Mean CVSS | Findings |")
        lines.append("|-------|------------|----------------|-----------|----------|")
        for mid in models:
            d = md.get(mid, {})
            lines.append(f"| {_short(mid)} | {d.get('cwe_count',0)} | "
                         f"{d.get('owasp_coverage',0):.0%} | "
                         f"{d.get('cvss_mean','N/A')} | {d.get('mean_findings',0)} |")

    if any(md[m].get("mean_runtime_min") for m in md):
        lines.append("\n## Runtime\n\n| Model | Avg Runtime (min) | Avg Cost |\n|-------|-------------------|----------|")
        for mid in models:
            d = md.get(mid, {})
            rt = d.get("mean_runtime_min")
            lines.append(f"| {_short(mid)} | {rt or 'N/A'} | ${d.get('mean_cost',0):.2f} |")

    if data.get("structural_failures"):
        lines.append("\n## Structural Failures\n")
        for mid, fails in data["structural_failures"].items():
            lines.append(f"- **{_short(mid)}:** {', '.join(fails)}")

    lines.append("\n---\n*Generated by Benchora — AEGIS Model Benchmark*")
    return "\n".join(lines)


# ─── Chart.js data builder ─────────────────────────────────────────────────────

def _build_chart_data(data: dict) -> str:
    models = data.get("models", [])
    ar = data.get("area_ratings", {})
    overall = data.get("overall", {})
    md = data.get("model_details", {})
    area_keys = sorted(ar.keys())

    ranking = []
    for mid, d in sorted(overall.items(), key=lambda x: x[1]["rank"]):
        ranking.append({"name": _short(mid), "score": d["overall_score"], "rank": d["rank"]})

    radar_data = {}
    for mid in models:
        scores = []
        for ak in area_keys:
            d = ar[ak].get(mid, {})
            m = d.get("mean")
            if ak == "10_cost":
                vals = [ar[ak][x].get("mean") or 999999 for x in models
                        if ar[ak].get(x, {}).get("mean") is not None]
                best = min(vals) if vals else 1
                scores.append(round(best / m, 3) if m and m > 0 else 0)
            else:
                scores.append(round(m, 3) if m is not None else 0)
        radar_data[_short(mid)] = scores

    severity_data = {}
    for mid in models:
        d = md.get(mid, {})
        sev = d.get("severity", {})
        severity_data[_short(mid)] = {
            "critical": sev.get("critical", 0), "high": sev.get("high", 0),
            "medium": sev.get("medium", 0), "low": sev.get("low", 0),
        }

    runtime_data = []
    cost_data = []
    findings_data = []
    cwe_data = []
    for mid in models:
        d = md.get(mid, {})
        name = _short(mid)
        runtime_data.append({"name": name, "value": d.get("mean_runtime_min") or 0})
        cost_data.append({"name": name, "value": d.get("mean_cost", 0)})
        findings_data.append({"name": name, "value": d.get("mean_findings", 0)})
        cwe_data.append({
            "name": name, "cwe_count": d.get("cwe_count", 0),
            "owasp_coverage": d.get("owasp_coverage", 0),
            "cvss_mean": d.get("cvss_mean"),
        })

    return json.dumps({
        "models": [_short(m) for m in models],
        "colors": MODEL_COLORS[:len(models)],
        "colors_alpha": MODEL_COLORS_ALPHA[:len(models)],
        "area_labels": [AREA_NAMES.get(ak, ak) for ak in area_keys],
        "ranking": ranking,
        "radar": radar_data,
        "severity": severity_data,
        "runtime": runtime_data,
        "cost": cost_data,
        "findings": findings_data,
        "cwe": cwe_data,
    })


def _build_model_detail_html(models: list, md: dict) -> str:
    """Build detailed per-model source truth sections with GT accuracy, cost, tokens, duplicates, refusals."""
    import html as htmlmod

    sections = ""
    for mid in models:
        mdata = md.get(mid, {})
        run_details = mdata.get("run_details", [])
        if not run_details:
            continue
        name = _short(mid)
        model_id = mid.replace('"', '&quot;')

        runs_html = ""
        for rd in run_details:
            run_id = htmlmod.escape(rd.get("run_id", "unknown"))

            # GT Accuracy — Endpoints
            ep_html = ""
            ec = rd.get("endpoint_coverage")
            if ec:
                missed_list = "".join(f"<li><code>{htmlmod.escape(str(e))}</code></li>" for e in (ec.get("missed") or []))
                unmatched_list = "".join(f"<li><code>{htmlmod.escape(str(e))}</code></li>" for e in _um_eps(ec))
                ep_html = (f'<div class="gt-block"><h5>Endpoint Coverage</h5>'
                    f'<div class="gt-metrics">'
                    f'<span class="gt-tp">TP={ec["tp"]}</span> '
                    f'<span class="gt-unmatched">Unmatched={_um(ec)}</span> '
                    f'<span class="gt-fn">FN={ec["fn"]}</span> '
                    f'<span>P={_fmt(ec.get("precision"))}</span> '
                    f'<span>R={_fmt(ec.get("recall"))}</span> '
                    f'<span>F1={_fmt(ec.get("f1"))}</span></div>')
                if missed_list:
                    ep_html += f'<details><summary>Missed endpoints ({ec["fn"]})</summary><ul class="gt-list">{missed_list}</ul></details>'
                if unmatched_list:
                    ep_html += f'<details><summary>Unmatched ({_um(ec)})</summary><ul class="gt-list">{unmatched_list}</ul></details>'
                ep_html += '</div>'

            # GT Accuracy — Findings
            fa_html = ""
            fa = rd.get("finding_accuracy")
            if fa:
                tp_list = ""
                for f in (fa.get("tp_findings") or []):
                    label = htmlmod.escape(str(f.get("gt_id", "") or f.get("title", "")))
                    tp_list += f"<li>{label}</li>"
                unmatched_list = ""
                for f in _um_finds(fa):
                    t = htmlmod.escape(f.get("title", ""))
                    cwe = f.get("cwe", "")
                    unmatched_list += f"<li>CWE-{cwe}: {t}</li>"
                missed_list = ""
                for v in (fa.get("missed_vulns") or []):
                    label = htmlmod.escape(str(v.get("id", "") or v.get("title", "")))
                    desc = htmlmod.escape(str(v.get("title", "") or v.get("vuln_class", "")))
                    missed_list += f"<li><strong>{label}</strong>: {desc}</li>"

                fa_html = (f'<div class="gt-block"><h5>Finding Accuracy (vs Ground Truth)</h5>'
                    f'<div class="gt-metrics">'
                    f'<span class="gt-tp">TP={fa["tp"]}</span> '
                    f'<span class="gt-unmatched">Unmatched={_um(fa)}</span> '
                    f'<span class="gt-fn">FN={fa["fn"]}</span> '
                    f'<span>P={_fmt(fa.get("precision"))}</span> '
                    f'<span>R={_fmt(fa.get("recall"))}</span> '
                    f'<span>F1={_fmt(fa.get("f1"))}</span></div>')
                if tp_list:
                    fa_html += f'<details><summary>True positives ({fa["tp"]})</summary><ul class="gt-list">{tp_list}</ul></details>'
                if unmatched_list:
                    fa_html += f'<details><summary>Unmatched ({_um(fa)})</summary><ul class="gt-list">{unmatched_list}</ul></details>'
                if missed_list:
                    fa_html += f'<details><summary>Missed vulnerabilities ({fa["fn"]})</summary><ul class="gt-list">{missed_list}</ul></details>'
                fa_html += '</div>'

            # Exploitation
            ex_html = ""
            ex = rd.get("exploitation")
            if ex:
                ex_html = (f'<div class="gt-block"><h5>Exploitation</h5>'
                    f'<div class="gt-metrics">'
                    f'<span>Rate={_fmt(ex.get("exploit_rate"))}</span> '
                    f'<span>Reproduced={ex.get("reproduced",0)}</span> '
                    f'<span>GT exploitable={ex.get("gt_exploitable",0)}</span></div></div>')

            # Cost breakdown
            cost = rd.get("cost", {})
            cost_rows = ""
            by_comp = cost.get("by_component", {})
            for comp, c in sorted(by_comp.items(), key=lambda x: -(x[1] if isinstance(x[1], (int, float)) else 0)):
                val = c if isinstance(c, (int, float)) else 0
                cost_rows += f"<tr><td>{htmlmod.escape(comp)}</td><td>${val:,.4f}</td></tr>"
            cost_html = ""
            if cost_rows:
                cost_html = (f'<div class="gt-block"><h5>Cost Breakdown (source: {htmlmod.escape(cost.get("source","transcript"))})</h5>'
                    f'<div class="gt-metrics"><span><strong>Total: ${cost.get("full_run_usd",0):,.2f}</strong></span></div>'
                    f'<details><summary>By component</summary>'
                    f'<table class="compact"><thead><tr><th>Component</th><th>Cost</th></tr></thead>'
                    f'<tbody>{cost_rows}</tbody></table></details></div>')

            # Token usage
            tokens = rd.get("tokens", {})
            tok_in = tokens.get("input", 0)
            tok_out = tokens.get("output", 0)
            tok_cw = tokens.get("cache_write", 0)
            tok_cr = tokens.get("cache_read", 0)
            tok_total = tok_in + tok_out + tok_cw + tok_cr
            tok_by_comp = rd.get("tokens_by_component", {})
            tok_rows = ""
            for comp, t in sorted(tok_by_comp.items(), key=lambda x: -(x[1].get("input", 0) + x[1].get("output", 0) + x[1].get("cache_write", 0) + x[1].get("cache_read", 0))):
                ctotal = t.get("input", 0) + t.get("output", 0) + t.get("cache_write", 0) + t.get("cache_read", 0)
                tok_rows += (f"<tr><td>{htmlmod.escape(comp)}</td>"
                    f"<td>{t.get('input',0):,}</td><td>{t.get('output',0):,}</td>"
                    f"<td>{t.get('cache_write',0):,}</td><td>{t.get('cache_read',0):,}</td>"
                    f"<td>{ctotal:,}</td></tr>")
            tok_html = (f'<div class="gt-block"><h5>Token Usage</h5>'
                f'<div class="gt-metrics">'
                f'<span>Input: {tok_in:,}</span> <span>Output: {tok_out:,}</span> '
                f'<span>Cache Write: {tok_cw:,}</span> <span>Cache Read: {tok_cr:,}</span> '
                f'<span><strong>Total: {tok_total:,}</strong></span></div>')
            if tok_rows:
                tok_html += (f'<details><summary>By component</summary>'
                    f'<table class="compact"><thead><tr><th>Component</th><th>Input</th><th>Output</th>'
                    f'<th>Cache W</th><th>Cache R</th><th>Total</th></tr></thead>'
                    f'<tbody>{tok_rows}</tbody></table></details>')
            tok_html += '</div>'

            # Duplicates
            dupes = rd.get("duplicates", {})
            dupes_html = (f'<div class="gt-block"><h5>Dedup Analysis</h5>'
                f'<div class="gt-metrics">'
                f'<span>Pre-dedup: {dupes.get("pre_dedup",0)}</span> '
                f'<span>Post-dedup: {dupes.get("post_dedup",0)}</span> '
                f'<span>Ratio: {_fmt(dupes.get("dedup_ratio"))}</span> '
                f'<span>AEGIS merges: {dupes.get("aegis_merges",0)}</span> '
                f'<span>Content dupes: {dupes.get("content_duplicates",0)}</span> '
                f'<span>Cross-comp overlaps: {dupes.get("cross_component_overlaps",0)}</span></div></div>')

            # Refusals
            ref = rd.get("refusals", {})
            ref_by_comp = ref.get("by_component", {})
            ref_comp_list = "".join(f"<li>{htmlmod.escape(k)}: {v}</li>" for k, v in ref_by_comp.items())
            ref_html = (f'<div class="gt-block"><h5>Refusals</h5>'
                f'<div class="gt-metrics">'
                f'<span>Total: {ref.get("total",0)}</span> '
                f'<span>Guardrail rate: {_fmt(ref.get("guardrail_rate"))}</span></div>')
            if ref_comp_list:
                ref_html += f'<details><summary>By component</summary><ul class="gt-list">{ref_comp_list}</ul></details>'
            ref_html += '</div>'

            # Reliability
            rel = rd.get("reliability", {})
            rel_html = (f'<div class="gt-block"><h5>Reliability</h5>'
                f'<div class="gt-metrics">'
                f'<span>Schema pass: {_fmt(rel.get("schema_pass_rate"))}</span> '
                f'<span>Gates passed: {rel.get("gates_passed",0)}</span> '
                f'<span>Gates failed: {rel.get("gates_failed",0)}</span></div></div>')

            runs_html += (f'<div class="run-detail"><h4>{run_id}</h4>'
                f'{ep_html}{fa_html}{ex_html}{cost_html}{tok_html}{dupes_html}{ref_html}{rel_html}</div>')

        sections += (f'<div class="model-detail-section">'
            f'<h3 class="model-detail-title" onclick="this.parentElement.classList.toggle(\'open\')">'
            f'{htmlmod.escape(name)} <span class="toggle-icon">&#9654;</span></h3>'
            f'<div class="model-detail-body">{runs_html}</div></div>')

    if not sections:
        return ""
    return (f'<h2>Per-Model Source Truth Detail</h2>'
            f'<p style="color:var(--muted);font-size:0.82rem;margin-bottom:1rem;">'
            f'Expandable detail for each model run — GT accuracy TP/Unmatched/FN, missed vulns, '
            f'cost breakdown, token usage, dedup analysis, refusals, reliability.</p>'
            f'{sections}')


# ─── HTML report ───────────────────────────────────────────────────────────────

def render_html(data: dict) -> str:
    models = data.get("models", [])
    ar = data.get("area_ratings", {})
    overall = data.get("overall", {})
    verdict = data.get("verdict", {})
    md = data.get("model_details", {})
    area_keys = sorted(ar.keys())

    overall_rows = ""
    for mid, d in sorted(overall.items(), key=lambda x: x[1]["rank"]):
        rank = d["rank"]
        cls = {1: ' class="rank-1"', 2: ' class="rank-2"', 3: ' class="rank-3"'}.get(rank, "")
        bar_w = d["overall_score"] * 100
        overall_rows += (f'<tr{cls}><td class="rank-num">#{rank}</td>'
                        f'<td class="model-name">{_short(mid)}</td>'
                        f'<td><div class="score-bar"><div class="score-fill" style="width:{bar_w}%"></div>'
                        f'<span>{d["overall_score"]:.4f}</span></div></td></tr>\n')

    heatmap_header = "".join(f"<th>{_short(m)}</th>" for m in models)
    heatmap_rows = ""
    for ak in area_keys:
        an = AREA_NAMES.get(ak, ak)
        cells = ""
        for m in models:
            d = ar[ak].get(m, {})
            rating = d.get("rating", "N/A")
            mean_val = _fmt(d.get("mean"), ak)
            cells += (f'<td class="hm-cell" data-rating="{rating}">'
                     f'<span class="hm-rating">{rating}</span>'
                     f'<span class="hm-score">{mean_val}</span></td>')
        heatmap_rows += f'<tr><td class="area-label">{an}</td>{cells}</tr>\n'

    area_details = ""
    for ak in area_keys:
        an = AREA_NAMES_FULL.get(ak, ak)
        leader = data.get("area_leaders", {}).get(ak, "?")
        rows = ""
        for mid, d in sorted(ar[ak].items(), key=lambda x: x[1].get("rank", 99)):
            rating = d.get("rating", "N/A")
            rows += (f'<tr><td>#{d.get("rank","?")}</td><td>{_short(mid)}</td>'
                    f'<td class="rating-cell" data-rating="{rating}">{rating}</td>'
                    f'<td>{_fmt(d.get("mean"), ak)}</td><td>{_fmt(d.get("stdev"))}</td></tr>\n')
        area_details += (f'<div class="detail-card"><h3>{an}</h3>'
                        f'<p class="detail-leader">Leader: <strong>{_short(leader)}</strong></p>'
                        f'<table><thead><tr><th>Rank</th><th>Model</th><th>Rating</th>'
                        f'<th>Mean</th><th>Stdev</th></tr></thead><tbody>{rows}</tbody></table></div>\n')

    failures_html = ""
    if data.get("structural_failures"):
        items = "".join(f'<li><strong>{_short(m)}:</strong> {", ".join(f)}</li>'
                       for m, f in data["structural_failures"].items())
        failures_html = f'<section class="failures"><h2>Structural Failures</h2><ul>{items}</ul></section>'

    model_detail_html = _build_model_detail_html(models, md)

    chart_json = _build_chart_data(data)

    has_runtime = any(md.get(m, {}).get("mean_runtime_min") for m in models)
    has_cwe = any(md.get(m, {}).get("cwe_count", 0) > 0 for m in models)

    runtime_section = ""
    if has_runtime:
        runtime_section = """<div class="chart-row">
    <div class="chart-box"><h3>Average Runtime (minutes)</h3><div class="chart-wrap"><canvas id="runtimeChart"></canvas></div></div>
    <div class="chart-box"><h3>Average Cost (USD)</h3><div class="chart-wrap"><canvas id="costChart"></canvas></div></div>
</div>"""

    cwe_section = ""
    if has_cwe:
        cwe_rows = ""
        for mid in models:
            d = md.get(mid, {})
            sev = d.get("severity", {})
            cvss_m = d.get("cvss_mean")
            cwe_rows += (f'<tr><td>{_short(mid)}</td><td>{d.get("cwe_count",0)}</td>'
                        f'<td>{d.get("owasp_coverage",0):.0%}</td>'
                        f'<td>{cvss_m if cvss_m else "N/A"}</td>'
                        f'<td class="sev-cell"><span class="sev-c">{sev.get("critical",0)}</span> / '
                        f'<span class="sev-h">{sev.get("high",0)}</span> / '
                        f'<span class="sev-m">{sev.get("medium",0)}</span> / '
                        f'<span class="sev-l">{sev.get("low",0)}</span></td>'
                        f'<td>{d.get("mean_findings",0):.0f}</td></tr>\n')
        cwe_section = f"""<h2>CWE / CVE / Severity</h2>
<div class="chart-row">
    <div class="chart-box wide"><div class="chart-wrap chart-wide"><canvas id="severityChart"></canvas></div></div>
</div>
<div class="cwe-table"><table><thead><tr>
    <th>Model</th><th>Unique CWEs</th><th>OWASP Coverage</th><th>Mean CVSS</th>
    <th>C / H / M / L</th><th>Findings</th></tr></thead>
    <tbody>{cwe_rows}</tbody></table></div>"""

    # The full HTML document
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS Benchmark — {data['target']}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
:root {{
    --bg: #f8fafc; --fg: #0f172a; --muted: #64748b; --border: #e2e8f0;
    --card: #ffffff; --card-hover: #f1f5f9; --accent: #3b82f6; --accent2: #6366f1;
    --sev-c: #dc2626; --sev-h: #ea580c; --sev-m: #d97706; --sev-l: #65a30d;
    --bar-bg: #e2e8f0; --rank1: #ca8a04; --rank2: #9ca3af; --rank3: #c2410c;
    --leading: #22c55e; --leading-bg: #dcfce7;
    --strong: #3b82f6; --strong-bg: #dbeafe;
    --adequate: #f59e0b; --adequate-bg: #fef3c7;
    --weak: #f97316; --weak-bg: #ffedd5;
    --noviable: #ef4444; --noviable-bg: #fee2e2;
    --grid: #e2e8f0; --tooltip-bg: #0f172a; --tooltip-fg: #f8fafc;
}}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
        --bg: #0c0f1a; --fg: #e2e8f0; --muted: #94a3b8; --border: #1e293b;
        --card: #151b2e; --card-hover: #1e2642; --accent: #60a5fa; --accent2: #818cf8;
        --sev-c: #f87171; --sev-h: #fb923c; --sev-m: #fbbf24; --sev-l: #a3e635;
        --bar-bg: #1e293b; --rank1: #fbbf24; --rank2: #cbd5e1; --rank3: #fb923c;
        --leading: #4ade80; --leading-bg: #14532d;
        --strong: #60a5fa; --strong-bg: #1e3a5f;
        --adequate: #fbbf24; --adequate-bg: #78350f;
        --weak: #fb923c; --weak-bg: #7c2d12;
        --noviable: #f87171; --noviable-bg: #7f1d1d;
        --grid: #1e293b; --tooltip-bg: #e2e8f0; --tooltip-fg: #0f172a;
    }}
}}
:root[data-theme="dark"] {{
    --bg: #0c0f1a; --fg: #e2e8f0; --muted: #94a3b8; --border: #1e293b;
    --card: #151b2e; --card-hover: #1e2642; --accent: #60a5fa; --accent2: #818cf8;
    --sev-c: #f87171; --sev-h: #fb923c; --sev-m: #fbbf24; --sev-l: #a3e635;
    --bar-bg: #1e293b; --rank1: #fbbf24; --rank2: #cbd5e1; --rank3: #fb923c;
    --leading: #4ade80; --leading-bg: #14532d;
    --strong: #60a5fa; --strong-bg: #1e3a5f;
    --adequate: #fbbf24; --adequate-bg: #78350f;
    --weak: #fb923c; --weak-bg: #7c2d12;
    --noviable: #f87171; --noviable-bg: #7f1d1d;
    --grid: #1e293b; --tooltip-bg: #e2e8f0; --tooltip-fg: #0f172a;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg); color: var(--fg);
    line-height: 1.6; max-width: 1320px; margin: 0 auto; padding: 2.5rem 2rem;
}}
h1 {{ font-size: 2rem; font-weight: 700; letter-spacing: -0.02em; }}
h2 {{ font-size: 1.25rem; font-weight: 600; margin: 2.5rem 0 1rem; color: var(--accent); letter-spacing: -0.01em; }}
h3 {{ font-size: 1rem; font-weight: 600; margin-bottom: 0.5rem; }}
.header {{ margin-bottom: 2rem; }}
.header-row {{ display: flex; align-items: baseline; gap: 1rem; flex-wrap: wrap; }}
.meta {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem; }}
.verdict-strip {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem; margin: 1.5rem 0 2.5rem;
}}
.v-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 1.25rem 1.5rem; text-align: center; transition: background 0.15s;
}}
.v-card:hover {{ background: var(--card-hover); }}
.v-label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); font-weight: 500; }}
.v-value {{ font-size: 1.15rem; font-weight: 700; margin-top: 0.35rem; color: var(--accent); }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-bottom: 1.5rem; }}
th, td {{ padding: 0.5rem 0.7rem; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ font-weight: 600; color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; }}
.rank-num {{ font-weight: 700; font-variant-numeric: tabular-nums; width: 3rem; }}
.rank-1 .rank-num {{ color: var(--rank1); }}
.rank-2 .rank-num {{ color: var(--rank2); }}
.rank-3 .rank-num {{ color: var(--rank3); }}
.model-name {{ font-weight: 600; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }}
.score-bar {{
    position: relative; background: var(--bar-bg); border-radius: 6px;
    height: 24px; overflow: hidden;
}}
.score-fill {{
    position: absolute; top: 0; left: 0; height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    border-radius: 6px; transition: width 0.8s cubic-bezier(0.22, 1, 0.36, 1);
}}
.score-bar span {{
    position: relative; z-index: 1; padding: 0 0.6rem;
    font-size: 0.75rem; font-weight: 600; line-height: 24px;
    font-variant-numeric: tabular-nums;
}}
.heatmap-wrap {{ overflow-x: auto; margin-bottom: 2rem; }}
.heatmap-wrap table {{ min-width: 600px; }}
.area-label {{ font-weight: 600; white-space: nowrap; font-size: 0.78rem; }}
.hm-cell {{ text-align: center; padding: 0.4rem 0.5rem; border-radius: 6px; }}
.hm-cell[data-rating="Leading"] {{ background: var(--leading-bg); color: var(--leading); }}
.hm-cell[data-rating="Strong"] {{ background: var(--strong-bg); color: var(--strong); }}
.hm-cell[data-rating="Adequate"] {{ background: var(--adequate-bg); color: var(--adequate); }}
.hm-cell[data-rating="Weak"] {{ background: var(--weak-bg); color: var(--weak); }}
.hm-cell[data-rating="Not viable"] {{ background: var(--noviable-bg); color: var(--noviable); }}
.hm-rating {{ display: block; font-weight: 700; font-size: 0.72rem; }}
.hm-score {{ display: block; font-size: 0.65rem; opacity: 0.8; font-variant-numeric: tabular-nums; }}
.rating-cell[data-rating="Leading"] {{ color: var(--leading); font-weight: 700; }}
.rating-cell[data-rating="Strong"] {{ color: var(--strong); font-weight: 700; }}
.rating-cell[data-rating="Adequate"] {{ color: var(--adequate); font-weight: 700; }}
.rating-cell[data-rating="Weak"] {{ color: var(--weak); font-weight: 700; }}
.rating-cell[data-rating="Not viable"] {{ color: var(--noviable); font-weight: 700; }}
.chart-row {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
    gap: 1.5rem; margin-bottom: 2rem;
}}
.chart-box {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.25rem 1.5rem;
}}
.chart-box.wide {{ grid-column: 1 / -1; }}
.chart-box h3 {{ font-size: 0.85rem; color: var(--muted); margin-bottom: 0.75rem; }}
.chart-wrap {{ position: relative; width: 100%; }}
.chart-wide {{ max-height: 400px; }}
.detail-grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
    gap: 1rem;
}}
.detail-card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 1rem 1.25rem;
}}
.detail-leader {{ color: var(--muted); font-size: 0.8rem; margin-bottom: 0.5rem; }}
.cwe-table {{ overflow-x: auto; margin-top: 1rem; }}
.sev-c {{ color: var(--sev-c); font-weight: 700; }}
.sev-h {{ color: var(--sev-h); font-weight: 700; }}
.sev-m {{ color: var(--sev-m); font-weight: 600; }}
.sev-l {{ color: var(--sev-l); }}
.failures {{
    background: var(--noviable-bg); border: 1px solid var(--noviable);
    border-radius: 12px; padding: 1rem 1.25rem; margin: 2rem 0;
}}
.failures h2 {{ color: var(--noviable); margin: 0 0 0.5rem; }}
.failures ul {{ padding-left: 1.5rem; }}
.legend {{ display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1rem 0; font-size: 0.78rem; }}
.legend-item {{ display: flex; align-items: center; gap: 0.3rem; }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
.model-detail-section {{
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    margin-bottom: 1rem; overflow: hidden;
}}
.model-detail-title {{
    padding: 1rem 1.25rem; cursor: pointer; font-size: 1rem; font-weight: 600;
    display: flex; align-items: center; gap: 0.5rem; user-select: none;
}}
.model-detail-title:hover {{ background: var(--card-hover); }}
.toggle-icon {{ font-size: 0.7rem; transition: transform 0.2s; color: var(--muted); }}
.model-detail-section.open .toggle-icon {{ transform: rotate(90deg); }}
.model-detail-body {{ display: none; padding: 0 1.25rem 1.25rem; }}
.model-detail-section.open .model-detail-body {{ display: block; }}
.run-detail {{ margin-bottom: 1.5rem; }}
.run-detail h4 {{
    font-size: 0.82rem; font-family: 'JetBrains Mono', monospace;
    color: var(--accent); margin-bottom: 0.75rem; padding-bottom: 0.4rem;
    border-bottom: 1px solid var(--border);
}}
.gt-block {{
    margin-bottom: 0.75rem; padding: 0.6rem 0.8rem;
    background: color-mix(in srgb, var(--card-hover) 50%, transparent);
    border-radius: 8px;
}}
.gt-block h5 {{
    font-size: 0.78rem; font-weight: 600; color: var(--accent2);
    margin-bottom: 0.35rem;
}}
.gt-metrics {{
    display: flex; flex-wrap: wrap; gap: 0.5rem 1.25rem; font-size: 0.78rem;
    font-variant-numeric: tabular-nums;
}}
.gt-tp {{ color: var(--leading); font-weight: 600; }}
.gt-unmatched {{ color: var(--sev-h); font-weight: 600; }}
.gt-fn {{ color: var(--sev-c); font-weight: 600; }}
.gt-list {{ padding-left: 1.25rem; font-size: 0.75rem; margin: 0.35rem 0; }}
.gt-list li {{ margin-bottom: 0.15rem; }}
.gt-block details {{ margin-top: 0.4rem; }}
.gt-block summary {{
    font-size: 0.75rem; cursor: pointer; color: var(--accent); font-weight: 500;
}}
.gt-block summary:hover {{ text-decoration: underline; }}
table.compact {{ font-size: 0.72rem; margin-top: 0.3rem; }}
table.compact td, table.compact th {{ padding: 0.25rem 0.5rem; font-variant-numeric: tabular-nums; }}
table.compact td {{ font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; }}
footer {{
    margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border);
    text-align: center; color: var(--muted); font-size: 0.75rem;
}}
</style>
</head>
<body>

<div class="header">
    <div class="header-row">
        <h1>AEGIS Model Benchmark</h1>
    </div>
    <div class="meta">Target: <strong>{data['target']}</strong> &middot; {data['model_count']} models &middot; {data['compared_at'][:10]}</div>
</div>

<div class="verdict-strip">
    <div class="v-card"><div class="v-label">Recommended</div><div class="v-value">{_short(verdict.get('recommended','N/A'))}</div></div>
    <div class="v-card"><div class="v-label">Runner-up</div><div class="v-value">{_short(verdict.get('runner_up','') or 'N/A')}</div></div>
    <div class="v-card"><div class="v-label">Cost Leader</div><div class="v-value">{_short(verdict.get('cost_leader','') or 'N/A')}</div></div>
</div>

<h2>Overall Ranking</h2>
<table><thead><tr><th>Rank</th><th>Model</th><th>Score</th></tr></thead>
<tbody>{overall_rows}</tbody></table>

<h2>Evaluation Areas</h2>
<div class="chart-row">
    <div class="chart-box"><h3>Radar — Area Scores per Model</h3><div class="chart-wrap"><canvas id="radarChart"></canvas></div></div>
    <div class="chart-box"><h3>Average Findings per Model</h3><div class="chart-wrap"><canvas id="findingsChart"></canvas></div></div>
</div>

<h2>Rating Heatmap</h2>
<div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background:var(--leading)"></div> Leading</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--strong)"></div> Strong</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--adequate)"></div> Adequate</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--weak)"></div> Weak</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--noviable)"></div> Not viable</div>
</div>
<div class="heatmap-wrap">
<table><thead><tr><th>Area</th>{heatmap_header}</tr></thead>
<tbody>{heatmap_rows}</tbody></table>
</div>

{runtime_section}
{cwe_section}

<h2>Area Details</h2>
<div class="detail-grid">{area_details}</div>

{failures_html}

{model_detail_html}

<footer>Generated by Benchora &mdash; AEGIS Model Benchmark</footer>

<script>
const D = {chart_json};

function getCSSVar(name) {{
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}}

const chartInstances = [];

function destroyAll() {{
    chartInstances.forEach(c => c.destroy());
    chartInstances.length = 0;
}}

function chartDefaults() {{
    const fg = getCSSVar('--fg');
    const muted = getCSSVar('--muted');
    const grid = getCSSVar('--grid');
    Chart.defaults.color = muted;
    Chart.defaults.borderColor = grid;
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.pointStyleWidth = 8;
    Chart.defaults.plugins.tooltip.backgroundColor = getCSSVar('--tooltip-bg');
    Chart.defaults.plugins.tooltip.titleColor = getCSSVar('--tooltip-fg');
    Chart.defaults.plugins.tooltip.bodyColor = getCSSVar('--tooltip-fg');
    Chart.defaults.plugins.tooltip.borderColor = getCSSVar('--border');
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
    Chart.defaults.plugins.tooltip.padding = 10;
}}

function buildRadar() {{
    const ctx = document.getElementById('radarChart');
    if (!ctx) return;
    const datasets = Object.entries(D.radar).map(([name, scores], i) => ({{
        label: name,
        data: scores,
        borderColor: D.colors[i],
        backgroundColor: D.colors_alpha[i],
        borderWidth: 2,
        pointRadius: 3,
        pointHoverRadius: 6,
        pointBackgroundColor: D.colors[i],
    }}));
    const c = new Chart(ctx, {{
        type: 'radar',
        data: {{ labels: D.area_labels, datasets }},
        options: {{
            responsive: true, maintainAspectRatio: true,
            scales: {{
                r: {{
                    beginAtZero: true, max: 1.0,
                    ticks: {{ stepSize: 0.25, backdropColor: 'transparent', font: {{ size: 9 }} }},
                    pointLabels: {{ font: {{ size: 10, weight: '500' }} }},
                    grid: {{ color: getCSSVar('--grid') + '80' }},
                    angleLines: {{ color: getCSSVar('--grid') + '60' }},
                }}
            }},
            plugins: {{
                legend: {{ position: 'bottom', labels: {{ font: {{ size: 10 }}, padding: 12 }} }},
            }},
        }}
    }});
    chartInstances.push(c);
}}

function buildHBarChart(canvasId, items, prefix) {{
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    prefix = prefix || '';
    const c = new Chart(ctx, {{
        type: 'bar',
        data: {{
            labels: items.map(d => d.name),
            datasets: [{{
                data: items.map(d => d.value),
                backgroundColor: items.map((_, i) => D.colors[i % D.colors.length] + 'cc'),
                borderColor: items.map((_, i) => D.colors[i % D.colors.length]),
                borderWidth: 1,
                borderRadius: 4,
                barPercentage: 0.7,
            }}]
        }},
        options: {{
            indexAxis: 'y', responsive: true, maintainAspectRatio: false,
            scales: {{
                x: {{ beginAtZero: true, grid: {{ color: getCSSVar('--grid') + '40' }},
                       ticks: {{ callback: v => prefix + v }} }},
                y: {{ grid: {{ display: false }},
                       ticks: {{ font: {{ family: "'JetBrains Mono', monospace", size: 11 }} }} }}
            }},
            plugins: {{
                legend: {{ display: false }},
                tooltip: {{ callbacks: {{ label: ctx => prefix + ctx.parsed.x.toFixed(1) }} }}
            }},
        }}
    }});
    ctx.parentElement.style.height = Math.max(160, items.length * 40 + 40) + 'px';
    chartInstances.push(c);
}}

function buildSeverityChart() {{
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    const names = Object.keys(D.severity);
    if (!names.length) return;

    const c = new Chart(ctx, {{
        type: 'bar',
        data: {{
            labels: names,
            datasets: [
                {{ label: 'Critical', data: names.map(n => D.severity[n].critical),
                   backgroundColor: getCSSVar('--sev-c'), borderRadius: 2 }},
                {{ label: 'High', data: names.map(n => D.severity[n].high),
                   backgroundColor: getCSSVar('--sev-h'), borderRadius: 2 }},
                {{ label: 'Medium', data: names.map(n => D.severity[n].medium),
                   backgroundColor: getCSSVar('--sev-m'), borderRadius: 2 }},
                {{ label: 'Low', data: names.map(n => D.severity[n].low),
                   backgroundColor: getCSSVar('--sev-l'), borderRadius: 2 }},
            ]
        }},
        options: {{
            indexAxis: 'y', responsive: true, maintainAspectRatio: false,
            scales: {{
                x: {{ stacked: true, beginAtZero: true, grid: {{ color: getCSSVar('--grid') + '40' }} }},
                y: {{ stacked: true, grid: {{ display: false }},
                       ticks: {{ font: {{ family: "'JetBrains Mono', monospace", size: 11 }} }} }}
            }},
            plugins: {{
                legend: {{ position: 'bottom', labels: {{ padding: 16, font: {{ size: 11 }} }} }},
            }},
        }}
    }});
    ctx.parentElement.style.height = Math.max(180, names.length * 48 + 60) + 'px';
    chartInstances.push(c);
}}

function buildAll() {{
    destroyAll();
    chartDefaults();
    buildRadar();
    buildHBarChart('findingsChart', D.findings);
    if (document.getElementById('runtimeChart')) buildHBarChart('runtimeChart', D.runtime);
    if (document.getElementById('costChart')) buildHBarChart('costChart', D.cost, '$');
    buildSeverityChart();
}}

buildAll();
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {{
    setTimeout(buildAll, 80);
}});
</script>
</body>
</html>"""
    return html


# ─── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Render comparison report")
    ap.add_argument("--comparison", required=True, help="Path to comparison.json")
    ap.add_argument("--output-dir", default=None, help="Output directory")
    ap.add_argument("--format", choices=["md", "html", "both"], default="both")
    args = ap.parse_args()

    with open(args.comparison, encoding="utf-8") as f:
        data = json.load(f)

    output_dir = args.output_dir or os.path.dirname(args.comparison) or "."
    os.makedirs(output_dir, exist_ok=True)

    if args.format in ("md", "both"):
        md = render_markdown(data)
        md_path = os.path.join(output_dir, "comparison.md")
        with open(md_path, "w", encoding="utf-8", newline="") as f:
            f.write(md)
        print(f"Written: {md_path}")

    if args.format in ("html", "both"):
        html = render_html(data)
        html_path = os.path.join(output_dir, "comparison.html")
        with open(html_path, "w", encoding="utf-8", newline="") as f:
            f.write(html)
        print(f"Written: {html_path}")


if __name__ == "__main__":
    main()
