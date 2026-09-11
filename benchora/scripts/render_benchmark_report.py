#!/usr/bin/env python3
"""render_benchmark_report.py — generate a self-contained HTML benchmark report.

Reads benchora_score.json and produces a comprehensive single-run report with
full source-of-truth for every metric. White + purple theme, Securin branding.

Usage:
    python render_benchmark_report.py --score benchora_score.json [--output report.html]
    python render_benchmark_report.py --score benchora_score.json --prices model_prices.json
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import sys
from datetime import datetime


def _read_json(path: str) -> dict | list | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _unmatched(d, default=None):
    """Unmatched count, accepting the legacy "fp" key.

    Score files written before the FP->unmatched rename carry "fp".  Reading
    only "unmatched" on those silently yields the default, which would print 0
    where the real count is non-zero — a zero score and "no data" are not the
    same thing, so the default here is None, not 0.
    """
    if not isinstance(d, dict):
        return default
    for k in ("unmatched", "fp"):
        if d.get(k) is not None:
            return d[k]
    return default


def _unmatched_endpoints(d):
    if not isinstance(d, dict):
        return []
    for k in ("unmatched_endpoints", "false_positives"):
        if d.get(k) is not None:
            return d[k]
    return []


def _unmatched_findings(d):
    if not isinstance(d, dict):
        return []
    for k in ("unmatched_findings", "fp_findings"):
        if d.get(k) is not None:
            return d[k]
    return []


def _fmt_num(n, decimals=2):
    if n is None:
        return "—"
    if isinstance(n, float):
        return f"{n:,.{decimals}f}"
    return f"{n:,}"


def _fmt_pct(n):
    if n is None:
        return "—"
    return f"{n * 100:.1f}%"


def _fmt_usd(n):
    if n is None:
        return "—"
    return f"${n:,.2f}"


def _esc(s):
    return html.escape(str(s)) if s else "—"


def _clean_component_name(raw: str) -> str:
    name = raw.rsplit("-", 1)[-1] if "-home-securin-AEGIS-components-" in raw else raw
    name = name.replace("-home-securin-AEGIS-components-", "")
    name = name.replace("-home-securin--claude-projects", "claude-projects")
    name = name.replace("-home-securin-AEGIS-", "")
    name = name.replace("-", "_")
    return name


def _severity_badge(sev: str) -> str:
    s = (sev or "").lower()
    colors = {
        "critical": ("#dc2626", "#fef2f2"),
        "high": ("#ea580c", "#fff7ed"),
        "medium": ("#d97706", "#fffbeb"),
        "low": ("#65a30d", "#f7fee7"),
        "info": ("#6b7280", "#f9fafb"),
    }
    fg, bg = colors.get(s, ("#6b7280", "#f9fafb"))
    return f'<span class="sev-badge" style="background:{bg};color:{fg};border:1px solid {fg}30">{_esc(sev or "Info")}</span>'


def _build_area_name_map() -> dict:
    return {
        "1_recon": "Reconnaissance & Surface Discovery",
        "2_interaction": "Interactive Surface Discovery",
        "3_sast": "White-Box Code Analysis (SAST)",
        "4_vuln_analysis": "Vulnerability Analysis",
        "5_exploitation": "Exploitation & Verification",
        "6_attack_path": "Attack Path & Chaining",
        "7_business_logic": "Business Logic Testing",
        "8_reporting": "Reporting Quality",
        "9_reliability": "Reliability & Autonomy",
        "10_cost": "Cost Efficiency",
        "11_reproducibility": "Reproducibility",
    }


def render_report(score: dict, prices: dict | None = None) -> str:
    model = score.get("model", "Unknown Model")
    target = score.get("target", "Unknown Target")
    run_id = score.get("run_id", "")
    ts = score.get("transcripts", {})
    cost_data = score.get("cost", {})
    refusals = score.get("refusals", {})
    reliability = score.get("reliability", {})
    accuracy = score.get("accuracy", {})
    duplicates = score.get("duplicates", {})
    cwe_cve = score.get("cwe_cve", {})
    area_scores = score.get("area_scores", {})
    area_names = _build_area_name_map()
    finding_details = score.get("finding_details", {})

    advisory_html = score.get("advisory_html", {})
    advisory_ids = set(advisory_html.keys()) if advisory_html else None

    endpoint_cov = accuracy.get("endpoint_coverage", {})
    finding_acc = accuracy.get("finding_accuracy", {})
    exploitation = accuracy.get("exploitation", {})
    findings_meta = cwe_cve.get("findings", {})
    runtime = cwe_cve.get("runtime", {})

    total_tokens = ts.get("total_tokens", {})
    tok_input = total_tokens.get("input", 0)
    tok_output = total_tokens.get("output", 0)
    tok_cache_write = total_tokens.get("cache_write", 0)
    tok_cache_read = total_tokens.get("cache_read", 0)
    tok_total = tok_input + tok_output + tok_cache_write + tok_cache_read

    by_component = ts.get("by_component", {})
    cost_by_component = cost_data.get("by_component", {})
    full_cost = cost_data.get("full_run_usd", 0)

    model_price = None
    if prices:
        model_price = prices.get(model)

    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    parts = []
    parts.append(_render_css())
    parts.append(_render_header(model, target, run_id, now))
    parts.append(_render_kpi_strip(endpoint_cov, finding_acc, exploitation, full_cost, refusals, reliability, runtime))
    parts.append(_render_endpoint_coverage(endpoint_cov))
    parts.append(_render_finding_accuracy(finding_acc, finding_details, advisory_ids))
    parts.append(_render_exploitation(exploitation))
    parts.append(_render_duplicates(duplicates))
    parts.append(_render_refusals(refusals))
    parts.append(_render_reliability(reliability))
    parts.append(_render_tokens(total_tokens, by_component, model_price, full_cost, cost_by_component))
    parts.append(_render_cwe_cve(findings_meta, cwe_cve))
    parts.append(_render_runtime(runtime))
    parts.append(_render_area_scores(area_scores, area_names))
    parts.append(_render_component_pipeline(score.get("component_results", {}), reliability.get("gates_detail", {})))
    parts.append(_render_all_findings_appendix(finding_details, _referenced_finding_ids(accuracy), advisory_ids))
    parts.append(_render_component_detail(by_component, cost_by_component, full_cost))
    if advisory_html:
        parts.append(_render_advisory_data(advisory_html))
        parts.append(_render_advisory_overlay())
    parts.append(_render_footer(now))

    return "\n".join(parts)


def _render_css() -> str:
    return """<title>AEGIS Benchmark Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #FAFAFE;
  --bg-card: #FFFFFF;
  --bg-muted: #F4F2FB;
  --text: #1A1A2E;
  --text-secondary: #5A5A7A;
  --border: #E8E5F0;
  --accent: #6C5CE7;
  --accent-light: #A29BFE;
  --accent-bg: #F0EEFF;
  --accent-dark: #4A3DB8;
  --green: #00B894;
  --green-bg: #EEFBF6;
  --red: #E17055;
  --red-bg: #FEF0EC;
  --orange: #FDCB6E;
  --orange-bg: #FFF9E6;
  --kpi-shadow: 0 2px 12px rgba(108,92,231,0.08);
  --card-shadow: 0 1px 4px rgba(26,26,46,0.06);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14121F;
    --bg-card: #1E1B2E;
    --bg-muted: #252238;
    --text: #E8E5F0;
    --text-secondary: #A09BBF;
    --border: #302D42;
    --accent: #A29BFE;
    --accent-light: #6C5CE7;
    --accent-bg: #252040;
    --accent-dark: #C4BFFF;
    --green: #55EFC4;
    --green-bg: #1A2E28;
    --red: #FAB1A0;
    --red-bg: #2E1E1A;
    --orange: #FFEAA7;
    --orange-bg: #2E2A1A;
    --kpi-shadow: 0 2px 12px rgba(0,0,0,0.3);
    --card-shadow: 0 1px 4px rgba(0,0,0,0.2);
  }
}
:root[data-theme="dark"] {
  --bg: #14121F;
  --bg-card: #1E1B2E;
  --bg-muted: #252238;
  --text: #E8E5F0;
  --text-secondary: #A09BBF;
  --border: #302D42;
  --accent: #A29BFE;
  --accent-light: #6C5CE7;
  --accent-bg: #252040;
  --accent-dark: #C4BFFF;
  --green: #55EFC4;
  --green-bg: #1A2E28;
  --red: #FAB1A0;
  --red-bg: #2E1E1A;
  --orange: #FFEAA7;
  --orange-bg: #2E2A1A;
  --kpi-shadow: 0 2px 12px rgba(0,0,0,0.3);
  --card-shadow: 0 1px 4px rgba(0,0,0,0.2);
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: 'Space Grotesk', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }
h1, h2, h3, h4 { font-weight: 600; }
h2 { font-size: 1.5rem; margin: 48px 0 20px; color: var(--text); border-bottom: 2px solid var(--accent); padding-bottom: 8px; }
h3 { font-size: 1.15rem; margin: 24px 0 12px; color: var(--accent-dark); }
code, .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.88em; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Header */
.report-header {
  background: linear-gradient(135deg, var(--accent) 0%, var(--accent-dark) 100%);
  color: #fff;
  padding: 40px 0 32px;
}
.report-header .eyebrow {
  font-size: 0.75rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  opacity: 0.85;
  margin-bottom: 8px;
}
.report-header h1 { font-size: 2rem; font-weight: 700; margin-bottom: 4px; }
.report-header .sub { font-size: 1rem; opacity: 0.9; }
.meta-row {
  display: flex; flex-wrap: wrap; gap: 24px; margin-top: 16px;
  font-size: 0.88rem; opacity: 0.9;
}
.meta-row span { display: inline-flex; align-items: center; gap: 6px; }

/* KPI strip */
.kpi-strip {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin: -28px 0 32px;
  position: relative;
  z-index: 1;
}
.kpi-card {
  background: var(--bg-card);
  border-radius: 12px;
  padding: 16px 20px;
  box-shadow: var(--kpi-shadow);
  border: 1px solid var(--border);
  text-align: center;
}
.kpi-card .kpi-val { font-size: 1.6rem; font-weight: 700; color: var(--accent); font-variant-numeric: tabular-nums; }
.kpi-card .kpi-label { font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.06em; margin-top: 4px; }

/* Cards */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 20px;
  box-shadow: var(--card-shadow);
}

/* Metric grid */
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 16px 0; }
.metric-box { background: var(--bg-muted); border-radius: 8px; padding: 14px 16px; }
.metric-box .val { font-size: 1.3rem; font-weight: 600; font-variant-numeric: tabular-nums; }
.metric-box .label { font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em; }
.metric-box.green .val { color: var(--green); }
.metric-box.red .val { color: var(--red); }
.metric-box.accent .val { color: var(--accent); }

/* Tables */
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th { text-align: left; font-weight: 600; padding: 10px 12px; background: var(--bg-muted); border-bottom: 2px solid var(--border); }
td { padding: 8px 12px; border-bottom: 1px solid var(--border); font-variant-numeric: tabular-nums; }
tr:hover td { background: var(--accent-bg); }
.tbl-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }

/* Expandable details */
details { margin: 12px 0; }
details summary {
  cursor: pointer; font-weight: 500; color: var(--accent);
  padding: 8px 12px; background: var(--accent-bg); border-radius: 8px;
  list-style: none; display: flex; align-items: center; gap: 8px;
}
details summary::-webkit-details-marker { display: none; }
details summary::before { content: "▸"; transition: transform 0.2s; display: inline-block; }
details[open] summary::before { transform: rotate(90deg); }
details .detail-body { padding: 12px 16px; background: var(--bg-muted); border-radius: 0 0 8px 8px; margin-top: -4px; }

/* Badges */
.sev-badge {
  display: inline-block; font-size: 0.72rem; font-weight: 600;
  padding: 2px 8px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.04em;
}
.tag { display: inline-block; font-size: 0.72rem; padding: 2px 8px; border-radius: 4px; background: var(--accent-bg); color: var(--accent); font-weight: 500; margin: 2px; }

/* Progress bar */
.pbar-wrap { height: 8px; background: var(--bg-muted); border-radius: 4px; overflow: hidden; margin: 6px 0; }
.pbar-fill { height: 100%; border-radius: 4px; transition: width 0.4s ease; }
.pbar-fill.green { background: var(--green); }
.pbar-fill.accent { background: var(--accent); }
.pbar-fill.red { background: var(--red); }

/* Area score row */
.area-row { display: flex; align-items: center; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border); }
.area-row:last-child { border-bottom: none; }
.area-num { font-size: 0.8rem; font-weight: 600; color: var(--accent); min-width: 28px; }
.area-name { flex: 1; font-weight: 500; }
.area-score { font-family: 'JetBrains Mono', monospace; font-weight: 600; min-width: 80px; text-align: right; }
.area-bar { width: 120px; }

/* Formula */
.formula {
  background: var(--bg-muted); border-left: 3px solid var(--accent);
  padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 12px 0;
  font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;
  overflow-x: auto; white-space: pre-wrap; word-break: break-all;
}

/* Footer */
.report-footer {
  text-align: center; padding: 32px 0; margin-top: 48px;
  border-top: 1px solid var(--border); color: var(--text-secondary); font-size: 0.8rem;
}

/* Endpoint list */
.ep-list { font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; line-height: 1.8; }
.ep-list .ep-item { padding: 2px 0; border-bottom: 1px solid var(--border); }
.ep-list .ep-method { font-weight: 600; color: var(--accent); }

/* Responsive */
@media (max-width: 768px) {
  .kpi-strip { grid-template-columns: repeat(2, 1fr); }
  .metric-grid { grid-template-columns: 1fr 1fr; }
  .area-bar { display: none; }
  .report-header h1 { font-size: 1.5rem; }
}
pre.fmd-raw {
  white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere;
  overflow-x: auto; max-width: 100%; margin: 6px 0; padding: 10px 12px;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 0.76rem; line-height: 1.45; tab-size: 2;
  background: var(--bg-muted); border: 1px solid var(--border); border-radius: 6px;
}
details.fmd, details.fmd-outer { content-visibility: auto; contain-intrinsic-size: auto 40px; }
.fmd-note { font-size: 0.7rem; color: var(--red); }
.fmd-list > details.fmd-outer { border-bottom: 1px solid var(--border); padding-bottom: 3px; }
/* Advisory modal overlay */
.adv-overlay { display:none; position:fixed; top:0; left:0; right:0; bottom:0; z-index:9999; background:rgba(0,0,0,0.6); backdrop-filter:blur(2px); }
.adv-overlay.active { display:flex; flex-direction:column; }
.adv-header { display:flex; align-items:center; justify-content:space-between; padding:10px 20px; background:var(--bg-card); border-bottom:3px solid var(--accent); flex-shrink:0; }
.adv-header h3 { font-size:0.95rem; margin:0; max-width:80%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.adv-close { background:var(--red); color:#fff; border:none; border-radius:4px; padding:6px 16px; cursor:pointer; font-weight:600; font-size:0.85rem; }
.adv-close:hover { opacity:0.85; }
.adv-iframe { flex:1; border:none; background:#fff; width:100%; min-height:0; }
.adv-btn { cursor:pointer; font-size:0.72rem; background:var(--accent-bg); color:var(--accent-dark); border:1px solid var(--accent-light); border-radius:4px; padding:2px 8px; font-weight:600; }
.adv-btn:hover { background:var(--accent); color:#fff; }
</style>
<script>
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.expand-all').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var card = btn.closest('.card');
      var details = card.querySelectorAll('details:not(.fmd):not(.fmd-outer)');
      var allOpen = Array.from(details).every(function(d) { return d.open; });
      details.forEach(function(d) { d.open = !allOpen; });
      btn.textContent = allOpen ? 'Expand all' : 'Collapse all';
    });
  });
  document.querySelectorAll('.fmd-expand-all').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var list = btn.closest('.card').querySelector('.fmd-list');
      if (!list) return;
      var ds = list.querySelectorAll('details');
      var allOpen = Array.from(ds).every(function(d) { return d.open; });
      ds.forEach(function(d) { d.open = !allOpen; });
      btn.textContent = allOpen ? 'Expand all raw markdown' : 'Collapse all raw markdown';
    });
  });
  document.querySelectorAll('.fmd-filter').forEach(function(inp) {
    inp.addEventListener('input', function() {
      var q = inp.value.toLowerCase();
      var list = inp.closest('.card').querySelector('.fmd-list');
      if (!list) return;
      list.querySelectorAll(':scope > details').forEach(function(d) {
        var s = d.querySelector('summary');
        d.hidden = !!q && !(s && s.textContent.toLowerCase().indexOf(q) !== -1);
      });
    });
  });
  // Advisory modal
  window.showAdvisory = function(fid) {
    var el = document.getElementById('advisory-data-' + fid);
    if (!el) return;
    try { var html = atob(el.dataset.html); } catch(e) { return; }
    document.getElementById('adv-title').textContent = el.dataset.title || fid;
    document.getElementById('adv-iframe').srcdoc = html;
    document.getElementById('adv-overlay').classList.add('active');
    document.body.style.overflow = 'hidden';
  };
  window.closeAdvisory = function() {
    document.getElementById('adv-overlay').classList.remove('active');
    document.body.style.overflow = '';
    document.getElementById('adv-iframe').srcdoc = '';
  };
  document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeAdvisory(); });
});
</script>"""


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _render_advisory_data(advisory_html: dict) -> str:
    """Emit hidden divs holding base64-encoded advisory HTML for modal display."""
    if not advisory_html:
        return ""
    parts = ['<div id="advisory-store" hidden>']
    for fid, html_content in advisory_html.items():
        title = ""
        m = re.search(r"<title>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()
            if title.startswith("Advisory:"):
                title = title[9:].strip()
        b64 = base64.b64encode(html_content.encode("utf-8")).decode("ascii")
        parts.append(
            f'<div id="advisory-data-{_esc(fid)}" '
            f'data-title="{_esc(title)}" '
            f'data-html="{b64}"></div>'
        )
    parts.append("</div>")
    return "\n".join(parts)


def _render_advisory_overlay() -> str:
    """Emit the modal overlay HTML structure with iframe."""
    return """
<div id="adv-overlay" class="adv-overlay" onclick="if(event.target===this)closeAdvisory()">
  <div class="adv-header">
    <h3 id="adv-title"></h3>
    <button class="adv-close" onclick="closeAdvisory()">Close</button>
  </div>
  <iframe id="adv-iframe" class="adv-iframe" sandbox="allow-same-origin"></iframe>
</div>"""


def _raw_md_block(text: str) -> str:
    """Verbatim markdown in a <pre>.

    Escapes & < > " ' so no tag or attribute context can be broken out of; a
    literal </pre> in the source becomes &lt;/pre&gt; and cannot close the
    element. C0 control characters are stripped because the HTML parser would
    mangle them. Deliberately NOT _esc(): that returns an em dash for falsy
    input, which would silently replace an empty finding body.
    """
    if text is None:
        text = ""
    return ('<pre class="fmd-raw">'
            + html.escape(_CTRL_RE.sub("", str(text)), quote=True)
            + "</pre>")


def _raw_md_details(detail: dict, note: str = "") -> str:
    """Collapsed <details> holding one finding.md, complete and verbatim."""
    raw = detail.get("raw_markdown", "")
    if not raw:
        return ""
    name = detail.get("source_file", "") or detail.get("finding_id", "")
    nbytes = detail.get("raw_bytes") or len(raw.encode("utf-8"))
    suffix = f' <span class="fmd-note">{_esc(note)}</span>' if note else ""
    return ('<details class="fmd" style="margin:8px 0"><summary style="font-size:0.82rem">'
            f'Full finding.md &mdash; <code>{_esc(name)}</code> '
            f'({nbytes:,} bytes, verbatim){suffix}</summary>'
            + _raw_md_block(raw) + "</details>")


def _referenced_finding_ids(accuracy: dict) -> set:
    """finding_ids reachable from a TP/Unmatched/FN table row."""
    out = set()
    fa = (accuracy or {}).get("finding_accuracy", {}) or {}
    for key in ("tp_findings", "unmatched_findings", "missed_vulns"):
        for f in (fa.get(key) or []):
            if isinstance(f, dict):
                fid = f.get("finding_id")
                if fid:
                    out.add(fid)
    return out


def _render_all_findings_appendix(finding_details: dict, referenced: set, advisory_ids: set | None = None) -> str:
    """Every finding.md, verbatim — including any not referenced by a TP/Unmatched row."""
    if not finding_details:
        return ""
    total = len(finding_details)
    has_advisories = bool(advisory_ids)

    def _sortkey(item):
        fid, d = item
        try:
            cvss = -float(d.get("cvss_score") or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        return (cvss, fid)

    blocks = []
    orphans = 0
    for fid, d in sorted(finding_details.items(), key=_sortkey):
        note = ""
        if fid not in referenced:
            orphans += 1
            note = "not referenced by any TP/Unmatched/FN row"
        title = d.get("title", "") or "(no title in frontmatter)"
        sev = d.get("severity", "") or "n/a"
        cvss = d.get("cvss_score")
        cvss_s = f" &middot; CVSS {cvss}" if cvss not in (None, "") else ""
        adv_btn = ""
        if has_advisories and fid in advisory_ids:
            adv_btn = f" <button class='adv-btn' onclick=\"event.stopPropagation();showAdvisory('{_esc(fid)}')\">View Advisory</button>"
        body = _raw_md_details(d, note) or _raw_md_block(d.get("raw_markdown", ""))
        blocks.append(
            '<details class="fmd-outer" style="margin:4px 0">'
            f'<summary style="font-size:0.82rem"><code>{_esc(fid)}</code> &mdash; '
            f'{_esc(title)} <span class="tag">{_esc(sev)}</span>{cvss_s}'
            + (f' <span class="fmd-note">{_esc(note)}</span>' if note else "")
            + adv_btn + "</summary>" + body + "</details>"
        )

    orphan_line = (
        f'<p style="font-size:0.82rem;color:var(--red)"><strong>{orphans}</strong> of these '
        f'are referenced by no TP/Unmatched/FN table row and would be invisible without this appendix.</p>'
        if orphans else
        '<p style="font-size:0.82rem;color:var(--text-secondary)">Every finding.md is also '
        'reachable from a TP/Unmatched/FN table row above.</p>'
    )

    return f"""<div class="container">
<h2>Annex D &mdash; Complete finding.md Corpus (Verbatim)</h2>
<div class="card">
  <p style="font-size:0.85rem">Showing <strong>{total}</strong> of <strong>{total}</strong>
  finding.md files, complete and byte-verbatim &mdash; no truncation, no section filtering.
  Source: <code>&lt;run&gt;/reporting/findings/*.md</code> via
  <code>extract_finding_details.py</code> field <code>raw_markdown</code>.</p>
  {orphan_line}
  <div style="margin:8px 0">
    <input class="fmd-filter" type="search" placeholder="Filter findings by id, title or severity&hellip;"
           style="width:100%;max-width:420px;padding:6px 10px;font-size:0.82rem;
                  border:1px solid var(--border);border-radius:6px;background:var(--bg-card);color:var(--text)">
    <button class="fmd-expand-all tag" style="cursor:pointer;margin-left:6px">Expand all raw markdown</button>
  </div>
  <div class="fmd-list">
  {"".join(blocks)}
  </div>
</div>
</div>"""


def _render_header(model, target, run_id, now) -> str:
    return f"""
<div class="report-header">
  <div class="container">
    <div class="eyebrow">Securin &middot; Application Penetration Testing &middot; AEGIS Programme &middot; Benchmark Round 1</div>
    <h1>Benchmark Report</h1>
    <div class="sub">Single-run scorecard with full source-of-truth for every metric</div>
    <div class="meta-row">
      <span><strong>Model:</strong> <code>{_esc(model)}</code></span>
      <span><strong>Target:</strong> <code>{_esc(target)}</code></span>
      <span><strong>Run ID:</strong> <code>{_esc(run_id)}</code></span>
      <span><strong>Generated:</strong> {_esc(now)}</span>
    </div>
  </div>
</div>"""


def _render_kpi_strip(ep, fa, ex, cost, ref, rel, runtime) -> str:
    recall = ep.get("recall")
    f1 = fa.get("f1")
    exploit_rate = ex.get("exploit_rate")
    rel_score = rel.get("schema_pass_rate")
    total_ref = ref.get("total_refusals", 0)
    wall = runtime.get("total_minutes")

    kpis = [
        (_fmt_pct(recall), "Endpoint Recall"),
        (_fmt_pct(f1), "Finding F1"),
        (_fmt_pct(exploit_rate), "Exploit Rate"),
        (_fmt_usd(cost), "Total Cost"),
        (str(total_ref), "Refusals"),
        (_fmt_pct(rel_score), "Schema Pass"),
        (f"{wall} min" if wall else "—", "Wall Clock"),
    ]
    cards = "\n".join(
        f'<div class="kpi-card"><div class="kpi-val">{v}</div><div class="kpi-label">{l}</div></div>'
        for v, l in kpis
    )
    return f'<div class="container"><div class="kpi-strip">{cards}</div></div>'


def _render_progress_bar(value, max_val=1.0, color="accent") -> str:
    pct = (value / max_val * 100) if max_val else 0
    pct = max(0, min(100, pct))
    return f'<div class="pbar-wrap"><div class="pbar-fill {color}" style="width:{pct:.1f}%"></div></div>'


def _render_endpoint_list(endpoints: list, label: str) -> str:
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


def _render_endpoint_coverage(ep: dict) -> str:
    if not ep.get("has_ground_truth"):
        return '<div class="container"><h2>1 &mdash; Endpoint Coverage</h2><div class="card"><p>No ground truth available.</p></div></div>'

    tp = ep.get("tp", 0)
    unmatched = _unmatched(ep)
    fn = ep.get("fn", 0)
    prec = ep.get("precision", 0)
    rec = ep.get("recall", 0)
    f1 = ep.get("f1", 0)
    gt = ep.get("gt_count", 0)
    found = ep.get("found_count", 0)
    filtered_404 = ep.get("filtered_404_only", 0)

    tp_eps = ep.get("tp_endpoints", [])
    unmatched_eps = _unmatched_endpoints(ep)
    fn_eps = ep.get("missed", [])
    mismatch_credited = ep.get("method_mismatch_credited", [])
    mismatch_probes = ep.get("method_mismatch_probes", [])

    formula = f"Precision = TP/(TP+Unmatched) = {tp}/({tp}+{unmatched}) = {_fmt_pct(prec)}\nRecall = TP/(TP+FN) = {tp}/({tp}+{fn}) = {_fmt_pct(rec)}\nF1 = 2·P·R/(P+R) = {f1:.4f}"

    return f"""<div class="container">
<h2>1 &mdash; Endpoint Coverage (Area 1: Reconnaissance)</h2>
<div class="card">
  <div class="metric-grid">
    <div class="metric-box accent"><div class="val">{gt}</div><div class="label">GT Endpoints</div></div>
    <div class="metric-box accent"><div class="val">{found}</div><div class="label">Found Endpoints</div></div>
    <div class="metric-box green"><div class="val">{tp}</div><div class="label">True Positives</div></div>
    <div class="metric-box orange"><div class="val">{unmatched}</div><div class="label">Unmatched</div></div>
    <div class="metric-box red"><div class="val">{fn}</div><div class="label">Missed (FN)</div></div>
    <div class="metric-box"><div class="val">{filtered_404}</div><div class="label">Filtered (404)</div></div>
  </div>
  <div class="metric-grid">
    <div class="metric-box green"><div class="val">{_fmt_pct(prec)}</div><div class="label">Precision</div>{_render_progress_bar(prec, 1, 'green')}</div>
    <div class="metric-box green"><div class="val">{_fmt_pct(rec)}</div><div class="label">Recall</div>{_render_progress_bar(rec, 1, 'green')}</div>
    <div class="metric-box accent"><div class="val">{f1:.4f}</div><div class="label">F1 Score</div>{_render_progress_bar(f1, 1, 'accent')}</div>
  </div>
  <h3>Calculation</h3>
  <div class="formula">{_esc(formula)}</div>
  <h3>Source of Truth</h3>
  <p style="font-size:0.88rem;color:var(--text-secondary)">
    Path normalization: template vars → <code>{{id}}</code>, trailing slashes stripped, hyphens/underscores unified, double slashes collapsed.
    Status-code-aware: 404-only endpoints filtered out. Method mismatch: when a probe (e.g. OPTIONS/HEAD) hits a path that exists in GT under a different method, the GT entry is credited as TP (only if not already matched directly) and the probe is excluded from unmatched.
  </p>
  <button class="expand-all tag" style="cursor:pointer;margin:8px 0">Expand all</button>
  {_render_endpoint_list(tp_eps, "✓ True Positive Endpoints")}
  {_render_endpoint_list(unmatched_eps, "? Unmatched Endpoints")}
  {_render_endpoint_list(fn_eps, "✗ Missed Endpoints (FN)")}
  {_render_endpoint_list(mismatch_credited, "↔ Method Mismatch Credited (GT entries credited via different-method probe)")}
  {_render_endpoint_list(mismatch_probes, "↔ Method Mismatch Probes (excluded from unmatched — path exists in GT under different method)")}
</div>
</div>"""


def _render_finding_detail_card(detail: dict) -> str:
    """Render an expandable detail card for a single finding from finding.md."""
    parts = []
    # No character caps anywhere in this function: finding.md is reproduced in full.
    desc = detail.get("description", "")
    if desc:
        parts.append(f'<div style="margin:8px 0"><strong>Description:</strong> <span style="font-size:0.85rem;white-space:pre-wrap">{_esc(desc)}</span></div>')

    aff_eps = detail.get("affected_endpoints", [])
    if aff_eps:
        eps_html = ", ".join(f'<code>{_esc(e)}</code>' for e in aff_eps)
        parts.append(f'<div style="margin:8px 0"><strong>Affected Endpoints:</strong> {eps_html}</div>')

    repl = detail.get("replication_steps", "")
    if repl:
        parts.append(f'<details style="margin:6px 0"><summary style="font-size:0.82rem">Replication Steps</summary><div class="detail-body" style="font-size:0.82rem;white-space:pre-wrap">{_esc(repl)}</div></details>')

    impact = detail.get("impact", "")
    if impact:
        parts.append(f'<div style="margin:8px 0"><strong>Impact:</strong> <span style="font-size:0.85rem;white-space:pre-wrap">{_esc(impact)}</span></div>')

    attempts = detail.get("attempts", "")
    if attempts:
        parts.append(f'<details style="margin:6px 0"><summary style="font-size:0.82rem">Attempts</summary><div class="detail-body" style="font-size:0.82rem;white-space:pre-wrap">{_esc(attempts)}</div></details>')

    proof = detail.get("proof_summary", "")
    if proof:
        parts.append(f'<details style="margin:6px 0"><summary style="font-size:0.82rem">Proof / Evidence</summary><div class="detail-body" style="font-size:0.82rem;white-space:pre-wrap">{_esc(proof)}</div></details>')

    exploit = detail.get("exploit_code", "")
    if exploit:
        parts.append(f'<details style="margin:6px 0"><summary style="font-size:0.82rem">Exploit Code</summary><div class="detail-body" style="font-size:0.82rem;white-space:pre-wrap">{_esc(exploit)}</div></details>')

    remed = detail.get("remediation", "")
    if remed:
        parts.append(f'<details style="margin:6px 0"><summary style="font-size:0.82rem">Remediation</summary><div class="detail-body" style="font-size:0.82rem;white-space:pre-wrap">{_esc(remed)}</div></details>')

    # Any ## section the named-field index does not cover (e.g. "References",
    # present in all 9 runs; "Compliance Mapping" in sonnet-4-6/run2).
    _covered = ("what it is", "summary", "description", "where", "affected endpoints",
                "where (affected endpoints)", "how to replicate", "reproduction",
                "what an attacker gains", "impact", "impact scenarios", "remediation",
                "fix", "proof", "evidence", "exploit code", "poc", "attempts")
    for _sname, _sbody in (detail.get("sections") or {}).items():
        if _sname.strip().lower() in _covered or not _sbody:
            continue
        parts.append(f'<details style="margin:6px 0"><summary style="font-size:0.82rem">{_esc(_sname)}</summary><div class="detail-body" style="font-size:0.82rem;white-space:pre-wrap">{_esc(_sbody)}</div></details>')

    vstatus = detail.get("verification_status", "")
    comp = detail.get("component", "")
    cvss_vec = detail.get("cvss_vector", "")
    meta_parts = []
    if vstatus:
        meta_parts.append(f'<span class="tag">{_esc(vstatus)}</span>')
    if comp:
        meta_parts.append(f'<span class="tag">{_esc(comp)}</span>')
    if cvss_vec:
        meta_parts.append(f'<code style="font-size:0.72rem">{_esc(cvss_vec)}</code>')
    if meta_parts:
        parts.append(f'<div style="margin:8px 0">{" ".join(meta_parts)}</div>')

    raw_block = _raw_md_details(detail)
    if raw_block:
        parts.append(raw_block)

    return "\n".join(parts) if parts else '<span style="font-size:0.82rem;color:var(--text-secondary)">No detail file available for this finding.</span>'


def _render_finding_table(findings: list, label: str, finding_details: dict | None = None, advisory_ids: set | None = None) -> str:
    if not findings:
        return ""
    has_id = any(f.get("id") for f in findings)
    has_fid = any(f.get("finding_id") for f in findings)
    has_advisories = bool(advisory_ids)
    col_count = 6 + (1 if has_id else 0) + (1 if has_advisories else 0)
    rows = ""
    for i, f in enumerate(findings):
        ep = f.get("endpoint", "")
        if isinstance(ep, list):
            ep = ep[0] if ep else ""
        cwe = f.get("cwe", "")
        if isinstance(cwe, list):
            cwe = ", ".join(str(c) for c in cwe)
        sev = f.get("severity", "")
        title = f.get("title", "")
        cvss = f.get("cvss_score")
        fid = f.get("id", "")
        finding_id = f.get("finding_id", "")
        id_col = f"<td><code>{_esc(fid)}</code></td>" if has_id else ""

        detail = None
        if finding_details and finding_id:
            detail = finding_details.get(finding_id)

        detail_html = ""
        if detail:
            detail_content = _render_finding_detail_card(detail)
            detail_html = (
                f'<tr class="finding-detail-row" id="detail-{i}-{_esc(finding_id)}">'
                f'<td colspan="{col_count}" style="padding:0;border:none">'
                f'<details style="margin:0"><summary style="font-size:0.8rem;padding:4px 12px;border-radius:0">View finding.md details</summary>'
                f'<div class="detail-body" style="border-radius:0 0 8px 8px;margin:0">{detail_content}</div>'
                f'</details></td></tr>\n'
            )
        elif finding_id and finding_details:
            detail_html = ""

        title_display = _esc(title)
        if detail and detail.get("verification_status"):
            vs = detail["verification_status"]
            vs_color = "#00B894" if "verified" in vs.lower() else "#6b7280"
            title_display += f' <span style="font-size:0.7rem;color:{vs_color};font-weight:600">[{_esc(vs)}]</span>'

        adv_col = ""
        if has_advisories:
            lookup_id = finding_id or fid
            if lookup_id and lookup_id in advisory_ids:
                adv_col = f"<td><button class='adv-btn' onclick=\"showAdvisory('{_esc(lookup_id)}')\">View Advisory</button></td>"
            else:
                adv_col = "<td></td>"

        rows += f"<tr>{id_col}<td><code>{_esc(ep)}</code></td><td>{title_display}</td><td><code>{_esc(cwe)}</code></td><td>{_severity_badge(sev)}</td><td class='mono'>{_fmt_num(cvss, 1) if cvss else '—'}</td>{adv_col}</tr>\n{detail_html}"

    id_header = "<th>ID</th>" if has_id else ""
    adv_header = "<th>Advisory</th>" if has_advisories else ""
    return f"""<details>
  <summary>{label} ({len(findings)})</summary>
  <div class="detail-body">
    <div class="tbl-wrap"><table>
      <thead><tr>{id_header}<th>Endpoint</th><th>Title</th><th>CWE</th><th>Severity</th><th>CVSS</th>{adv_header}</tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
  </div>
</details>"""


def _render_finding_accuracy(fa: dict, finding_details: dict | None = None, advisory_ids: set | None = None) -> str:
    if not fa.get("has_ground_truth"):
        return '<div class="container"><h2>4 &mdash; Vulnerability Analysis</h2><div class="card"><p>No ground truth available.</p></div></div>'

    tp = fa.get("tp", 0)
    unmatched = _unmatched(fa)
    fn = fa.get("fn", 0)
    prec = fa.get("precision", 0)
    rec = fa.get("recall", 0)
    f1 = fa.get("f1", 0)
    gt = fa.get("gt_count", 0)
    found = fa.get("found_count", 0)
    owasp_b = fa.get("owasp_breadth", 0)
    owasp_cats = fa.get("owasp_categories", [])
    sev_acc = fa.get("severity_accuracy", 0)

    tp_findings = fa.get("tp_findings", [])
    unmatched_list = _unmatched_findings(fa)
    fn_vulns = fa.get("missed_vulns", [])
    fd = finding_details or {}

    formula = f"Precision = TP/(TP+Unmatched) = {tp}/({tp}+{unmatched}) = {_fmt_pct(prec)}\nRecall = TP/(TP+FN) = {tp}/({tp}+{fn}) = {_fmt_pct(rec)}\nF1 = 2·P·R/(P+R) = {f1:.4f}"

    owasp_tags = " ".join(f'<span class="tag">{_esc(c)}</span>' for c in owasp_cats) if owasp_cats else "—"

    return f"""<div class="container">
<h2>4 &mdash; Vulnerability Analysis (Area 4)</h2>
<div class="card">
  <div class="metric-grid">
    <div class="metric-box accent"><div class="val">{gt}</div><div class="label">GT Vulnerabilities</div></div>
    <div class="metric-box accent"><div class="val">{found}</div><div class="label">Found (deduped)</div></div>
    <div class="metric-box green"><div class="val">{tp}</div><div class="label">True Positives</div></div>
    <div class="metric-box orange"><div class="val">{unmatched}</div><div class="label">Unmatched</div></div>
    <div class="metric-box red"><div class="val">{fn}</div><div class="label">Missed (FN)</div></div>
    <div class="metric-box"><div class="val">{_fmt_pct(sev_acc)}</div><div class="label">Severity Accuracy</div></div>
  </div>
  <div class="metric-grid">
    <div class="metric-box green"><div class="val">{_fmt_pct(prec)}</div><div class="label">Precision</div>{_render_progress_bar(prec, 1, 'green')}</div>
    <div class="metric-box green"><div class="val">{_fmt_pct(rec)}</div><div class="label">Recall</div>{_render_progress_bar(rec, 1, 'green')}</div>
    <div class="metric-box accent"><div class="val">{f1:.4f}</div><div class="label">F1 Score</div>{_render_progress_bar(f1, 1, 'accent')}</div>
  </div>
  <h3>OWASP Coverage ({owasp_b}/10)</h3>
  <div style="margin:8px 0">{owasp_tags}</div>
  <h3>Calculation</h3>
  <div class="formula">{_esc(formula)}</div>
  <h3>Matching Logic</h3>
  <p style="font-size:0.85rem;color:var(--text-secondary)">
    <strong>Path match:</strong> exact after normalization, or prefix (GT <code>/admin/</code> matches finding <code>/admin/login/</code>).<br>
    <strong>CWE match:</strong> exact CWE-ID, or same CWE family (e.g. access_control: 284/285/639/862/863).<br>
    <strong>Class match:</strong> case-insensitive substring of vuln_class.<br>
    <strong>Content dedup:</strong> CWE + first 60 chars of title as dedup key.
  </p>
  <button class="expand-all tag" style="cursor:pointer;margin:8px 0">Expand all</button>
  {_render_finding_table(tp_findings, "✓ True Positive Findings", fd, advisory_ids)}
  {_render_finding_table(unmatched_list, "? Unmatched Findings", fd, advisory_ids)}
  {_render_finding_table(fn_vulns, "✗ Missed Vulnerabilities (FN)", fd, advisory_ids)}
</div>
</div>"""


def _render_exploitation(ex: dict) -> str:
    if not ex.get("has_ground_truth"):
        return '<div class="container"><h2>5 &mdash; Exploitation</h2><div class="card"><p>No ground truth available.</p></div></div>'

    gt_exp = ex.get("gt_exploitable", 0)
    found = ex.get("exploits_found", 0)
    repro = ex.get("reproduced", 0)
    rate = ex.get("exploit_rate", 0)
    depth = ex.get("mean_depth", 0)

    formula = f"Exploit Rate = min(reproduced, gt_exploitable) / gt_exploitable\n           = min({repro}, {gt_exp}) / {gt_exp} = {rate:.4f}"

    return f"""<div class="container">
<h2>5 &mdash; Exploitation & Verification (Area 5)</h2>
<div class="card">
  <div class="metric-grid">
    <div class="metric-box accent"><div class="val">{gt_exp}</div><div class="label">GT Exploitable</div></div>
    <div class="metric-box accent"><div class="val">{found}</div><div class="label">Exploits Found</div></div>
    <div class="metric-box green"><div class="val">{repro}</div><div class="label">Reproduced</div></div>
    <div class="metric-box green"><div class="val">{_fmt_pct(rate)}</div><div class="label">Exploit Rate</div>{_render_progress_bar(rate, 1, 'green')}</div>
    <div class="metric-box"><div class="val">{depth:.2f}</div><div class="label">Mean Depth</div></div>
  </div>
  <h3>Calculation</h3>
  <div class="formula">{_esc(formula)}</div>
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:8px">
    Exploits deduped by finding_id. Status verified/success/reproduced counts as reproduced.
    Depth scoring: verified-exploit=3, verified-poc=2, otherwise from exploit.depth field.
  </p>
</div>
</div>"""


def _render_duplicates(dup: dict) -> str:
    pre = dup.get("pre_dedup_count", 0)
    post = dup.get("post_dedup_count", 0)
    removed = dup.get("duplicates_removed", 0)
    ratio = dup.get("dedup_ratio", 0)
    by_comp = dup.get("by_component", {})
    aegis_merges = dup.get("aegis_merges", [])
    content_dupes = dup.get("content_duplicates", [])
    cross_overlaps = dup.get("cross_component_overlaps", [])

    comp_rows = ""
    for comp, data in sorted(by_comp.items()):
        pre_c = data.get("pre_dedup", 0)
        post_c = data.get("post_dedup", 0)
        rem_c = pre_c - post_c
        comp_rows += f"<tr><td>{_esc(comp)}</td><td class='mono'>{pre_c}</td><td class='mono'>{post_c}</td><td class='mono'>{rem_c}</td></tr>\n"

    aegis_html = ""
    if aegis_merges:
        aegis_rows = ""
        for m in aegis_merges:
            merged_detail = ", ".join(m.get("merged_titles", m.get("merged_ids", []))[:5])
            aegis_rows += (
                f"<tr><td>{_esc(str(m.get('finding_index','')))}</td>"
                f"<td>{_esc(m.get('component',''))}</td>"
                f"<td>{_esc(m.get('title',''))}</td>"
                f"<td>{_esc(m.get('merge_type',''))}</td>"
                f"<td class='mono'>{m.get('merged_count',0)}</td>"
                f"<td style='font-size:0.8rem'>{_esc(merged_detail)}</td></tr>\n"
            )
        aegis_html = (
            f'<details><summary>AEGIS Merges ({len(aegis_merges)})</summary>'
            '<div class="detail-body"><div class="tbl-wrap"><table>'
            '<thead><tr><th>#</th><th>Component</th><th>Title</th><th>Merge Type</th><th>Merged</th><th>Details</th></tr></thead>'
            f'<tbody>{aegis_rows}</tbody></table></div></div></details>'
        )

    content_html = ""
    if content_dupes:
        cd_rows = ""
        for d in content_dupes:
            cd_rows += (
                f"<tr><td>CWE-{_esc(d.get('cwe',''))}</td>"
                f"<td>{_esc(d.get('duplicate_component',''))}</td>"
                f"<td>{_esc(d.get('duplicate_title',''))}</td>"
                f"<td>{_esc(d.get('original_component',''))}</td>"
                f"<td>{_esc(d.get('original_title',''))}</td></tr>\n"
            )
        content_html = (
            f'<details><summary>Content Duplicates ({len(content_dupes)})</summary>'
            '<div class="detail-body"><p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:8px">'
            'Findings with identical CWE + title prefix (first 40 chars) &mdash; potential duplicates not merged by AEGIS.</p>'
            '<div class="tbl-wrap"><table>'
            '<thead><tr><th>CWE</th><th>Dup Component</th><th>Dup Title</th><th>Orig Component</th><th>Orig Title</th></tr></thead>'
            f'<tbody>{cd_rows}</tbody></table></div></div></details>'
        )

    cross_html = ""
    if cross_overlaps:
        co_rows = ""
        for o in cross_overlaps:
            first = True
            for ff in o.get("findings", []):
                if first:
                    rowspan = len(o["findings"])
                    co_rows += (
                        f"<tr><td rowspan='{rowspan}' class='mono'>CWE-{_esc(o.get('cwe',''))}</td>"
                        f"<td rowspan='{rowspan}' class='mono'>{o.get('count',0)}</td>"
                    )
                    first = False
                else:
                    co_rows += "<tr>"
                co_rows += (
                    f"<td>{_esc(ff.get('component',''))}</td>"
                    f"<td>{_esc(ff.get('title',''))}</td>"
                    f"<td>{_esc(ff.get('endpoint',''))}</td>"
                    f"<td>{_esc(ff.get('severity',''))}</td></tr>\n"
                )
        cross_html = (
            f'<details open><summary>Cross-Component Overlaps ({len(cross_overlaps)} CWEs)</summary>'
            '<div class="detail-body"><p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:8px">'
            'Same CWE found by multiple components &mdash; may indicate real overlap or independent discovery of the same vulnerability.</p>'
            '<div class="tbl-wrap"><table>'
            '<thead><tr><th>CWE</th><th>Count</th><th>Component</th><th>Title</th><th>Endpoint</th><th>Severity</th></tr></thead>'
            f'<tbody>{co_rows}</tbody></table></div></div></details>'
        )

    banner = ""
    if removed == 0 and cross_overlaps:
        banner = (
            '<div style="background:var(--pass-bg,#e6f4ea);border:1px solid var(--pass-border,#34a853);'
            'border-radius:8px;padding:12px 16px;margin-top:12px">'
            f'<strong>No duplicates removed</strong> &mdash; AEGIS produced {post} unique findings. '
            f'However, {len(cross_overlaps)} CWE(s) were found by multiple components (see Cross-Component Overlaps below).'
            '</div>'
        )
    elif removed == 0 and not cross_overlaps:
        banner = (
            '<div style="background:var(--pass-bg,#e6f4ea);border:1px solid var(--pass-border,#34a853);'
            'border-radius:8px;padding:12px 16px;margin-top:12px">'
            f'<strong>No duplicates detected</strong> &mdash; all {post} findings are unique across all analysis layers.'
            '</div>'
        )

    cross_metric = ""
    if cross_overlaps is not None:
        cross_metric = (
            f'<div class="metric-box"><div class="val">{len(cross_overlaps)}</div>'
            '<div class="label">Cross-Component Overlaps</div></div>'
        )

    comp_section = ""
    if by_comp:
        comp_section = (
            f'<details><summary>By Component ({len(by_comp)})</summary>'
            '<div class="detail-body"><div class="tbl-wrap"><table>'
            '<thead><tr><th>Component</th><th>Pre-dedup</th><th>Post-dedup</th><th>Removed</th></tr></thead>'
            f'<tbody>{comp_rows}</tbody></table></div></div></details>'
        )

    return (
        '<div class="container">\n'
        '<h2>Duplicate Analysis</h2>\n'
        '<div class="card">\n'
        '  <div class="metric-grid">\n'
        f'    <div class="metric-box accent"><div class="val">{pre}</div><div class="label">Pre-dedup Count</div></div>\n'
        f'    <div class="metric-box accent"><div class="val">{post}</div><div class="label">Post-dedup Count</div></div>\n'
        f'    <div class="metric-box"><div class="val">{removed}</div><div class="label">Duplicates Removed</div></div>\n'
        f'    <div class="metric-box"><div class="val">{_fmt_pct(ratio)}</div><div class="label">Dedup Ratio</div></div>\n'
        f'    {cross_metric}\n'
        '  </div>\n'
        '  <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:8px">\n'
        '    Three-layer analysis: (1) AEGIS merge tracking via <code>_grouped_from</code>/<code>_merged_ids</code>, '
        '(2) content-based dedup (CWE + title prefix), (3) cross-component overlap (same CWE by different components).\n'
        '  </p>\n'
        f'  {banner}\n'
        f'  {comp_section}\n'
        f'  {aegis_html}\n'
        f'  {content_html}\n'
        f'  {cross_html}\n'
        '</div>\n'
        '</div>'
    )


def _render_refusal_evidence(details: list) -> str:
    """Render source-of-truth evidence cards for each refusal detection."""
    if not details:
        return ""
    cards = ""
    for i, d in enumerate(details, 1):
        rtype = _esc(d.get("type", "unknown"))
        matched = _esc(d.get("matched_text", ""))
        context = _esc(d.get("context", ""))
        entry_type = _esc(d.get("entry_type", ""))
        type_color = {
            "guardrail_scope": "#7c3aed",
            "guardrail_security": "#dc2626",
            "guardrail_ethical": "#dc2626",
            "guardrail_capability": "#d97706",
            "api_content_filter": "#2563eb",
            "api_error_block": "#2563eb",
            "hook_scope_block": "#059669",
            "hook_destructive_block": "#059669",
        }.get(d.get("type", ""), "#6b7280")
        cards += f"""
      <div style="border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:12px;background:var(--bg)">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <span style="font-weight:700;font-size:0.95rem;color:var(--text)">#{i}</span>
          <span style="background:{type_color};color:#fff;padding:2px 10px;border-radius:12px;font-size:0.78rem;font-weight:600">{rtype}</span>
          <span style="color:var(--text-secondary);font-size:0.8rem;margin-left:auto">entry: <code>{entry_type}</code></span>
        </div>
        <div style="margin-bottom:8px">
          <span style="font-size:0.8rem;color:var(--text-secondary);font-weight:600">Regex Match:</span>
          <code style="background:var(--code-bg);padding:2px 8px;border-radius:4px;font-size:0.85rem;color:{type_color};font-weight:600">{matched}</code>
        </div>
        <div>
          <span style="font-size:0.8rem;color:var(--text-secondary);font-weight:600">Model Log Context:</span>
          <pre style="margin:6px 0 0 0;padding:10px 12px;background:var(--code-bg);border-radius:6px;font-size:0.8rem;line-height:1.5;white-space:pre-wrap;word-break:break-word;color:var(--text);border:1px solid var(--border);max-height:200px;overflow-y:auto">{context}</pre>
        </div>
      </div>"""
    return cards


def _render_refusals(ref: dict) -> str:
    total = ref.get("total_refusals", 0)
    guardrail = ref.get("model_guardrail_count", 0)
    api_block = ref.get("api_block_count", 0)
    hook_block = ref.get("hook_block_count", 0)
    g_rate = ref.get("guardrail_rate", 0)
    r_rate = ref.get("refusal_rate", 0)
    msgs = ref.get("total_assistant_messages", 0)
    by_type = ref.get("by_type", {})
    by_comp = ref.get("by_component", {})
    structural = ref.get("structural_failures", [])
    details = ref.get("details", [])

    type_rows = ""
    for t, count in sorted(by_type.items()):
        type_rows += f"<tr><td><code>{_esc(t)}</code></td><td class='mono'>{count}</td></tr>\n"

    comp_rows = ""
    for comp, data in sorted(by_comp.items()):
        name = _clean_component_name(comp)
        comp_total = data.get("total", 0)
        g = data.get("model_guardrail_count", 0)
        a = data.get("api_block_count", 0)
        types_str = ", ".join(f"{k}={v}" for k, v in data.get("types", {}).items() if v > 0)
        comp_rows += f"<tr><td>{_esc(name)}</td><td class='mono'>{comp_total}</td><td class='mono'>{g}</td><td class='mono'>{a}</td><td style='font-size:0.8rem'>{_esc(types_str)}</td></tr>\n"

    formula = f"Guardrail Rate = guardrail_count / total_messages = {guardrail} / {msgs} = {g_rate:.4f}"

    evidence_html = _render_refusal_evidence(details)

    return f"""<div class="container">
<h2>Refusal Analysis</h2>
<div class="card">
  <div class="metric-grid">
    <div class="metric-box {'green' if total <= 5 else 'red'}"><div class="val">{total}</div><div class="label">Total Refusals</div></div>
    <div class="metric-box"><div class="val">{guardrail}</div><div class="label">Model Guardrail</div></div>
    <div class="metric-box"><div class="val">{api_block}</div><div class="label">API Block</div></div>
    <div class="metric-box"><div class="val">{hook_block}</div><div class="label">Hook Block</div></div>
    <div class="metric-box"><div class="val">{_fmt_pct(g_rate)}</div><div class="label">Guardrail Rate</div></div>
    <div class="metric-box"><div class="val">{msgs}</div><div class="label">Total Messages</div></div>
  </div>
  <h3>Calculation</h3>
  <div class="formula">{_esc(formula)}</div>
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:8px">
    30+ regex patterns across 8 types. Rate-limit errors (429) excluded. Components with ≥3 guardrail refusals → structural failures.
  </p>
  {f'<div style="margin:8px 0"><strong>Structural failures:</strong> {", ".join(structural)}</div>' if structural else ''}
  {f'<div style="margin:8px 0;padding:10px 14px;background:var(--green-bg);border-radius:6px;font-size:0.88rem;color:var(--text)">No refusals detected across {msgs:,} assistant messages. The model completed all security testing tasks without guardrail blocks, API content filters, or hook blocks.</div>' if total == 0 and msgs > 0 else ''}
  <details>
    <summary>By Type ({len(by_type)})</summary>
    <div class="detail-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>Type</th><th>Count</th></tr></thead>
        <tbody>{type_rows}</tbody>
      </table></div>
    </div>
  </details>
  {f'''<details>
    <summary>By Component ({len(by_comp)})</summary>
    <div class="detail-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>Component</th><th>Total</th><th>Guardrail</th><th>API Block</th><th>Types</th></tr></thead>
        <tbody>{comp_rows}</tbody>
      </table></div>
    </div>
  </details>''' if by_comp else ''}
  {f'''<details open>
    <summary>Source of Truth — Refusal Evidence ({len(details)})</summary>
    <div class="detail-body">
      <p style="font-size:0.82rem;color:var(--text-secondary);margin-bottom:12px">
        Each card shows the exact regex match and surrounding model log context from the transcript. This is the raw evidence the detector used to classify each refusal.
      </p>
      {evidence_html}
    </div>
  </details>''' if details else ''}
</div>
</div>"""


def _render_reliability(rel: dict) -> str:
    schema_rate = rel.get("schema_pass_rate", 0)
    gates_passed = rel.get("gates_passed", 0)
    gates_failed = rel.get("gates_failed", 0)
    gate_total = gates_passed + gates_failed
    gate_rate = gates_passed / gate_total if gate_total else 1.0
    error_count = rel.get("error_count", 0)

    formula = (
        f"Reliability = 0.30*(1-guardrail_rate) + 0.25*schema_pass + 0.25*gate_pass + 0.20*(1-error_rate)\n"
        f"Schema Pass Rate = {schema_rate:.4f}\n"
        f"Gate Pass Rate = {gates_passed}/{gate_total} = {gate_rate:.4f}\n"
        f"Error Count = {error_count}"
    )

    return f"""<div class="container">
<h2>Reliability & Autonomy (Area 9)</h2>
<div class="card">
  <div class="metric-grid">
    <div class="metric-box {'green' if schema_rate > 0.8 else 'red'}"><div class="val">{_fmt_pct(schema_rate)}</div><div class="label">Schema Pass Rate</div>{_render_progress_bar(schema_rate, 1, 'green' if schema_rate > 0.8 else 'red')}</div>
    <div class="metric-box green"><div class="val">{gates_passed}/{gate_total}</div><div class="label">Gates Passed</div></div>
    <div class="metric-box {'green' if gates_failed == 0 else 'red'}"><div class="val">{gates_failed}</div><div class="label">Gates Failed</div></div>
    <div class="metric-box"><div class="val">{error_count}</div><div class="label">Errors</div></div>
  </div>
  <h3>Reliability Formula</h3>
  <div class="formula">{_esc(formula)}</div>
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:8px">
    Schema validation checks 9 component artifact files against lightweight structural schemas.
    Gates are per-component completion checks.
  </p>
</div>
</div>"""


def _render_tokens(total_tokens, by_component, model_price, full_cost, cost_by_component) -> str:
    tok_in = total_tokens.get("input", 0)
    tok_out = total_tokens.get("output", 0)
    tok_cw = total_tokens.get("cache_write", 0)
    tok_cr = total_tokens.get("cache_read", 0)
    tok_total = tok_in + tok_out + tok_cw + tok_cr

    price_info = ""
    cost_formula = ""
    if model_price:
        p_in = model_price.get("input_per_million", 0)
        p_out = model_price.get("output_per_million", 0)
        p_cw = model_price.get("cache_write_per_million", 0)
        p_cr = model_price.get("cache_read_per_million", 0)

        c_in = tok_in * p_in / 1_000_000
        c_out = tok_out * p_out / 1_000_000
        c_cw = tok_cw * p_cw / 1_000_000
        c_cr = tok_cr * p_cr / 1_000_000

        price_info = f"""<h3>Pricing (per million tokens)</h3>
<div class="metric-grid">
  <div class="metric-box"><div class="val">${p_in:.2f}</div><div class="label">Input</div></div>
  <div class="metric-box"><div class="val">${p_out:.2f}</div><div class="label">Output</div></div>
  <div class="metric-box"><div class="val">${p_cw:.2f}</div><div class="label">Cache Write</div></div>
  <div class="metric-box"><div class="val">${p_cr:.2f}</div><div class="label">Cache Read</div></div>
</div>"""

        cost_formula = f"""<h3>Cost Calculation</h3>
<div class="formula">Input:       {tok_in:>14,} × ${p_in}/M = ${c_in:>10,.2f}
Output:      {tok_out:>14,} × ${p_out}/M = ${c_out:>10,.2f}
Cache Write: {tok_cw:>14,} × ${p_cw}/M = ${c_cw:>10,.2f}
Cache Read:  {tok_cr:>14,} × ${p_cr}/M = ${c_cr:>10,.2f}
{'─' * 52}
Total:       {tok_total:>14,}          = ${c_in + c_out + c_cw + c_cr:>10,.2f}</div>"""

    comp_rows = ""
    for comp, data in sorted(by_component.items()):
        name = _clean_component_name(comp)
        t = data.get("tokens", {})
        c_in = t.get("input", 0)
        c_out = t.get("output", 0)
        c_cw = t.get("cache_write", 0)
        c_cr = t.get("cache_read", 0)
        c_total = c_in + c_out + c_cw + c_cr
        turns = data.get("turns", 0)
        cost_c = cost_by_component.get(comp, 0)
        share = (cost_c / full_cost * 100) if full_cost else 0
        comp_rows += f"<tr><td>{_esc(name)}</td><td class='mono'>{c_in:,}</td><td class='mono'>{c_out:,}</td><td class='mono'>{c_cw:,}</td><td class='mono'>{c_cr:,}</td><td class='mono'>{c_total:,}</td><td class='mono'>{turns:,}</td><td class='mono'>{_fmt_usd(cost_c)}</td><td class='mono'>{share:.1f}%</td></tr>\n"

    return f"""<div class="container">
<h2>Token Consumption & Cost (Area 10)</h2>
<div class="card">
  <div class="metric-grid">
    <div class="metric-box accent"><div class="val">{tok_in:,}</div><div class="label">Input Tokens</div></div>
    <div class="metric-box accent"><div class="val">{tok_out:,}</div><div class="label">Output Tokens</div></div>
    <div class="metric-box"><div class="val">{tok_cw:,}</div><div class="label">Cache Write</div></div>
    <div class="metric-box"><div class="val">{tok_cr:,}</div><div class="label">Cache Read</div></div>
    <div class="metric-box accent"><div class="val">{tok_total:,}</div><div class="label">Total Tokens</div></div>
    <div class="metric-box {'green' if full_cost < 100 else 'red' if full_cost > 500 else 'accent'}"><div class="val">{_fmt_usd(full_cost)}</div><div class="label">Total Cost</div></div>
  </div>
  {price_info}
  {cost_formula}
  <details>
    <summary>By Component ({len(by_component)})</summary>
    <div class="detail-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>Component</th><th>Input</th><th>Output</th><th>Cache Write</th><th>Cache Read</th><th>Total</th><th>Turns</th><th>Cost</th><th>Share</th></tr></thead>
        <tbody>{comp_rows}</tbody>
      </table></div>
    </div>
  </details>
</div>
</div>"""


def _render_cwe_cve(findings_meta, cwe_cve) -> str:
    cwe = findings_meta.get("cwe", {})
    cvss = findings_meta.get("cvss", {})
    owasp = findings_meta.get("owasp", {})
    severity = findings_meta.get("severity", {})
    cves = cwe_cve.get("cves", {})

    cwe_dist = cwe.get("distribution", {})
    cwe_rows = ""
    for c, count in sorted(cwe_dist.items(), key=lambda x: -x[1]):
        cwe_rows += f"<tr><td><code>{_esc(c)}</code></td><td class='mono'>{count}</td></tr>\n"

    owasp_dist = owasp.get("distribution", {})
    owasp_names = {
        "A01:2025": "Broken Access Control", "A02:2025": "Cryptographic Failures",
        "A03:2025": "Injection", "A04:2025": "Insecure Design",
        "A05:2025": "Security Misconfiguration", "A06:2025": "Vulnerable Components",
        "A07:2025": "Authentication Failures", "A08:2025": "Software Integrity",
        "A09:2025": "Logging & Monitoring", "A10:2025": "SSRF",
    }
    owasp_rows = ""
    for cat, count in sorted(owasp_dist.items(), key=lambda x: -x[1]):
        name = owasp_names.get(cat, "")
        owasp_rows += f"<tr><td><code>{_esc(cat)}</code></td><td>{_esc(name)}</td><td class='mono'>{count}</td></tr>\n"

    sev_dist = severity.get("distribution", {})
    sev_rows = ""
    for s, count in sorted(sev_dist.items(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[0], 4)):
        sev_rows += f"<tr><td>{_severity_badge(s)}</td><td class='mono'>{count}</td></tr>\n"

    cvss_scores = cvss.get("scores", [])
    cvss_list = ", ".join(str(s) for s in cvss_scores) if cvss_scores else "—"

    cve_section = ""
    if cves.get("unique", 0) > 0:
        cve_ids = cves.get("cve_ids", [])
        cve_tags = " ".join(f'<span class="tag">{_esc(c)}</span>' for c in cve_ids[:30])
        cve_section = f"""<h3>CVE Detection</h3>
<div class="metric-grid">
  <div class="metric-box accent"><div class="val">{cves.get('unique', 0)}</div><div class="label">Unique CVEs</div></div>
</div>
<div style="margin:8px 0">{cve_tags}</div>"""

    return f"""<div class="container">
<h2>Security Intelligence</h2>
<div class="card">
  <div class="metric-grid">
    <div class="metric-box accent"><div class="val">{cwe.get('count', 0)}</div><div class="label">Unique CWEs</div></div>
    <div class="metric-box accent"><div class="val">{_fmt_pct(owasp.get('coverage', 0))}</div><div class="label">OWASP Coverage</div></div>
    <div class="metric-box"><div class="val">{_fmt_num(cvss.get('mean_score'), 1)}</div><div class="label">Mean CVSS</div></div>
    <div class="metric-box"><div class="val">{_fmt_num(cvss.get('max_score'), 1)}</div><div class="label">Max CVSS</div></div>
  </div>

  <details>
    <summary>CWE Distribution ({cwe.get('count', 0)} unique)</summary>
    <div class="detail-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>CWE</th><th>Count</th></tr></thead>
        <tbody>{cwe_rows}</tbody>
      </table></div>
    </div>
  </details>

  <details>
    <summary>OWASP Top 10 2025 Coverage ({len(owasp_dist)}/10)</summary>
    <div class="detail-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>Category</th><th>Name</th><th>Findings</th></tr></thead>
        <tbody>{owasp_rows}</tbody>
      </table></div>
    </div>
  </details>

  <details>
    <summary>Severity Distribution</summary>
    <div class="detail-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>{sev_rows}</tbody>
      </table></div>
    </div>
  </details>

  <details>
    <summary>CVSS Scores ({len(cvss_scores)} findings)</summary>
    <div class="detail-body">
      <p class="mono" style="font-size:0.85rem;line-height:2">{_esc(cvss_list)}</p>
    </div>
  </details>

  {cve_section}
</div>
</div>"""


def _render_runtime(runtime: dict) -> str:
    total_min = runtime.get("total_minutes")
    by_comp = runtime.get("by_component", {})

    if not total_min:
        return """<div class="container">
<h2>Wall-Clock Time</h2>
<div class="card"><p style="color:var(--text-secondary)">Runtime data not available. Transcripts may lack timestamp entries.</p></div>
</div>"""

    comp_rows = ""
    for comp, mins in sorted(by_comp.items(), key=lambda x: -x[1]):
        name = _clean_component_name(comp)
        share = (mins / total_min * 100) if total_min else 0
        comp_rows += f"<tr><td>{_esc(name)}</td><td class='mono'>{mins:.1f} min</td><td class='mono'>{share:.1f}%</td></tr>\n"

    return f"""<div class="container">
<h2>Wall-Clock Time</h2>
<div class="card">
  <div class="metric-grid">
    <div class="metric-box accent"><div class="val">{total_min:.1f} min</div><div class="label">Total Runtime</div></div>
    <div class="metric-box"><div class="val">{total_min / 60:.1f} hrs</div><div class="label">Hours</div></div>
  </div>
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:8px">
    Computed from first/last timestamps in Claude Code transcript .jsonl files.
  </p>
  {f'''<details>
    <summary>By Component ({len(by_comp)})</summary>
    <div class="detail-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>Component</th><th>Duration</th><th>Share</th></tr></thead>
        <tbody>{comp_rows}</tbody>
      </table></div>
    </div>
  </details>''' if by_comp else ''}
</div>
</div>"""


def _render_area_scores(area_scores, area_names) -> str:
    rows = ""
    for area_key in sorted(area_scores.keys(), key=lambda x: int(x.split("_")[0])):
        data = area_scores[area_key]
        score = data.get("score")
        method = data.get("method", "")
        name = area_names.get(area_key, area_key)
        num = area_key.split("_")[0]

        if score is None:
            score_str = "Deferred"
            bar = ""
            css_class = "color:var(--text-secondary)"
        elif method == "computed" and data.get("inverse"):
            score_str = _fmt_usd(score)
            bar = ""
            css_class = ""
        else:
            score_str = f"{score:.4f}" if isinstance(score, float) and score <= 1 else str(score)
            bar_val = score if isinstance(score, (int, float)) and score <= 1 else 0
            bar = _render_progress_bar(bar_val, 1, "green" if bar_val >= 0.8 else "accent" if bar_val >= 0.5 else "red")
            css_class = ""

        detail = data.get("detail", "")
        detail_str = ""
        if isinstance(detail, dict):
            detail_str = " · ".join(f"{k}={v}" for k, v in detail.items())
        elif isinstance(detail, str):
            detail_str = detail

        rows += f"""<div class="area-row">
  <div class="area-num">{num}</div>
  <div class="area-name">{_esc(name)}<br><span style="font-size:0.75rem;color:var(--text-secondary)">{_esc(method)} · {_esc(detail_str[:100])}</span></div>
  <div class="area-score" style="{css_class}">{score_str}</div>
  <div class="area-bar">{bar}</div>
</div>"""

    return f"""<div class="container">
<h2>Area Scores (11 Evaluation Areas)</h2>
<div class="card">
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:16px">
    GT-based areas (1, 4, 5): scored against ground truth. Computed areas (9, 10, 11): from metrics.
    Test-case areas (2, 3, 6, 7, 8): deferred to cross-model comparison phase.
    Rating scale (needs ≥2 models): Leading &gt; Strong &gt; Adequate &gt; Weak &gt; Not viable.
  </p>
  {rows}
</div>
</div>"""


def _render_component_detail(by_component, cost_by_component, full_cost) -> str:
    rows = ""
    for comp, data in sorted(by_component.items()):
        name = _clean_component_name(comp)
        t = data.get("tokens", {})
        c_in = t.get("input", 0)
        c_out = t.get("output", 0)
        c_cw = t.get("cache_write", 0)
        c_cr = t.get("cache_read", 0)
        c_total = c_in + c_out + c_cw + c_cr
        turns = data.get("turns", 0)
        transcripts = data.get("transcripts", [])
        cost_c = cost_by_component.get(comp, 0)
        share = (cost_c / full_cost * 100) if full_cost else 0

        tx_list = "<br>".join(f'<code style="font-size:0.75rem">{_esc(t)}</code>' for t in transcripts)

        rows += f"""<details>
  <summary>{_esc(name)} — {_fmt_usd(cost_c)} ({share:.1f}%) · {turns:,} turns</summary>
  <div class="detail-body">
    <div class="metric-grid">
      <div class="metric-box"><div class="val">{c_in:,}</div><div class="label">Input</div></div>
      <div class="metric-box"><div class="val">{c_out:,}</div><div class="label">Output</div></div>
      <div class="metric-box"><div class="val">{c_cw:,}</div><div class="label">Cache Write</div></div>
      <div class="metric-box"><div class="val">{c_cr:,}</div><div class="label">Cache Read</div></div>
      <div class="metric-box accent"><div class="val">{c_total:,}</div><div class="label">Total Tokens</div></div>
      <div class="metric-box accent"><div class="val">{_fmt_usd(cost_c)}</div><div class="label">Cost</div></div>
    </div>
    <h4 style="margin:12px 0 6px;font-size:0.85rem">Transcript Files ({len(transcripts)})</h4>
    <div style="font-size:0.8rem;line-height:1.8">{tx_list}</div>
  </div>
</details>"""

    return f"""<div class="container">
<h2>Component Detail (Annex C)</h2>
<div class="card">
  <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:12px">
    Per-component breakdown: tokens, cost, cost share %, turns, and transcript files.
  </p>
  <button class="expand-all tag" style="cursor:pointer;margin-bottom:12px">Expand all</button>
  {rows}
</div>
</div>"""


# Headline metrics per component: (label, dotted path into the component dict)
_COMPONENT_HEADLINES = {
    "crawler": [
        ("Endpoints", "endpoints_inventory.count"),
        ("Roles", "role_matrix.roles"),
        ("Pages Visited", "frontier.visited_count"),
        ("Screenshots", "screenshots.total"),
        ("Business Flows", "inferred_flows.count"),
    ],
    "attack_surface_discovery": [
        ("Hosts", "hosts_count"),
        ("Subdomains", "subdomains_count"),
        ("Open Ports", "services.count"),
        ("CVEs", "cves.count"),
        ("Secrets", "secrets.count"),
    ],
    "planner": [
        ("Test Cases", "test_cases.count"),
        ("Tasks", "plan.task_count"),
        ("Endpoints Cataloged", "endpoint_catalog_count"),
        ("Coverage Cells", "coverage_ledger.total_cells"),
        ("Uncovered", "coverage_ledger.uncovered"),
    ],
    "vulnerability_discovery": [
        ("Findings", "findings.unique_finding_ids"),
        ("Entries", "findings.total_entries"),
        ("Targets", "findings.unique_targets"),
        ("Batches", "finding_batches"),
    ],
    "vulnerability_exploitation": [
        ("Attempts", "exploits_summary.count"),
        ("Verified PoC", "verified_poc_count"),
        ("Verified Exploit", "verified_exploit_count"),
        ("PoC Writeups", "exploit_md_count"),
        ("Destructive", "destructive_count"),
    ],
    "hacker": [
        ("Findings", "findings.count"),
        ("Screenshots", "screenshot_count"),
    ],
    "vulnerability_chaining": [
        ("Objectives", "objectives.count"),
        ("Chains Scored", "scored_chains.count"),
        ("Graph Nodes", "graph_analysis.node_count"),
        ("Graph Edges", "graph_analysis.edge_count"),
        ("Choke Points", "graph_analysis.choke_point_count"),
    ],
    "reporting": [
        ("Final Findings", "scored_findings.count"),
        ("Advisories", "advisory_count"),
        ("Finding Groups", "finding_groups.count"),
        ("Severity Overrides", "severity_overrides_count"),
        ("Screenshots", "screenshot_count"),
    ],
}


def _dig(d, path):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _headline_value(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int):
        return _fmt_num(v, 0)
    if isinstance(v, float):
        return _fmt_num(v)
    if isinstance(v, (list, dict)):
        return str(len(v))
    text = str(v)
    return text if len(text) <= 24 else text[:21] + "..."


def _detail_value_html(v, depth=0):
    """Render an arbitrary JSON value from component_results as readable HTML."""
    if v is None:
        return "<span class='cp-muted'>null</span>"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int):
        return "<span class='mono'>" + _fmt_num(v, 0) + "</span>"
    if isinstance(v, float):
        return "<span class='mono'>" + _fmt_num(v) + "</span>"
    if isinstance(v, str):
        txt = v if len(v) <= 600 else v[:600] + " ..."
        return "<span class='mono'>" + _esc(txt) + "</span>"
    if isinstance(v, list):
        if not v:
            return "<span class='cp-muted'>(empty)</span>"
        if all(not isinstance(x, (dict, list)) for x in v):
            shown = ", ".join("<span class='mono'>" + _esc(str(x)) + "</span>" for x in v[:40])
            more = ""
            if len(v) > 40:
                more = " <span class='cp-muted'>+" + str(len(v) - 40) + " more</span>"
            return shown + more
        if depth >= 2:
            return "<span class='cp-muted'>" + str(len(v)) + " items</span>"
        rows = "".join("<li>" + _detail_value_html(x, depth + 1) + "</li>" for x in v[:15])
        if len(v) > 15:
            rows += "<li class='cp-muted'>+" + str(len(v) - 15) + " more</li>"
        return "<ul class='cp-list'>" + rows + "</ul>"
    if isinstance(v, dict):
        if not v:
            return "<span class='cp-muted'>(empty)</span>"
        if depth >= 2:
            return "<span class='cp-muted'>" + str(len(v)) + " keys</span>"
        rows = "".join(
            "<tr><td class='cp-k'>" + _esc(str(k)) + "</td><td>"
            + _detail_value_html(val, depth + 1) + "</td></tr>"
            for k, val in list(v.items())[:40]
        )
        return "<table class='cp-sub'>" + rows + "</table>"
    return _esc(str(v))


_CP_STYLE = """<style>
.cp-head { display:flex; align-items:center; justify-content:space-between; gap:12px; }
.cp-head h3 { margin:0; }
.cp-gate { font-size:0.65rem; font-weight:700; letter-spacing:0.06em; padding:3px 8px; border-radius:4px; white-space:nowrap; }
.cp-pass { background:var(--green-bg); color:var(--green); }
.cp-fail { background:var(--red-bg); color:var(--red); }
.cp-none { background:var(--bg-muted); color:var(--text-secondary); }
.cp-metrics { display:flex; flex-wrap:wrap; gap:10px; margin:12px 0; }
.cp-metric { background:var(--bg-muted); border-radius:5px; padding:8px 14px; min-width:88px; }
.cp-val { font-family:'JetBrains Mono',monospace; font-size:1.15rem; font-weight:600; color:var(--accent-dark); }
.cp-lbl { font-size:0.65rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--text-secondary); margin-top:2px; }
.cp-na { opacity:0.55; }
table.cp-detail { width:100%; border-collapse:collapse; font-size:0.8rem; }
table.cp-detail > tbody > tr > td { border-top:1px solid var(--border); padding:6px 8px; vertical-align:top; }
td.cp-k { font-weight:600; white-space:nowrap; width:1%; padding-right:14px !important; }
table.cp-sub { border-collapse:collapse; font-size:0.78rem; }
table.cp-sub td { padding:2px 6px 2px 0; vertical-align:top; }
ul.cp-list { margin:0; padding-left:16px; }
.cp-muted { color:var(--text-secondary); }
</style>"""


def _render_component_pipeline(component_results: dict, gates_detail: dict) -> str:
    """Per-component pipeline results, sourced from benchora_score.json > component_results."""
    if not component_results:
        return ""

    known = list(_COMPONENT_HEADLINES.keys())
    ordered = [c for c in known if c in component_results]
    ordered += [c for c in sorted(component_results) if c not in known]

    cards = []
    for comp in ordered:
        data = component_results.get(comp)
        gate = (gates_detail or {}).get(comp)
        if gate == "PASS":
            badge = "<span class='cp-gate cp-pass'>GATE PASS</span>"
        elif gate == "FAIL":
            badge = "<span class='cp-gate cp-fail'>GATE FAIL</span>"
        else:
            badge = "<span class='cp-gate cp-none'>NO GATE</span>"

        head = ("<div class='cp-head'><h3>" + _esc(_clean_component_name(comp))
                + "</h3>" + badge + "</div>")

        if not isinstance(data, dict) or not data:
            cards.append("<div class='card cp-na'>" + head
                         + "<p class='cp-muted'>N/A &mdash; component produced no output.</p></div>")
            continue

        metrics = []
        for label, path in _COMPONENT_HEADLINES.get(comp, []):
            val = _headline_value(_dig(data, path))
            if val is not None:
                metrics.append("<div class='cp-metric'><div class='cp-val'>"
                               + _esc(str(val)) + "</div><div class='cp-lbl'>"
                               + _esc(label) + "</div></div>")
        if not metrics:
            for k, v in list(data.items())[:4]:
                val = _headline_value(v)
                if val is not None:
                    metrics.append("<div class='cp-metric'><div class='cp-val'>"
                                   + _esc(str(val)) + "</div><div class='cp-lbl'>"
                                   + _esc(k.replace("_", " ")) + "</div></div>")

        rows = "".join(
            "<tr><td class='cp-k'>" + _esc(k.replace("_", " ")) + "</td><td>"
            + _detail_value_html(v) + "</td></tr>"
            for k, v in data.items()
        )
        cards.append(
            "<div class='card'>" + head
            + "<div class='cp-metrics'>" + "".join(metrics) + "</div>"
            + "<details><summary>All " + str(len(data))
            + " extracted metrics &amp; source artifacts</summary>"
            + "<div class='table-wrap'><table class='cp-detail'>" + rows
            + "</table></div></details></div>"
        )

    return ("<section>\n<h2>Component Pipeline Results</h2>\n"
            "<p class='cp-muted'>What each AEGIS component actually produced. Source of truth: "
            "<span class='mono'>benchora_score.json &gt; component_results</span>, extracted by "
            "<span class='mono'>extract_component_results.py</span> from the component artifact "
            "files; gate status from <span class='mono'>gates/&lt;component&gt;.PASS|.FAIL</span>.</p>\n"
            + _CP_STYLE + "\n" + "".join(cards) + "\n</section>\n")


def _render_footer(now) -> str:
    return f"""<div class="report-footer">
  <div class="container">
    <strong>Securin</strong> &middot; Internal &middot; Confidential &middot; v1.0<br>
    AEGIS Programme &middot; Benchmark Round 1<br>
    Generated by <code>render_benchmark_report.py</code> on {_esc(now)}
  </div>
</div>"""


def main():
    ap = argparse.ArgumentParser(description="Generate AEGIS benchmark HTML report")
    ap.add_argument("--score", required=True, help="Path to benchora_score.json")
    ap.add_argument("--prices", default=None, help="Path to model_prices.json (for cost derivation)")
    ap.add_argument("--output", default=None, help="Output HTML path (default: <score-dir>/benchmark_report.html)")
    args = ap.parse_args()

    score = _read_json(args.score)
    if not score:
        print(f"ERROR: Cannot read {args.score}", file=sys.stderr)
        sys.exit(1)

    prices = None
    if args.prices:
        all_prices = _read_json(args.prices)
        if all_prices:
            model = score.get("model", "")
            prices = all_prices.get(model) or all_prices.get(f"anthropic/{model}")
            if not prices:
                print(f"WARNING: No pricing found for model '{model}' in {args.prices}", file=sys.stderr)

    html_content = render_report(score, prices)

    output = args.output
    if not output:
        output = os.path.join(os.path.dirname(args.score), "benchmark_report.html")

    with open(output, "w", encoding="utf-8", newline="") as f:
        f.write("<!doctype html>\n<html lang='en'>\n<head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>\n")
        f.write(html_content.split("</style>")[0] + "</style>\n</head>\n<body>\n<!--email_off-->\n")
        f.write(html_content.split("</style>", 1)[1])
        f.write("\n<!--/email_off-->\n</body>\n</html>")

    print(f"Report written to {output}")
    print(f"  Score: {args.score}")
    print(f"  Model: {score.get('model', '?')}")
    print(f"  Target: {score.get('target', '?')}")


if __name__ == "__main__":
    main()
