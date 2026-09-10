#!/usr/bin/env python3
"""base.py — shared design system and formatters for comparison report sections.

Every module in report_sections/ imports from here and from nothing else in the
package.  Sections never import each other, so one section can be rewritten
without touching any other.

Contract for a section module:

    def render(data: dict) -> str
        data  — the full comparison_data.json dict
        return — an HTML fragment (a <section> element), or "" to be omitted

Formatters return "—" for None.  Nothing here ever invents a value.
"""
from __future__ import annotations

import html as _html

# ─── formatters ───────────────────────────────────────────────────────────────

DASH = "&mdash;"


def esc(s) -> str:
    """HTML-escape any value."""
    return _html.escape(str(s if s is not None else ""))


def fmt_pct(v, places=1) -> str:
    if v is None:
        return DASH
    return f"{v * 100:.{places}f}%"


def fmt_ratio(v, places=3) -> str:
    if v is None:
        return DASH
    return f"{v:.{places}f}"


def fmt_int(v) -> str:
    if v is None:
        return DASH
    try:
        return f"{int(round(float(v))):,}"
    except (TypeError, ValueError):
        return DASH


def fmt_usd(v) -> str:
    if v is None:
        return DASH
    return f"${v:,.2f}"


def fmt_min(v) -> str:
    if v is None:
        return DASH
    return f"{v:,.1f}"


def fmt_num(v, places=3) -> str:
    if v is None:
        return DASH
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, int):
        return f"{v:,}"
    if isinstance(v, float):
        return f"{v:,.{places}f}"
    return esc(v)


_FMT = {
    "pct": fmt_pct, "ratio": fmt_ratio, "int": fmt_int,
    "usd": fmt_usd, "min": fmt_min, "num": fmt_num,
}


def fmt_value(v, kind="num") -> str:
    """Format by the `format` field carried on every stat row."""
    return _FMT.get(kind, fmt_num)(v)


def fmt_delta(v, kind="num") -> str:
    """Signed formatting, for spread and difference columns."""
    if v is None:
        return DASH
    s = fmt_value(abs(v), kind)
    return f"+{s}" if v > 0 else (f"&minus;{s}" if v < 0 else s)


def pct_of(v, total) -> float:
    """Safe percentage for bar widths. Always 0..100."""
    if not total or v is None:
        return 0.0
    return max(0.0, min(100.0, (v / total) * 100.0))


# ─── badges and status chips ──────────────────────────────────────────────────

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def severity_badge(sev) -> str:
    s = str(sev or "").strip().lower()
    if s not in SEV_ORDER:
        return f'<span class="badge badge-none">{esc(sev) if sev else DASH}</span>'
    return f'<span class="badge sev-{s}">{s.title()}</span>'


def verdict_badge(verdict) -> str:
    """consistent | variable | unstable | unknown"""
    v = str(verdict or "unknown").lower()
    label = {"consistent": "Consistent", "variable": "Variable",
             "unstable": "Unstable", "unknown": "No data"}.get(v, v.title())
    return f'<span class="badge vd-{v}">{label}</span>'


def status_cell(status) -> str:
    """One run's status for a finding: tp | unmatched | absent."""
    s = str(status or "absent").lower()
    label = {"tp": "Matched", "unmatched": "Unmatched", "absent": DASH}.get(s, esc(s))
    return f'<td class="st st-{s}">{label}</td>'


def consistency_badge(count, total) -> str:
    if not total:
        return DASH
    if count == total:
        cls = "cons-all"
    elif count == 0:
        cls = "cons-none"
    else:
        cls = "cons-partial"
    return f'<span class="badge {cls}">{count}/{total}</span>'


def tone_class(tone) -> str:
    return {"good": "tone-good", "warn": "tone-warn", "bad": "tone-bad"}.get(
        str(tone or "").lower(), "tone-neutral")


def bool_mark(ok) -> str:
    return ('<span class="mark ok">&#10003;</span>' if ok
            else '<span class="mark no">&#10007;</span>')


# ─── layout primitives ────────────────────────────────────────────────────────

def section(anchor: str, title: str, body: str, subtitle: str = "") -> str:
    """Standard section wrapper. `anchor` must match the nav id."""
    sub = f'<p class="sec-sub">{subtitle}</p>' if subtitle else ""
    return f"""<section id="{esc(anchor)}" class="sec">
  <div class="container">
    <h2 class="sec-title">{esc(title)}</h2>
    {sub}
    {body}
  </div>
</section>"""


def card(body: str, title: str = "", cls: str = "") -> str:
    h = f'<h3 class="card-title">{esc(title)}</h3>' if title else ""
    return f'<div class="card {cls}">{h}{body}</div>'


def table(headers: list, rows_html: str, cls: str = "") -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    return (f'<div class="tbl-wrap"><table class="{cls}">'
            f"<thead><tr>{head}</tr></thead><tbody>{rows_html}</tbody></table></div>")


def note(text: str) -> str:
    return f'<p class="note">{text}</p>'


def run_headers(meta: dict, extra: list = None) -> list:
    """Column headers for a per-run table."""
    cols = list(meta.get("run_labels") or [])
    return cols + (extra or [])


# ─── document shell ───────────────────────────────────────────────────────────

NAV_ITEMS = [
    ("summary", "Summary"),
    ("metrics", "Metrics"),
    ("repeatability", "Repeatability"),
    ("severity", "Severity"),
    ("findings", "Findings"),
    ("endpoints", "Endpoints"),
    ("components", "Components"),
    ("cost", "Cost & Tokens"),
    ("verdict", "Verdict"),
]


def build_nav(present_anchors: set) -> str:
    links = "".join(
        f'<a href="#{a}">{esc(l)}</a>' for a, l in NAV_ITEMS if a in present_anchors)
    return f'<nav class="topnav"><div class="container nav-inner">{links}</div></nav>'


def build_header(meta: dict) -> str:
    ids = " &middot; ".join(f"<code>{esc(r)}</code>" for r in meta.get("run_ids", []))
    return f"""<header class="report-header">
  <div class="container">
    <div class="eyebrow">Securin &middot; Application Penetration Testing &middot; AEGIS Programme</div>
    <h1>{esc(meta.get('model_display', 'Model'))} &mdash; {meta.get('run_count', 0)}-Run Comparison</h1>
    <p class="sub">Cross-run repeatability and metric comparison against ground truth</p>
    <div class="meta-row">
      <span><strong>Target:</strong> <code>{esc(meta.get('target'))}</code></span>
      <span><strong>Runs:</strong> {meta.get('run_count', 0)}</span>
      <span><strong>Generated:</strong> {esc(meta.get('generated_at'))}</span>
    </div>
    <div class="run-ids">{ids}</div>
  </div>
</header>"""


def build_footer(meta: dict) -> str:
    srcs = "".join(f"<li><code>{esc(p)}</code></li>" for p in meta.get("source_files", []))
    return f"""<footer class="report-footer">
  <div class="container">
    <details class="src">
      <summary>Source artefacts ({len(meta.get('source_files', []))})</summary>
      <ul>{srcs}</ul>
    </details>
    <p><strong>Securin</strong> &middot; Internal &middot; Confidential<br>
    Generated by <code>render_comparison_v2.py</code> on {esc(meta.get('generated_at'))}</p>
  </div>
</footer>"""


CSS = """
:root{
  --bg:#f6f7fb; --panel:#ffffff; --fg:#0f172a; --muted:#64748b; --faint:#94a3b8;
  --border:#e4e8f0; --border-strong:#cbd5e1; --hover:#f1f5f9;
  --accent:#6d28d9; --accent-2:#8b5cf6; --accent-bg:#f3f0ff; --accent-fg:#5b21b6;
  --good:#15803d; --good-bg:#dcfce7; --warn:#b45309; --warn-bg:#fef3c7;
  --bad:#b91c1c; --bad-bg:#fee2e2; --info:#1d4ed8; --info-bg:#dbeafe;
  --sev-critical:#b91c1c; --sev-critical-bg:#fee2e2;
  --sev-high:#c2410c; --sev-high-bg:#ffedd5;
  --sev-medium:#b45309; --sev-medium-bg:#fef3c7;
  --sev-low:#3f6212; --sev-low-bg:#ecfccb;
  --sev-info:#475569; --sev-info-bg:#f1f5f9;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  --radius:12px; --shadow:0 1px 2px rgba(15,23,42,.05),0 1px 3px rgba(15,23,42,.04);
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0b0f19; --panel:#141a29; --fg:#e6ebf4; --muted:#94a3b8; --faint:#64748b;
  --border:#1f2937; --border-strong:#334155; --hover:#1b2333;
  --accent:#a78bfa; --accent-2:#c4b5fd; --accent-bg:#211a3a; --accent-fg:#c4b5fd;
  --good:#4ade80; --good-bg:#14311f; --warn:#fbbf24; --warn-bg:#3a2c0a;
  --bad:#f87171; --bad-bg:#3b1414; --info:#60a5fa; --info-bg:#12233d;
  --sev-critical:#f87171; --sev-critical-bg:#3b1414;
  --sev-high:#fb923c; --sev-high-bg:#3a1f0b;
  --sev-medium:#fbbf24; --sev-medium-bg:#3a2c0a;
  --sev-low:#a3e635; --sev-low-bg:#1f2d0b;
  --sev-info:#94a3b8; --sev-info-bg:#1b2333;
  --shadow:0 1px 2px rgba(0,0,0,.4);
}}
:root[data-theme="dark"]{
  --bg:#0b0f19; --panel:#141a29; --fg:#e6ebf4; --muted:#94a3b8; --faint:#64748b;
  --border:#1f2937; --border-strong:#334155; --hover:#1b2333;
  --accent:#a78bfa; --accent-2:#c4b5fd; --accent-bg:#211a3a; --accent-fg:#c4b5fd;
  --good:#4ade80; --good-bg:#14311f; --warn:#fbbf24; --warn-bg:#3a2c0a;
  --bad:#f87171; --bad-bg:#3b1414; --info:#60a5fa; --info-bg:#12233d;
  --sev-critical:#f87171; --sev-critical-bg:#3b1414;
  --sev-high:#fb923c; --sev-high-bg:#3a1f0b;
  --sev-medium:#fbbf24; --sev-medium-bg:#3a2c0a;
  --sev-low:#a3e635; --sev-low-bg:#1f2d0b;
  --sev-info:#94a3b8; --sev-info-bg:#1b2333;
  --shadow:0 1px 2px rgba(0,0,0,.4);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);
  font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
.container{max-width:1280px;margin:0 auto;padding:0 24px}
code{font-family:var(--mono);font-size:.86em}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

/* header */
.report-header{background:linear-gradient(135deg,var(--accent) 0%,var(--accent-2) 100%);
  color:#fff;padding:40px 0 52px}
.report-header h1{margin:6px 0 4px;font-size:1.9rem;font-weight:700;letter-spacing:-.02em}
.eyebrow{font-size:.7rem;text-transform:uppercase;letter-spacing:.12em;opacity:.85;font-weight:600}
.report-header .sub{margin:0 0 14px;opacity:.92;font-size:.95rem}
.meta-row{display:flex;flex-wrap:wrap;gap:20px;font-size:.82rem;opacity:.95}
.meta-row code{background:rgba(255,255,255,.16);padding:1px 6px;border-radius:4px}
.run-ids{margin-top:10px;font-size:.72rem;opacity:.8}
.run-ids code{background:rgba(255,255,255,.12);padding:1px 5px;border-radius:4px}

/* nav */
.topnav{position:sticky;top:0;z-index:50;background:var(--panel);
  border-bottom:1px solid var(--border);box-shadow:var(--shadow)}
.nav-inner{display:flex;gap:4px;overflow-x:auto;padding-top:0;padding-bottom:0}
.topnav a{padding:12px 14px;font-size:.8rem;font-weight:500;color:var(--muted);
  white-space:nowrap;border-bottom:2px solid transparent}
.topnav a:hover{color:var(--accent);background:var(--hover);text-decoration:none}

/* sections */
.sec{padding:32px 0}
.sec-title{font-size:1.15rem;font-weight:650;margin:0 0 4px;letter-spacing:-.01em}
.sec-sub{margin:0 0 16px;color:var(--muted);font-size:.85rem;max-width:80ch}
.card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 20px;box-shadow:var(--shadow);margin-bottom:16px}
.card-title{font-size:.92rem;font-weight:600;margin:0 0 12px}
.note{font-size:.78rem;color:var(--muted);margin:10px 0 0}

/* kpi */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;
  margin-top:-32px;position:relative;z-index:1}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px 18px;box-shadow:var(--shadow)}
.kpi-val{font-size:1.6rem;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.kpi-label{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
  font-weight:600;margin-top:2px}
.kpi-sub{font-size:.74rem;color:var(--faint);margin-top:6px;font-variant-numeric:tabular-nums}

/* tables */
.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th,td{padding:8px 11px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  font-weight:650;white-space:nowrap;background:var(--panel);position:sticky;top:0}
tbody tr:hover{background:var(--hover)}
td.num,th.num{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums}
td.ctr,th.ctr{text-align:center}
tr.group-row td{background:var(--accent-bg);color:var(--accent-fg);font-weight:650;
  font-size:.76rem;text-transform:uppercase;letter-spacing:.06em}
tr.total-row td{font-weight:700;background:var(--hover)}
.rowlabel{font-weight:500}

/* badges */
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.7rem;
  font-weight:650;white-space:nowrap;line-height:1.5}
.badge-none{background:var(--hover);color:var(--muted)}
.sev-critical{background:var(--sev-critical-bg);color:var(--sev-critical)}
.sev-high{background:var(--sev-high-bg);color:var(--sev-high)}
.sev-medium{background:var(--sev-medium-bg);color:var(--sev-medium)}
.sev-low{background:var(--sev-low-bg);color:var(--sev-low)}
.sev-info{background:var(--sev-info-bg);color:var(--sev-info)}
.vd-consistent{background:var(--good-bg);color:var(--good)}
.vd-variable{background:var(--warn-bg);color:var(--warn)}
.vd-unstable{background:var(--bad-bg);color:var(--bad)}
.vd-unknown{background:var(--hover);color:var(--muted)}
.cons-all{background:var(--good-bg);color:var(--good)}
.cons-partial{background:var(--warn-bg);color:var(--warn)}
.cons-none{background:var(--bad-bg);color:var(--bad)}

/* status cells */
.st{text-align:center;font-weight:650;font-size:.74rem}
.st-tp{background:var(--good-bg);color:var(--good)}
.st-unmatched{background:var(--warn-bg);color:var(--warn)}
.st-absent{color:var(--faint)}
.mark{font-weight:700}
.mark.ok{color:var(--good)}
.mark.no{color:var(--bad)}

/* bars */
.bar{height:8px;border-radius:999px;background:var(--hover);overflow:hidden;min-width:60px}
.bar>span{display:block;height:100%;border-radius:999px;
  background:linear-gradient(90deg,var(--accent),var(--accent-2))}
.sbar{display:flex;height:22px;border-radius:6px;overflow:hidden;background:var(--hover)}
.sbar>span{display:block;height:100%}
.sbar .s-critical{background:var(--sev-critical)}
.sbar .s-high{background:var(--sev-high)}
.sbar .s-medium{background:var(--sev-medium)}
.sbar .s-low{background:var(--sev-low)}
.sbar .s-info{background:var(--sev-info)}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:.75rem;color:var(--muted);margin-top:10px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;
  vertical-align:middle;font-style:normal}

/* tones */
.tone-good{color:var(--good)}
.tone-warn{color:var(--warn)}
.tone-bad{color:var(--bad)}
.tone-neutral{color:var(--muted)}

/* verdict */
.verdict-box{border-left:4px solid var(--accent);background:var(--accent-bg);
  border-radius:var(--radius);padding:20px 24px}
.verdict-head{font-size:1.2rem;font-weight:700;margin:0 0 12px;color:var(--accent-fg)}
.vpoint{display:flex;gap:12px;padding:9px 0;border-top:1px solid var(--border)}
.vpoint:first-of-type{border-top:none}
.vpoint b{min-width:150px;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);font-weight:650;flex-shrink:0}
.vpoint span{font-size:.86rem}

/* details */
details{border:1px solid var(--border);border-radius:8px;margin-bottom:8px;background:var(--panel)}
details[open]{box-shadow:var(--shadow)}
summary{cursor:pointer;padding:9px 13px;font-size:.82rem;font-weight:550;
  list-style:none;display:flex;align-items:center;gap:8px}
summary::-webkit-details-marker{display:none}
summary::before{content:"\\25B8";color:var(--muted);font-size:.75rem;transition:transform .15s}
details[open]>summary::before{transform:rotate(90deg)}
summary:hover{background:var(--hover)}
.detail-body{padding:4px 13px 13px;border-top:1px solid var(--border)}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;
  margin:10px 0;font-size:.78rem}
.meta-grid div{background:var(--hover);border-radius:6px;padding:7px 10px}
.meta-grid b{display:block;font-size:.66rem;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);margin-bottom:2px}

/* footer */
.report-footer{border-top:1px solid var(--border);margin-top:40px;padding:26px 0 40px;
  color:var(--muted);font-size:.78rem;text-align:center}
.report-footer .src{max-width:760px;margin:0 auto 16px;text-align:left}
.report-footer ul{margin:6px 0;padding-left:20px}

@media print{
  .topnav{display:none}
  .card,details{break-inside:avoid}
  body{background:#fff}
}
"""


def build_document(meta: dict, nav: str, sections: list) -> str:
    """Assemble the full standalone HTML document."""
    body = "\n".join(s for s in sections if s)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(meta.get('model_display', 'Model'))} &mdash; {meta.get('run_count', 0)}-Run Comparison</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>
{build_header(meta)}
{nav}
{body}
{build_footer(meta)}
</body>
</html>"""
