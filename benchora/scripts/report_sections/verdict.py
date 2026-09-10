#!/usr/bin/env python3
"""verdict.py — Verdict section.

Renders the data layer's headline verdict, its supporting points, a
provenance block (model / target / run count / generated-at / run ids),
and a fixed methodology note. This module computes nothing: every claim
comes from data["verdict"], every provenance fact from data["meta"].
"""
from __future__ import annotations

from .base import esc, verdict_badge, tone_class, section, card, note


def _points(points: list) -> str:
    rows = []
    for p in points:
        label = esc(p.get("label"))
        text = esc(p.get("text"))
        cls = tone_class(p.get("tone"))
        rows.append(f'<div class="vpoint"><b>{label}</b><span class="{cls}">{text}</span></div>')
    return "".join(rows)


def _box(v: dict) -> str:
    headline = esc(v.get("headline"))
    badge = verdict_badge(v.get("verdict"))
    points = _points(v.get("points") or [])
    return (
        f'<div class="verdict-box">'
        f'<p class="verdict-head">{headline} {badge}</p>'
        f"{points}"
        f"</div>"
    )


def _provenance(meta: dict) -> str:
    run_ids = "".join(f"<code>{esc(r)}</code> " for r in meta.get("run_ids", []))
    rows = (
        f"<div><b>Model</b>{esc(meta.get('model_display'))}</div>"
        f"<div><b>Target</b><code>{esc(meta.get('target'))}</code></div>"
        f"<div><b>Runs</b>{esc(meta.get('run_count'))}</div>"
        f"<div><b>Generated</b>{esc(meta.get('generated_at'))}</div>"
    )
    body = (
        f'<div class="meta-grid">{rows}</div>'
        f'<p class="note">Run ids: {run_ids.strip()}</p>'
    )
    return card(body, title="Provenance")


def _methodology() -> str:
    return f"""<details>
  <summary>Methodology &amp; how to read this verdict</summary>
  <div class="detail-body">
    <p>Findings are matched to ground truth, then matched across runs by CWE and
    normalised endpoint, because the model rewords the same vulnerability
    differently in each run.</p>
    <p>&ldquo;Unmatched&rdquo; means a finding was reported but has no ground-truth
    entry. Its status is UNKNOWN &mdash; it is not a confirmed false positive.
    The ground truth covers only what was tested, so an unmatched finding may
    still be a real issue that simply falls outside the tested scope.</p>
    <p>Consistency is judged by coefficient of variation (CV) across runs:
    CV &lt; 0.05 is consistent, 0.05&ndash;0.20 is variable, &gt; 0.20 is unstable.</p>
  </div>
</details>"""


def render(data: dict) -> str:
    v = data.get("verdict") or {}
    if not v:
        return ""

    meta = data.get("meta") or {}
    body = _box(v) + _provenance(meta) + _methodology()
    return section("verdict", "Verdict", body,
                    "Overall repeatability assessment, with full provenance for audit.")
