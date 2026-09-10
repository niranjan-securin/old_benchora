#!/usr/bin/env python3
"""render_comparison_v2.py — assemble the multi-run comparison report.

Reads comparison_data.json (from prepare_comparison_data.py) and calls each
section module in report_sections/ in order.  The assembler holds no metric
logic and no HTML of its own beyond the document shell: every number comes from
the data file, every fragment from a section module.

A section that raises does NOT silently vanish — it renders an explicit error
block naming the module and the exception, because a missing section that looks
like an intentionally empty one is how a report starts lying.

Usage:
    python render_comparison_v2.py --data comparison_data.json [--output report.html]
    python render_comparison_v2.py --scores r1.json r2.json r3.json [--prices ...]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from report_sections import base  # noqa: E402

# (module name, anchor id) — rendering order is report order.
SECTIONS = [
    ("executive_summary", "summary"),
    ("metrics_table", "metrics"),
    ("repeatability", "repeatability"),
    ("severity", "severity"),
    ("findings", "findings"),
    ("endpoints", "endpoints"),
    ("components", "components"),
    ("cost_tokens", "cost"),
    ("verdict", "verdict"),
]


def _error_block(mod_name: str, exc: Exception) -> str:
    tb = base.esc(traceback.format_exc()[-1200:])
    return f"""<section class="sec"><div class="container">
<div class="card" style="border-color:var(--bad)">
  <h3 class="card-title tone-bad">Section failed to render: {base.esc(mod_name)}</h3>
  <p class="note">{base.esc(type(exc).__name__)}: {base.esc(exc)}</p>
  <details><summary>Traceback</summary><div class="detail-body"><pre style="white-space:pre-wrap;font-size:.72rem">{tb}</pre></div></details>
</div></div></section>"""


def render(data: dict, strict: bool = False) -> tuple[str, list]:
    """Render the full document. Returns (html, problems)."""
    fragments, present, problems = [], set(), []

    for mod_name, anchor in SECTIONS:
        try:
            mod = __import__(f"report_sections.{mod_name}", fromlist=["render"])
        except Exception as e:
            problems.append((mod_name, f"import failed: {e}"))
            fragments.append(_error_block(mod_name, e))
            if strict:
                raise
            continue

        if not hasattr(mod, "render"):
            problems.append((mod_name, "no render() function"))
            fragments.append(_error_block(mod_name, AttributeError("no render()")))
            continue

        try:
            html = mod.render(data)
        except Exception as e:
            problems.append((mod_name, f"render failed: {e}"))
            fragments.append(_error_block(mod_name, e))
            if strict:
                raise
            continue

        if html and html.strip():
            fragments.append(html)
            present.add(anchor)
        else:
            problems.append((mod_name, "returned empty (section omitted)"))

    nav = base.build_nav(present)
    return base.build_document(data.get("meta", {}), nav, fragments), problems


def main():
    ap = argparse.ArgumentParser(description="Assemble the multi-run comparison report")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--data", help="Path to comparison_data.json")
    src.add_argument("--scores", nargs="+", help="Score files (runs prepare step inline)")
    ap.add_argument("--prices", default=None, help="model_prices.json (only with --scores)")
    ap.add_argument("--model-display", default=None)
    ap.add_argument("--output", default=None, help="Output HTML path")
    ap.add_argument("--strict", action="store_true",
                    help="Abort on the first section failure instead of embedding an error block")
    args = ap.parse_args()

    if args.data:
        with open(args.data, encoding="utf-8") as f:
            data = json.load(f)
        default_dir = os.path.dirname(os.path.abspath(args.data))
    else:
        import prepare_comparison_data as prep
        scores = []
        for p in args.scores:
            with open(p, encoding="utf-8") as f:
                scores.append(json.load(f))
        prices = None
        if args.prices and os.path.exists(args.prices):
            with open(args.prices, encoding="utf-8") as f:
                allp = json.load(f)
            model = scores[0].get("model", "")
            prices = allp.get(model) or allp.get(f"anthropic/{model}")
        data = prep.build(scores, args.scores, prices, args.model_display)
        default_dir = os.path.dirname(os.path.dirname(os.path.abspath(args.scores[0])))

    html, problems = render(data, strict=args.strict)

    out = args.output or os.path.join(default_dir, "comparison_report.html")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)

    meta = data.get("meta", {})
    print(f"Wrote {out}  ({len(html):,} bytes)")
    print(f"  {meta.get('model_display')} · {meta.get('target')} · {meta.get('run_count')} runs")
    rendered = len(SECTIONS) - len(problems)
    print(f"  Sections: {rendered}/{len(SECTIONS)} rendered")
    if problems:
        print("  Problems:")
        for name, why in problems:
            print(f"    - {name}: {why}")
        # A section that failed to import or render is a real defect.
        if any("failed" in w for _, w in problems):
            sys.exit(2)


if __name__ == "__main__":
    main()
