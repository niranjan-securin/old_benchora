---
description: Generate cross-model comparison report — render comparison.json to Markdown + standalone HTML. For single-run reports use /benchmark-report instead.
---

# Generate Comparison Report

Render comparison.json into human-readable Markdown and HTML reports.
**For single-run reports**, use `/benchmark-report` which calls `render_benchmark_report.py`.

## Inputs

- `COMPARISON_JSON` — path to comparison.json (from the compare step)
- `OUTPUT_DIR` (optional) — where to write reports (defaults to same directory as comparison.json)

## Procedure

1. **Render** — run render_comparison.py:
   ```bash
   python scripts/render_comparison.py --comparison "$COMPARISON_JSON" --output-dir "$OUTPUT_DIR" --format both
   ```

2. **Verify Markdown** — read comparison.md and check:
   - Verdict section has recommended/runner-up/cost leader
   - Overall ranking table has all models
   - Per-area ratings table has all 11 areas × all models
   - Area detail sections have mean/stdev/rank
   - No "N/A" in unexpected places

3. **Verify HTML** — check comparison.html is well-formed:
   - Self-contained (no external dependencies)
   - Dark/light theme support
   - Rating colors match the scale (green=Leading → red=Not viable)
   - Heatmap renders all areas × models
   - Responsive layout

4. **Present** to user:
   - Summary of what was generated
   - Key findings from the verdict
   - Path to output files

## Output

- `OUTPUT_DIR/comparison.md` — Markdown report
- `OUTPUT_DIR/comparison.html` — standalone HTML report
