---
description: Compare all scored models for a target — compute 11-area ratings, reproducibility, overall ranking, write comparison.json
---

# Compare Models

Run the cross-model comparison for a scored target.

## Inputs

- `AEGIS_IQ` — path to AEGIS_IQ folder
- `TARGET` — target name
- `OUTPUT_DIR` (optional) — where to write comparison.json (defaults to `benchora/output/`)

## Prerequisites

All runs for this target must be scored (have `benchora_score.json`). Run `score-batch` first if needed.

## Procedure

1. **Load scores** — run compare_models.py:
   ```bash
   python scripts/compare_models.py --aegis-iq "$AEGIS_IQ" --target "$TARGET" --output "$OUTPUT_DIR" --json
   ```

2. **Review output** — check comparison.json contains:
   - `model_count` matches expected (10 models × 3 repeats = 30 runs → 10 model entries)
   - `area_ratings` has all 11 areas
   - `overall` has rankings for all models
   - `verdict.recommended` is set

3. **Validate ratings** — quick sanity checks:
   - At most 1 model per area rated "Leading"
   - Models with structural_failures are "Not viable" in affected areas
   - Cost area uses inverse ranking (lowest cost = best)
   - Reproducibility computed from cross-repeat Jaccard

4. **Report** verdict to user:
   - Recommended model and runner-up
   - Cost leader
   - Areas where different models lead
   - Any structural failures

## Output

`OUTPUT_DIR/comparison.json` — the full comparison data used by report generation.
