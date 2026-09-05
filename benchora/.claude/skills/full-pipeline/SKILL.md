---
description: Run the full benchmark pipeline — score all runs, compare models, generate report in one go
---

# Full Pipeline

Run the complete benchora pipeline end-to-end for a target.

## Inputs

- `AEGIS_IQ` — path to AEGIS_IQ folder
- `TARGET` — target name
- `GT_DIR` (optional) — ground truth directory
- `OUTPUT_DIR` (optional) — output directory (defaults to `benchora/output/<target>/`)

## Procedure

### Phase 1: Score

1. Invoke `/score-batch` to score all unscored runs for the target.
2. Verify all expected runs are scored:
   - Expected: 10 models × 3 repeats = 30 runs
   - Report any missing models or repeats

### Phase 2: Compare

3. Invoke `/compare` to run the cross-model comparison.
4. Read comparison.json and verify it looks correct:
   - All models present
   - All 11 areas scored
   - Verdict populated

### Phase 3: Report

5. Invoke `/report` to generate Markdown + HTML reports.
6. Present the final verdict to the user.

## Output

```
OUTPUT_DIR/
  comparison.json    — full comparison data
  comparison.md      — Markdown report
  comparison.html    — standalone HTML report
```

## Quick start

```
BENCHORA_AEGIS_IQ=/path/to/AEGIS_IQ
# In a benchora Claude session:
/full-pipeline
# Answer: target name, AEGIS_IQ path
# Pipeline runs automatically
```

## Error handling

- If fewer than 2 models have scored runs, abort comparison (ratings need ≥ 2 models)
- If a model has fewer than 3 repeats, warn but proceed (stdev will be 0 for single-repeat)
- If no ground truth exists, GT-based areas fall back to test-case scoring or N/A
