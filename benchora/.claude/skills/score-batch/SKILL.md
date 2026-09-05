---
description: Score all unscored runs for a target — finds runs missing benchora_score.json and scores each one
---

# Score Batch

Score all unscored AEGIS runs for a given target.

## Inputs

- `AEGIS_IQ` — path to AEGIS_IQ folder
- `TARGET` — target name to filter by
- `GT_DIR` (optional) — ground truth directory

## Procedure

1. **Scan runs** — list all `AEGIS_IQ/runs/*/manifest.json`, filter by target name.

2. **Identify unscored** — check which runs lack `benchora_score.json`.

3. **Score each** — for each unscored run, invoke the `score-run` skill:
   - Pass the run directory and GT directory
   - Log progress: "Scoring run N of M: <run_id> (<model>)"

4. **Summary** — report:
   - Total runs found for target
   - Already scored (skipped)
   - Newly scored
   - Failed (with error details)

## Output

Each scored run gets its own `benchora_score.json`. No batch output file — the comparison step reads them all.

## Error handling

- If a run's transcripts are missing or empty, log a warning and skip (don't fail the batch)
- If a script errors on one run, record the error and continue to next run
- Report all failures at the end
