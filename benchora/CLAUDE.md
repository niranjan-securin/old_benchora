# Benchora — Model Benchmark Intelligence

You are operating inside **benchora**, the AEGIS model benchmarking application.
You analyse completed AEGIS run data to produce cross-model comparison reports.

## What you do here

- **Score** individual runs: read pre-computed metrics, detect refusals, validate schemas, compute GT accuracy and test case results
- **Compare** models: load scored runs, compute 11-area ratings, rank models
- **Report**: generate self-contained HTML comparison reports
- **Ground truth**: build/manage endpoints.json + vulns.json for targets

## What you DO NOT do

- DO NOT hit any target host, scan, probe, or make network requests
- DO NOT modify the operator's AEGIS_IQ data — read it, never mutate it
- DO NOT fabricate metrics — every number must trace to a source artifact file and field

## Source of truth

Every metric in benchora output must be traceable:
- Endpoint counts → crawl_surface.json or endpoints.inventory.json matched against groundtruth/endpoints.json
- Finding counts → scored-findings.jsonl from the reporting component
- Cost data → bench/benchmark_results.json (primary) or transcript token counts × model_prices.json (fallback)
- Token counts → bench/benchmark_results.json per-component A1_tokens
- Exploit rates → vulnerability_exploitation exploits.jsonl verification_status fields
- Gate status → gates/{component}.PASS or .FAIL files

When data is missing, report null — never silently default to 0. A zero score and "no data" are different things.

## Input

The AEGIS_IQ folder path is in env var `BENCHORA_AEGIS_IQ`.

```
AEGIS_IQ/
  runs/<run_id>/
    manifest.json              — model, target, repeat#
    artifacts/                 — full run output from AEGIS
      bench/benchmark_results.json  — pre-computed per-component metrics
      bench/metrics.json            — Group A/B/C metrics
      bench/score_metrics.json      — P1-G1 named metrics
      trace.jsonl              — component → session mapping
      gates/                   — per-component gate status
      <component>/             — component artifacts
    transcripts/               — Claude Code session .jsonl files
      <component>/<uuid>.jsonl
  ground_truth/<target>/       — endpoints.json + vulns.json (optional)
  config/                      — model_prices.json, evaluation_areas.json, etc.
```

## Scoring methodology

Two grading tracks:
- **GT-based** (Areas 1, 4, 5): compare output to ground truth → TP/Unmatched/FN/precision/recall
- **Test-case** (Areas 2, 3, 6, 7, 8): user-provided minimum criteria → pass/fail rate
- **Computed** (Areas 9, 10, 11): refusals, cost, reproducibility from metrics

Rating scale (relative, needs ≥ 2 models):
Leading > Strong > Adequate > Weak > Not viable

## Key scripts (in benchora/scripts/)

- `parse_transcript.py` — standalone token/cost extractor from .jsonl transcripts
- `detect_refusals.py` — 8-type refusal scanner (guardrails + API blocks + hook blocks)
- `compute_gt_accuracy.py` — TP/Unmatched/FN against ground truth
- `evaluate_test_cases.py` — test case assertion runner
- `count_duplicates.py` — dedup stats from _grouped_from
- `compute_area_scores.py` — 11 scoring formulas
- `assign_ratings.py` — rating scale algorithm
- `compare_models.py` — cross-model comparison engine
- `render_comparison.py` — Markdown + HTML report generator
- `build_ground_truth.py` — ground truth bootstrapper (seed from existing runs)
- `validate_schemas.py` — lightweight structural validation of component artifacts
- `extract_finding_details.py` — read finding.md files from reporting/findings/, parse frontmatter + sections
- `extract_cwe_cve.py` — CWE/CVE/CVSS/OWASP/runtime extraction from run artifacts
- `extract_component_results.py` — per-component result extraction (endpoints, findings, exploits, chains, etc.)
