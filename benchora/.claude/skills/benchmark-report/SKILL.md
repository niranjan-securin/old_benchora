---
description: Generate a comprehensive single-run HTML benchmark report from benchora_score.json — white+purple theme, full source-of-truth for every metric, Securin branding
---

# Benchmark Report

Generate a self-contained HTML benchmark report for a single AEGIS run.

## Quick start

```bash
python scripts/render_benchmark_report.py \
  --score output/<run>/benchora_score.json \
  --prices config/model_prices.json \
  --output output/<run>/benchmark_report.html
```

## What it produces

A self-contained HTML file (no CDN dependencies, embeds Google Fonts only) with:

- **White + purple theme** (Securin branding), dark theme support
- **Executive KPI strip**: endpoint recall, finding F1, exploit rate, cost, refusals, schema pass, wall clock
- **Full source-of-truth** for every metric — expandable detail lists, calculation formulas, matching logic explanations

### Report sections

1. **Header**: Model, target, run ID, generation date. Context: Securin · Application Penetration Testing · AEGIS Programme · Benchmark Round 1
2. **KPI Strip**: 7 key metrics at a glance
3. **Endpoint Coverage (Area 1)**: GT vs found, TP/Unmatched/FN with expandable lists of every endpoint, precision/recall/F1 with formula, path normalization rules, 404 filtering, method mismatch credits
4. **Vulnerability Analysis (Area 4)**: TP/Unmatched/FN with expandable tables showing endpoint, title, CWE, severity, CVSS for each finding. Matching logic explained (path, CWE family, class). OWASP coverage tags
5. **Exploitation (Area 5)**: GT exploitable, found, reproduced, exploit rate with formula
6. **Duplicate Analysis**: Pre/post dedup counts, ratio, by-component breakdown
7. **Refusal Analysis**: Total/guardrail/API/hook counts, guardrail rate formula, by-type and by-component tables, structural failures
8. **Reliability (Area 9)**: Schema pass rate, gate pass/fail, error count, reliability formula
9. **Token Consumption & Cost (Area 10)**: 4-way token split (input/output/cache_write/cache_read), pricing per million, full cost derivation showing token × price for each type, by-component table with cost share %
10. **Security Intelligence**: CWE distribution, OWASP Top 10 coverage, severity distribution, CVSS scores, CVE detection
11. **Wall-Clock Time**: Total runtime, by-component durations
12. **Component Pipeline Results**: Per-component output summary — what each AEGIS component produced (see §Component Pipeline below)
13. **Area Scores**: All 11 evaluation areas with scores, methods, progress bars
14. **Component Detail (Annex C)**: Per-component tokens, cost, share %, turns, transcript files

## Context: AEGIS Model Benchmark Experiment Plan

### 11 Evaluation Areas
| # | Area | Grading Track | Primary Metric |
|---|------|--------------|----------------|
| 1 | Reconnaissance & Surface Discovery | GT-based | recall |
| 2 | Interactive Surface Discovery | Test-case | pass_rate |
| 3 | White-Box Code Analysis (SAST) | Test-case | pass_rate |
| 4 | Vulnerability Analysis | GT-based | F1 |
| 5 | Exploitation & Verification | GT-based | exploit_rate |
| 6 | Attack Path & Chaining | Test-case | pass_rate |
| 7 | Business Logic Testing | Test-case | pass_rate |
| 8 | Reporting Quality | Test-case | pass_rate |
| 9 | Reliability & Autonomy | Computed | composite |
| 10 | Cost Efficiency | Computed | inverse USD |
| 11 | Reproducibility | Computed multi-run | composite |

### Scoring methodology
- **GT-based** (Areas 1, 4, 5): compare output to ground truth → TP/Unmatched/FN/precision/recall/F1
- **Test-case** (Areas 2, 3, 6, 7, 8): user-provided criteria → pass/fail rate (deferred to comparison phase)
- **Computed** (Areas 9, 10, 11): from run metrics

### Rating scale (needs ≥2 models)
Leading > Strong > Adequate > Weak > Not viable

### Key matching logic
- **Path normalization**: template vars → `{id}`, slashes unified, hyphens/underscores equivalent
- **CWE families**: access_control (284/285/639/862/863), info_exposure (200/203/204/209), injection (74/79/89), auth (287/306/307), file (22/434), crypto (326/327/328)
- **Prefix path matching**: GT `/admin/` matches scanner `/admin/login/`
- **Content dedup**: CWE + first 60 chars of title

### Reliability formula
`0.30*(1-guardrail_rate) + 0.25*schema_pass_rate + 0.25*gate_pass_rate + 0.20*(1-error_rate)`

### Cost calculation
`input × input_per_million/1M + output × output_per_million/1M + cache_write × cache_write_per_million/1M + cache_read × cache_read_per_million/1M`

## Inputs

| Input | Source | Required |
|-------|--------|----------|
| `benchora_score.json` | Output of `score_run.py` | Yes |
| `model_prices.json` | `config/model_prices.json` | No (enables cost derivation display) |

## Component Pipeline Results (Section 12)

Show a card per AEGIS component summarizing what it produced. Data source: `benchora_score.json > component_results` (populated by `extract_component_results.py`).

### Per-component metrics

| Component | Key Metrics to Surface | Source Files |
|-----------|----------------------|--------------|
| **Crawler** | Endpoint count, roles crawled, role matrix (role×endpoint reachability), forms found/submitted, mutation ratio, business flows inferred, screenshots captured, noteworthy behaviors (from SUMMARY.md) | `_workdir/<target>/reports/endpoints.inventory.json`, `role_matrix.json`, `inferred_flows.json`, `frontier.json`, `SUMMARY.md` |
| **Attack Surface Discovery** | Hosts discovered (count + in-scope), tech fingerprints (product, category, confidence), paths found, CVEs identified, secrets exposed, JS findings, cloud assets, subdomain takeover candidates | `surface.json`, `hosts.jsonl`, `techstack.jsonl`, `paths.jsonl`, `cves.jsonl`, `secrets.jsonl`, `js_findings.jsonl`, `cloud_assets.jsonl`, `takeovers.jsonl` |
| **Planner** | Test case count, OWASP categories covered, priority distribution (critical/high/medium/low), coverage ledger completion %, endpoint catalog size | `plan.json`, `test_cases.jsonl`, `coverage_ledger.json` |
| **Vulnerability Discovery** | Finding count by severity, by OWASP category, verification status breakdown (unverified/verified-poc/verified-exploit), unique endpoints targeted, finding batches produced | `findings.jsonl` (all batches) |
| **Exploitation** | Total attempts, success count, verification statuses (verified-poc / verified-exploit / failed / skipped), PoC scripts available, exploit writeups produced, destructive flag summary | `exploits.jsonl`, `f_{id}.exploit.json`, `f_{id}.exploit.md`, `scripts/f_{id}.sh` |
| **Hacker** | Additional findings count, unique findings not already in discovery, chain escalations (e.g. SQLi→RCE, credential dumps, ATO chains), screenshots captured | `hacker_findings.jsonl`, `screenshots/` |
| **Vulnerability Chaining** | Objectives defined/achieved (CIA + priv-esc + CVE), chain count, graph metrics (node count, edge count, entry points, choke points, dead ends, clusters), mermaid diagram availability | `attack_chain.json`, `chain_graph_analysis.json`, `scored-chains.jsonl`, `objectives.jsonl`, `attack_chain.mermaid.md` |
| **Reporting** | Final finding count, severity distribution, CVSS score spread (min/max/mean), deliverables produced (report.md, HTML, PDF, DOCX, SARIF, CSV, Jira, DefectDojo), screenshots captured, severity reconciliation count | `reporting-manifest.json`, `render-manifest.json`, `scored-findings.jsonl`, `screenshots/index.json` |

### Display format

Each component renders as a card with:
- Component name + gate status badge (PASS/FAIL from `gates/`)
- 2–4 key metric values (endpoint count, finding count, etc.)
- Expandable detail list with all metrics
- Source file links for traceability

Components that did not run or produced no output show as "N/A" (greyed-out card, `.na-card` class).

## Design System

All reports MUST follow this design system for visual consistency. Reference implementation: `output/benchora-report.html`.

### Color Palette (CSS Custom Properties)

**Light theme** (`:root`):
| Token | Hex | Usage |
|-------|-----|-------|
| `--bg` | `#F4F6FA` | Page background |
| `--bg-card` | `#FFFFFF` | Card/panel background |
| `--bg-card-alt` | `#EDF0F5` | Table header, alternating rows |
| `--ink` | `#1A1E2E` | Primary text |
| `--ink-secondary` | `#4A5068` | Secondary text, subheadings |
| `--ink-muted` | `#7A8098` | Labels, captions |
| `--border` | `#D0D5E0` | Major dividers |
| `--border-subtle` | `#E4E8F0` | Card borders, table lines |
| `--accent` | `#0A8F7F` | Teal — primary accent, links, highlighted cards |
| `--accent-light` | `#E0F5F2` | Accent badge backgrounds |
| `--warn` | `#D4880F` | Warning/medium severity |
| `--warn-light` | `#FFF3DC` | Warning backgrounds |
| `--critical` | `#C4384B` | Critical/high severity |
| `--critical-light` | `#FDEDEF` | Critical backgrounds |
| `--success` | `#2D8A56` | Good/pass values |
| `--success-light` | `#E6F5ED` | Success backgrounds |
| `--chart-1` through `--chart-8` | Teal→Blue→Purple→Amber→Red→Green→Indigo→Pink | Chart series colors |
| `--gantt-track` | `#E4E8F0` | Gantt track background |
| `--shadow` | `0 1px 3px rgba(26,30,46,0.08)` | Card shadow |

**Dark theme** (`@media (prefers-color-scheme: dark)` guarded by `:root:not([data-theme="light"])`, duplicated under `:root[data-theme="dark"]`):
| Token | Hex |
|-------|-----|
| `--bg` | `#0E1219` |
| `--bg-card` | `#171D28` |
| `--bg-card-alt` | `#1E2535` |
| `--ink` | `#D8DCE6` |
| `--ink-secondary` | `#9BA3B8` |
| `--ink-muted` | `#6B7390` |
| `--accent` | `#2ECDB5` |
| `--warn` | `#F0A030` |
| `--critical` | `#F06070` |
| `--success` | `#4ADE80` |

### Typography

| Role | Face | Weight | Size |
|------|------|--------|------|
| Display / headings | `Source Serif 4`, Georgia, serif | 600–700 | h1: 1.75rem, h2: 1.35rem, h3: 1.05rem |
| Body | `IBM Plex Sans`, system-ui, sans-serif | 400–600 | Base: 0.88rem, line-height: 1.55 |
| Data / code | `JetBrains Mono`, monospace | 500 | 0.85rem |
| Labels | `IBM Plex Sans` | 600 | 0.7–0.75rem, uppercase, letter-spacing: 0.04–0.06em |

All headings use `text-wrap: balance`. Body uses `font-variant-numeric: tabular-nums`.

### Component Patterns

| Class | Usage |
|-------|-------|
| `.score-card` | KPI metric card — `.area-label` (tiny uppercase), `.area-value` (large number), `.area-detail` (subtitle) |
| `.score-card.highlight` | Left border accent (3px solid `--accent`) |
| `.score-card.warn-card` | Left border warning (3px solid `--warn`) |
| `.score-card.na-card` | Greyed-out (opacity: 0.55) |
| `.sev-critical` | Severity badge — `--critical-light` bg, `--critical` text |
| `.sev-high` | Severity badge — `--warn-light` bg, `--warn` text |
| `.sev-medium` | Severity badge — `--accent-light` bg, `--accent` text |
| `.val-good` / `.val-warn` / `.val-bad` | Value color classes for metrics |
| `.gantt-row` / `.gantt-bar` / `.gantt-track` | Timeline visualization |
| `.owasp-grid` / `.owasp-hit` / `.owasp-miss` | OWASP coverage grid |
| `.table-wrap > table` | Responsive table with overflow-x scroll |
| `.card` | Generic content card with border-radius: 6px |
| `.chart-row` / `.chart-container` | 2-column chart layout, responsive to 1-column at 700px |

### Theme implementation

1. Define complete light palette on bare `:root`
2. Redefine tokens under `@media (prefers-color-scheme: dark)` guarded as `:root:not([data-theme="light"])`
3. Duplicate dark tokens under `:root[data-theme="dark"]`
4. `body` must set explicit `background: var(--bg)` and `color: var(--ink)`
5. Never define a color only inside a media or `[data-theme]` block

## Reference methodologies
BountyBench, Cybench, CyberGym/ExploitGym — as referenced in the AEGIS Model Benchmark Experiment Plan.
