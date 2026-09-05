---
description: Build or update ground truth for a target — seed endpoints.json + vulns.json from an existing run, then curate
---

# Build Ground Truth

Create or update ground truth files for GT-based scoring (Areas 1, 4, 5).

## Inputs

- `TARGET` — target name (e.g., "juice-shop", "medicare")
- `GT_DIR` — where to write ground truth (typically `AEGIS_IQ/ground_truth/<target>/`)
- `SEED_RUN` (optional) — path to an existing run directory to seed from

## Procedure

1. **Check existing** — see if endpoints.json and vulns.json already exist in GT_DIR.

2. **Seed** (if SEED_RUN provided) — run build_ground_truth.py:
   ```bash
   python scripts/build_ground_truth.py --target "$TARGET" --gt-dir "$GT_DIR" --seed-from "$SEED_RUN" --json
   ```
   This extracts:
   - Endpoints from crawl_surface.json → endpoints.json
   - Vulns from scored-findings.jsonl → vulns.json

3. **Review seeded data** — read the generated files and report:
   - Endpoint count (total, unique after normalization)
   - Vuln count (total, by severity, by CWE category)
   - Which are marked exploitable
   - How many need manual verification (verified: false)

4. **Guide curation** — tell the user:
   - All entries start with `"verified": false`
   - They need to set `"verified": true` for entries they've confirmed
   - They can add missing endpoints/vulns manually
   - For vulns: set `"exploitable": true` for vulns that should count in Area 5

5. **Create empty** (if no SEED_RUN) — write skeleton files:
   ```bash
   python scripts/build_ground_truth.py --target "$TARGET" --gt-dir "$GT_DIR" --json
   ```

## Output

- `GT_DIR/endpoints.json` — `{"target": "...", "endpoints": [...]}`
- `GT_DIR/vulns.json` — `{"target": "...", "vulns": [...]}`

## Schema

### endpoints.json entries
```json
{
    "url": "https://target/path",
    "method": "GET",
    "path": "/path",
    "normalized_path": "/path/{id}",
    "auth_required": false,
    "verified": true
}
```

### vulns.json entries
```json
{
    "endpoint": "https://target/api/endpoint",
    "cwe": "CWE-79",
    "vuln_class": "xss",
    "severity": "high",
    "exploitable": true,
    "description": "Reflected XSS in search parameter",
    "verified": true
}
```
