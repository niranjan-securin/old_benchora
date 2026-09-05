#!/usr/bin/env python3
"""compare_models.py — cross-model comparison engine.

Reads all benchora_score.json files from AEGIS_IQ/runs/, groups by model,
computes per-area scores with mean/stdev across repeats, assigns ratings,
computes reproducibility (Area 11), and outputs comparison.json.

Usage:
    compare_models.py --aegis-iq <path> --target <name> [--gt-dir <path>] [--json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from statistics import mean, stdev

sys.path.insert(0, os.path.dirname(__file__))
from compute_area_scores import compute_all_areas, AREA_SCORERS
from assign_ratings import assign_ratings_for_area, compute_overall_ranking, compute_repeat_stats


def _read_json(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _read_jsonl(path: str) -> list[dict]:
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    pass
    return out


def _finding_key(f: dict) -> str:
    """Stable key for a finding, for Jaccard computation."""
    endpoint = f.get("endpoint") or ""
    if not endpoint:
        aff = f.get("affected_endpoints") or []
        if aff:
            endpoint = aff[0] if isinstance(aff[0], str) else (aff[0].get("url") or "")
    cwe = f.get("cwe") or ""
    vuln_class = f.get("test_type") or f.get("owasp") or f.get("vuln_class") or ""
    return f"{endpoint}|{cwe}|{vuln_class}".lower()


def _finding_count(score: dict) -> int:
    """Number of final (post-dedup) findings for a run.

    Sources, in order of preference:
      cwe_cve.findings.finding_count  (extract_cwe_cve.py)
      duplicates.post_dedup_count     (count_duplicates.py)
      findings.scored_count           (legacy key)
    """
    for path in (("cwe_cve", "findings", "finding_count"),
                 ("duplicates", "post_dedup_count"),
                 ("findings", "scored_count")):
        cur = score
        for k in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(k)
        if isinstance(cur, (int, float)) and cur:
            return int(cur)
    return 0


def compute_reproducibility(run_scores: list[dict]) -> dict:
    """Compute Area 11 reproducibility from 3 repeats' findings."""
    if len(run_scores) < 2:
        return {"jaccard": None, "cv_finding_count": None, "cv_cost": None, "score": None}

    finding_sets = []
    finding_counts = []
    costs = []

    for score in run_scores:
        scored_path = None
        run_dir = score.get("_run_dir", "")
        if run_dir:
            for pattern in ["**/scored-findings.jsonl", "**/findings.jsonl"]:
                hits = sorted(glob.glob(os.path.join(run_dir, pattern), recursive=True))
                if hits:
                    scored_path = hits[-1]
                    break

        if scored_path:
            findings = _read_jsonl(scored_path)
            keys = {_finding_key(f) for f in findings}
            finding_sets.append(keys)
            finding_counts.append(len(findings))
        else:
            finding_counts.append(_finding_count(score))

        cost = score.get("cost", {}).get("full_run_usd", 0)
        costs.append(cost if cost else 0)

    jaccard = None
    if len(finding_sets) >= 2:
        union = set()
        intersection = finding_sets[0].copy() if finding_sets else set()
        for s in finding_sets:
            union |= s
            intersection &= s
        jaccard = len(intersection) / len(union) if union else 1.0

    cv_findings = None
    if len(finding_counts) >= 2:
        m = mean(finding_counts)
        if m > 0:
            cv_findings = stdev(finding_counts) / m

    cv_cost = None
    valid_costs = [c for c in costs if c > 0]
    if len(valid_costs) >= 2:
        m = mean(valid_costs)
        if m > 0:
            cv_cost = stdev(valid_costs) / m

    composite = None
    if jaccard is not None:
        j_part = 0.50 * jaccard
        fc_part = 0.30 * (1 - min(cv_findings or 0, 1.0))
        cc_part = 0.20 * (1 - min(cv_cost or 0, 1.0))
        composite = round(j_part + fc_part + cc_part, 4)

    return {
        "jaccard": round(jaccard, 4) if jaccard is not None else None,
        "cv_finding_count": round(cv_findings, 4) if cv_findings is not None else None,
        "cv_cost": round(cv_cost, 4) if cv_cost is not None else None,
        "score": composite,
    }


def load_all_scores(aegis_iq: str, target: str) -> dict[str, list[dict]]:
    """Load all benchora_score.json files, grouped by model."""
    models = defaultdict(list)

    for manifest_path in sorted(glob.glob(os.path.join(aegis_iq, "runs", "*", "manifest.json"))):
        manifest = _read_json(manifest_path)
        if not manifest:
            continue
        if manifest.get("target") != target:
            continue

        run_dir = os.path.dirname(manifest_path)
        model = manifest.get("model", "unknown")

        score_path = os.path.join(run_dir, "benchora_score.json")
        score = _read_json(score_path)
        if not score:
            continue

        score["_run_dir"] = run_dir
        score["_manifest"] = manifest
        models[model].append(score)

    return dict(models)


def load_scores_from_paths(score_paths: list[str]) -> dict[str, list[dict]]:
    """Load benchora_score.json files directly from paths, grouped by model."""
    models = defaultdict(list)
    for p in score_paths:
        score = _read_json(p)
        if not score:
            continue
        model = score.get("model", "unknown")
        score["_run_dir"] = os.path.dirname(p)
        models[model].append(score)
    return dict(models)


def compare(aegis_iq: str, target: str, gt_dir: str = None, score_paths: list[str] = None) -> dict:
    """Run the full comparison pipeline."""
    if score_paths:
        model_runs = load_scores_from_paths(score_paths)
    else:
        model_runs = load_all_scores(aegis_iq, target)

    if not model_runs:
        return {"error": "No scored runs found for target", "target": target}

    all_area_scores = defaultdict(dict)
    model_details = {}
    structural_failures = {}

    for model_id, runs in model_runs.items():
        per_area_per_repeat = defaultdict(list)

        for run_score in runs:
            area_scores = compute_all_areas(run_score)
            for area_key, result in area_scores.items():
                if result.get("score") is not None:
                    per_area_per_repeat[area_key].append(result["score"])

        repro = compute_reproducibility(runs)
        per_area_per_repeat["11_reproducibility"] = (
            [repro["score"]] if repro["score"] is not None else []
        )

        model_stats = {}
        for area_key in AREA_SCORERS.keys():
            scores = per_area_per_repeat.get(area_key, [])
            stats = compute_repeat_stats(scores)
            model_stats[area_key] = stats
            all_area_scores[area_key][model_id] = stats

        failures = []
        for run_score in runs:
            sf = run_score.get("reliability", {}).get("structural_failures", [])
            if not sf:
                refusals = run_score.get("refusals", {})
                if isinstance(refusals, dict):
                    sf = refusals.get("structural_failures", [])
            failures.extend(sf if isinstance(sf, list) else [])
        if failures:
            structural_failures[model_id] = failures

        all_cwes = set()
        all_owasp = set()
        cve_counts = []
        runtimes = []
        severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cvss_scores_all = []

        for run_score in runs:
            cwe_cve = run_score.get("cwe_cve", {})
            fd = cwe_cve.get("findings", {})
            cwe_data = fd.get("cwe", {})
            all_cwes.update(cwe_data.get("unique", []))
            owasp_data = fd.get("owasp", {})
            all_owasp.update(owasp_data.get("categories_hit", []))
            sev = fd.get("severity", {})
            for k in severity_totals:
                severity_totals[k] += sev.get(k, 0)
            cvss_data = fd.get("cvss", {})
            cvss_scores_all.extend(cvss_data.get("scores", []))

            cve_data = cwe_cve.get("cves", {})
            cve_counts.append(cve_data.get("unique", 0))

            rt = cwe_cve.get("runtime", {})
            rt_min = rt.get("total_minutes")
            if rt_min:
                runtimes.append(rt_min)

        # Collect per-run detailed data for source truth reference
        run_details = []
        for run_score in runs:
            rd = {"run_id": run_score.get("run_id", "")}
            # GT accuracy
            acc = run_score.get("accuracy", {})
            ec = acc.get("endpoint_coverage", {})
            fa = acc.get("finding_accuracy", {})
            ex = acc.get("exploitation", {})
            rd["endpoint_coverage"] = {
                "tp": ec.get("tp", 0), "fp": ec.get("fp", 0), "fn": ec.get("fn", 0),
                "precision": ec.get("precision"), "recall": ec.get("recall"), "f1": ec.get("f1"),
                "missed": ec.get("missed", [])[:10],
                "false_positives": ec.get("false_positives", [])[:10],
            } if ec.get("has_ground_truth") else None
            rd["finding_accuracy"] = {
                "tp": fa.get("tp", 0), "fp": fa.get("fp", 0), "fn": fa.get("fn", 0),
                "precision": fa.get("precision"), "recall": fa.get("recall"), "f1": fa.get("f1"),
                "tp_findings": fa.get("tp_findings", []),
                "fp_findings": [{"title": f.get("title", ""), "cwe": f.get("cwe", ""), "component": f.get("component", "")} for f in fa.get("fp_findings", [])[:20]],
                "missed_vulns": fa.get("missed_vulns", []),
            } if fa.get("has_ground_truth") else None
            rd["exploitation"] = {
                "exploit_rate": ex.get("exploit_rate"),
                "reproduced": ex.get("reproduced", 0),
                "gt_exploitable": ex.get("gt_exploitable", 0),
            } if ex.get("has_ground_truth") else None
            # Cost breakdown
            cost = run_score.get("cost", {})
            rd["cost"] = {
                "full_run_usd": cost.get("full_run_usd"),
                "source": cost.get("source", "transcript"),
                "by_component": cost.get("by_component", {}),
            }
            # Token usage
            tx = run_score.get("transcripts", {})
            rd["tokens"] = tx.get("total_tokens", {})
            rd["tokens_by_component"] = {}
            for comp, cdata in tx.get("by_component", {}).items():
                rd["tokens_by_component"][comp] = cdata.get("tokens", {})
            # Duplicates
            dupes = run_score.get("duplicates", {})
            rd["duplicates"] = {
                "pre_dedup": dupes.get("pre_dedup_count", 0),
                "post_dedup": dupes.get("post_dedup_count", 0),
                "dedup_ratio": dupes.get("dedup_ratio"),
                "aegis_merges": len(dupes.get("aegis_merges", [])),
                "content_duplicates": len(dupes.get("content_duplicates", [])),
                "cross_component_overlaps": len(dupes.get("cross_component_overlaps", [])),
            }
            # Refusals
            ref = run_score.get("refusals", {})
            rd["refusals"] = {
                "total": ref.get("total_refusals", 0),
                "guardrail_rate": ref.get("guardrail_rate", 0),
                "by_type": ref.get("by_type", {}),
                "by_component": {k: (v.get("total", 0) if isinstance(v, dict) else v) for k, v in ref.get("by_component", {}).items() if (v.get("total", 0) if isinstance(v, dict) else v) > 0},
            }
            # Reliability
            rel = run_score.get("reliability", {})
            rd["reliability"] = {
                "schema_pass_rate": rel.get("schema_pass_rate"),
                "gates_passed": rel.get("gates_passed", 0),
                "gates_failed": rel.get("gates_failed", 0),
            }
            run_details.append(rd)

        model_details[model_id] = {
            "runs": len(runs),
            "area_stats": model_stats,
            "reproducibility": repro,
            "mean_cost": round(mean([
                r.get("cost", {}).get("full_run_usd", 0) or 0 for r in runs
            ]), 2) if runs else 0,
            "mean_findings": round(mean([
                _finding_count(r) for r in runs
            ]), 1) if runs else 0,
            "mean_runtime_min": round(mean(runtimes), 1) if runtimes else None,
            "cwe_unique": sorted(all_cwes),
            "cwe_count": len(all_cwes),
            "owasp_categories": sorted(all_owasp),
            "owasp_coverage": round(len([c for c in all_owasp if c.startswith("A") and ":2025" in c]) / 10, 2),
            "cve_mean": round(mean(cve_counts), 1) if cve_counts else 0,
            "severity": {k: round(v / max(len(runs), 1)) for k, v in severity_totals.items()},
            "cvss_mean": round(mean(cvss_scores_all), 2) if cvss_scores_all else None,
            "cvss_max": max(cvss_scores_all) if cvss_scores_all else None,
            "run_details": run_details,
        }

    area_ratings = {}
    inverse_areas = {"10_cost"}
    for area_key, model_stats in all_area_scores.items():
        area_ratings[area_key] = assign_ratings_for_area(
            model_stats, area_key,
            is_inverse=(area_key in inverse_areas),
            structural_failures=structural_failures,
        )

    overall = compute_overall_ranking(area_ratings)

    area_leaders = {}
    for area_key, models in area_ratings.items():
        for model_id, data in models.items():
            if data.get("rank") == 1:
                area_leaders[area_key] = model_id
                break

    best_model = None
    for model_id, data in overall.items():
        if data["rank"] == 1:
            best_model = model_id
            break

    return {
        "target": target,
        "compared_at": datetime.now(timezone.utc).isoformat(),
        "model_count": len(model_runs),
        "models": list(model_runs.keys()),
        "area_ratings": area_ratings,
        "area_leaders": area_leaders,
        "overall": overall,
        "verdict": {
            "recommended": best_model,
            "runner_up": next(
                (m for m, d in overall.items() if d["rank"] == 2), None
            ),
            "cost_leader": next(
                (m for m, d in area_ratings.get("10_cost", {}).items() if d.get("rank") == 1), None
            ),
        },
        "model_details": model_details,
        "structural_failures": structural_failures,
    }


def main():
    ap = argparse.ArgumentParser(description="Cross-model comparison engine")
    ap.add_argument("--aegis-iq", default=None, help="Path to AEGIS_IQ folder")
    ap.add_argument("--target", required=True, help="Target name to compare")
    ap.add_argument("--scores", nargs="+", default=None, help="Direct paths to benchora_score.json files")
    ap.add_argument("--gt-dir", default=None, help="Path to ground truth directory")
    ap.add_argument("--output", default=None, help="Output directory for comparison.json")
    ap.add_argument("--json", action="store_true", help="Output as JSON to stdout")
    args = ap.parse_args()

    if not args.scores and not args.aegis_iq:
        ap.error("Either --aegis-iq or --scores is required")

    result = compare(args.aegis_iq, args.target, args.gt_dir, score_paths=args.scores)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        out_path = os.path.join(args.output, "comparison.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Written to {out_path}")

    if args.json:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        if "error" in result:
            print(f"ERROR: {result['error']}")
            sys.exit(1)

        print(f"Comparison: {result['target']}")
        print(f"Models: {result['model_count']} ({', '.join(result['models'])})")
        print()

        v = result["verdict"]
        print(f"Verdict: {v['recommended']} (recommended)")
        if v.get("runner_up"):
            print(f"         {v['runner_up']} (runner-up)")
        if v.get("cost_leader"):
            print(f"         {v['cost_leader']} (cost leader)")
        print()

        print("Area ratings:")
        for area_key, models in result["area_ratings"].items():
            leader = result["area_leaders"].get(area_key, "?")
            print(f"  {area_key}: leader={leader}")
            for model_id, data in sorted(models.items(), key=lambda x: x[1].get("rank", 99)):
                rank = data.get('rank', '?')
                rating = data.get('rating', 'N/A')
                m = data.get('mean', 'N/A')
                sd = data.get('stdev', 'N/A')
                print(f"    #{rank} {model_id}: {rating} (mean={m}, stdev={sd})")


if __name__ == "__main__":
    main()
