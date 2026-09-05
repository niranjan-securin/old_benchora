#!/usr/bin/env python3
"""score_run.py — score a single AEGIS run, producing benchora_score.json.

Computes all per-run metrics:
  - Transcript parsing (tokens, cost, model)
  - Refusal detection
  - Schema validation
  - GT accuracy (endpoints, findings, exploits)
  - Duplicate counting
  - CWE/CVE/OWASP extraction
  - Area scores (GT-based + computed; test-case areas deferred to comparison)

Usage:
    score_run.py --run-dir <path> [--gt-dir <path>] [--transcripts-dir <path>] [--output <path>] [--json]

If --transcripts-dir is not given, looks for transcripts/ under run-dir,
then tries to locate them via trace.jsonl.
"""
from __future__ import annotations

import argparse
import glob as globmod
import json
import os
import subprocess
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)
from resolve_gates import resolve_gates  # noqa: E402
from extract_judge_verdict import extract_judge_verdict  # noqa: E402


def run_script(name: str, args: list[str], label: str = "") -> dict | None:
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, name)] + args
    if label:
        print(f"  [{label}] {name} ...")
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0 and r.stderr.strip():
        print(f"    STDERR: {r.stderr[:300]}")
    try:
        return json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return None


def extract_run_id(run_dir: str) -> str:
    base = os.path.basename(run_dir.rstrip("/\\"))
    if base.startswith("run-"):
        return base
    manifest = os.path.join(run_dir, "manifest.json")
    if os.path.exists(manifest):
        with open(manifest, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("run_id", base)
    return base


def find_transcripts_dir(run_dir: str) -> str | None:
    candidate = os.path.join(run_dir, "transcripts")
    if os.path.isdir(candidate):
        return candidate
    trace = os.path.join(run_dir, "trace.jsonl")
    if os.path.exists(trace):
        with open(trace, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                tp = entry.get("transcript_path", "")
                if tp:
                    parent = os.path.dirname(os.path.dirname(tp))
                    local = os.path.join(os.path.dirname(run_dir), os.path.basename(parent))
                    if os.path.isdir(local):
                        return local
    parent = os.path.dirname(run_dir)
    for d in os.listdir(parent):
        full = os.path.join(parent, d)
        if os.path.isdir(full) and "claude_projects" in d:
            return full
    return None


def find_scored_findings(run_dir: str) -> str | None:
    hits = sorted(globmod.glob(os.path.join(run_dir, "**", "*scored-findings.jsonl"), recursive=True))
    if not hits:
        for root, _dirs, files in os.walk(run_dir):
            for f in sorted(files):
                if f.endswith("scored-findings.jsonl"):
                    hits.append(os.path.join(root, f))
    return hits[-1] if hits else None


def main():
    ap = argparse.ArgumentParser(description="Score a single AEGIS run")
    ap.add_argument("--run-dir", required=True, help="Path to the run directory")
    ap.add_argument("--gt-dir", help="Path to ground truth directory (endpoints.json, vulns.json)")
    ap.add_argument("--transcripts-dir", help="Path to transcript .jsonl files")
    ap.add_argument("--model", help="Model name (auto-detected from transcripts if not given)")
    ap.add_argument("--target", help="Target name (auto-detected from manifest if not given)")
    ap.add_argument("--prices", help="Path to model_prices.json for cost computation")
    ap.add_argument("--output", help="Output path for benchora_score.json (default: <run-dir>/benchora_score.json)")
    ap.add_argument("--json", action="store_true", help="Print final score to stdout as JSON")
    args = ap.parse_args()

    run_dir = os.path.abspath(args.run_dir)
    run_id = extract_run_id(run_dir)

    transcripts_dir = args.transcripts_dir
    if not transcripts_dir:
        transcripts_dir = find_transcripts_dir(run_dir)

    gt_dir = args.gt_dir
    if gt_dir:
        gt_dir = os.path.abspath(gt_dir)

    prices_path = args.prices
    if not prices_path:
        default_prices = os.path.join(SCRIPTS_DIR, "..", "config", "model_prices.json")
        if os.path.exists(default_prices):
            prices_path = os.path.abspath(default_prices)

    output_path = args.output or os.path.join(run_dir, "benchora_score.json")

    print(f"Scoring run: {run_id}")
    print(f"  run_dir:        {run_dir}")
    print(f"  gt_dir:         {gt_dir or '(none)'}")
    print(f"  transcripts:    {transcripts_dir or '(none)'}")
    print(f"  output:         {output_path}")
    print()

    score: dict = {"run_id": run_id}

    # Read manifest if present
    manifest_path = os.path.join(run_dir, "manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        score["target"] = manifest.get("target", "")
        score["model"] = manifest.get("model", "")

    if args.model:
        score["model"] = args.model
    if args.target:
        score["target"] = args.target

    # ---- 1. Parse transcripts (tokens + cost) ----
    print("[1/8] Parsing transcripts...")
    if transcripts_dir and os.path.isdir(transcripts_dir):
        parse_args = ["--dir", transcripts_dir]
        if prices_path:
            parse_args += ["--prices", prices_path]
        if args.model:
            parse_args += ["--model", args.model]
        parse_args.append("--json")
        transcript_result = run_script("parse_transcript.py", parse_args, label="transcripts")
        if transcript_result:
            score["transcripts"] = transcript_result.get("summary", transcript_result)
            cost_data = transcript_result.get("cost", {})
            if cost_data:
                score["cost"] = cost_data
            elif "cost_usd" in transcript_result:
                by_comp_costs = {}
                for cname, cdata in transcript_result.get("by_component", {}).items():
                    if "cost_usd" in cdata:
                        by_comp_costs[cname] = cdata["cost_usd"]
                score["cost"] = {
                    "full_run_usd": transcript_result["cost_usd"],
                    "by_component": by_comp_costs,
                }
            elif "full_run_usd" in transcript_result:
                score["cost"] = {"full_run_usd": transcript_result["full_run_usd"]}
            model = transcript_result.get("model")
            if model and "model" not in score:
                score["model"] = model
            print(f"  Tokens parsed. Model: {score.get('model', 'unknown')}")
            if "cost" in score:
                print(f"  Cost: ${score['cost'].get('full_run_usd', 0):.2f}")
        else:
            print("  Warning: transcript parsing returned no data")
    else:
        print("  Skipped (no transcripts directory)")

    # Compute cost from tokens + prices if not already set
    if "cost" not in score and prices_path and score.get("transcripts"):
        model_name = score.get("model", "")
        if model_name and os.path.exists(prices_path):
            with open(prices_path, encoding="utf-8") as f:
                all_prices = json.load(f)
            prices = all_prices.get(model_name) or all_prices.get(f"anthropic/{model_name}")
            if prices:
                by_comp = score["transcripts"].get("by_component", {})
                cost_by_comp = {}
                total_cost = 0.0
                for comp, data in by_comp.items():
                    t = data.get("tokens", {})
                    c = (
                        t.get("input", 0) * prices.get("input_per_million", 0) / 1e6
                        + t.get("output", 0) * prices.get("output_per_million", 0) / 1e6
                        + t.get("cache_write", 0) * prices.get("cache_write_per_million", 0) / 1e6
                        + t.get("cache_read", 0) * prices.get("cache_read_per_million", 0) / 1e6
                    )
                    cost_by_comp[comp] = round(c, 4)
                    total_cost += c
                score["cost"] = {
                    "full_run_usd": round(total_cost, 3),
                    "by_component": cost_by_comp,
                }
                print(f"  Cost computed: ${total_cost:.2f}")

    # ---- Override cost/timing from bench folder if available ----
    bench_results_path = os.path.join(run_dir, "bench", "benchmark_results.json")
    if os.path.exists(bench_results_path):
        try:
            with open(bench_results_path, encoding="utf-8") as f:
                bench_data = json.load(f)
            bench_cost = bench_data.get("overall", {}).get("total_cost")
            if bench_cost is not None:
                by_comp_costs = {}
                for cname, cdata in (bench_data.get("components") or {}).items():
                    c3 = (cdata.get("C") or {}).get("C3_cost")
                    if c3 is not None:
                        by_comp_costs[cname] = round(c3, 4)
                score["cost"] = {
                    "full_run_usd": round(bench_cost, 3),
                    "by_component": by_comp_costs,
                    "source": "bench/benchmark_results.json",
                }
                print(f"  Cost overridden from bench: ${bench_cost:.2f}")
            overhead = bench_data.get("pipeline_overhead", {})
            if overhead.get("elapsed_s"):
                score["_bench_runtime_ms"] = int(overhead["elapsed_s"] * 1000)
                print(f"  Runtime from bench: {round(overhead['elapsed_s'] / 60, 1)} min")
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Warning: could not read bench results: {e}")

    # ---- 2. Detect refusals ----
    print("\n[2/8] Detecting refusals...")
    if transcripts_dir and os.path.isdir(transcripts_dir):
        refusals = run_script("detect_refusals.py", [
            "--transcripts-dir", transcripts_dir, "--json"
        ], label="refusals")
        if refusals:
            score["refusals"] = refusals
            print(f"  Total refusals: {refusals.get('total_refusals', 0)}, "
                  f"guardrail_rate: {refusals.get('guardrail_rate', 0):.4f}")
        else:
            print("  Warning: refusal detection returned no data")
    else:
        print("  Skipped (no transcripts directory)")

    # ---- 3. Validate schemas ----
    print("\n[3/8] Validating schemas...")
    schemas = run_script("validate_schemas.py", ["--run-dir", run_dir, "--json"], label="schemas")
    _gates = resolve_gates(run_dir)
    if schemas:
        score["reliability"] = {
            "schema_pass_rate": schemas.get("schema_pass_rate", schemas.get("pass_rate", 0)),
            # validate_schemas.py emits total_files/valid_files; the old fallback chain
            # looked for schema_valid/valid and schema_total/total, so both mirror
            # fields silently read 0 while schema_pass_rate came through correctly.
            # The rate was always a real measurement; only these counters were broken.
            "schema_valid": schemas.get("schema_valid", schemas.get("valid_files",
                                        schemas.get("valid", 0))),
            "schema_total": schemas.get("schema_total", schemas.get("total_files",
                                        schemas.get("total", 0))),
            # Per-COMPONENT gate resolution (see resolve_gates.py). The old
            # len(glob("*.PASS")) / len(glob("*.FAIL")) counted FILES, so a
            # component with only a .TIMEOUT vanished from the denominator and a
            # component with both .PASS and .FAIL was counted in both.
            "gates_passed": _gates["gates_passed"],
            "gates_failed": _gates["gates_failed"],
            "gates_timeout_unresolved": _gates["gates_timeout_unresolved"],
            "gates_health_excluded": _gates["gates_health_excluded"],
            "gate_pass_rate": _gates["gate_pass_rate"],
            "gate_components": _gates["components"],
            "gate_conflicts": _gates["conflicts"],
            "gate_rubber_stamp_suspects": _gates["rubber_stamp_suspects"],
            "gate_unknown_suffixes": _gates["ignored_suffixes"],
            "error_count": 0,
        }
        print(f"  Schema pass rate: {score['reliability']['schema_pass_rate']}")
        print(f"  Gates: {score['reliability']['gates_passed']} passed, "
              f"{score['reliability']['gates_failed']} failed "
              f"({_gates['gates_timeout_unresolved']} unresolved timeout, "
              f"{_gates['gates_health_excluded']} browser-health excluded) "
              f"rate={_gates['gate_pass_rate']}")
        if _gates["ignored_suffixes"]:
            print(f"  WARNING unrecognised gate suffixes: {_gates["ignored_suffixes"]}")
        if _gates["rubber_stamp_suspects"]:
            print("  NOTE rubber-stamp PASS suspects (counted as pass): "
                  + ", ".join(s["component"] for s in _gates["rubber_stamp_suspects"]))
    else:
        print("  Warning: schema validation returned no data")
        score["reliability"] = {
            "schema_pass_rate": None,
            "gates_passed": _gates["gates_passed"],
            "gates_failed": _gates["gates_failed"],
            "gates_timeout_unresolved": _gates["gates_timeout_unresolved"],
            "gates_health_excluded": _gates["gates_health_excluded"],
            "gate_pass_rate": _gates["gate_pass_rate"],
            "gate_components": _gates["components"],
            "gate_conflicts": _gates["conflicts"],
            "gate_rubber_stamp_suspects": _gates["rubber_stamp_suspects"],
            "gate_unknown_suffixes": _gates["ignored_suffixes"],
            "error_count": 0,
        }

    # ---- 4. Compute GT accuracy ----
    print("\n[4/8] Computing GT accuracy...")
    if gt_dir and os.path.isdir(gt_dir):
        gt_accuracy = run_script("compute_gt_accuracy.py", [
            "--run-dir", run_dir, "--gt-dir", gt_dir, "--json"
        ], label="gt_accuracy")
        if gt_accuracy:
            score["accuracy"] = gt_accuracy
            ec = gt_accuracy.get("endpoint_coverage", {})
            fa = gt_accuracy.get("finding_accuracy", {})
            ex = gt_accuracy.get("exploitation", {})
            if ec.get("has_ground_truth"):
                print(f"  Endpoints:  TP={ec['tp']}, FP={ec['fp']}, FN={ec['fn']}, "
                      f"F1={ec['f1']}, Recall={ec['recall']}")
            if fa.get("has_ground_truth"):
                print(f"  Findings:   TP={fa['tp']}, FP={fa['fp']}, FN={fa['fn']}, "
                      f"F1={fa['f1']}")
            if ex.get("has_ground_truth"):
                print(f"  Exploits:   rate={ex['exploit_rate']}")
        else:
            print("  Warning: GT accuracy returned no data")
    else:
        print("  Skipped (no ground truth directory)")

    # ---- 5. Count duplicates ----
    print("\n[5/8] Counting duplicates...")
    scored_path = find_scored_findings(run_dir)
    if scored_path:
        dupes = run_script("count_duplicates.py", [
            "--scored-findings", scored_path, "--json"
        ], label="duplicates")
        if dupes:
            score["duplicates"] = dupes
            score["duplicates"]["scored_findings_path"] = scored_path
            print(f"  Post-dedup: {dupes.get('post_dedup_count', 0)}, "
                  f"Pre-dedup: {dupes.get('pre_dedup_count', 0)}")
    else:
        print("  Skipped (no scored-findings.jsonl found)")

    # ---- 6. Extract finding details from reporting/findings/*.md ----
    print("\n[6/8] Extracting finding details...")
    finding_details_result = run_script("extract_finding_details.py", [
        "--run-dir", run_dir, "--json"
    ], label="finding_details")
    if finding_details_result:
        count = finding_details_result.get("finding_count", 0)
        score["finding_details"] = finding_details_result.get("findings", {})
        print(f"  Found {count} finding detail files")
    else:
        print("  No finding detail files found")

    # ---- 7. Extract CWE/CVE/runtime ----
    print("\n[7/8] Extracting CWE/CVE/OWASP...")
    cwe_args = ["--run-dir", run_dir]
    if transcripts_dir:
        cwe_args += ["--transcripts-dir", transcripts_dir]
    cwe_args.append("--json")
    cwe_cve = run_script("extract_cwe_cve.py", cwe_args, label="cwe_cve")
    if cwe_cve:
        score["cwe_cve"] = cwe_cve
        findings_data = cwe_cve.get("findings", {})
        print(f"  CWE unique: {findings_data.get('cwe', {}).get('count', 0)}, "
              f"OWASP coverage: {findings_data.get('owasp', {}).get('coverage', 0):.0%}")
    else:
        print("  Warning: CWE/CVE extraction returned no data")

    # ---- 8. Extract component results ----
    print("\n[8/8] Extracting per-component results...")
    sys.path.insert(0, SCRIPTS_DIR)
    from extract_component_results import extract_all as extract_component_results
    component_results = extract_component_results(run_dir)
    if component_results.get("components"):
        score["component_results"] = component_results["components"]
        score["_component_layout"] = component_results.get("layout", "unknown")
        if component_results.get("gates"):
            score.setdefault("reliability", {})["gates_detail"] = component_results["gates"]
        if component_results.get("bench"):
            score["bench_summary"] = component_results["bench"]
        found = sorted(component_results.get("components_found", []))
        print(f"  Components: {', '.join(found)}")
    else:
        print("  No component results found")

    # ---- Compute area scores ----
    judge = extract_judge_verdict(run_dir)
    score["judge"] = judge
    if judge.get("found"):
        print(f"\nAEGIS judge verdict: {judge.get('verdict')} "
              f"({judge.get('issue_count')} issues"
              + (f", {judge.get('major_count')} major" if judge.get("major_count") else "")
              + ")")
    else:
        print("\nAEGIS judge verdict: none found in run artifacts")

    print("\nComputing area scores...")
    sys.path.insert(0, SCRIPTS_DIR)
    from compute_area_scores import compute_all_areas
    area_scores = compute_all_areas(score)
    score["area_scores"] = area_scores

    for key, result in area_scores.items():
        s = result.get("score")
        method = result.get("method", "")
        if s is None:
            print(f"  {key}: N/A ({method})")
        elif result.get("inverse"):
            print(f"  {key}: ${s:.2f} ({method})")
        else:
            print(f"  {key}: {s:.4f} ({method})")

    # ---- Write output ----
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(score, f, indent=2, ensure_ascii=False)
    print(f"\nWrote: {output_path}")

    if args.json:
        print(json.dumps(score, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
