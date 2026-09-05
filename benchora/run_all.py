#!/usr/bin/env python3
"""run_all.py — score + render all 9 AEGIS runs across 3 models, then compare.

Reads run_manifest.json (built by scouting the three target trees) and drives
score_run.py -> render_benchmark_report.py per run, then compare_models.py +
render_comparison.py + render_combined_report.py per model.

Run from the benchora root:  python run_all.py [--only <model>] [--skip-score]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys

BENCH = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(BENCH, "..", ".."))
GT = os.path.join(ROOT, "benchora_", "groundtruth")
OUT = os.path.join(BENCH, "output", "final")
PRICES = os.path.join(BENCH, "config", "model_prices.json")

MODEL_IDS = {
    "kimi-k3": "moonshotai/kimi-k3",
    "sonnet-4-6": "claude-sonnet-4-6",
    "opus-4-6": "claude-opus-4-6",
}
DISPLAY = {
    "kimi-k3": "Kimi K3 (moonshotai/kimi-k3)",
    "sonnet-4-6": "Claude Sonnet 4.6",
    "opus-4-6": "Claude Opus 4.6",
}


def sh(args, label):
    r = subprocess.run([sys.executable] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=BENCH)
    if r.returncode != 0:
        print(f"    !! {label} FAILED rc={r.returncode}")
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-6:]
        for t in tail:
            print(f"       {t}")
        return False, r.stdout
    return True, r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="limit to one model key")
    ap.add_argument("--skip-score", action="store_true")
    a = ap.parse_args()

    man = json.load(open(os.path.join(BENCH, "run_manifest.json")))
    by_model: dict[str, list] = {}
    for key, v in man.items():
        by_model.setdefault(v["model"], []).append((key, v))

    summary = []
    for model, runs in sorted(by_model.items()):
        if a.only and model != a.only:
            continue
        print(f"\n{'='*78}\n{model}  ({len(runs)} runs)\n{'='*78}")
        score_paths = []
        for i, (key, v) in enumerate(sorted(runs, key=lambda x: x[0]), 1):
            slug = f"run{i}"
            d = os.path.join(OUT, model, slug)
            os.makedirs(d, exist_ok=True)
            spath = os.path.join(d, "benchora_score.json")
            arts = os.path.join(ROOT, v["artifacts"])
            trans = os.path.join(ROOT, v["transcripts"])

            print(f"\n-- [{i}/{len(runs)}] {key}")
            if not a.skip_score:
                ok, out = sh([os.path.join("scripts", "score_run.py"),
                              "--run-dir", arts,
                              "--transcripts-dir", trans,
                              "--gt-dir", GT,
                              "--target", "medicare",
                              "--model", MODEL_IDS[model],
                              "--prices", PRICES,
                              "--output", spath], f"score {key}")
                if not ok:
                    continue
                for line in out.splitlines():
                    if any(t in line for t in ("Endpoints:", "Findings:", "Exploits:",
                                               "Gates:", "refusals:", "judge verdict:",
                                               "finding detail files", "WARNING", "NOTE")):
                        print(f"   {line.strip()}")

            # stage the latest scored-findings next to the score so
            # compare_models' reproducibility Jaccard can find it
            hits = sorted(glob.glob(os.path.join(arts, "**", "*scored-findings.jsonl"),
                                    recursive=True))
            if hits:
                shutil.copyfile(hits[-1], os.path.join(d, "scored-findings.jsonl"))

            ok, _ = sh([os.path.join("scripts", "render_benchmark_report.py"),
                        "--score", spath, "--prices", PRICES,
                        "--output", os.path.join(d, "benchmark_report.html")],
                       f"render {key}")
            if ok:
                sz = os.path.getsize(os.path.join(d, "benchmark_report.html"))
                print(f"   report: {sz/1024:.0f} KB")
            score_paths.append(spath)
            summary.append((model, slug, key, spath))

        if len(score_paths) < 1:
            continue
        cdir = os.path.join(OUT, model, "comparison")
        os.makedirs(cdir, exist_ok=True)
        print(f"\n-- comparison for {model}")
        sh([os.path.join("scripts", "compare_models.py"), "--target", "medicare",
            "--gt-dir", GT, "--scores"] + score_paths + ["--output", cdir],
           f"compare {model}")
        sh([os.path.join("scripts", "render_comparison.py"),
            "--comparison", os.path.join(cdir, "comparison.json"),
            "--output-dir", cdir, "--format", "both"], f"render-cmp {model}")
        sh([os.path.join("scripts", "render_combined_report.py"),
            "--scores"] + score_paths + ["--prices", PRICES,
            "--model-display", DISPLAY[model],
            "--output", os.path.join(cdir, f"{model}_combined_report.html")],
           f"combined {model}")
        for f in ("comparison.json", "comparison.md", "comparison.html",
                  f"{model}_combined_report.html"):
            p = os.path.join(cdir, f)
            print(f"   {'OK  ' if os.path.exists(p) else 'MISS'} {f}"
                  + (f"  {os.path.getsize(p)/1024:.0f} KB" if os.path.exists(p) else ""))

    print(f"\n\nscored {len(summary)} runs")
    # merge into any existing index so a --only run does not clobber other models
    ipath = os.path.join(OUT, "index.json")
    merged = {}
    if os.path.exists(ipath):
        try:
            for e in json.load(open(ipath)):
                merged[e["score"]] = e
        except (ValueError, KeyError):
            pass
    for m, s, k, p in summary:
        merged[p] = {"model": m, "slug": s, "key": k, "score": p}
    json.dump(sorted(merged.values(), key=lambda e: e["score"]), open(ipath, "w"), indent=1)


if __name__ == "__main__":
    main()
