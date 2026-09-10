#!/usr/bin/env python3
"""run_comparison_pipeline.py — staged, checkpointed multi-run benchmark pipeline.

Processes one run at a time and verifies each before moving on, rather than
computing everything at once.  The comparison report is only built after every
individual run has been scored, rendered and checked.

    Stage 1..N   per run:  score -> per-run HTML report -> verify
    Stage N+1    combine:  prepare comparison data
    Stage N+2    render:   assemble the comparison report
    Stage N+3    verify:   cross-check the report against the source score files

Each stage writes a checkpoint, so a re-run skips completed work unless --force.
A failing stage halts the pipeline: a later stage never consumes unverified
output from an earlier one.

Usage:
    python run_comparison_pipeline.py --run-dirs out/run1 out/run2 out/run3 \\
        --gt-dir groundtruth --prices config/model_prices.json \\
        --model-display "Claude Opus 4.7" --output-dir out/opus47
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT = ".pipeline_state.json"

C_OK, C_ERR, C_HEAD, C_DIM, C_RST = "\033[32m", "\033[31m", "\033[1;36m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    C_OK = C_ERR = C_HEAD = C_DIM = C_RST = ""


def banner(text):
    print(f"\n{C_HEAD}{'=' * 78}\n{text}\n{'=' * 78}{C_RST}")


def stage(text):
    print(f"\n{C_HEAD}--- {text} ---{C_RST}")


def ok(text):
    print(f"  {C_OK}ok{C_RST}   {text}")


def fail(text):
    print(f"  {C_ERR}FAIL{C_RST} {text}")


def run(cmd, label):
    """Run a subprocess, streaming nothing, returning (success, output)."""
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE)
    dt = time.time() - t0
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode == 0:
        ok(f"{label}  {C_DIM}({dt:.1f}s){C_RST}")
        return True, out
    fail(f"{label}  (exit {p.returncode}, {dt:.1f}s)")
    for line in out.strip().splitlines()[-25:]:
        print(f"       {line}")
    return False, out


class State:
    def __init__(self, path, force=False):
        self.path = path
        self.force = force
        self.data = {}
        if os.path.exists(path) and not force:
            try:
                with open(path, encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                self.data = {}

    def done(self, key, produces=None):
        if self.force or not self.data.get(key):
            return False
        # A checkpoint is only valid if what it produced still exists.
        if produces and not all(os.path.exists(p) for p in produces):
            return False
        return True

    def mark(self, key, produces=None):
        self.data[key] = {"at": time.strftime("%Y-%m-%d %H:%M:%S"),
                          "produces": produces or []}
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description="Staged multi-run benchmark comparison pipeline")
    ap.add_argument("--run-dirs", nargs="+", required=True,
                    help="Run artifact directories, in order")
    ap.add_argument("--output-dir", required=True, help="Where reports are written")
    ap.add_argument("--gt-dir", default=None, help="Ground truth directory (enables scoring)")
    ap.add_argument("--prices", default=None, help="model_prices.json")
    ap.add_argument("--model-display", default=None)
    ap.add_argument("--score", action="store_true",
                    help="Run score_run.py for each run (otherwise reuse existing benchora_score.json)")
    ap.add_argument("--force", action="store_true", help="Ignore checkpoints and redo every stage")
    ap.add_argument("--skip-run-reports", action="store_true",
                    help="Skip the per-run HTML reports (still scores and verifies)")
    args = ap.parse_args()

    outdir = os.path.abspath(args.output_dir)
    os.makedirs(outdir, exist_ok=True)
    st = State(os.path.join(outdir, CHECKPOINT), args.force)
    n = len(args.run_dirs)

    banner(f"Benchmark comparison pipeline — {n} run(s)\n"
           f"Output: {outdir}")

    score_paths = []

    # ── per-run stages ────────────────────────────────────────────────────────
    for i, rd in enumerate(args.run_dirs, start=1):
        rd = os.path.abspath(rd)
        stage(f"Stage {i}/{n}  Run {i}  {C_DIM}{rd}{C_RST}")

        if not os.path.isdir(rd):
            fail(f"run directory not found: {rd}")
            sys.exit(1)

        score_path = os.path.join(rd, "benchora_score.json")

        # 1a. score
        if args.score:
            key = f"run{i}.score"
            if st.done(key, [score_path]):
                ok(f"score (cached) {C_DIM}{score_path}{C_RST}")
            else:
                cmd = [sys.executable, "score_run.py", "--run-dir", rd]
                if args.gt_dir:
                    cmd += ["--gt-dir", os.path.abspath(args.gt_dir)]
                if args.prices:
                    cmd += ["--prices", os.path.abspath(args.prices)]
                good, _ = run(cmd, f"score run {i}")
                if not good:
                    sys.exit(1)
                st.mark(key, [score_path])

        if not os.path.exists(score_path):
            fail(f"no benchora_score.json in {rd} — pass --score to generate it")
            sys.exit(1)
        score_paths.append(score_path)

        # 1b. per-run HTML report
        if not args.skip_run_reports:
            report_path = os.path.join(outdir, f"run{i}_report.html")
            key = f"run{i}.report"
            if st.done(key, [report_path]):
                ok(f"per-run report (cached) {C_DIM}{report_path}{C_RST}")
            else:
                cmd = [sys.executable, "render_benchmark_report.py",
                       "--score", score_path, "--output", report_path]
                if args.prices:
                    cmd += ["--prices", os.path.abspath(args.prices)]
                good, _ = run(cmd, f"render run {i} report")
                if not good:
                    sys.exit(1)
                st.mark(key, [report_path])

        # 1c. verify this run in isolation, against its own source
        single_data = os.path.join(outdir, f".run{i}_data.json")
        cmd = [sys.executable, "prepare_comparison_data.py",
               "--scores", score_path, "--output", single_data]
        if args.prices:
            cmd += ["--prices", os.path.abspath(args.prices)]
        if args.model_display:
            cmd += ["--model-display", args.model_display]
        good, _ = run(cmd, f"prepare run {i} data")
        if not good:
            sys.exit(1)

        good, out = run([sys.executable, "verify_report.py",
                         "--scores", score_path, "--data", single_data],
                        f"verify run {i} against source")
        if not good:
            fail(f"run {i} failed verification — halting before the comparison stage")
            sys.exit(1)
        tail = [l for l in out.strip().splitlines() if "passed," in l]
        if tail:
            print(f"       {C_DIM}{tail[-1].strip()}{C_RST}")

    # ── combine ───────────────────────────────────────────────────────────────
    stage(f"Stage {n+1}  Combine — build comparison data from {n} verified run(s)")
    data_path = os.path.join(outdir, "comparison_data.json")
    cmd = [sys.executable, "prepare_comparison_data.py",
           "--scores", *score_paths, "--output", data_path]
    if args.prices:
        cmd += ["--prices", os.path.abspath(args.prices)]
    if args.model_display:
        cmd += ["--model-display", args.model_display]
    good, out = run(cmd, "prepare comparison data")
    if not good:
        sys.exit(1)
    for line in out.strip().splitlines()[1:]:
        print(f"       {C_DIM}{line.strip()}{C_RST}")

    # ── render ────────────────────────────────────────────────────────────────
    stage(f"Stage {n+2}  Render — assemble the comparison report")
    html_path = os.path.join(outdir, "comparison_report.html")
    good, out = run([sys.executable, "render_comparison_v2.py",
                     "--data", data_path, "--output", html_path],
                    "render comparison report")
    if not good:
        sys.exit(1)
    for line in out.strip().splitlines():
        print(f"       {C_DIM}{line.strip()}{C_RST}")

    # ── verify ────────────────────────────────────────────────────────────────
    stage(f"Stage {n+3}  Verify — cross-check the report against all source files")
    good, out = run([sys.executable, "verify_report.py",
                     "--scores", *score_paths,
                     "--data", data_path, "--html", html_path],
                    "verify comparison report")
    summary = [l for l in out.strip().splitlines() if "passed," in l or "VERIFICATION" in l]
    for line in summary:
        print(f"       {line.strip()}")
    if not good:
        print(f"\n{C_ERR}Pipeline halted: the comparison report did not verify.{C_RST}")
        for line in out.strip().splitlines():
            if "FAIL" in line:
                print(f"  {line.strip()}")
        sys.exit(1)

    # cleanup per-run scratch data
    for i in range(1, n + 1):
        p = os.path.join(outdir, f".run{i}_data.json")
        if os.path.exists(p):
            os.remove(p)

    banner("Pipeline complete")
    print(f"  Comparison report : {html_path}")
    print(f"  Comparison data   : {data_path}")
    if not args.skip_run_reports:
        for i in range(1, n + 1):
            print(f"  Run {i} report      : {os.path.join(outdir, f'run{i}_report.html')}")
    print()


if __name__ == "__main__":
    main()
