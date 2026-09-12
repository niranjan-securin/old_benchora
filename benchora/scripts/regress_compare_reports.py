#!/usr/bin/env python3
"""regress_compare_reports.py — regression check: old renderer vs new pipeline.

Renders the same score files through render_combined_report.py (legacy) and
render_comparison_v2.py (modular), then checks that every source-derived figure
appears in BOTH.  Any figure present in one and not the other is reported.

Matching is done on the rendered text with word boundaries, not raw substrings:
"0.310" occurs inside "0.3103", and a substring test would call that a match.

Known intentional divergences (the legacy report is wrong in these places) are
declared in EXPECTED_DIVERGENCES and reported separately from regressions, so a
real regression is never buried among them.

Exit 0 when no unexpected divergence is found, 1 otherwise.

Usage:
    python regress_compare_reports.py --scores r1.json r2.json r3.json \
        [--prices config/model_prices.json] [--keep-dir /tmp/regress]
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

EXPECTED_DIVERGENCES = [
    ("jaccard",
     "Legacy keys findings by CWE + title[:60]. The model rewords titles between "
     "runs, so the legacy report prints Mean = 0.000 and claims no findings are "
     "shared. The new pipeline keys on CWE + normalised endpoint."),
    ("cost-by-component",
     "Legacy renders the transcript path fragments 'home'/'projects' as components "
     "and fabricates $0.00 for runs where the key is absent. The new pipeline "
     "suppresses the breakdown and states why."),
    ("component-gates",
     "The component gate-status section is new; the legacy report has none."),
    ("severity-distribution",
     "The severity distribution section is new; the legacy report renders no "
     "severity breakdown, so those counts are not comparable."),
]

# Presence testing cannot distinguish a real match from a coincidence when the
# value is a small integer — "6" occurs somewhere in any long report.  Only
# figures at or above this width are treated as evidence.
MIN_DISTINCTIVE_DIGITS = 2


def _text(path):
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw)))


def _present(value, text):
    """Word-boundary match so 0.310 does not match inside 0.3103."""
    return re.search(rf"(?<![\d.]){re.escape(value)}(?![\d])", text) is not None


def _um(d):
    for k in ("unmatched", "fp"):
        if isinstance(d, dict) and d.get(k) is not None:
            return d[k]
    return None


def _g(d, *ks):
    for k in ks:
        d = d.get(k) if isinstance(d, dict) else None
    return d


def collect_expected(scores):
    """Every figure that both reports must render, derived from the source."""
    out = []
    for i, s in enumerate(scores, 1):
        ec = _g(s, "accuracy", "endpoint_coverage") or {}
        fa = _g(s, "accuracy", "finding_accuracy") or {}
        for tag, acc in (("ep", ec), ("fa", fa)):
            if not acc.get("has_ground_truth"):
                continue
            for field in ("tp", "fn"):
                if acc.get(field) is not None:
                    out.append((f"run{i}.{tag}.{field}", f"{acc[field]:,}"))
            if _um(acc) is not None:
                out.append((f"run{i}.{tag}.unmatched", f"{_um(acc):,}"))
        cost = _g(s, "cost", "full_run_usd")
        if cost is not None:
            out.append((f"run{i}.cost", f"${cost:,.2f}"))
        turns = _g(s, "transcripts", "total_turns")
        if turns:
            out.append((f"run{i}.turns", f"{turns:,}"))
        for tt in ("input", "output"):
            v = _g(s, "transcripts", "total_tokens", tt)
            if v:
                out.append((f"run{i}.tokens.{tt}", f"{v:,}"))
        # Severity is deliberately excluded: the legacy report has no severity
        # section, so any apparent match would be a coincidental digit.

    # Drop figures too short to be evidence of anything.
    keep, dropped = [], []
    for name, val in out:
        digits = sum(c.isdigit() for c in val)
        (keep if digits >= MIN_DISTINCTIVE_DIGITS else dropped).append((name, val))
    return keep, dropped


def main():
    ap = argparse.ArgumentParser(description="Regression: legacy renderer vs modular pipeline")
    ap.add_argument("--scores", nargs="+", required=True)
    ap.add_argument("--prices", default=None)
    ap.add_argument("--model-display", default=None)
    ap.add_argument("--keep-dir", default=None, help="Keep rendered reports here")
    args = ap.parse_args()

    workdir = args.keep_dir or tempfile.mkdtemp(prefix="benchora_regress_")
    os.makedirs(workdir, exist_ok=True)
    old_html = os.path.join(workdir, "legacy_combined.html")
    new_html = os.path.join(workdir, "modular_comparison.html")
    data_json = os.path.join(workdir, "comparison_data.json")

    scores = []
    for p in args.scores:
        with open(p, encoding="utf-8") as f:
            scores.append(json.load(f))

    def sh(cmd, label):
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE)
        if r.returncode != 0:
            print(f"ERROR: {label} failed\n{(r.stdout or '') + (r.stderr or '')}", file=sys.stderr)
            sys.exit(1)

    common = []
    if args.prices:
        common += ["--prices", os.path.abspath(args.prices)]
    if args.model_display:
        common += ["--model-display", args.model_display]

    print("Rendering both reports from the same score files...")
    sh([sys.executable, "render_combined_report.py", "--scores", *map(os.path.abspath, args.scores),
        "--output", old_html, *common], "legacy renderer")
    sh([sys.executable, "prepare_comparison_data.py", "--scores", *map(os.path.abspath, args.scores),
        "--output", data_json, *common], "prepare data")
    sh([sys.executable, "render_comparison_v2.py", "--data", data_json,
        "--output", new_html], "modular renderer")

    TO, TN = _text(old_html), _text(new_html)
    expected, dropped = collect_expected(scores)

    both = []
    only_old, only_new, neither = [], [], []
    for name, val in expected:
        o, n = _present(val, TO), _present(val, TN)
        if o and n:
            both.append((name, val))
        elif o:
            only_old.append((name, val))
        elif n:
            only_new.append((name, val))
        else:
            neither.append((name, val))

    print()
    print("=" * 74)
    print("SHARED FIGURES — must appear in both reports")
    print("=" * 74)
    print(f"  checked           : {len(expected)}")
    print(f"  in both           : {len(both)}")
    print(f"  legacy only       : {len(only_old)}")
    print(f"  modular only      : {len(only_new)}")
    print(f"  in neither        : {len(neither)}")
    if dropped:
        print(f"  not testable      : {len(dropped)} figure(s) under "
              f"{MIN_DISTINCTIVE_DIGITS} digits — a presence test on those "
              f"would match coincidental text")
    for label, group in (("LEGACY ONLY", only_old), ("MODULAR ONLY", only_new),
                         ("NEITHER", neither)):
        if group:
            print(f"\n  {label}:")
            for n, v in group:
                print(f"    {n:24} {v}")

    print()
    print("=" * 74)
    print("EXPECTED DIVERGENCES — legacy is wrong here by design of the fix")
    print("=" * 74)
    jac_old = re.search(r"Jaccard index of TP findings \(([^)]*)\)\. Mean = ([\d.]+)", TO)
    if jac_old:
        print(f"  legacy jaccard    : mean {jac_old.group(2)}  (keyed on {jac_old.group(1)})")
    jac_new = re.search(r"(\d+) common of (\d+) union", TN)
    if jac_new:
        print(f"  modular jaccard   : {jac_new.group(1)} common of {jac_new.group(2)} union")
    bogus = re.findall(r"\b(home|projects) \$[\d,.]+", TO)
    if bogus:
        print(f"  legacy cost rows  : renders {sorted(set(bogus))} as components")
    if "Per-component cost is unavailable" in TN:
        print("  modular cost      : breakdown suppressed with a stated reason")
    print()
    for key, why in EXPECTED_DIVERGENCES:
        print(f"  - {key}\n      {why}")

    print()
    print("-" * 74)
    unexpected = only_old + neither
    if unexpected:
        print(f"REGRESSION: {len(unexpected)} source figure(s) missing from the modular report")
        sys.exit(1)
    if only_new:
        print(f"No regression. {len(only_new)} figure(s) appear only in the modular report "
              f"(legacy renders these at different precision or omits them).")
    else:
        print("No regression. Every source figure appears in both reports.")
    print(f"Reports kept in: {workdir}")


if __name__ == "__main__":
    main()
