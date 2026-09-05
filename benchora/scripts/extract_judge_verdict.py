#!/usr/bin/env python3
"""extract_judge_verdict.py — surface the AEGIS judge's own verdict for a run.

Most AEGIS runs write a *judge_verdict.json from an independent judge component.
benchora ignored these entirely, discarding high-value independent signal about
run quality. Measured across the 9-run corpus, the judge frequently disagrees
with benchora's computed scores - e.g. kimi-k3/run2 scores a clean gate sweep and
0 refusals, while its judge raised a MAJOR false_positive_risk issue reading:
"The main findings table contains 432 unverified entries, the majority titled
'not_vulnerable - <class> on <endpoint>'."

When several verdict files exist, the LAST by sorted filename is authoritative
(filenames are timestamp-prefixed), matching how benchora picks scored-findings.
All of them are listed in `all_verdict_files` for traceability.

Reports null/found=False rather than a zero when no verdict exists - a run with no
judge and a run with a clean judge are different things.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import Counter


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def extract_judge_verdict(run_dir: str) -> dict:
    # Order by mtime, NOT by filename: some runs write a bare "judge_verdict.json"
    # alongside timestamp-prefixed ones, and 'j' sorts after '2', so filename order
    # is not chronological. Measured: sonnet-4-6/run3 has 4 verdicts progressing
    # FAIL -> CONDITIONAL_PASS -> CONDITIONAL_PASS -> CONDITIONAL_PASS as the
    # reporting component fixed the issues the judge raised.
    hits = glob.glob(os.path.join(run_dir, "**", "*judge_verdict.json"), recursive=True)
    hits.sort(key=lambda p: (os.path.getmtime(p), os.path.basename(p)))

    history = []
    for h in hits:
        hd = _read_json(h)
        if not isinstance(hd, dict):
            continue
        hiss = hd.get("issues") if isinstance(hd.get("issues"), list) else []
        history.append({
            "file": os.path.relpath(h, run_dir),
            "verdict": hd.get("verdict"),
            "issue_count": len(hiss),
        })

    out = {
        "found": False,
        "verdict": None,
        "issue_count": None,
        "issues": [],
        "by_severity": {},
        "by_category": {},
        "major_count": 0,
        "source_file": None,
        "all_verdict_files": [os.path.relpath(h, run_dir) for h in hits],
        # The judge is re-run until it stops objecting; the path matters as much as
        # the endpoint. A final PASS reached after an initial FAIL is not the same
        # result as a first-pass PASS.
        "judge_rounds": len(history),
        "initial_verdict": history[0]["verdict"] if history else None,
        "initial_issue_count": history[0]["issue_count"] if history else None,
        "verdict_history": history,
    }
    if not hits:
        return out

    path = hits[-1]
    data = _read_json(path)
    if not isinstance(data, dict):
        out["source_file"] = os.path.relpath(path, run_dir)
        out["parse_error"] = True
        return out

    issues = data.get("issues")
    if not isinstance(issues, list):
        issues = []

    norm = []
    for it in issues:
        if not isinstance(it, dict):
            continue
        norm.append({
            "severity": it.get("severity") or "",
            "category": it.get("category") or "",
            "description": it.get("description") or "",
            "recommendation": it.get("recommendation") or "",
        })

    out.update({
        "found": True,
        "verdict": data.get("verdict"),
        "issue_count": len(norm),
        "issues": norm,
        "by_severity": dict(Counter(i["severity"] for i in norm if i["severity"])),
        "by_category": dict(Counter(i["category"] for i in norm if i["category"])),
        "major_count": sum(1 for i in norm if str(i["severity"]).lower() == "major"),
        "source_file": os.path.relpath(path, run_dir),
    })
    # keep any extra top-level scalar the judge emitted (scores, notes, etc.)
    extras = {k: v for k, v in data.items()
              if k not in ("verdict", "issues") and not isinstance(v, (dict, list))}
    if extras:
        out["extra_fields"] = extras
    return out


def main():
    ap = argparse.ArgumentParser(description="Extract the AEGIS judge verdict for a run")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = extract_judge_verdict(os.path.abspath(a.run_dir))
    if a.json:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        if not r["found"]:
            print("no judge verdict found")
            return
        print(f"verdict={r['verdict']}  issues={r['issue_count']}  major={r['major_count']}")
        print(f"source={r['source_file']}")
        for i in r["issues"]:
            print(f"  [{i['severity']}] {i['category']}: {i['description'][:160]}")


if __name__ == "__main__":
    main()
