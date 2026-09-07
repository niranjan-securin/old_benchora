#!/usr/bin/env python3
"""Triage run 2's 405 false positives: classify every row of scored-findings.jsonl,
then recompute Area 4 accuracy with the non-finding rows excluded.

Read-only analysis. Writes nothing except a triage JSON next to the run outputs.
"""
import io
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "..", "output", "kimi-k3-final")

from compute_gt_accuracy import compute_finding_accuracy  # noqa: E402


def read_jsonl(p):
    return [json.loads(l) for l in io.open(p, encoding="utf-8", errors="replace") if l.strip()]


def classify(r):
    title = str(r.get("title") or "").strip()
    low = title.lower()
    if low.startswith("not_vulnerable"):
        return "negative_test_result"
    if re.match(r"^exposed secret \(", low):
        return "har_secret_selfcapture"
    if low.startswith("schema/contract violation:"):
        return "schema_contract_note"
    if low.startswith("operation reachable without credentials:"):
        return "unauth_reachable_note"
    if low.startswith("undocumented- looking shadow route"):
        return "shadow_route_note"
    return "vulnerability_claim"


rows = read_jsonl(os.path.join(OUT, "run2", "scored-findings.jsonl"))
buckets = {}
for r in rows:
    buckets.setdefault(classify(r), []).append(r)

print(f"run 2 scored-findings.jsonl — {len(rows)} rows\n")
print(f"{'bucket':28} {'rows':>6}  {'severities'}")
for k in sorted(buckets, key=lambda x: -len(buckets[x])):
    sev = dict(Counter(r.get("severity", "?") for r in buckets[k]))
    print(f"{k:28} {len(buckets[k]):>6}  {sev}")

claims = buckets.get("vulnerability_claim", [])
print(f"\nreal vulnerability claims: {len(claims)}")
print("  verification:", dict(Counter(r.get("verification_status", "?") for r in claims)))

# Recompute Area 4 with only the vulnerability claims.
gt_dir = os.path.abspath(os.path.join(HERE, "..", "..", "groundtruth"))
tmpdir = os.path.join(OUT, "run2", "_claims_only")
os.makedirs(tmpdir, exist_ok=True)
tmp = os.path.join(tmpdir, "claims-scored-findings.jsonl")
with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
    for r in claims:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

orig = json.load(io.open(os.path.join(OUT, "run2", "benchora_score.json"),
                         encoding="utf-8"))["accuracy"]["finding_accuracy"]
# compute_finding_accuracy takes a run DIRECTORY and globs for *scored-findings.jsonl
recomputed = compute_finding_accuracy(tmpdir, gt_dir)

print("\nArea 4 (vulnerability analysis) — run 2")
print(f"{'':22} {'as scored':>12} {'claims only':>13}")
for k in ("tp", "unmatched", "fn", "precision", "recall", "f1"):
    print(f"{k:22} {str(orig.get(k)):>12} {str(recomputed.get(k)):>13}")

json.dump(
    {
        "run": "run2",
        "total_rows": len(rows),
        "buckets": {k: len(v) for k, v in buckets.items()},
        "bucket_titles_sample": {
            k: [str(r.get("title"))[:120] for r in v[:3]] for k, v in buckets.items()
        },
        "area4_as_scored": orig,
        "area4_claims_only": recomputed,
    },
    io.open(os.path.join(OUT, "run2", "fp_triage.json"), "w", encoding="utf-8"),
    indent=2,
    ensure_ascii=False,
)
import shutil; shutil.rmtree(tmpdir, ignore_errors=True)
print("\nwrote run2/fp_triage.json")
