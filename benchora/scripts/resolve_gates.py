#!/usr/bin/env python3
"""resolve_gates.py — resolve an AEGIS gates/ directory to ONE verdict per component.

Why this exists
---------------
benchora previously derived gate_pass_rate in score_run.py from
    gates_passed = len(glob("gates/*.PASS"))
    gates_failed = len(glob("gates/*.FAIL"))
which counts FILES, not COMPONENTS, and recognises only two of the twelve suffixes
that actually occur. Measured across 9 AEGIS runs that produced two opposite errors:

  * kimi-k3/run2 — vulnerability_exploitation has ONLY a .TIMEOUT (no .PASS/.FAIL).
    It vanished from numerator AND denominator, scoring the run 9/9 = 1.0000 even
    though _loop_state.json records terminal:true with that phase still TIMEOUT.
  * sonnet-4-6/run2 — hacker has BOTH .PASS and .FAIL, so it was counted once in
    the numerator and once in the denominator: 10/11 = 0.9091 over 10 components.

Precedence is not invented here; it is AEGIS's own documented contract:

  shared/hooks/phase-gate.sh:117
    "A PASS supersedes any earlier FAIL/TIMEOUT for this phase - the contract
     artifact now exists."  (followed by rm -f <gate>.FAIL <gate>.TIMEOUT)

  shared/hooks/orchestrator-loop-stop.sh:134
    "...writes gates/<comp>.FAIL with reason=BROWSER_UNHEALTHY AND a sibling
     gates/<comp>.HEALTHFAIL marker. This is NOT a content failure - the phase
     never got to run."

Resolution rules
----------------
  PASS      .PASS present                        -> passed
  FAIL      .FAIL present, no .PASS              -> failed
            ...unless it is a browser-health fail (reason BROWSER_UNHEALTHY, or a
               sibling .HEALTHFAIL): infrastructure, not a work verdict -> health
  TIMEOUT   .TIMEOUT present, no .PASS/.FAIL     -> failed (unresolved timeout)

Ignored (never gates): .progress, .last, .bench_scored, .json, .BLOCKED_ON
(non-blocking advisory, carries non_blocking:true), .HEALTHFAIL,
.HEALTHFAIL_CLEARED, .COMPLETE, and anything ending .stale (AEGIS's explicit
retirement convention). Unknown suffixes are collected in `ignored_suffixes` so a
future terminal state cannot be dropped silently.

gate_pass_rate = passed / (passed + failed), over components.

NOTE deliberately out of scope: a "rubber-stamp PASS" is still counted as a pass.
Two exist in this corpus - sonnet-4-6/run1 planner.PASS is 0 bytes written 4m38s
after its .TIMEOUT with progress frozen at 25%, and sonnet-4-6/run3 crawler.PASS
says "orchestrator writing PASS to unblock pipeline". Judging PASS *content* is a
separate change; see `rubber_stamp_suspects` for the flag this module raises.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

TERMINAL = ("PASS", "FAIL", "TIMEOUT")

NON_GATE_SUFFIXES = {
    "progress", "last", "bench_scored", "json", "stale",
    "BLOCKED_ON", "HEALTHFAIL", "HEALTHFAIL_CLEARED", "COMPLETE",
}


def _read(path: str, limit: int = 8192) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def _is_browser_health_fail(gates_dir: str, comp: str) -> bool:
    """A .FAIL that is really an infrastructure health probe, per AEGIS spec 3.6."""
    if os.path.exists(os.path.join(gates_dir, comp + ".HEALTHFAIL")):
        return True
    body = _read(os.path.join(gates_dir, comp + ".FAIL"))
    return "BROWSER_UNHEALTHY" in body


def resolve_gates(run_dir: str) -> dict:
    gates_dir = os.path.join(run_dir, "gates")
    result = {
        "gates_dir_exists": os.path.isdir(gates_dir),
        "components": {},
        "gates_passed": 0,
        "gates_failed": 0,
        "gates_timeout_unresolved": 0,
        "gates_health_excluded": 0,
        "gate_pass_rate": 1.0,
        "conflicts": {},
        "ignored_suffixes": {},
        "rubber_stamp_suspects": [],
    }
    if not result["gates_dir_exists"]:
        return result

    markers: dict[str, set] = {}
    for fname in sorted(os.listdir(gates_dir)):
        fpath = os.path.join(gates_dir, fname)
        if not os.path.isfile(fpath) or fname.startswith("."):
            continue
        if "." not in fname:
            continue
        comp, suffix = fname.rsplit(".", 1)
        if suffix in TERMINAL:
            markers.setdefault(comp, set()).add(suffix)
        elif suffix not in NON_GATE_SUFFIXES:
            result["ignored_suffixes"][suffix] = result["ignored_suffixes"].get(suffix, 0) + 1

    for comp, suf in sorted(markers.items()):
        if len(suf) > 1:
            result["conflicts"][comp] = sorted(suf)

        if "PASS" in suf:
            status, counts_as = "PASS", "passed"
            # AEGIS contract says a real PASS deletes the sentinels; a surviving
            # .TIMEOUT means the PASS was written by the orchestrator to unblock.
            pass_body = _read(os.path.join(gates_dir, comp + ".PASS")).strip()
            if "TIMEOUT" in suf or not pass_body:
                result["rubber_stamp_suspects"].append({
                    "component": comp,
                    "reason": ("PASS body is empty" if not pass_body
                               else "PASS coexists with an unresolved .TIMEOUT"),
                    "pass_body": pass_body[:300],
                })
        elif "FAIL" in suf:
            if _is_browser_health_fail(gates_dir, comp):
                status, counts_as = "FAIL_BROWSER_HEALTH", "health"
            else:
                status, counts_as = "FAIL", "failed"
        elif "TIMEOUT" in suf:
            status, counts_as = "TIMEOUT", "failed"
        else:
            status, counts_as = "UNKNOWN", "ignored"

        result["components"][comp] = {"status": status, "counts_as": counts_as,
                                      "markers": sorted(suf)}
        if counts_as == "passed":
            result["gates_passed"] += 1
        elif counts_as == "failed":
            result["gates_failed"] += 1
            if status == "TIMEOUT":
                result["gates_timeout_unresolved"] += 1
        elif counts_as == "health":
            result["gates_health_excluded"] += 1

    denom = result["gates_passed"] + result["gates_failed"]
    result["gate_pass_rate"] = round(result["gates_passed"] / denom, 4) if denom else 1.0
    result["component_count"] = len(result["components"])
    return result


def main():
    ap = argparse.ArgumentParser(description="Resolve AEGIS gate states per component")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = resolve_gates(os.path.abspath(a.run_dir))
    if a.json:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(json.dumps(r, indent=2))
    else:
        print(f"passed={r['gates_passed']} failed={r['gates_failed']} "
              f"(timeout={r['gates_timeout_unresolved']}) "
              f"health_excluded={r['gates_health_excluded']} "
              f"rate={r['gate_pass_rate']}")
        for c, d in r["components"].items():
            print(f"  {c:32} {d['status']:20} {d['markers']}")
        if r["conflicts"]:
            print(f"  conflicts: {r['conflicts']}")
        if r["rubber_stamp_suspects"]:
            print(f"  rubber-stamp PASS suspects: "
                  f"{[s['component'] for s in r['rubber_stamp_suspects']]}")
        if r["ignored_suffixes"]:
            print(f"  UNKNOWN suffixes seen: {r['ignored_suffixes']}")


if __name__ == "__main__":
    main()
