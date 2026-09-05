#!/usr/bin/env python3
"""extract_cwe_cve.py — extract CWE/CVE/CVSS/OWASP metrics from run artifacts.

Aggregates:
  - CWE coverage: unique CWE IDs found, breadth across OWASP categories
  - CVE detection: count from attack_surface_discovery cves.jsonl
  - CVSS distribution: severity breakdown (critical/high/medium/low/info)
  - OWASP coverage: which Top 10 2025 categories were hit
  - Runtime: total elapsed time from transcripts

Usage:
    extract_cwe_cve.py --run-dir <path> [--transcripts-dir <path>] [--json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict


def _read_json(path: str) -> dict | list | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return None


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


def _find_files(base_dir: str, pattern: str) -> list[str]:
    return sorted(glob.glob(os.path.join(base_dir, "**", pattern), recursive=True))


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _normalize_owasp(raw: str) -> str | None:
    """Extract OWASP category ID like 'A01:2025' from raw string."""
    m = re.match(r'(A\d{2}:\d{4}|API\d+:\d{4})', raw or "")
    return m.group(1) if m else None


OWASP_2025_CATEGORIES = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Cryptographic Failures",
    "A03:2025": "Injection",
    "A04:2025": "Insecure Design",
    "A05:2025": "Security Misconfiguration",
    "A06:2025": "Vulnerable & Outdated Components",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software & Data Integrity Failures",
    "A09:2025": "Security Logging & Monitoring Failures",
    "A10:2025": "Server-Side Request Forgery",
}


def extract_from_findings(run_dir: str) -> dict:
    """Extract CWE/CVSS/OWASP from findings files."""
    findings_files = (
        _find_files(run_dir, "*scored-findings.jsonl")
        or _find_files(run_dir, "*-findings.jsonl")
        or _find_files(run_dir, "*findings.jsonl")
    )

    all_findings = []
    for f in findings_files:
        all_findings.extend(_read_jsonl(f))

    if not all_findings:
        return {
            "finding_count": 0,
            "cwe": {"unique": [], "count": 0, "distribution": {}},
            "cvss": {"distribution": {}, "scores": [], "mean_score": None, "max_score": None},
            "owasp": {"categories_hit": [], "coverage": 0, "distribution": {}},
            "severity": {"distribution": {}, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

    seen_ids = set()
    unique_findings = []
    for f in all_findings:
        fid = f.get("finding_id") or f.get("task_id") or id(f)
        if fid not in seen_ids:
            seen_ids.add(fid)
            unique_findings.append(f)

    cwe_counter = Counter()
    cvss_scores = []
    owasp_counter = Counter()
    severity_counter = Counter()

    for f in unique_findings:
        cwe = f.get("cwe") or ""
        if cwe:
            cwe_counter[cwe] += 1

        cvss = f.get("cvss_score")
        if cvss is not None and isinstance(cvss, (int, float)):
            cvss_scores.append(cvss)

        sev = (f.get("severity") or "").lower()
        if sev:
            severity_counter[sev] += 1

        owasp_raw = f.get("owasp_2025") or f.get("owasp") or ""
        owasp_id = _normalize_owasp(owasp_raw)
        if owasp_id:
            owasp_counter[owasp_id] += 1

    owasp_2025_hit = [k for k in owasp_counter if k.startswith("A") and ":2025" in k]
    owasp_coverage = len(set(owasp_2025_hit)) / 10.0

    return {
        "finding_count": len(unique_findings),
        "cwe": {
            "unique": sorted(cwe_counter.keys()),
            "count": len(cwe_counter),
            "distribution": dict(cwe_counter.most_common()),
        },
        "cvss": {
            "distribution": dict(Counter(_cvss_to_severity(s) for s in cvss_scores)),
            "scores": sorted(cvss_scores, reverse=True),
            "mean_score": round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else None,
            "max_score": max(cvss_scores) if cvss_scores else None,
        },
        "owasp": {
            "categories_hit": sorted(set(owasp_counter.keys())),
            "coverage": round(owasp_coverage, 2),
            "distribution": dict(owasp_counter.most_common()),
        },
        "severity": {
            "distribution": dict(severity_counter.most_common()),
            "critical": severity_counter.get("critical", 0),
            "high": severity_counter.get("high", 0),
            "medium": severity_counter.get("medium", 0),
            "low": severity_counter.get("low", 0),
        },
    }


def extract_cves(run_dir: str) -> dict:
    """Extract CVEs from attack_surface_discovery cves.jsonl."""
    cve_files = _find_files(run_dir, "cves.jsonl")
    all_cves = []
    for f in cve_files:
        all_cves.extend(_read_jsonl(f))

    if not all_cves:
        return {"total": 0, "unique": 0, "by_severity": {}, "by_product": {}, "cve_ids": []}

    seen = set()
    unique_cves = []
    for c in all_cves:
        cve_id = c.get("cve_id", "")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique_cves.append(c)

    by_severity = Counter()
    by_product = Counter()
    for c in unique_cves:
        sev = (c.get("severity") or "medium").lower()
        by_severity[sev] += 1
        product = c.get("product") or "unknown"
        by_product[product] += 1

    return {
        "total": len(all_cves),
        "unique": len(unique_cves),
        "by_severity": dict(by_severity.most_common()),
        "by_product": dict(by_product.most_common()),
        "cve_ids": sorted(seen),
    }


def extract_runtime(transcripts_dir: str) -> dict:
    """Extract total runtime from Claude Code transcripts.

    Tries three strategies per transcript:
      1. summary entry with durationMs
      2. costUSD entry with durationMs
      3. First/last timestamp delta (ISO 8601 ``timestamp`` fields)
    """
    if not transcripts_dir or not os.path.exists(transcripts_dir):
        return {"total_ms": None, "total_minutes": None, "by_component": {}}

    from datetime import datetime, timezone

    def _parse_ts(raw):
        if not raw or not isinstance(raw, str):
            return None
        try:
            raw = raw.replace("Z", "+00:00")
            return datetime.fromisoformat(raw)
        except (ValueError, TypeError):
            return None

    transcript_files = _find_files(transcripts_dir, "*.jsonl")

    # Separate top-level sessions from subagent sessions.
    # Subagents live under <component>/<session>/subagents/ — their time
    # overlaps with the parent, so only count top-level sessions.
    top_level_files = []
    for tf in transcript_files:
        norm = os.path.normpath(tf)
        if os.sep + "subagents" + os.sep in norm:
            continue
        top_level_files.append(tf)

    by_component = {}
    total_ms = 0

    for tf in top_level_files:
        parts = os.path.normpath(tf).split(os.sep)
        component = "unknown"
        # Try "transcripts" (standard layout) then "projects" (Claude Code layout)
        for marker in ("transcripts", "projects"):
            for i, p in enumerate(parts):
                if p == marker and i + 1 < len(parts):
                    component = parts[i + 1]
                    break
            if component != "unknown":
                break
        if "-components-" in component:
            component = component.rsplit("-components-", 1)[-1]

        entries = _read_jsonl(tf)
        session_elapsed = 0

        for entry in entries:
            if entry.get("type") == "summary":
                elapsed = entry.get("durationMs") or entry.get("elapsed_ms") or 0
                session_elapsed = max(session_elapsed, elapsed)
            elif "costUSD" in entry and "durationMs" in entry:
                session_elapsed = max(session_elapsed, entry.get("durationMs", 0))

        if session_elapsed == 0 and entries:
            first_ts = None
            last_ts = None
            for entry in entries:
                ts = _parse_ts(entry.get("timestamp"))
                if ts is None:
                    continue
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts
            if first_ts and last_ts and last_ts > first_ts:
                session_elapsed = int((last_ts - first_ts).total_seconds() * 1000)

        if session_elapsed > 0:
            by_component[component] = by_component.get(component, 0) + session_elapsed
            total_ms += session_elapsed

    return {
        "total_ms": total_ms if total_ms > 0 else None,
        "total_minutes": round(total_ms / 60000, 1) if total_ms > 0 else None,
        "by_component": {k: round(v / 60000, 1) for k, v in sorted(by_component.items())},
    }


def extract_runtime_from_bench(run_dir: str) -> dict | None:
    """Read authoritative timing from bench/benchmark_results.json if available."""
    bench_path = os.path.join(run_dir, "bench", "benchmark_results.json")
    if not os.path.exists(bench_path):
        return None
    try:
        with open(bench_path, encoding="utf-8", errors="replace") as f:
            bench = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    overhead = bench.get("pipeline_overhead", {})
    wall_clock_s = overhead.get("elapsed_s")
    if wall_clock_s is None:
        return None

    total_ms = int(wall_clock_s * 1000)
    by_component = {}
    for comp_name, comp_data in (bench.get("components") or {}).items():
        elapsed_ms = (comp_data.get("A") or {}).get("A7_time", {}).get("elapsed_ms")
        if elapsed_ms and elapsed_ms > 0:
            by_component[comp_name] = round(elapsed_ms / 60000, 1)

    return {
        "total_ms": total_ms,
        "total_minutes": round(total_ms / 60000, 1),
        "by_component": by_component,
        "source": "bench/benchmark_results.json",
    }


def extract_all(run_dir: str, transcripts_dir: str = None) -> dict:
    """Extract all CWE/CVE/CVSS/runtime metrics from a run."""
    findings_data = extract_from_findings(run_dir)
    cve_data = extract_cves(run_dir)
    runtime_data = extract_runtime_from_bench(run_dir) or extract_runtime(transcripts_dir)

    return {
        "findings": findings_data,
        "cves": cve_data,
        "runtime": runtime_data,
    }


def main():
    ap = argparse.ArgumentParser(description="Extract CWE/CVE/CVSS/OWASP metrics")
    ap.add_argument("--run-dir", required=True, help="Path to run artifacts directory")
    ap.add_argument("--transcripts-dir", default=None, help="Path to transcripts directory")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    result = extract_all(args.run_dir, args.transcripts_dir)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        fd = result["findings"]
        print(f"Findings: {fd['finding_count']}")
        print(f"  CWEs: {fd['cwe']['count']} unique — {', '.join(fd['cwe']['unique'][:10])}")
        print(f"  OWASP coverage: {fd['owasp']['coverage']:.0%} "
              f"({len(fd['owasp']['categories_hit'])} categories)")
        print(f"  Severity: {fd['severity']['critical']}C / {fd['severity']['high']}H / "
              f"{fd['severity']['medium']}M / {fd['severity']['low']}L")
        if fd["cvss"]["mean_score"]:
            print(f"  CVSS: mean={fd['cvss']['mean_score']}, max={fd['cvss']['max_score']}")

        cv = result["cves"]
        print(f"\nCVEs: {cv['unique']} unique from ASD")
        if cv["by_product"]:
            print(f"  Products: {', '.join(f'{k}({v})' for k, v in list(cv['by_product'].items())[:5])}")

        rt = result["runtime"]
        if rt["total_minutes"]:
            print(f"\nRuntime: {rt['total_minutes']} minutes")
            for comp, mins in rt["by_component"].items():
                print(f"  {comp}: {mins} min")


if __name__ == "__main__":
    main()
