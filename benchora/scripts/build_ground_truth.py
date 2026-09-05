#!/usr/bin/env python3
"""build_ground_truth.py — bootstrap ground truth files for a target.

Creates or updates:
  - endpoints.json   — known endpoints for Area 1 accuracy
  - vulns.json       — known vulnerabilities for Areas 4 & 5

Can seed from an existing AEGIS run's artifacts (crawl_surface.json,
scored-findings.jsonl) and then the user curates by hand.

Usage:
    build_ground_truth.py --target <name> --gt-dir <path> [--seed-from <run_dir>] [--json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import OrderedDict


def _read_json(path: str) -> dict | list | None:
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


def _find_file(base_dir: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        hits = sorted(glob.glob(os.path.join(base_dir, "**", pattern), recursive=True))
        if hits:
            return hits[-1]
    return None


def _normalize_path(path: str) -> str:
    """Normalize URL path for dedup: collapse IDs, UUIDs, etc."""
    path = re.sub(r'/[0-9a-f]{24}(?=/|$)', '/{objectid}', path)
    path = re.sub(
        r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)',
        '/{uuid}', path
    )
    path = re.sub(r'/\d+(?=/|$)', '/{id}', path)
    return path


def seed_endpoints(run_dir: str) -> list[dict]:
    """Extract endpoints from a run's crawl_surface.json."""
    crawl_path = _find_file(run_dir, ["crawl_surface.json"])
    if not crawl_path:
        return []

    crawl = _read_json(crawl_path)
    if not crawl:
        return []

    raw_endpoints = crawl.get("endpoints") or []
    if not raw_endpoints:
        return []

    seen = set()
    endpoints = []

    for ep in raw_endpoints:
        url = ep.get("url") or ""
        method = (ep.get("method") or "GET").upper()

        from urllib.parse import urlparse
        parsed = urlparse(url)
        norm_path = _normalize_path(parsed.path or "/")
        key = f"{method}|{norm_path}"

        if key in seen:
            continue
        seen.add(key)

        endpoints.append({
            "url": url,
            "method": method,
            "path": parsed.path or "/",
            "normalized_path": norm_path,
            "auth_required": ep.get("auth_required", False),
            "verified": False,
        })

    return endpoints


def seed_vulns(run_dir: str) -> list[dict]:
    """Extract vulns from a run's scored-findings.jsonl."""
    findings_path = _find_file(run_dir, [
        "scored-findings.jsonl", "findings.jsonl"
    ])
    if not findings_path:
        return []

    findings = _read_jsonl(findings_path)
    if not findings:
        return []

    seen = set()
    vulns = []

    for f in findings:
        endpoint = f.get("endpoint") or ""
        if not endpoint:
            aff = f.get("affected_endpoints") or []
            if aff:
                endpoint = aff[0] if isinstance(aff[0], str) else (aff[0].get("url") or "")

        cwe = f.get("cwe") or ""
        vuln_class = f.get("test_type") or f.get("owasp") or f.get("vuln_class") or ""
        severity = f.get("severity") or "medium"

        key = f"{endpoint}|{cwe}|{vuln_class}".lower()
        if key in seen:
            continue
        seen.add(key)

        vuln = {
            "endpoint": endpoint,
            "cwe": cwe,
            "vuln_class": vuln_class,
            "severity": severity,
            "exploitable": bool(f.get("exploit_id") or f.get("exploited")),
            "description": f.get("title") or f.get("description") or "",
            "verified": False,
        }

        if f.get("cvss_score"):
            vuln["cvss_score"] = f["cvss_score"]
        if f.get("cvss_vector"):
            vuln["cvss_vector"] = f["cvss_vector"]

        vulns.append(vuln)

    return vulns


def build_ground_truth(
    target: str,
    gt_dir: str,
    seed_from: str = None,
    merge: bool = True,
) -> dict:
    """Build or update ground truth files."""
    os.makedirs(gt_dir, exist_ok=True)

    endpoints_path = os.path.join(gt_dir, "endpoints.json")
    vulns_path = os.path.join(gt_dir, "vulns.json")

    existing_endpoints = _read_json(endpoints_path) or {"target": target, "endpoints": []}
    existing_vulns = _read_json(vulns_path) or {"target": target, "vulns": []}

    if isinstance(existing_endpoints, list):
        existing_endpoints = {"target": target, "endpoints": existing_endpoints}
    if isinstance(existing_vulns, list):
        existing_vulns = {"target": target, "vulns": existing_vulns}

    new_ep_count = 0
    new_vuln_count = 0

    if seed_from:
        seeded_eps = seed_endpoints(seed_from)
        seeded_vulns = seed_vulns(seed_from)

        if merge:
            existing_keys = set()
            for ep in existing_endpoints.get("endpoints", []):
                norm = _normalize_path(ep.get("path") or "/")
                method = (ep.get("method") or "GET").upper()
                existing_keys.add(f"{method}|{norm}")

            for ep in seeded_eps:
                key = f"{ep['method']}|{ep['normalized_path']}"
                if key not in existing_keys:
                    existing_endpoints.setdefault("endpoints", []).append(ep)
                    existing_keys.add(key)
                    new_ep_count += 1

            existing_vuln_keys = set()
            for v in existing_vulns.get("vulns", []):
                key = f"{v.get('endpoint', '')}|{v.get('cwe', '')}|{v.get('vuln_class', '')}".lower()
                existing_vuln_keys.add(key)

            for v in seeded_vulns:
                key = f"{v['endpoint']}|{v['cwe']}|{v['vuln_class']}".lower()
                if key not in existing_vuln_keys:
                    existing_vulns.setdefault("vulns", []).append(v)
                    existing_vuln_keys.add(key)
                    new_vuln_count += 1
        else:
            existing_endpoints["endpoints"] = seeded_eps
            existing_vulns["vulns"] = seeded_vulns
            new_ep_count = len(seeded_eps)
            new_vuln_count = len(seeded_vulns)

    existing_endpoints["target"] = target
    existing_vulns["target"] = target

    with open(endpoints_path, "w", encoding="utf-8") as f:
        json.dump(existing_endpoints, f, indent=2)

    with open(vulns_path, "w", encoding="utf-8") as f:
        json.dump(existing_vulns, f, indent=2)

    return {
        "target": target,
        "gt_dir": gt_dir,
        "endpoints": {
            "total": len(existing_endpoints.get("endpoints", [])),
            "new": new_ep_count,
            "verified": sum(
                1 for ep in existing_endpoints.get("endpoints", [])
                if ep.get("verified")
            ),
            "path": endpoints_path,
        },
        "vulns": {
            "total": len(existing_vulns.get("vulns", [])),
            "new": new_vuln_count,
            "verified": sum(
                1 for v in existing_vulns.get("vulns", [])
                if v.get("verified")
            ),
            "exploitable": sum(
                1 for v in existing_vulns.get("vulns", [])
                if v.get("exploitable")
            ),
            "path": vulns_path,
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Build ground truth for a benchmark target")
    ap.add_argument("--target", required=True, help="Target name")
    ap.add_argument("--gt-dir", required=True, help="Ground truth output directory")
    ap.add_argument("--seed-from", default=None, help="Seed from an existing run directory")
    ap.add_argument("--no-merge", action="store_true", help="Replace instead of merge")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    result = build_ground_truth(
        target=args.target,
        gt_dir=args.gt_dir,
        seed_from=args.seed_from,
        merge=not args.no_merge,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Ground truth: {result['target']}")
        print(f"  Endpoints: {result['endpoints']['total']} "
              f"({result['endpoints']['new']} new, "
              f"{result['endpoints']['verified']} verified)")
        print(f"  Vulns:     {result['vulns']['total']} "
              f"({result['vulns']['new']} new, "
              f"{result['vulns']['verified']} verified, "
              f"{result['vulns']['exploitable']} exploitable)")
        print(f"\nFiles:")
        print(f"  {result['endpoints']['path']}")
        print(f"  {result['vulns']['path']}")
        print(f"\nNext: manually verify entries (set \"verified\": true)")


if __name__ == "__main__":
    main()
