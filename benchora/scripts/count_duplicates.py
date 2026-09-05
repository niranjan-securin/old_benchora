#!/usr/bin/env python3
"""count_duplicates.py — detailed dedup analysis of scored-findings.jsonl.

Analyses three layers:
  1. AEGIS merge tracking: _grouped_from / _merged_ids fields
  2. Content-based dedup: CWE + title prefix collisions
  3. Cross-component overlap: same CWE+endpoint found by multiple components

Usage:
    count_duplicates.py --scored-findings <path> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict


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


def _normalize_cwe(cwe) -> str:
    if not cwe:
        return ""
    return re.sub(r"\D", "", str(cwe))


def _title_key(title: str) -> str:
    return (title or "")[:60].strip().lower()


def _endpoint_norm(ep: str) -> str:
    if not ep:
        return ""
    ep = re.sub(r"/\d+(?=/|$)", "/{id}", ep)
    ep = ep.rstrip("/")
    return ep.lower()


def count_duplicates(scored_findings_path: str) -> dict:
    """Full dedup analysis of scored-findings.jsonl."""
    findings = _read_jsonl(scored_findings_path)

    if not findings:
        return {
            "scored_findings_path": scored_findings_path,
            "post_dedup_count": 0,
            "pre_dedup_count": 0,
            "dedup_ratio": 0.0,
            "duplicates_removed": 0,
            "by_component": {},
            "aegis_merges": [],
            "content_duplicates": [],
            "cross_component_overlaps": [],
        }

    post_dedup = len(findings)

    # --- Layer 1: AEGIS merge tracking ---
    pre_dedup = 0
    by_component = {}
    aegis_merges = []

    for i, f in enumerate(findings):
        grouped = f.get("_grouped_from") or []
        merged_ids = f.get("_merged_ids") or []
        merge_count = len(grouped) if grouped else (len(merged_ids) if len(merged_ids) > 1 else 1)
        pre_dedup += merge_count

        component = f.get("component") or "unknown"
        if component not in by_component:
            by_component[component] = {"post_dedup": 0, "pre_dedup": 0}
        by_component[component]["post_dedup"] += 1
        by_component[component]["pre_dedup"] += merge_count

        if grouped and len(grouped) > 1:
            aegis_merges.append({
                "finding_index": i,
                "finding_id": f.get("finding_id", ""),
                "title": (f.get("title") or "")[:100],
                "component": component,
                "merge_type": "_grouped_from",
                "merged_count": len(grouped),
                "merged_titles": [(g.get("title") or "")[:80] for g in grouped[:5]],
            })
        elif merged_ids and len(merged_ids) > 1:
            aegis_merges.append({
                "finding_index": i,
                "finding_id": f.get("finding_id", ""),
                "title": (f.get("title") or "")[:100],
                "component": component,
                "merge_type": "_merged_ids",
                "merged_count": len(merged_ids),
                "merged_ids": merged_ids[:10],
            })

    dedup_ratio = 1 - (post_dedup / pre_dedup) if pre_dedup > 0 else 0.0

    # --- Layer 2: Content-based dedup (CWE + title prefix) ---
    content_seen: dict[str, int] = {}
    content_duplicates = []

    for i, f in enumerate(findings):
        cwe = _normalize_cwe(f.get("cwe"))
        title = _title_key(f.get("title") or f.get("vulnerability") or "")
        key = f"{cwe}|{title[:40]}"

        if key in content_seen and cwe:
            orig = content_seen[key]
            content_duplicates.append({
                "duplicate_index": i,
                "original_index": orig,
                "cwe": cwe,
                "duplicate_title": (f.get("title") or "")[:100],
                "original_title": (findings[orig].get("title") or "")[:100],
                "duplicate_component": f.get("component", ""),
                "original_component": findings[orig].get("component", ""),
            })
        else:
            content_seen[key] = i

    # --- Layer 3: Cross-component overlap ---
    # 3a: Same CWE found by multiple components (regardless of endpoint)
    cwe_comp_map: dict[str, list] = defaultdict(list)
    for i, f in enumerate(findings):
        cwe = _normalize_cwe(f.get("cwe"))
        if not cwe:
            continue
        cwe_comp_map[cwe].append({
            "index": i,
            "component": f.get("component", ""),
            "title": (f.get("title") or "")[:100],
            "finding_id": f.get("finding_id", ""),
            "severity": f.get("severity", ""),
            "endpoint": (f.get("endpoint") or f.get("affected_endpoint") or f.get("target") or "")[:100],
        })

    cross_component_overlaps = []
    for cwe, entries in cwe_comp_map.items():
        components = set(e["component"] for e in entries)
        if len(components) > 1:
            cross_component_overlaps.append({
                "cwe": cwe,
                "components": sorted(components),
                "count": len(entries),
                "findings": entries,
            })

    return {
        "scored_findings_path": scored_findings_path,
        "post_dedup_count": post_dedup,
        "pre_dedup_count": pre_dedup,
        "dedup_ratio": round(dedup_ratio, 4),
        "duplicates_removed": pre_dedup - post_dedup,
        "by_component": by_component,
        "aegis_merges": aegis_merges,
        "content_duplicates": content_duplicates,
        "cross_component_overlaps": cross_component_overlaps,
    }


def main():
    ap = argparse.ArgumentParser(description="Count pre/post dedup findings")
    ap.add_argument("--scored-findings", required=True, help="Path to scored-findings.jsonl")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    result = count_duplicates(args.scored_findings)

    if args.json:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Pre-dedup:  {result['pre_dedup_count']}")
        print(f"Post-dedup: {result['post_dedup_count']}")
        print(f"Removed:    {result['duplicates_removed']}")
        print(f"Dedup ratio: {result['dedup_ratio']:.1%}")
        if result["aegis_merges"]:
            print(f"\nAEGIS merges: {len(result['aegis_merges'])}")
            for m in result["aegis_merges"]:
                print(f"  [{m['finding_index']}] {m['component']}: {m['title'][:60]} ({m['merge_type']}, {m['merged_count']} merged)")
        if result["content_duplicates"]:
            print(f"\nContent duplicates: {len(result['content_duplicates'])}")
            for d in result["content_duplicates"]:
                print(f"  [{d['duplicate_index']}] dupes [{d['original_index']}]: CWE-{d['cwe']} | {d['duplicate_title'][:50]}")
        if result["cross_component_overlaps"]:
            print(f"\nCross-component overlaps: {len(result['cross_component_overlaps'])}")
            for o in result["cross_component_overlaps"]:
                print(f"  CWE-{o['cwe']}: {' + '.join(o['components'])} ({o['count']} findings)")
                for f in o["findings"]:
                    print(f"    [{f['index']}] {f['component']}: {f['title'][:60]}")


if __name__ == "__main__":
    main()
