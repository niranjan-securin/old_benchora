#!/usr/bin/env python3
"""compute_gt_accuracy.py — compare run output to ground truth.

Handles three GT-based evaluation areas:
  Area 1 (Recon): crawl_surface.json vs endpoints.json → endpoint TP/Unmatched/FN
  Area 4 (Vuln Analysis): findings.jsonl vs vulns.json → finding TP/Unmatched/FN
  Area 5 (Exploitation): exploits.jsonl vs vulns.json → exploit rate

Usage:
    compute_gt_accuracy.py --run-dir <path> --gt-dir <path> [--json]
                           [--judge-model MODEL] [--no-judge] [--judge-cache-dir DIR]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import defaultdict


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


_DYN_PATTERNS = [
    (re.compile(r"/[0-9a-f]{24}(?=/|$)"), "/{id}"),
    (re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)"), "/{id}"),
    (re.compile(r"/\d+(?=/|$)"), "/{id}"),
]

# Unify all template variable names to {id}
_TEMPLATE_VAR_RE = re.compile(r"\{[^}]+\}")


def _normalize_path(url: str) -> str:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
    except Exception:
        path = url if url else "/"
    path = re.sub(r"/+", "/", path).rstrip("/") or "/"
    for pattern, replacement in _DYN_PATTERNS:
        path = pattern.sub(replacement, path)
    # Unify all template variables: {token}, {path}, {patientId}, etc. → {id}
    path = _TEMPLATE_VAR_RE.sub("{id}", path)
    # Normalize hyphens ↔ underscores so lab-results == lab_results
    path = path.replace("_", "-")
    return path


def _endpoint_key(method: str, url: str) -> str:
    return f"{(method or 'GET').upper()} {_normalize_path(url)}"


def _cwe_matches(found_cwe: str, gt_cwe: str) -> bool:
    """Check if CWEs match. Allows exact match or parent-child."""
    if not found_cwe or not gt_cwe:
        return False
    f = re.sub(r"\D", "", str(found_cwe))
    g = re.sub(r"\D", "", str(gt_cwe))
    return f == g


_CWE_FAMILIES = {
    "access_control": {"284", "285", "639", "862", "863"},
    "info_exposure": {"200", "203", "204", "209"},
    "injection": {"74", "79", "89"},
    "auth": {"287", "306", "307"},
    "file": {"22", "434"},
    "crypto": {"326", "327", "328"},
}


def _cwe_family_matches(found_cwe: str, gt_cwe: str) -> bool:
    """Check if CWEs are in the same vulnerability family."""
    if not found_cwe or not gt_cwe:
        return False
    f = re.sub(r"\D", "", str(found_cwe))
    g = re.sub(r"\D", "", str(gt_cwe))
    for _family, members in _CWE_FAMILIES.items():
        if f in members and g in members:
            return True
    return False


def _vuln_class_matches(found: str, gt: str) -> bool:
    """Check if vulnerability classes match (case-insensitive substring)."""
    if not found or not gt:
        return False
    return found.lower() in gt.lower() or gt.lower() in found.lower()


def _build_gt_prefix_matchers(gt_endpoints_raw: list[dict]) -> list[tuple[str, str]]:
    """Build (method, prefix) pairs for GT endpoints that had {path} wildcards.

    These are endpoints like GET /static/{path} or GET /{path} where the original
    url_pattern ended with {path}, {file}, or similar catch-all segments. After
    template-var unification to {id}, we remember the prefix so we can match
    multi-segment crawler paths like /static/admin/js/theme.js under /static/.
    """
    matchers = []
    for ep in gt_endpoints_raw:
        raw_url = ep.get("url_pattern") or ep.get("path", "")
        method = (ep.get("method") or "GET").upper()
        # Detect catch-all patterns: path ends with {path}, {file}, or similar
        # before template-var unification
        if re.search(r"/\{(path|file|filename|asset)\}/?$", raw_url, re.IGNORECASE):
            prefix = re.sub(r"/\{[^}]+\}/?$", "", raw_url)
            prefix = re.sub(r"/+", "/", prefix).rstrip("/")
            if prefix:
                matchers.append((method, prefix))
            else:
                # bare /{path} → matches any single-level SPA route
                matchers.append((method, ""))
    return matchers


def _matches_gt_prefix(endpoint_key: str, prefix_matchers: list[tuple[str, str]]) -> bool:
    """Check if a found endpoint matches any GT wildcard prefix."""
    parts = endpoint_key.split(" ", 1)
    if len(parts) != 2:
        return False
    method, path = parts
    for gt_method, prefix in prefix_matchers:
        if method != gt_method:
            continue
        if prefix == "":
            # Bare catch-all like /{path}: match any single-segment path
            # that isn't already an API/admin/cdn path
            if not path.startswith("/api") and not path.startswith("/admin") and not path.startswith("/cdn-cgi"):
                return True
        elif path.startswith(prefix + "/") or path == prefix:
            return True
    return False


def compute_endpoint_accuracy(run_dir: str, gt_dir: str, judge=None) -> dict:
    """Area 1: Compare crawler endpoints to ground truth endpoints.json."""
    gt_path = os.path.join(gt_dir, "endpoints.json")
    gt_data = _read_json(gt_path)
    if not gt_data:
        return {"has_ground_truth": False, "error": "endpoints.json not found"}
    if isinstance(gt_data, list):
        gt_data = {"endpoints": gt_data}

    gt_endpoints_raw = gt_data.get("endpoints", [])

    gt_endpoints = set()
    for ep in gt_endpoints_raw:
        method = ep.get("method", "GET")
        url = ep.get("url_pattern") or ep.get("path", "")
        gt_endpoints.add(_endpoint_key(method, url))

    # Build prefix matchers for wildcard GT endpoints (e.g. /static/{path})
    prefix_matchers = _build_gt_prefix_matchers(gt_endpoints_raw)

    crawl_path = _find_file(run_dir, [
        "crawl_surface.json", "*crawl_surface.json",
        "endpoints.inventory.json", "*endpoints.inventory.json",
    ])
    found_endpoints = set()
    # Track status codes and paths for status-code-aware scoring
    _endpoint_status: dict[str, set[int]] = {}
    _path_to_methods: dict[str, set[str]] = defaultdict(set)
    _NOT_FOUND = {404}

    if crawl_path:
        crawl_data = _read_json(crawl_path)
        if crawl_data and isinstance(crawl_data, dict):
            for ep in crawl_data.get("endpoints", []):
                url = ep.get("url_pattern") or ep.get("url") or ""
                status_codes = set(ep.get("status_codes", []))
                for method in (ep.get("methods") or [ep.get("method", "GET")]):
                    key = _endpoint_key(method, url)
                    _endpoint_status[key] = status_codes
                    norm_path = _normalize_path(url)
                    _path_to_methods[norm_path].add(method.upper())

    # Phase 0: Filter out 404-only endpoints (server confirmed non-existent)
    for key, codes in _endpoint_status.items():
        if codes and codes <= _NOT_FOUND:
            continue  # skip — server returned only 404
        found_endpoints.add(key)

    # Phase 0b: Method mismatch handling.
    # The crawler may probe a path with a method not in GT (e.g. OPTIONS for
    # CORS preflight, or HEAD).  When the PATH exists in GT under a different
    # method we:
    #   1. Credit the GT entry as TP — but ONLY if that GT entry was not
    #      already matched directly (prevents false double-crediting).
    #   2. Always exclude the probe from unmatched (it found a real path, just used
    #      a different method).
    method_mismatch_credited = set()
    method_mismatch_probes = set()
    _gt_paths: dict[str, set[str]] = defaultdict(set)
    for gt_key in gt_endpoints:
        gt_parts = gt_key.split(" ", 1)
        if len(gt_parts) == 2:
            _gt_paths[gt_parts[1]].add(gt_key)

    for key, codes in _endpoint_status.items():
        if codes and codes <= _NOT_FOUND:
            continue
        parts = key.split(" ", 1)
        if len(parts) != 2:
            continue
        _found_method, found_path = parts
        if key not in gt_endpoints and found_path in _gt_paths:
            new_credits = {gt_key for gt_key in _gt_paths[found_path]
                           if gt_key not in found_endpoints}
            if new_credits:
                method_mismatch_credited.update(new_credits)
                found_endpoints.update(new_credits)
            method_mismatch_probes.add(key)

    # Phase 1: exact match after normalization
    tp = found_endpoints & gt_endpoints
    remaining_found = found_endpoints - gt_endpoints
    remaining_gt = gt_endpoints - found_endpoints

    # Phase 2: prefix/wildcard match for GT catch-all patterns
    prefix_matched_found = set()
    prefix_matched_gt = set()
    if prefix_matchers:
        for ep in remaining_found:
            if _matches_gt_prefix(ep, prefix_matchers):
                prefix_matched_found.add(ep)
        # Mark the corresponding GT wildcard entries as matched
        for ep in remaining_gt:
            parts = ep.split(" ", 1)
            if len(parts) == 2:
                method, path = parts
                for gt_method, prefix in prefix_matchers:
                    if method == gt_method:
                        norm_prefix = _normalize_path(prefix) if prefix else ""
                        if (prefix == "" and path == "/{id}") or \
                           (norm_prefix and (path.startswith(norm_prefix) or path == norm_prefix + "/{id}")):
                            prefix_matched_gt.add(ep)
                            break

    tp = tp | prefix_matched_found
    unmatched = remaining_found - prefix_matched_found - method_mismatch_probes
    fn = remaining_gt - prefix_matched_gt

    # Phase 3: LLM judge on remaining unmatched pairs
    _ep_judge_used = judge is not None and getattr(judge, "available", False)
    _ep_judge_matches = 0
    if _ep_judge_used and unmatched and fn:
        judge_tp_found = set()
        judge_tp_gt = set()
        # Only check pairs that share at least one path segment
        for f_ep in sorted(unmatched):
            if f_ep in judge_tp_found:
                continue
            f_parts = f_ep.split(" ", 1)
            if len(f_parts) != 2:
                continue
            f_segs = set(f_parts[1].strip("/").split("/")) - {"", "{id}"}
            for g_ep in sorted(fn):
                if g_ep in judge_tp_gt:
                    continue
                g_parts = g_ep.split(" ", 1)
                if len(g_parts) != 2:
                    continue
                g_segs = set(g_parts[1].strip("/").split("/")) - {"", "{id}"}
                if not (f_segs & g_segs):
                    continue
                verdict = judge.judge_endpoint_match(f_ep, g_ep)
                if verdict and verdict.get("match"):
                    judge_tp_found.add(f_ep)
                    judge_tp_gt.add(g_ep)
                    _ep_judge_matches += 1
                    break
        tp = tp | judge_tp_found
        unmatched = unmatched - judge_tp_found
        fn = fn - judge_tp_gt

    tp_count = len(tp)
    unmatched_count = len(unmatched)
    fn_count = len(fn)
    precision = tp_count / (tp_count + unmatched_count) if (tp_count + unmatched_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # Count filtered entries for transparency
    only_404 = {k for k, codes in _endpoint_status.items() if codes and codes <= _NOT_FOUND}
    only_405 = {k for k, codes in _endpoint_status.items() if codes == {405}}

    return {
        "has_ground_truth": True,
        "area": "1_recon",
        "gt_count": len(gt_endpoints),
        "found_count": len(found_endpoints),
        "tp": tp_count,
        "unmatched": unmatched_count,
        "fn": fn_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp_endpoints": sorted(tp),
        "missed": sorted(fn),
        "unmatched_endpoints": sorted(unmatched),
        "filtered_404_only": len(only_404),
        "method_mismatch_credited": sorted(method_mismatch_credited),
        "method_mismatch_probes": sorted(method_mismatch_probes),
        "judge_used": _ep_judge_used,
        "judge_endpoint_matches": _ep_judge_matches,
    }


# Three distinct conventions occur across the three models:
#   kimi-k3    "not_vulnerable - <class> on <endpoint>"   (run2: 364 rows)
#   opus-4-6   "Not vulnerable: <class> on <endpoint>"    (run2: 56 rows, from
#              vulnerability_chaining, also carrying verification_status=false-positive)
#   sonnet-4-6 verification_status=false-positive, prose title
_NEGATIVE_TITLE_PREFIXES = ("not_vulnerable", "not vulnerable:")
_NEGATIVE_BODY_MARKERS = (
    "probe exhausted without confirmation",
    "test case probe yielded no confirmed finding",
    "no confirmed vulnerability observed",
)

# Tool-generated mechanical notes, not vulnerability claims. Verified across all 9
# runs: these buckets produce ZERO true positives against ground truth, so
# excluding them costs no recall at all and is a pure precision correction.
# Counts: kimi run2 = 64 rows (27 schema/contract, 23 secret-in-HAR,
# 13 unauth-reachable, 1 shadow-route), kimi run3 = 3, opus run3 = 2.
_NOTE_TITLE_PREFIXES = (
    "exposed secret (",
    "schema/contract violation:",
    "operation reachable without credentials:",
    "undocumented- looking shadow route",
)


def _is_negative_test_result(f: dict) -> bool:
    """True when a row is NOT a vulnerability claim.

    Four independent signals, any one sufficient:
      1. title starts with "not_vulnerable"                    (kimi-k3/run2: 364 rows)
      2. body says no finding was confirmed                    (title-format independent)
      3. the run itself marks it verification_status=false-positive
                                                               (kimi run2, sonnet run2/run3)
      4. it was merged away as a duplicate (_superseded_by)     (sonnet run3)
      5. title is a tool-generated mechanical note              (see _NOTE_TITLE_PREFIXES)

    Signal 2 keeps this from being a title-format special case: a run wording its
    negative results differently but still saying "no confirmed finding" is caught.

    Deliberately NOT treated as negative - both are real findings:
      verification_status == "failed"     - a genuine finding whose verification step
                                           failed (kimi run1: 5 rows, up to CVSS 8.1)
      verification_status == "unverified" - a genuine but unconfirmed finding, incl.
                                           rows marked _verification_blocked by target
                                           rate-limiting (sonnet run2)
    """
    if not isinstance(f, dict):
        return False

    status = str(f.get("verification_status") or "").strip().lower()

    # The run's own reporting pipeline declared this not a vulnerability.
    if status == "false-positive":
        return True
    # Merged into a canonical finding; counting it again would double-count.
    if f.get("_superseded_by"):
        return True

    # A verified finding is never a negative result, however it is titled.
    if status.startswith("verified"):
        return False

    title = str(f.get("title") or "").strip().lower()
    if title.startswith(_NEGATIVE_TITLE_PREFIXES):
        return True
    if title.startswith(_NOTE_TITLE_PREFIXES):
        return True

    blob = " ".join(str(f.get(k) or "").lower()
                    for k in ("summary", "description", "observation", "why_it_matters"))
    return any(m in blob for m in _NEGATIVE_BODY_MARKERS)


def compute_finding_accuracy(run_dir: str, gt_dir: str, judge=None) -> dict:
    """Area 4: Compare vulnerability findings to ground truth vulns.json."""
    gt_path = os.path.join(gt_dir, "vulns.json")
    gt_data = _read_json(gt_path)
    if not gt_data:
        return {"has_ground_truth": False, "error": "vulns.json not found"}
    if isinstance(gt_data, list):
        gt_data = {"vulnerabilities": gt_data}

    gt_vulns = gt_data.get("vulnerabilities", [])
    gt_keys = {}
    for v in gt_vulns:
        ae = v.get("affected_endpoint", "")
        method = v.get("method") or (ae.split(" ")[0] if " " in ae else "GET")
        endpoint = v.get("endpoint") or (ae.split(" ", 1)[-1].strip() if ae else "")
        key = _endpoint_key(method, endpoint)
        cwe_raw = v.get("cwe", "")
        cwe = v.get("cwe_primary") or (cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else cwe_raw if isinstance(cwe_raw, str) else "")
        vuln_class = v.get("vuln_class", "")
        gt_keys[(key, cwe, vuln_class)] = v

    # Collect findings — prefer the latest scored-findings (already deduped
    # by the reporting pipeline and enriched with endpoints/IDs).
    scored_hits = sorted(glob.glob(os.path.join(run_dir, "**", "*scored-findings.jsonl"), recursive=True))
    if scored_hits:
        found_findings = _read_jsonl(scored_hits[-1])
    else:
        found_findings = []
        for pattern in ["findings.jsonl", "*findings.jsonl", "*-findings.jsonl"]:
            hits = sorted(glob.glob(os.path.join(run_dir, "**", pattern), recursive=True))
            for h in hits:
                found_findings.extend(_read_jsonl(h))

    # Drop rows that record a test finding NOTHING. Counting those as claimed
    # vulnerabilities is what collapsed kimi-k3/run2 precision to 0.0288.
    _raw_row_count = len(found_findings)
    _negatives = [f for f in found_findings if _is_negative_test_result(f)]
    if _negatives:
        found_findings = [f for f in found_findings if not _is_negative_test_result(f)]
    _excluded_non_findings = {
        "rows_in_source_file": _raw_row_count,
        "excluded_negative_results": len(_negatives),
        "rows_scored_as_claims": len(found_findings),
        "sample_excluded_titles": [str(f.get("title") or "")[:120] for f in _negatives[:10]],
    }

    # Content-based dedup: CWE + normalized title prefix.
    # This catches duplicates across files even with different IDs.
    def _content_key(f):
        cwe = f.get("cwe", "")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        title = (f.get("title", f.get("vulnerability", "")) or "")[:60].strip().lower()
        return f"{cwe}|{title}"

    seen_content = set()
    deduped_findings = []
    for f in found_findings:
        ck = _content_key(f)
        if ck == "|":
            continue  # skip empty entries (no CWE, no title)
        if ck in seen_content:
            continue
        seen_content.add(ck)
        deduped_findings.append(f)

    tp_findings = []
    unmatched_findings = []
    matched_gt = set()
    _judge_calls = 0
    _judge_used = judge is not None and getattr(judge, "available", False)

    # Pre-compute finding metadata for matching
    _finding_meta = []
    for finding in deduped_findings:
        endpoint = finding.get("endpoint") or ""
        if isinstance(endpoint, list):
            endpoint = endpoint[0] if endpoint else ""
        if not endpoint:
            aff = finding.get("affected_endpoints")
            if isinstance(aff, dict):
                endpoint = aff.get("target") or aff.get("url") or ""
            elif isinstance(aff, list) and aff:
                endpoint = aff[0] if isinstance(aff[0], str) else (aff[0].get("url") or aff[0].get("target") or "")
        if not endpoint:
            endpoint = finding.get("target") or ""
        if " and " in endpoint:
            endpoint = endpoint.split(" and ")[0].strip()

        method = finding.get("method") or "GET"
        if endpoint and endpoint.split()[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            method = endpoint.split()[0].upper()
            endpoint = endpoint.split(None, 1)[-1]

        f_key = _endpoint_key(method, endpoint)
        f_cwe_raw = finding.get("cwe", "")
        f_cwe = f_cwe_raw[0] if isinstance(f_cwe_raw, list) and f_cwe_raw else (f_cwe_raw if isinstance(f_cwe_raw, str) else "")
        f_class = finding.get("test_type") or finding.get("owasp") or finding.get("vuln_class") or ""
        has_endpoint = bool(endpoint.strip()) and endpoint.strip() not in ("", "/")
        f_path_norm = _normalize_path(f_key.split(" ", 1)[-1]) if has_endpoint else ""

        _finding_meta.append({
            "finding": finding, "f_key": f_key, "f_cwe": f_cwe, "f_class": f_class,
            "has_endpoint": has_endpoint, "f_path_norm": f_path_norm,
        })

    # Stage 1: Rule-based matching (always runs)
    matched_finding_indices = set()
    for fi, fm in enumerate(_finding_meta):
        finding = fm["finding"]
        matched = False
        for (gt_key, gt_cwe, gt_class), gt_vuln in gt_keys.items():
            if (gt_key, gt_cwe, gt_class) in matched_gt:
                continue
            gt_path_raw = gt_key.split(" ", 1)[-1]
            is_wildcard = gt_path_raw in ("/*", "/", "")
            gt_path_norm = _normalize_path(gt_path_raw) if not is_wildcard else ""
            path_exact = is_wildcard or (fm["has_endpoint"] and fm["f_path_norm"] == gt_path_norm)
            path_prefix = (
                fm["has_endpoint"] and not is_wildcard and gt_path_norm != "/"
                and fm["f_path_norm"].startswith(gt_path_norm + "/")
            )
            path_match = path_exact or path_prefix
            cwe_match = _cwe_matches(fm["f_cwe"], gt_cwe) or _cwe_family_matches(fm["f_cwe"], gt_cwe)
            class_match = _vuln_class_matches(fm["f_class"], gt_class)

            if path_match and (cwe_match or class_match):
                matched = True
                matched_gt.add((gt_key, gt_cwe, gt_class))
                matched_finding_indices.add(fi)
                tp_findings.append(finding)
                break
            if not fm["has_endpoint"] and cwe_match:
                matched = True
                matched_gt.add((gt_key, gt_cwe, gt_class))
                matched_finding_indices.add(fi)
                tp_findings.append(finding)
                break

        if not matched:
            unmatched_findings.append(finding)

    # Stage 2: LLM judge on remaining unmatched findings vs FN GT entries
    # Pre-filter: only check pairs sharing a CWE family/number or path segment
    if _judge_used and unmatched_findings:
        remaining_gt_keys = [
            k for k in gt_keys if k not in matched_gt
        ]
        if remaining_gt_keys:
            # Build lookup for pre-filtering
            def _cwe_num(cwe_str):
                return re.sub(r"\D", "", str(cwe_str)) if cwe_str else ""

            def _cwe_families(cwe_str):
                n = _cwe_num(cwe_str)
                return {fam for fam, members in _CWE_FAMILIES.items() if n in members}

            def _path_segments(endpoint_str):
                from urllib.parse import urlparse
                try:
                    path = urlparse(endpoint_str).path or ""
                except Exception:
                    path = endpoint_str or ""
                segs = set(path.strip("/").split("/")) - {"", "api", "v1", "v2"}
                return {s for s in segs if len(s) > 2 and not re.match(r"^\d+$|^[0-9a-f-]{8,}$", s)}

            judge_tp = []
            judge_matched_gt = set()
            judge_matched_um_idx = set()

            for umi, finding in enumerate(unmatched_findings):
                if umi in judge_matched_um_idx:
                    continue
                f_cwe_raw = finding.get("cwe", "")
                f_cwe_str = f_cwe_raw[0] if isinstance(f_cwe_raw, list) and f_cwe_raw else str(f_cwe_raw)
                f_cwe_n = _cwe_num(f_cwe_str)
                f_fams = _cwe_families(f_cwe_str)
                f_endpoint = finding.get("target") or finding.get("endpoint") or ""
                if isinstance(f_endpoint, list):
                    f_endpoint = f_endpoint[0] if f_endpoint else ""
                f_segs = _path_segments(f_endpoint)

                for gt_tuple in remaining_gt_keys:
                    if gt_tuple in judge_matched_gt:
                        continue
                    gt_key, gt_cwe, gt_class = gt_tuple
                    gt_cwe_n = _cwe_num(gt_cwe)
                    gt_fams = _cwe_families(gt_cwe)
                    gt_endpoint = gt_keys[gt_tuple].get("endpoint") or ""
                    gt_segs = _path_segments(gt_endpoint)

                    # Pre-filter: at least one shared signal
                    shared_cwe = f_cwe_n and gt_cwe_n and f_cwe_n == gt_cwe_n
                    shared_family = bool(f_fams & gt_fams)
                    shared_path = bool(f_segs & gt_segs)
                    if not (shared_cwe or shared_family or shared_path):
                        continue

                    verdict = judge.judge_vuln_match(finding, gt_keys[gt_tuple])
                    if verdict and verdict.get("match"):
                        judge_tp.append(finding)
                        judge_matched_gt.add(gt_tuple)
                        judge_matched_um_idx.add(umi)
                        break

            _judge_calls = getattr(judge, "calls_made", 0)
            if judge_tp:
                tp_findings.extend(judge_tp)
                matched_gt.update(judge_matched_gt)
                unmatched_findings = [f for i, f in enumerate(unmatched_findings)
                                      if i not in judge_matched_um_idx]

    fn_vulns = [
        v for (k, c, vc), v in gt_keys.items()
        if (k, c, vc) not in matched_gt
    ]

    tp_count = len(tp_findings)
    unmatched_count = len(unmatched_findings)
    fn_count = len(fn_vulns)
    precision = tp_count / (tp_count + unmatched_count) if (tp_count + unmatched_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    owasp_found = set()
    for f in tp_findings:
        owasp = f.get("owasp") or ""
        if owasp:
            owasp_found.add(owasp.split(":")[0] if ":" in owasp else owasp)

    severity_matches = 0
    for f in tp_findings:
        f_sev = (f.get("severity") or "").lower()
        for (_, _, _), v in gt_keys.items():
            gt_sev = (v.get("severity") or "").lower()
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            if abs(sev_order.get(f_sev, -1) - sev_order.get(gt_sev, -1)) <= 1:
                severity_matches += 1
                break
    severity_accuracy = severity_matches / tp_count if tp_count > 0 else 0.0

    def _finding_summary(f):
        return {
            "finding_id": f.get("finding_id", ""),
            "endpoint": f.get("endpoint") or f.get("affected_endpoint") or f.get("target") or "",
            "cwe": f.get("cwe", ""),
            "severity": f.get("severity", ""),
            "title": (f.get("title") or f.get("vulnerability") or "")[:120],
            "cvss_score": f.get("cvss_score"),
        }

    return {
        "has_ground_truth": True,
        "area": "4_vuln_analysis",
        "gt_count": len(gt_vulns),
        "found_count": len(deduped_findings),
        "excluded_non_findings": _excluded_non_findings,
        "tp": tp_count,
        "unmatched": unmatched_count,
        "fn": fn_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "owasp_breadth": len(owasp_found),
        "owasp_categories": sorted(owasp_found),
        "severity_accuracy": round(severity_accuracy, 4),
        "tp_findings": [_finding_summary(f) for f in tp_findings],
        "unmatched_findings": [_finding_summary(f) for f in unmatched_findings],
        "missed_vulns": [
            {
                "endpoint": v.get("endpoint") or v.get("affected_endpoint", ""),
                "cwe": v.get("cwe"),
                "severity": v.get("severity"),
                "title": (v.get("title") or v.get("vulnerability") or v.get("description", ""))[:120],
                "cvss_score": v.get("cvss_score"),
                "id": v.get("id", ""),
            }
            for v in fn_vulns
        ],
        "judge_used": _judge_used,
        "judge_calls": _judge_calls,
        "judge_fallback_reason": None if _judge_used else (
            getattr(judge, "_reason", "disabled") if judge else "no judge provided"
        ),
    }


def compute_exploitation_accuracy(run_dir: str, gt_dir: str) -> dict:
    """Area 5: Compare exploits to ground truth exploitable vulns."""
    gt_path = os.path.join(gt_dir, "vulns.json")
    gt_data = _read_json(gt_path)
    if not gt_data:
        return {"has_ground_truth": False, "error": "vulns.json not found"}
    if isinstance(gt_data, list):
        gt_data = {"vulnerabilities": gt_data}

    exploitable_gt = [
        v for v in gt_data.get("vulnerabilities", [])
        if v.get("exploitable", True) or v.get("best_verification") in ("verified-exploit", "verified-poc")
    ]
    if not exploitable_gt:
        return {"has_ground_truth": True, "area": "5_exploitation", "gt_exploitable": 0,
                "exploit_rate": 0.0, "mean_depth": 0.0}

    # Collect ALL exploit JSONL files (may be split across many files)
    exploits = []
    for pattern in ["exploits.jsonl", "*exploits.jsonl", "*-exploits.jsonl"]:
        hits = sorted(glob.glob(os.path.join(run_dir, "**", pattern), recursive=True))
        for h in hits:
            exploits.extend(_read_jsonl(h))
    # Dedup by finding_id
    seen_ids = set()
    deduped = []
    for e in exploits:
        eid = e.get("finding_id") or e.get("id") or id(e)
        if eid not in seen_ids:
            seen_ids.add(eid)
            deduped.append(e)
    exploits = deduped

    reproduced = 0
    depth_sum = 0.0
    for exploit in exploits:
        status = (exploit.get("status") or exploit.get("verification_status") or "").lower()
        if "verified" in status or "success" in status or "reproduced" in status:
            reproduced += 1
        depth = exploit.get("depth", 0)
        if isinstance(depth, (int, float)):
            depth_sum += depth
        elif status == "verified-exploit":
            depth_sum += 3
        elif status == "verified-poc":
            depth_sum += 2

    exploit_rate = min(reproduced, len(exploitable_gt)) / len(exploitable_gt) if exploitable_gt else 0.0
    mean_depth = depth_sum / len(exploits) if exploits else 0.0

    return {
        "has_ground_truth": True,
        "area": "5_exploitation",
        "gt_exploitable": len(exploitable_gt),
        "exploits_found": len(exploits),
        "reproduced": reproduced,
        "exploit_rate": round(exploit_rate, 4),
        "mean_depth": round(mean_depth, 2),
    }


def compute_all(run_dir: str, gt_dir: str, judge=None) -> dict:
    """Compute all GT-based accuracy metrics for a run."""
    return {
        "endpoint_coverage": compute_endpoint_accuracy(run_dir, gt_dir, judge=judge),
        "finding_accuracy": compute_finding_accuracy(run_dir, gt_dir, judge=judge),
        "exploitation": compute_exploitation_accuracy(run_dir, gt_dir),
    }


def _make_judge(args):
    if getattr(args, "no_judge", False):
        return None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from llm_judge import LLMJudge
        model = getattr(args, "judge_model", None) or "claude-haiku-4-5"
        cache_dir = getattr(args, "judge_cache_dir", None) or args.run_dir
        j = LLMJudge(model=model, cache_dir=cache_dir)
        if j.available:
            print(f"  LLM judge: {model} (available)", file=sys.stderr)
        else:
            print(f"  LLM judge: unavailable ({j._reason}), falling back to rule-based", file=sys.stderr)
        return j
    except Exception as e:
        print(f"  LLM judge: failed to initialize ({e}), falling back to rule-based", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser(description="Compute GT accuracy for a run")
    ap.add_argument("--run-dir", required=True, help="Path to run artifacts directory")
    ap.add_argument("--gt-dir", required=True, help="Path to ground truth directory")
    ap.add_argument("--area", choices=["1_recon", "4_vuln_analysis", "5_exploitation", "all"],
                    default="all", help="Which area to compute")
    ap.add_argument("--judge-model", default="claude-haiku-4-5",
                    help="LLM model for semantic matching judge (default: claude-haiku-4-5)")
    ap.add_argument("--no-judge", action="store_true",
                    help="Disable LLM judge, use rule-based matching only")
    ap.add_argument("--judge-cache-dir", default=None,
                    help="Directory for judge cache file (default: same as --run-dir)")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    judge = _make_judge(args)

    if args.area == "1_recon":
        result = compute_endpoint_accuracy(args.run_dir, args.gt_dir, judge=judge)
    elif args.area == "4_vuln_analysis":
        result = compute_finding_accuracy(args.run_dir, args.gt_dir, judge=judge)
    elif args.area == "5_exploitation":
        result = compute_exploitation_accuracy(args.run_dir, args.gt_dir)
    else:
        result = compute_all(args.run_dir, args.gt_dir, judge=judge)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
