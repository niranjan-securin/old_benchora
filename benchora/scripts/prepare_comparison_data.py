#!/usr/bin/env python3
"""prepare_comparison_data.py — build the comparison data contract for N runs.

Pure data layer: reads N benchora_score.json files, normalises legacy keys,
computes cross-run statistics, and writes comparison_data.json.

Emits NO HTML.  Every section renderer in report_sections/ consumes only the
JSON this produces, so the rendering layer never touches a raw score file.

Key normalisation: score files written before the FP->unmatched rename carry
"fp" / "false_positives" / "fp_findings".  Newer files carry "unmatched" /
"unmatched_endpoints" / "unmatched_findings".  Both are accepted; the output
always uses the new names.

Missing data is emitted as null, never silently defaulted to 0.

Usage:
    python prepare_comparison_data.py --scores run1.json run2.json run3.json \
        [--prices config/model_prices.json] [--model-display "Claude Opus 4.7"] \
        [--output comparison_data.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from statistics import mean as _mean, stdev as _stdev

SCHEMA_VERSION = 1

# ─── key normalisation ────────────────────────────────────────────────────────

_UNMATCHED_COUNT_KEYS = ("unmatched", "fp")
_UNMATCHED_EP_KEYS = ("unmatched_endpoints", "false_positives")
_UNMATCHED_FIND_KEYS = ("unmatched_findings", "fp_findings")


def _first_key(d: dict, keys, default=None):
    """Return the first present key's value. Accepts legacy and current names."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _get(d, *keys, default=None):
    """Nested dict get that never raises."""
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur if cur is not None else default


# ─── statistics ───────────────────────────────────────────────────────────────

def _nums(vals):
    return [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]


def _safe_mean(vals):
    n = _nums(vals)
    return round(_mean(n), 6) if n else None


def _safe_stdev(vals):
    n = _nums(vals)
    return round(_stdev(n), 6) if len(n) >= 2 else None


def _safe_cv(vals):
    m = _safe_mean(vals)
    s = _safe_stdev(vals)
    if m is None or s is None or m == 0:
        return None
    return round(s / abs(m), 6)


def _cv_verdict(cv):
    """Classify reproducibility from the coefficient of variation."""
    if cv is None:
        return "unknown"
    if cv < 0.05:
        return "consistent"
    if cv <= 0.20:
        return "variable"
    return "unstable"


def _stat_row(key, label, values, fmt="num", note=None):
    """One comparable metric across runs, with derived statistics."""
    row = {
        "key": key,
        "label": label,
        "values": values,
        "mean": _safe_mean(values),
        "stdev": _safe_stdev(values),
        "cv": _safe_cv(values),
        "format": fmt,
    }
    row["verdict"] = _cv_verdict(row["cv"])
    if note:
        row["note"] = note
    return row


# ─── finding / endpoint keys ──────────────────────────────────────────────────

def _norm_cwe_id(cwe) -> str:
    """Reduce a CWE value to a canonical CWE-NNN token."""
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    m = re.search(r"(\d+)", str(cwe or ""))
    return f"CWE-{m.group(1)}" if m else ""


def _norm_ep_path(ep) -> str:
    """Normalise an endpoint to a comparable path.

    Strips scheme+host and query, collapses numeric and template path segments
    to {id}, drops the trailing slash, lowercases.
    """
    if isinstance(ep, list):
        ep = ep[0] if ep else ""
    ep = str(ep or "")
    ep = re.sub(r"^https?://[^/]+", "", ep)
    ep = ep.split("?")[0].split("#")[0]
    ep = re.sub(r"/\d+(?=/|$)", "/{id}", ep)
    ep = re.sub(r"\{[^}]+\}", "{id}", ep)
    ep = ep.rstrip("/").lower()
    return ep or "/"


def _finding_key(f: dict) -> str:
    """Stable identity for one finding across runs.

    Model-authored titles drift between runs for the same vulnerability
    ("Mass-assignment: role escalation via PUT /api/auth/profile/" vs
    "Mass-assignment role escalation — any authenticated user can PUT role="),
    so a title-derived key reports zero overlap even when the runs agree.

    Identity precedence:
      1. gt_id / matched_gt_id — the ground-truth entry the finding matched.
         Exact, but only present if the scorer recorded it.
      2. CWE + normalised endpoint — what the GT match itself keys on.
    """
    gt_id = f.get("gt_id") or f.get("matched_gt_id")
    if gt_id:
        return f"gt:{str(gt_id).strip().lower()}"
    return f"ce:{_norm_cwe_id(f.get('cwe'))}|{_norm_ep_path(f.get('endpoint'))}"


def _norm_cwe(f: dict) -> str:
    cwe = f.get("cwe", "")
    if isinstance(cwe, list):
        return ", ".join(str(c) for c in cwe)
    return str(cwe) if cwe else ""


def _norm_endpoint(f: dict) -> str:
    ep = f.get("endpoint", "")
    if isinstance(ep, list):
        ep = ep[0] if ep else ""
    return str(ep) if ep else ""


# ─── section builders ─────────────────────────────────────────────────────────

def _build_meta(scores, paths, model_display):
    return {
        "schema_version": SCHEMA_VERSION,
        "model": scores[0].get("model", "Unknown"),
        "model_display": model_display or scores[0].get("model", "Unknown"),
        "target": scores[0].get("target", "Unknown"),
        "run_count": len(scores),
        "run_ids": [s.get("run_id", f"run-{i+1}") for i, s in enumerate(scores)],
        "run_labels": [f"Run {i+1}" for i in range(len(scores))],
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "source_files": [os.path.abspath(p) for p in paths],
    }


def _build_kpis(scores):
    recalls = [_get(s, "accuracy", "endpoint_coverage", "recall") for s in scores]
    f1s = [_get(s, "accuracy", "finding_accuracy", "f1") for s in scores]
    exploits = [_get(s, "accuracy", "exploitation", "exploit_rate") for s in scores]
    costs = [_get(s, "cost", "full_run_usd") for s in scores]
    refusals = [_get(s, "refusals", "total_refusals") for s in scores]
    schema = [_get(s, "reliability", "schema_pass_rate") for s in scores]
    runtime = [_get(s, "cwe_cve", "runtime", "total_minutes") for s in scores]
    findings = [_get(s, "cwe_cve", "findings", "finding_count") for s in scores]

    return [
        _stat_row("endpoint_recall", "Endpoint Recall", recalls, "pct"),
        _stat_row("finding_f1", "Finding F1", f1s, "ratio"),
        _stat_row("exploit_rate", "Exploit Rate", exploits, "pct"),
        _stat_row("findings", "Findings Reported", findings, "int"),
        _stat_row("cost", "Run Cost", costs, "usd"),
        _stat_row("runtime", "Runtime (min)", runtime, "min"),
        _stat_row("refusals", "Refusals", refusals, "int"),
        _stat_row("schema_pass", "Schema Pass Rate", schema, "pct"),
    ]


def _build_metrics(scores):
    """Grouped side-by-side metric tables — one group per evaluation area."""

    def col(*path, norm=None):
        out = []
        for s in scores:
            node = _get(s, *path[:-1], default={})
            if norm:
                out.append(_first_key(node, norm))
            else:
                out.append(node.get(path[-1]) if isinstance(node, dict) else None)
        return out

    groups = {}

    groups["endpoint_coverage"] = {
        "label": "Endpoint Coverage",
        "area": "Area 1",
        "rows": [
            _stat_row("gt_count", "Ground Truth Endpoints",
                      col("accuracy", "endpoint_coverage", "gt_count"), "int"),
            _stat_row("found_count", "Endpoints Found",
                      col("accuracy", "endpoint_coverage", "found_count"), "int"),
            _stat_row("tp", "Matched (TP)",
                      col("accuracy", "endpoint_coverage", "tp"), "int"),
            _stat_row("unmatched", "Unmatched",
                      col("accuracy", "endpoint_coverage", "x", norm=_UNMATCHED_COUNT_KEYS), "int",
                      note="Found but not in ground truth — status unknown, not confirmed false"),
            _stat_row("fn", "Missed (FN)",
                      col("accuracy", "endpoint_coverage", "fn"), "int"),
            _stat_row("precision", "Precision",
                      col("accuracy", "endpoint_coverage", "precision"), "pct"),
            _stat_row("recall", "Recall",
                      col("accuracy", "endpoint_coverage", "recall"), "pct"),
            _stat_row("f1", "F1",
                      col("accuracy", "endpoint_coverage", "f1"), "ratio"),
        ],
    }

    groups["finding_accuracy"] = {
        "label": "Vulnerability Analysis",
        "area": "Area 4",
        "rows": [
            _stat_row("gt_count", "Ground Truth Vulns",
                      col("accuracy", "finding_accuracy", "gt_count"), "int"),
            _stat_row("found_count", "Findings Evaluated",
                      col("accuracy", "finding_accuracy", "found_count"), "int"),
            _stat_row("tp", "Matched (TP)",
                      col("accuracy", "finding_accuracy", "tp"), "int"),
            _stat_row("unmatched", "Unmatched",
                      col("accuracy", "finding_accuracy", "x", norm=_UNMATCHED_COUNT_KEYS), "int",
                      note="Reported but not in ground truth — status unknown, not confirmed false"),
            _stat_row("fn", "Missed (FN)",
                      col("accuracy", "finding_accuracy", "fn"), "int"),
            _stat_row("precision", "Precision",
                      col("accuracy", "finding_accuracy", "precision"), "pct"),
            _stat_row("recall", "Recall",
                      col("accuracy", "finding_accuracy", "recall"), "pct"),
            _stat_row("f1", "F1",
                      col("accuracy", "finding_accuracy", "f1"), "ratio"),
            _stat_row("owasp_breadth", "OWASP Breadth",
                      col("accuracy", "finding_accuracy", "owasp_breadth"), "int"),
            _stat_row("severity_accuracy", "Severity Accuracy",
                      col("accuracy", "finding_accuracy", "severity_accuracy"), "pct"),
        ],
    }

    groups["exploitation"] = {
        "label": "Exploitation",
        "area": "Area 5",
        "rows": [
            _stat_row("gt_exploitable", "GT Exploitable",
                      col("accuracy", "exploitation", "gt_exploitable"), "int"),
            _stat_row("reproduced", "Reproduced",
                      col("accuracy", "exploitation", "reproduced"), "int"),
            _stat_row("exploit_rate", "Exploit Rate",
                      col("accuracy", "exploitation", "exploit_rate"), "pct"),
        ],
    }

    groups["reliability"] = {
        "label": "Operational Reliability",
        "area": "Area 9",
        "rows": [
            _stat_row("schema_pass_rate", "Schema Pass Rate",
                      col("reliability", "schema_pass_rate"), "pct"),
            _stat_row("gates_passed", "Gates Passed",
                      col("reliability", "gates_passed"), "int"),
            _stat_row("gates_failed", "Gates Failed",
                      col("reliability", "gates_failed"), "int"),
            _stat_row("error_count", "Errors",
                      col("reliability", "error_count"), "int"),
            _stat_row("total_refusals", "Total Refusals",
                      col("refusals", "total_refusals"), "int"),
            _stat_row("guardrail_rate", "Guardrail Rate",
                      col("refusals", "guardrail_rate"), "pct"),
        ],
    }

    groups["efficiency"] = {
        "label": "Cost & Efficiency",
        "area": "Area 10",
        "rows": [
            _stat_row("cost", "Total Cost",
                      col("cost", "full_run_usd"), "usd"),
            _stat_row("turns", "Total Turns",
                      col("transcripts", "total_turns"), "int"),
            _stat_row("runtime", "Runtime (min)",
                      col("cwe_cve", "runtime", "total_minutes"), "min"),
        ],
    }

    groups["dedup"] = {
        "label": "Deduplication",
        "area": "Quality",
        "rows": [
            _stat_row("pre_dedup", "Pre-dedup Findings",
                      col("duplicates", "pre_dedup_count"), "int"),
            _stat_row("post_dedup", "Post-dedup Findings",
                      col("duplicates", "post_dedup_count"), "int"),
            _stat_row("dedup_ratio", "Dedup Ratio",
                      col("duplicates", "dedup_ratio"), "ratio"),
            _stat_row("content_duplicates", "Content Duplicates",
                      col("duplicates", "content_duplicates"), "int"),
        ],
    }

    return groups


AREA_LABELS = {
    "1_recon": "Reconnaissance", "2_interaction": "Interactive Discovery",
    "3_sast": "SAST", "4_vuln_analysis": "Vulnerability Analysis",
    "5_exploitation": "Exploitation", "6_attack_path": "Attack Path",
    "7_business_logic": "Business Logic", "8_reporting": "Reporting",
    "9_reliability": "Reliability", "10_cost": "Cost Efficiency",
    "11_reproducibility": "Reproducibility",
}


def _build_area_scores(scores):
    keys = set()
    for s in scores:
        keys |= set(_get(s, "area_scores", default={}).keys())
    ordered = sorted(keys, key=lambda k: int(k.split("_")[0]) if k.split("_")[0].isdigit() else 99)

    rows = []
    for ak in ordered:
        vals = [_get(s, "area_scores", ak, "score") for s in scores]
        inverse = any(_get(s, "area_scores", ak, "inverse") for s in scores)
        methods = [_get(s, "area_scores", ak, "method") for s in scores]
        row = _stat_row(ak, AREA_LABELS.get(ak, ak), vals, "usd" if inverse else "ratio")
        row["num"] = ak.split("_")[0]
        row["inverse"] = bool(inverse)
        row["method"] = next((m for m in methods if m), None)
        rows.append(row)
    return {"rows": rows}


def _build_reproducibility(scores):
    tracked = [
        ("Endpoint Recall", ("accuracy", "endpoint_coverage", "recall"), "pct"),
        ("Endpoint F1", ("accuracy", "endpoint_coverage", "f1"), "ratio"),
        ("Finding Precision", ("accuracy", "finding_accuracy", "precision"), "pct"),
        ("Finding Recall", ("accuracy", "finding_accuracy", "recall"), "pct"),
        ("Finding F1", ("accuracy", "finding_accuracy", "f1"), "ratio"),
        ("Exploit Rate", ("accuracy", "exploitation", "exploit_rate"), "pct"),
        ("Findings Reported", ("cwe_cve", "findings", "finding_count"), "int"),
        ("Total Cost", ("cost", "full_run_usd"), "usd"),
        ("Runtime (min)", ("cwe_cve", "runtime", "total_minutes"), "min"),
        ("Schema Pass Rate", ("reliability", "schema_pass_rate"), "pct"),
    ]
    rows = []
    for label, path, fmt in tracked:
        vals = [_get(s, *path) for s in scores]
        if not _nums(vals):
            continue
        rows.append(_stat_row(label.lower().replace(" ", "_"), label, vals, fmt))

    jaccard = _build_jaccard(scores)

    cvs = [r["cv"] for r in rows if r["cv"] is not None]
    overall_cv = round(_mean(cvs), 6) if cvs else None

    return {
        "rows": rows,
        "jaccard": jaccard,
        "overall_cv": overall_cv,
        "overall_verdict": _cv_verdict(overall_cv),
    }


def _build_jaccard(scores):
    """Pairwise Jaccard of matched (TP) findings."""
    sets = []
    for s in scores:
        tp = _get(s, "accuracy", "finding_accuracy", "tp_findings", default=[]) or []
        sets.append({_finding_key(f) for f in tp})

    n = len(sets)
    matrix = []
    pair_vals = []
    for i in range(n):
        row = []
        for j in range(n):
            if i == j:
                row.append(1.0)
                continue
            inter = len(sets[i] & sets[j])
            union = len(sets[i] | sets[j])
            v = round(inter / union, 6) if union else 0.0
            row.append(v)
            if j > i:
                pair_vals.append(v)
        matrix.append(row)

    common = set.intersection(*sets) if sets and all(sets) else set()
    union_all = set.union(*sets) if sets else set()

    return {
        "matrix": matrix,
        "mean": round(_mean(pair_vals), 6) if pair_vals else None,
        "common_count": len(common),
        "union_count": len(union_all),
        "per_run_counts": [len(x) for x in sets],
    }


def _build_severity(scores):
    runs = []
    for i, s in enumerate(scores):
        dist = _get(s, "cwe_cve", "findings", "severity", "distribution", default={}) or {}
        entry = {
            "label": f"Run {i+1}",
            "critical": dist.get("critical", 0),
            "high": dist.get("high", 0),
            "medium": dist.get("medium", 0),
            "low": dist.get("low", 0),
            "info": dist.get("info", 0),
        }
        entry["total"] = sum(entry[k] for k in ("critical", "high", "medium", "low", "info"))
        runs.append(entry)
    return {"runs": runs, "max_total": max((r["total"] for r in runs), default=0)}


def _build_endpoints(scores):
    n = len(scores)
    if not any(_get(s, "accuracy", "endpoint_coverage", "has_ground_truth") for s in scores):
        return {"gt_rows": [], "unmatched_rows": [], "gt_total": 0, "available": False}

    gt_all = set()
    run_tp, run_um = [], []
    for s in scores:
        ec = _get(s, "accuracy", "endpoint_coverage", default={})
        tp = set(ec.get("tp_endpoints") or [])
        um = set(_first_key(ec, _UNMATCHED_EP_KEYS, default=[]) or [])
        fn = set(ec.get("missed") or [])
        gt_all |= tp | fn
        run_tp.append(tp)
        run_um.append(um)

    gt_rows = []
    for ep in sorted(gt_all):
        hits = [ep in run_tp[i] for i in range(n)]
        hc = sum(hits)
        gt_rows.append({
            "endpoint": ep,
            "hits": hits,
            "hit_count": hc,
            "consistency": f"{hc}/{n}",
            "classification": "all" if hc == n else ("none" if hc == 0 else "partial"),
        })

    um_only = set().union(*run_um) - gt_all if run_um else set()
    um_rows = []
    for ep in sorted(um_only):
        present = [ep in run_um[i] for i in range(n)]
        um_rows.append({
            "endpoint": ep,
            "present": present,
            "hit_count": sum(present),
            "consistency": f"{sum(present)}/{n}",
        })

    return {
        "gt_rows": gt_rows,
        "unmatched_rows": um_rows,
        "gt_total": len(gt_all),
        "available": True,
        "all_found_count": sum(1 for r in gt_rows if r["hit_count"] == n),
        "never_found_count": sum(1 for r in gt_rows if r["hit_count"] == 0),
    }


def _build_findings(scores):
    n = len(scores)
    if not any(_get(s, "accuracy", "finding_accuracy", "has_ground_truth") for s in scores):
        return {"rows": [], "missed": [], "per_run": [], "available": False}

    catalogue = {}
    run_tp, run_um = [], []
    for s in scores:
        fa = _get(s, "accuracy", "finding_accuracy", default={})
        tp_map, um_map = {}, {}
        for f in (fa.get("tp_findings") or []):
            k = _finding_key(f)
            tp_map[k] = f
            catalogue.setdefault(k, f)
        for f in (_first_key(fa, _UNMATCHED_FIND_KEYS, default=[]) or []):
            k = _finding_key(f)
            um_map[k] = f
            catalogue.setdefault(k, f)
        run_tp.append(tp_map)
        run_um.append(um_map)

    rows = []
    for k in sorted(catalogue):
        f = catalogue[k]
        status, fid = [], ""
        titles = []          # per-run title as authored by the model (None if absent)
        for i in range(n):
            src = None
            if k in run_tp[i]:
                status.append("tp")
                src = run_tp[i][k]
            elif k in run_um[i]:
                status.append("unmatched")
                src = run_um[i][k]
            else:
                status.append("absent")
            if src is not None:
                fid = fid or (src.get("finding_id") or src.get("id") or "")
                titles.append((src.get("title") or "").strip())
            else:
                titles.append(None)

        present = sum(1 for x in status if x != "absent")
        seen = [t for t in titles if t]
        # Representative title: the most descriptive wording seen across runs.
        rep_title = max(seen, key=len) if seen else (f.get("title") or "").strip()
        rows.append({
            "key": k,
            "cwe": _norm_cwe_id(f.get("cwe")) or _norm_cwe(f),
            "title": rep_title,
            "titles_per_run": titles,
            "title_variants": len(set(seen)),
            "endpoint": _norm_ep_path(f.get("endpoint")),
            "endpoint_raw": _norm_endpoint(f),
            "severity": (f.get("severity") or "").lower(),
            "cvss": f.get("cvss_score"),
            "finding_id": fid,
            "status": status,
            "tp_count": sum(1 for x in status if x == "tp"),
            "present_count": present,
            "consistency": f"{present}/{n}",
            "classification": "shared" if present == n else ("unique" if present == 1 else "partial"),
        })
    # Most-agreed findings first, then by severity weight.
    _sev_w = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda r: (-r["present_count"], -r["tp_count"],
                             _sev_w.get(r["severity"], 5), r["cwe"]))

    missed_cat = {}
    for i, s in enumerate(scores):
        for v in (_get(s, "accuracy", "finding_accuracy", "missed_vulns", default=[]) or []):
            vid = v.get("id") or _finding_key(v)
            entry = missed_cat.setdefault(vid, {
                "id": v.get("id", ""),
                "cwe": _norm_cwe(v),
                "title": (v.get("title") or "").strip(),
                "endpoint": _norm_endpoint(v),
                "severity": (v.get("severity") or "").lower(),
                "cvss": v.get("cvss_score"),
                "missed_by": [False] * n,
            })
            entry["missed_by"][i] = True
    missed = sorted(missed_cat.values(), key=lambda x: (-sum(x["missed_by"]), x["id"]))
    for m in missed:
        m["miss_count"] = sum(m["missed_by"])
        m["consistency"] = f"{m['miss_count']}/{n}"

    per_run = []
    for i, s in enumerate(scores):
        fa = _get(s, "accuracy", "finding_accuracy", default={})
        per_run.append({
            "label": f"Run {i+1}",
            "run_id": s.get("run_id", ""),
            "tp": fa.get("tp"),
            "unmatched": _first_key(fa, _UNMATCHED_COUNT_KEYS),
            "fn": fa.get("fn"),
            "precision": fa.get("precision"),
            "recall": fa.get("recall"),
            "f1": fa.get("f1"),
        })

    return {
        "rows": rows,
        "missed": missed,
        "per_run": per_run,
        "available": True,
        "shared_count": sum(1 for r in rows if r["classification"] == "shared"),
        "unique_count": sum(1 for r in rows if r["classification"] == "unique"),
        "partial_count": sum(1 for r in rows if r["classification"] == "partial"),
        "total_unique": len(rows),
    }


def _clean_label(name: str) -> str:
    return name.replace("_", " ").title()


_VALID_GATE_STATUSES = {"PASS", "FAIL", "TIMEOUT", "SKIP", "SKIPPED", "UNKNOWN", "ERROR"}


def _clean_gate_status(raw):
    """Accept only genuine gate verdicts.

    Some runs write progress-log markers into gates_detail, where the value is
    an entire timestamped log rather than a verdict.  Those are not statuses and
    must not be rendered as if they were.
    """
    if raw is None:
        return None
    s = str(raw).strip().upper()
    if len(s) > 12 or "\n" in s or "\t" in s:
        return None
    return s if s in _VALID_GATE_STATUSES else None


def _build_components(scores):
    """Per-component gate status across runs.

    The authoritative component set is component_results, which is stable across
    runs.  gates_detail is used only for status, and only for keys that are real
    components with a real verdict — it also collects marker files
    (--where_progress, orchestrator_progress) that are not components at all.
    """
    n = len(scores)
    names = set()
    for s in scores:
        names |= set(_get(s, "component_results", default={}).keys())

    gate_keys = set()
    for s in scores:
        gate_keys |= set(_get(s, "reliability", "gates_detail", default={}).keys())
    # Gate-only components (e.g. cross_app, judge) are real when they carry a
    # real verdict in at least one run.
    for k in gate_keys - names:
        if any(_clean_gate_status(_get(s, "reliability", "gates_detail", k)) for s in scores):
            names.add(k)

    ignored = sorted(k for k in gate_keys - names)

    if not names:
        return {"rows": [], "available": False, "ignored_gate_keys": ignored}

    rows = []
    for c in sorted(names):
        statuses, produced = [], []
        for s in scores:
            statuses.append(_clean_gate_status(_get(s, "reliability", "gates_detail", c)))
            produced.append(bool(_get(s, "component_results", c)))
        pass_count = sum(1 for x in statuses if x == "PASS")
        rows.append({
            "component": c,
            "label": _clean_label(c),
            "status": statuses,
            "produced_output": produced,
            "pass_count": pass_count,
            "produced_count": sum(1 for x in produced if x),
            "consistency": f"{pass_count}/{n}",
            "all_pass": pass_count == n,
        })
    return {"rows": rows, "available": True, "ignored_gate_keys": ignored}


def _build_cost(scores, prices, known_components=None):
    """Total cost plus a per-component breakdown, when the breakdown is real.

    When transcript directory names cannot be resolved to component names,
    parse_transcript.py falls back to a path fragment ("projects", "home") and
    the whole run's cost lands under that single bogus key.  A breakdown like
    that is not a breakdown; it is suppressed with a stated reason rather than
    rendered as a component costing 100% of the run.
    """
    comps = set()
    for s in scores:
        comps |= set(_get(s, "cost", "by_component", default={}).keys())

    totals = [_get(s, "cost", "full_run_usd") for s in scores]
    known = set(known_components or [])
    recognised = comps & known if known else comps

    breakdown_ok = bool(recognised) and len(recognised) > 1
    reason = None
    if not comps:
        reason = "No per-component cost data in the score files."
    elif not breakdown_ok:
        bogus = ", ".join(sorted(comps))
        reason = (f"Per-component cost is unavailable: the scorer could not resolve "
                  f"transcript directories to component names, so the entire run cost "
                  f"is filed under {bogus!r}. Run totals below are unaffected.")

    by_comp = []
    if breakdown_ok:
        total_mean = _safe_mean(totals)
        for c in sorted(recognised):
            vals = [_get(s, "cost", "by_component", c) for s in scores]
            m = _safe_mean(vals)
            by_comp.append({
                "component": c,
                "label": _clean_label(c),
                "values": vals,
                "mean": m,
                "share": round(m / total_mean, 6) if m is not None and total_mean else None,
            })
        by_comp.sort(key=lambda x: -(x["mean"] or 0))

    return {
        "totals": _stat_row("total", "Total Cost", totals, "usd"),
        "by_component": by_comp,
        "breakdown_available": breakdown_ok,
        "breakdown_note": reason,
        "raw_component_keys": sorted(comps),
        "sources": [_get(s, "cost", "source") for s in scores],
        "prices": prices,
    }


def _build_tokens(scores):
    types = [("input", "Input"), ("output", "Output"),
             ("cache_write", "Cache Write"), ("cache_read", "Cache Read")]
    rows = []
    for k, label in types:
        vals = [_get(s, "transcripts", "total_tokens", k) for s in scores]
        rows.append(_stat_row(k, label, vals, "int"))

    totals = []
    for s in scores:
        t = _get(s, "transcripts", "total_tokens", default={}) or {}
        vals = _nums([t.get(k) for k, _ in types])
        totals.append(sum(vals) if vals else None)

    turns = [_get(s, "transcripts", "total_turns") for s in scores]
    return {
        "rows": rows,
        "totals": _stat_row("total", "Total Tokens", totals, "int"),
        "turns": _stat_row("turns", "Total Turns", turns, "int"),
    }


def _build_runtime(scores):
    vals = [_get(s, "cwe_cve", "runtime", "total_minutes") for s in scores]
    if not _nums(vals):
        return {"available": False, "total": None, "by_component": []}
    comps = set()
    for s in scores:
        comps |= set(_get(s, "cwe_cve", "runtime", "by_component", default={}).keys())
    by_comp = []
    for c in sorted(comps):
        cv = [_get(s, "cwe_cve", "runtime", "by_component", c) for s in scores]
        by_comp.append({
            "component": c, "label": _clean_label(c),
            "values": cv, "mean": _safe_mean(cv),
        })
    by_comp.sort(key=lambda x: -(x["mean"] or 0))
    return {
        "available": True,
        "total": _stat_row("runtime", "Runtime (min)", vals, "min"),
        "by_component": by_comp,
    }


def _build_verdict(kpis, repro, findings, endpoints):
    """Derive an evidence-backed summary. Every claim traces to a computed value."""
    points = []

    def kpi(key):
        return next((k for k in kpis if k["key"] == key), None)

    f1 = kpi("finding_f1")
    if f1 and f1["mean"] is not None:
        tone = "good" if f1["mean"] >= 0.6 else ("warn" if f1["mean"] >= 0.35 else "bad")
        nr = len(f1["values"])
        vals = _nums(f1["values"]) or [0]
        spread = (f" (spread {min(vals):.3f}–{max(vals):.3f})" if nr > 1 else "")
        points.append({
            "label": "Detection quality",
            "text": f"{'Mean f' if nr > 1 else 'F'}inding F1 {f1['mean']:.3f} "
                    f"across {nr} run{'s' if nr != 1 else ''}{spread}.",
            "tone": tone,
        })

    rec = kpi("endpoint_recall")
    if rec and rec["mean"] is not None:
        tone = "good" if rec["mean"] >= 0.9 else ("warn" if rec["mean"] >= 0.7 else "bad")
        points.append({
            "label": "Surface coverage",
            "text": f"Mean endpoint recall {rec['mean']:.1%}; "
                    f"{endpoints.get('all_found_count', 0)} of {endpoints.get('gt_total', 0)} "
                    f"ground-truth endpoints found in every run.",
            "tone": tone,
        })

    verdict = repro.get("overall_verdict", "unknown")
    jac = repro.get("jaccard", {}).get("mean")
    tone = {"consistent": "good", "variable": "warn", "unstable": "bad"}.get(verdict, "warn")
    jac_txt = f" Mean Jaccard overlap of matched findings {jac:.3f}." if jac is not None else ""
    points.append({
        "label": "Reproducibility",
        "text": f"Mean CV {repro.get('overall_cv'):.3f} — classified {verdict}.{jac_txt}"
                if repro.get("overall_cv") is not None else f"Classified {verdict}.{jac_txt}",
        "tone": tone,
    })

    if findings.get("available"):
        points.append({
            "label": "Finding stability",
            "text": f"{findings['shared_count']} findings appeared in all runs, "
                    f"{findings['partial_count']} in some, "
                    f"{findings['unique_count']} in exactly one "
                    f"(of {findings['total_unique']} unique).",
            "tone": "good" if findings["shared_count"] >= findings["unique_count"] else "warn",
        })

    cost = kpi("cost")
    if cost and cost["mean"] is not None:
        points.append({
            "label": "Cost",
            "text": f"Mean run cost ${cost['mean']:,.2f}"
                    + (f", CV {cost['cv']:.3f}." if cost["cv"] is not None else "."),
            "tone": "good" if (cost["cv"] or 1) < 0.1 else "warn",
        })

    ref = kpi("refusals")
    if ref and ref["mean"] is not None:
        total = sum(_nums(ref["values"]))
        points.append({
            "label": "Refusals",
            "text": f"{int(total)} refusal(s) across all runs."
                    if total else "No guardrail, API, or hook refusals in any run.",
            "tone": "good" if not total else "warn",
        })

    headline = {
        "consistent": "Repeatable across runs",
        "variable": "Moderately repeatable — measurable run-to-run variance",
        "unstable": "Not repeatable — high run-to-run variance",
    }.get(verdict, "Repeatability inconclusive")

    return {"headline": headline, "verdict": verdict, "points": points}


# ─── orchestration ────────────────────────────────────────────────────────────

def build(scores, paths, prices=None, model_display=None) -> dict:
    kpis = _build_kpis(scores)
    repro = _build_reproducibility(scores)
    findings = _build_findings(scores)
    endpoints = _build_endpoints(scores)
    components = _build_components(scores)
    known = {r["component"] for r in components.get("rows", [])}

    return {
        "meta": _build_meta(scores, paths, model_display),
        "kpis": kpis,
        "metrics": _build_metrics(scores),
        "area_scores": _build_area_scores(scores),
        "reproducibility": repro,
        "severity": _build_severity(scores),
        "endpoints": endpoints,
        "findings": findings,
        "components": components,
        "cost": _build_cost(scores, prices, known),
        "tokens": _build_tokens(scores),
        "runtime": _build_runtime(scores),
        "verdict": _build_verdict(kpis, repro, findings, endpoints),
    }


def main():
    ap = argparse.ArgumentParser(description="Build comparison data contract from N score files")
    ap.add_argument("--scores", nargs="+", required=True, help="Paths to benchora_score.json files")
    ap.add_argument("--prices", default=None, help="Path to model_prices.json")
    ap.add_argument("--model-display", default=None, help="Display name for the model")
    ap.add_argument("--output", default=None, help="Output JSON path")
    args = ap.parse_args()

    scores = []
    for p in args.scores:
        if not os.path.exists(p):
            print(f"ERROR: not found: {p}", file=sys.stderr)
            sys.exit(1)
        with open(p, encoding="utf-8") as f:
            scores.append(json.load(f))

    prices = None
    if args.prices and os.path.exists(args.prices):
        with open(args.prices, encoding="utf-8") as f:
            allp = json.load(f)
        model = scores[0].get("model", "")
        prices = allp.get(model) or allp.get(f"anthropic/{model}")

    data = build(scores, args.scores, prices, args.model_display)

    out = args.output or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(args.scores[0]))),
        "comparison_data.json")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    m = data["meta"]
    print(f"Wrote {out}")
    print(f"  Model:  {m['model_display']}")
    print(f"  Target: {m['target']}")
    print(f"  Runs:   {m['run_count']}  ({', '.join(m['run_ids'])})")
    print(f"  Verdict: {data['verdict']['verdict']}  (mean CV "
          f"{data['reproducibility']['overall_cv']})")
    print(f"  Findings: {data['findings'].get('total_unique', 0)} unique "
          f"({data['findings'].get('shared_count', 0)} shared, "
          f"{data['findings'].get('unique_count', 0)} single-run)")
    print(f"  Endpoints: {data['endpoints'].get('gt_total', 0)} GT "
          f"({data['endpoints'].get('all_found_count', 0)} found in all runs)")


if __name__ == "__main__":
    main()
