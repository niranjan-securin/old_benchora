#!/usr/bin/env python3
"""verify_report.py — independently cross-check a comparison report against source.

Recomputes every headline figure directly from the benchora_score.json files,
then checks (a) the intermediate comparison_data.json agrees, and (b) the
rendered HTML actually contains those figures.

The point is independence: this script does NOT import prepare_comparison_data,
so a bug in the data layer cannot hide by being reused here.  Statistics are
recomputed from first principles.

Exit codes: 0 all checks passed, 1 one or more FAILs.

Usage:
    python verify_report.py --scores r1.json r2.json r3.json \
        --data comparison_data.json --html comparison_report.html
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from statistics import mean as _mean, stdev as _stdev

PASS, FAIL, WARN = "PASS", "FAIL", "WARN"
_results = []


def check(name, ok, detail=""):
    _results.append((PASS if ok else FAIL, name, detail))
    return ok


def warn(name, detail=""):
    _results.append((WARN, name, detail))


def approx(a, b, tol=1e-4):
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return abs(float(a) - float(b)) <= tol


def _get(d, *keys):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur


def _um(d):
    """Unmatched count under either the current or legacy key."""
    if not isinstance(d, dict):
        return None
    for k in ("unmatched", "fp"):
        if d.get(k) is not None:
            return d[k]
    return None


def _um_findings(d):
    if not isinstance(d, dict):
        return []
    for k in ("unmatched_findings", "fp_findings"):
        if d.get(k) is not None:
            return d[k]
    return []


def _norm_cwe(cwe):
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    m = re.search(r"(\d+)", str(cwe or ""))
    return f"CWE-{m.group(1)}" if m else ""


def _norm_ep(ep):
    if isinstance(ep, list):
        ep = ep[0] if ep else ""
    ep = str(ep or "")
    ep = re.sub(r"^https?://[^/]+", "", ep).split("?")[0].split("#")[0]
    ep = re.sub(r"/\d+(?=/|$)", "/{id}", ep)
    ep = re.sub(r"\{[^}]+\}", "{id}", ep)
    return ep.rstrip("/").lower() or "/"


def _key(f):
    gt = f.get("gt_id") or f.get("matched_gt_id")
    if gt:
        return f"gt:{str(gt).strip().lower()}"
    return f"ce:{_norm_cwe(f.get('cwe'))}|{_norm_ep(f.get('endpoint'))}"


# ─── layer 0: is the source internally consistent? ────────────────────────────

def verify_source_integrity(scores, paths):
    """Recompute each run's derived metrics from its own counts.

    Layer 1 only proves the report faithfully reproduces the score file.  A
    corrupted or miscomputed score file would pass that and still be wrong, so
    the arithmetic is re-derived here from tp / unmatched / fn.
    """
    for i, (s, p) in enumerate(zip(scores, paths), start=1):
        tag = f"run {i}"
        for group in ("endpoint_coverage", "finding_accuracy"):
            acc = _get(s, "accuracy", group)
            if not isinstance(acc, dict) or not acc.get("has_ground_truth"):
                continue
            tp, fn, um = acc.get("tp"), acc.get("fn"), _um(acc)
            prec, rec, f1 = acc.get("precision"), acc.get("recall"), acc.get("f1")
            if tp is None or fn is None or um is None:
                warn(f"{tag} {group}: incomplete counts", f"tp={tp} unmatched={um} fn={fn}")
                continue

            exp_p = tp / (tp + um) if (tp + um) else 0.0
            exp_r = tp / (tp + fn) if (tp + fn) else 0.0
            exp_f = (2 * exp_p * exp_r / (exp_p + exp_r)) if (exp_p + exp_r) else 0.0

            check(f"{tag} {group}: precision = tp/(tp+unmatched)", approx(prec, exp_p, 5e-4),
                  f"stored {prec} but {tp}/({tp}+{um}) = {exp_p:.4f}")
            check(f"{tag} {group}: recall = tp/(tp+fn)", approx(rec, exp_r, 5e-4),
                  f"stored {rec} but {tp}/({tp}+{fn}) = {exp_r:.4f}")
            check(f"{tag} {group}: f1 = 2PR/(P+R)", approx(f1, exp_f, 5e-4),
                  f"stored {f1} but 2*{exp_p:.4f}*{exp_r:.4f}/({exp_p:.4f}+{exp_r:.4f}) = {exp_f:.4f}")

            gt = acc.get("gt_count")
            if gt is not None:
                if group == "finding_accuracy":
                    # Findings match 1:1 against GT vulns, so these are complementary.
                    check(f"{tag} {group}: tp + fn = gt_count", tp + fn == gt,
                          f"{tp} + {fn} = {tp+fn}, gt_count = {gt}")
                elif tp + fn != gt:
                    # Endpoint TP is counted on the FOUND side (prefix and
                    # method-mismatch rules let several discovered endpoints
                    # credit one GT entry) while FN is counted on the GT side.
                    # They are not complementary, so recall here is tp/(tp+fn),
                    # not the fraction of ground truth covered.
                    covered = gt - fn
                    warn(f"{tag} {group}: tp+fn != gt_count (expected for endpoints)",
                         f"tp={tp} fn={fn} gt={gt}; GT entries covered = {covered}/{gt} "
                         f"= {covered/gt:.1%}, whereas stored recall tp/(tp+fn) = {rec}")

            # List lengths must agree with the counts they summarise.
            if group == "finding_accuracy":
                lists = [("tp_findings", tp, acc.get("tp_findings")),
                         ("unmatched_findings", um, _um_findings(acc)),
                         ("missed_vulns", fn, acc.get("missed_vulns"))]
            else:
                lists = [("tp_endpoints", tp, acc.get("tp_endpoints")),
                         ("missed", fn, acc.get("missed"))]
            for lname, count, lst in lists:
                if lst is None:
                    continue
                check(f"{tag} {group}: len({lname}) = {count}", len(lst) == count,
                      f"list has {len(lst)} entries, count says {count}")

        # Cost must be the sum of its parts when a real breakdown exists.
        total = _get(s, "cost", "full_run_usd")
        parts = _get(s, "cost", "by_component")
        if isinstance(parts, dict) and len(parts) > 1 and total:
            ssum = sum(v for v in parts.values() if isinstance(v, (int, float)))
            check(f"{tag}: cost total = sum(by_component)", approx(total, ssum, 0.02),
                  f"total {total} vs component sum {ssum:.4f}")


# ─── layer 1: source -> comparison_data ───────────────────────────────────────

def verify_data_layer(scores, data):
    n = len(scores)
    check("run count matches", _get(data, "meta", "run_count") == n,
          f"data says {_get(data, 'meta', 'run_count')}, {n} score files given")

    ids_src = [s.get("run_id") for s in scores]
    check("run ids match source", _get(data, "meta", "run_ids") == ids_src)

    # Per-run accuracy figures, straight from the score files.
    pairs = [
        ("endpoint_coverage", "accuracy", "endpoint_coverage"),
        ("finding_accuracy", "accuracy", "finding_accuracy"),
    ]
    for group, *path in pairs:
        rows = {r["key"]: r for r in _get(data, "metrics", group, "rows") or []}
        for field in ("tp", "fn", "precision", "recall", "f1"):
            src = [_get(s, *path, field) for s in scores]
            got = (rows.get(field) or {}).get("values")
            check(f"{group}.{field} values match source",
                  got is not None and all(approx(a, b) for a, b in zip(src, got)),
                  f"source={src} data={got}")
        src_um = [_um(_get(s, *path)) for s in scores]
        got_um = (rows.get("unmatched") or {}).get("values")
        check(f"{group}.unmatched values match source (legacy key aware)",
              got_um is not None and all(approx(a, b) for a, b in zip(src_um, got_um)),
              f"source={src_um} data={got_um}")

    # Recompute mean/stdev/cv independently for finding F1.
    f1s = [_get(s, "accuracy", "finding_accuracy", "f1") for s in scores]
    f1s = [v for v in f1s if isinstance(v, (int, float))]
    if len(f1s) >= 2:
        row = next((r for r in _get(data, "metrics", "finding_accuracy", "rows") or []
                    if r["key"] == "f1"), {})
        exp_m, exp_s = _mean(f1s), _stdev(f1s)
        check("finding F1 mean recomputed", approx(row.get("mean"), exp_m),
              f"expected {exp_m:.6f} got {row.get('mean')}")
        check("finding F1 stdev recomputed", approx(row.get("stdev"), exp_s),
              f"expected {exp_s:.6f} got {row.get('stdev')}")
        check("finding F1 cv recomputed", approx(row.get("cv"), exp_s / abs(exp_m)),
              f"expected {exp_s/abs(exp_m):.6f} got {row.get('cv')}")

    # Recompute cost mean independently.
    costs = [_get(s, "cost", "full_run_usd") for s in scores]
    costs = [c for c in costs if isinstance(c, (int, float))]
    if costs:
        check("cost mean recomputed", approx(_get(data, "cost", "totals", "mean"), _mean(costs)),
              f"expected {_mean(costs):.6f} got {_get(data, 'cost', 'totals', 'mean')}")

    # Recompute the Jaccard matrix from scratch.
    sets = []
    for s in scores:
        tp = _get(s, "accuracy", "finding_accuracy", "tp_findings") or []
        sets.append({_key(f) for f in tp})
    exp_common = len(set.intersection(*sets)) if sets and all(sets) else 0
    got_common = _get(data, "reproducibility", "jaccard", "common_count")
    check("jaccard common_count recomputed", exp_common == got_common,
          f"expected {exp_common} got {got_common}")

    pair = []
    for i in range(n):
        for j in range(i + 1, n):
            u = len(sets[i] | sets[j])
            pair.append(len(sets[i] & sets[j]) / u if u else 0.0)
    if pair:
        check("jaccard mean recomputed",
              approx(_get(data, "reproducibility", "jaccard", "mean"), _mean(pair)),
              f"expected {_mean(pair):.6f} got {_get(data, 'reproducibility', 'jaccard', 'mean')}")

    # Cross-run finding catalogue size.
    catalogue = set()
    for s in scores:
        fa = _get(s, "accuracy", "finding_accuracy") or {}
        for f in (fa.get("tp_findings") or []):
            catalogue.add(_key(f))
        for f in _um_findings(fa):
            catalogue.add(_key(f))
    check("finding catalogue size recomputed",
          len(catalogue) == _get(data, "findings", "total_unique"),
          f"expected {len(catalogue)} got {_get(data, 'findings', 'total_unique')}")

    # Integrity of the bogus-cost-breakdown guard.
    raw_keys = set(_get(data, "cost", "raw_component_keys") or [])
    known = {r["component"] for r in _get(data, "components", "rows") or []}
    if raw_keys and not (raw_keys & known):
        check("bogus cost breakdown suppressed",
              _get(data, "cost", "breakdown_available") is False,
              f"cost by_component keys {sorted(raw_keys)} match no real component, "
              f"breakdown must be suppressed")

    # Gate statuses must be real verdicts, never log dumps.
    bad = []
    for r in _get(data, "components", "rows") or []:
        for st in r.get("status") or []:
            if st is not None and (len(str(st)) > 12 or "\n" in str(st)):
                bad.append(r["component"])
    check("no log dumps leaked into gate statuses", not bad, f"offenders: {sorted(set(bad))}")


# ─── layer 2: comparison_data -> rendered HTML ────────────────────────────────

def _fmt(v, kind):
    if v is None:
        return None
    if kind == "pct":
        return f"{v * 100:.1f}%"
    if kind == "ratio":
        return f"{v:.3f}"
    if kind == "usd":
        return f"${v:,.2f}"
    if kind == "min":
        return f"{v:,.1f}"
    if kind == "int":
        return f"{int(round(v)):,}"
    return None


def verify_html_layer(data, html):
    check("html is non-trivial", len(html) > 20000, f"{len(html):,} bytes")
    check("no section render errors embedded",
          "Section failed to render" not in html,
          "an error block is present in the output")

    # Every KPI mean must literally appear in the page.
    missing = []
    for k in data.get("kpis", []):
        s = _fmt(k.get("mean"), k.get("format"))
        if s and s not in html:
            missing.append(f"{k['label']}={s}")
    check("all KPI means appear in the HTML", not missing, f"missing: {missing}")

    # Section anchors.
    expected = ["summary", "metrics", "repeatability", "severity",
                "findings", "endpoints", "components", "cost", "verdict"]
    absent = [a for a in expected if f'id="{a}"' not in html]
    check("all sections rendered", not absent, f"missing anchors: {absent}")

    # Nav links resolve to real anchors.
    nav = re.findall(r'<a href="#([a-z_]+)"', html)
    dangling = [a for a in set(nav) if f'id="{a}"' not in html]
    check("no dangling nav links", not dangling, f"dangling: {dangling}")

    # Row-count sanity: the findings table must have one status cell per finding per run.
    n = _get(data, "meta", "run_count") or 0
    total = _get(data, "findings", "total_unique") or 0
    if total and n:
        got = len(re.findall(r'class="st st-(?:tp|unmatched|absent)"', html))
        check("findings status cells match catalogue x runs", got == total * n,
              f"expected {total * n} got {got}")

    # Endpoint marks.
    gt_rows = len(_get(data, "endpoints", "gt_rows") or [])
    um_rows = len(_get(data, "endpoints", "unmatched_rows") or [])
    if gt_rows and n:
        got = len(re.findall(r'class="mark (?:ok|no)"', html))
        exp = (gt_rows + um_rows) * n
        check("endpoint marks match rows x runs", got >= exp,
              f"expected >= {exp} got {got}")

    # Leakage of Python sentinels into user-visible text.
    for token in (">None<", ">nan<", ">NaN<", "&gt;None&lt;"):
        check(f"no {token.strip('><')} leaked into rendered text", token not in html)

    # The unmatched terminology must not be described as false positives.
    low = html.lower()
    bad_phrases = [p for p in ("false positive endpoints", "false positive findings",
                               "✗ false positive") if p in low]
    check("unmatched not mislabelled as false positives", not bad_phrases,
          f"found: {bad_phrases}")

    # Suppressed cost breakdown must not render bogus components as real.
    if _get(data, "cost", "breakdown_available") is False:
        for k in _get(data, "cost", "raw_component_keys") or []:
            if re.search(rf"<td[^>]*>\s*{re.escape(k.title())}\s*</td>", html):
                check(f"bogus cost component {k!r} not rendered as a row", False,
                      "suppressed breakdown leaked into a table")
        else:
            check("suppressed cost breakdown not rendered as components", True)


def main():
    ap = argparse.ArgumentParser(description="Cross-verify a comparison report against source")
    ap.add_argument("--scores", nargs="+", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--html", default=None)
    args = ap.parse_args()

    scores = []
    for p in args.scores:
        with open(p, encoding="utf-8") as f:
            scores.append(json.load(f))
    with open(args.data, encoding="utf-8") as f:
        data = json.load(f)

    print("=" * 78)
    print("LAYER 0 — source score files are internally consistent")
    print("=" * 78)
    verify_source_integrity(scores, args.scores)

    print()
    print("=" * 78)
    print("LAYER 1 — source score files -> comparison_data.json")
    print("=" * 78)
    verify_data_layer(scores, data)

    if args.html and os.path.exists(args.html):
        print()
        print("=" * 78)
        print("LAYER 2 — comparison_data.json -> rendered HTML")
        print("=" * 78)
        with open(args.html, encoding="utf-8") as f:
            verify_html_layer(data, f.read())
    elif args.html:
        warn("html not found", args.html)

    print()
    fails = [r for r in _results if r[0] == FAIL]
    warns = [r for r in _results if r[0] == WARN]
    for status, name, detail in _results:
        mark = {PASS: "  ok  ", FAIL: " FAIL ", WARN: " warn "}[status]
        line = f"[{mark}] {name}"
        if detail and status != PASS:
            line += f"\n           {detail}"
        print(line)

    print()
    print("-" * 78)
    print(f"{len(_results) - len(fails) - len(warns)} passed, {len(fails)} failed, {len(warns)} warnings")
    if fails:
        print("VERIFICATION FAILED")
        sys.exit(1)
    print("VERIFICATION PASSED — every headline figure traces to a source field")


if __name__ == "__main__":
    main()
