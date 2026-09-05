#!/usr/bin/env python3
"""extract_component_results.py — extract per-component results from an AEGIS run.

Walks the run directory, reads every component's result files, and produces
a structured dict with metrics, counts, and key data for each component.

Supports two run layouts:
  - Direct:   <run-dir>/<component>/...
  - Artifact: <run-dir>/shared/_artifacts/<component>/...

Usage:
    extract_component_results.py --run-dir <path> [--json]
"""
from __future__ import annotations

import argparse
import glob as globmod
import json
import os
import re
import sys
from collections import Counter, defaultdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_json(path: str) -> dict | list | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _read_jsonl(path: str) -> list[dict]:
    out = []
    if not os.path.isfile(path):
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


def _read_text(path: str, max_bytes: int = 64_000) -> str | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except OSError:
        return None


def _file_info(path: str) -> dict | None:
    if not os.path.isfile(path):
        return None
    try:
        sz = os.path.getsize(path)
        return {"path": os.path.basename(path), "size_bytes": sz}
    except OSError:
        return None


def _count_lines(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    count = 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    count += 1
    except OSError:
        pass
    return count


def _glob_sorted(pattern: str) -> list[str]:
    return sorted(globmod.glob(pattern))


def _glob_latest(pattern: str) -> str | None:
    hits = _glob_sorted(pattern)
    return hits[-1] if hits else None


def _count_files(directory: str, ext: str = "") -> int:
    if not os.path.isdir(directory):
        return 0
    count = 0
    for f in os.listdir(directory):
        if ext and not f.endswith(ext):
            continue
        if os.path.isfile(os.path.join(directory, f)):
            count += 1
    return count


def _severity_dist(items: list[dict], key: str = "severity") -> dict:
    dist: dict[str, int] = Counter()
    for item in items:
        sev = (item.get(key) or "unknown").lower()
        dist[sev] += 1
    return dict(dist)


def _discover_workdir_target(comp_dir: str) -> str | None:
    wd = os.path.join(comp_dir, "_workdir")
    if not os.path.isdir(wd):
        return None
    for name in os.listdir(wd):
        full = os.path.join(wd, name)
        if os.path.isdir(full) and not name.startswith("."):
            return full
    return None


# ---------------------------------------------------------------------------
# Layout detection
# ---------------------------------------------------------------------------

COMPONENTS = [
    "crawler",
    "attack_surface_discovery",
    "planner",
    "vulnerability_discovery",
    "vulnerability_exploitation",
    "hacker",
    "vulnerability_chaining",
    "reporting",
]


def _detect_layout(run_dir: str) -> dict[str, str]:
    """Return {component_name: absolute_path} for every present component."""
    found = {}

    # Layout 1: direct — <run-dir>/<component>/
    for comp in COMPONENTS:
        d = os.path.join(run_dir, comp)
        if os.path.isdir(d):
            found[comp] = d

    if found:
        return found

    # Layout 2: shared/_artifacts/<component>/
    artifacts = os.path.join(run_dir, "shared", "_artifacts")
    if os.path.isdir(artifacts):
        for comp in COMPONENTS:
            d = os.path.join(artifacts, comp)
            if os.path.isdir(d):
                found[comp] = d

    # Layout 3: look inside run-* subdirs for components
    if not found:
        for entry in os.listdir(run_dir):
            full = os.path.join(run_dir, entry)
            if os.path.isdir(full) and entry.startswith("run-"):
                for comp in COMPONENTS:
                    d = os.path.join(full, comp)
                    if os.path.isdir(d):
                        found[comp] = d
                if found:
                    break

    return found


def _find_gates_dir(run_dir: str) -> str | None:
    d = os.path.join(run_dir, "gates")
    if os.path.isdir(d):
        return d
    for entry in os.listdir(run_dir):
        full = os.path.join(run_dir, entry)
        if os.path.isdir(full) and entry.startswith("run-"):
            gd = os.path.join(full, "gates")
            if os.path.isdir(gd):
                return gd
    artifacts = os.path.join(run_dir, "shared", "_artifacts")
    if os.path.isdir(artifacts):
        for entry in os.listdir(artifacts):
            full = os.path.join(artifacts, entry)
            if os.path.isdir(full) and entry.startswith("run-"):
                gd = os.path.join(full, "gates")
                if os.path.isdir(gd):
                    return gd
    return None


def _find_bench_dir(run_dir: str) -> str | None:
    d = os.path.join(run_dir, "bench")
    if os.path.isdir(d):
        return d
    for entry in os.listdir(run_dir):
        full = os.path.join(run_dir, entry)
        if os.path.isdir(full) and entry.startswith("run-"):
            bd = os.path.join(full, "bench")
            if os.path.isdir(bd):
                return bd
    return None


# ---------------------------------------------------------------------------
# Per-component extractors
# ---------------------------------------------------------------------------

def extract_crawler(comp_dir: str) -> dict:
    result: dict = {}

    # --- _workdir reports ---
    target_dir = _discover_workdir_target(comp_dir)
    if target_dir:
        reports_dir = os.path.join(target_dir, "reports")

        # endpoints.inventory.json
        inv = _read_json(os.path.join(reports_dir, "endpoints.inventory.json"))
        if inv and isinstance(inv, dict):
            eps = inv.get("endpoints", [])
            result["endpoints_inventory"] = {
                "count": len(eps),
                "methods": dict(Counter(m for e in eps for m in (e.get("methods") or []))),
                "auth_required": sum(1 for e in eps if e.get("auth_required")),
                "auth_not_required": sum(1 for e in eps if not e.get("auth_required")),
            }

        # role_matrix.json
        rm = _read_json(os.path.join(reports_dir, "role_matrix.json"))
        if rm and isinstance(rm, dict):
            roles = rm.get("roles", [])
            matrix = rm.get("matrix", [])
            per_role: dict[str, int] = Counter()
            for entry in matrix:
                for r in entry.get("reachable_by", []):
                    per_role[r] += 1
            result["role_matrix"] = {
                "roles": roles,
                "total_entries": len(matrix),
                "endpoints_per_role": dict(per_role),
            }

        # frontier.json
        frontier = _read_json(os.path.join(reports_dir, "frontier.json"))
        if frontier and isinstance(frontier, dict):
            visited = frontier.get("visited", [])
            todo = frontier.get("todo", [])
            result["frontier"] = {
                "visited_count": len(visited),
                "todo_count": len(todo) if isinstance(todo, list) else 0,
            }

        # inferred_flows.json
        flows = _read_json(os.path.join(reports_dir, "inferred_flows.json"))
        if flows and isinstance(flows, dict):
            flow_list = flows.get("inferred_flows", [])
            result["inferred_flows"] = {
                "count": len(flow_list),
                "names": [f.get("name", "") for f in flow_list],
            }

        # mutation_gate.json
        mg = _read_json(os.path.join(reports_dir, "mutation_gate.json"))
        if mg and isinstance(mg, dict):
            result["mutation_gate"] = mg

        # uncrawled_known.json
        uc = _read_json(os.path.join(reports_dir, "uncrawled_known.json"))
        if uc is not None:
            items = uc if isinstance(uc, list) else uc.get("endpoints", []) if isinstance(uc, dict) else []
            result["uncrawled_known_count"] = len(items)

        # unsubmitted_forms.json
        uf = _read_json(os.path.join(reports_dir, "unsubmitted_forms.json"))
        if uf is not None:
            items = uf if isinstance(uf, list) else uf.get("forms", []) if isinstance(uf, dict) else []
            result["unsubmitted_forms_count"] = len(items)

        # SUMMARY.md
        summary_path = os.path.join(target_dir, "SUMMARY.md")
        summary_text = _read_text(summary_path)
        if summary_text:
            result["summary_md"] = summary_text

        # screenshots
        ss_dir = os.path.join(target_dir, "screenshots")
        if os.path.isdir(ss_dir):
            per_role_ss: dict[str, int] = {}
            for role_name in os.listdir(ss_dir):
                role_path = os.path.join(ss_dir, role_name)
                if os.path.isdir(role_path):
                    per_role_ss[role_name] = _count_files(role_path, ".png")
            result["screenshots"] = {
                "total": sum(per_role_ss.values()),
                "per_role": per_role_ss,
            }

        # capture.har
        har = _file_info(os.path.join(target_dir, "capture.har"))
        if har:
            result["capture_har"] = har

        # capture.openapi.yaml
        openapi_path = os.path.join(target_dir, "capture.openapi.yaml")
        oa = _file_info(openapi_path)
        if oa:
            result["capture_openapi"] = oa

        # capture.mitm
        mitm = _file_info(os.path.join(target_dir, "capture.mitm"))
        if mitm:
            result["capture_mitm"] = mitm

        # per-role baseline MDs
        baselines = _glob_sorted(os.path.join(reports_dir, "*-baseline.md"))
        if baselines:
            result["baseline_reports"] = [os.path.basename(b) for b in baselines]

        # crawl_mode.json
        cm = _read_json(os.path.join(reports_dir, "crawl_mode.json"))
        if cm:
            result["crawl_mode"] = cm

        # session_context.proxy.json
        sc = _read_json(os.path.join(reports_dir, "session_context.proxy.json"))
        if sc and isinstance(sc, dict):
            result["proxy_roles"] = list(sc.get("credentials", {}).keys()) if "credentials" in sc else []

        # reachability_justifications.json
        rj = _read_json(os.path.join(reports_dir, "reachability_justifications.json"))
        if rj:
            items = rj if isinstance(rj, list) else rj.get("justifications", []) if isinstance(rj, dict) else []
            result["reachability_justifications_count"] = len(items)

    # --- Timestamped pipeline artifacts ---
    crawl_surface = _glob_latest(os.path.join(comp_dir, "*-crawl_surface.json"))
    if crawl_surface:
        cs = _read_json(crawl_surface)
        if cs and isinstance(cs, dict):
            eps = cs.get("endpoints", [])
            result["crawl_surface_endpoint_count"] = len(eps)

    session_ctx = _glob_latest(os.path.join(comp_dir, "*-session_context.json"))
    if session_ctx:
        sc = _read_json(session_ctx)
        if sc and isinstance(sc, dict):
            creds = sc.get("credentials", {})
            result["session_roles"] = list(creds.keys()) if isinstance(creds, dict) else []

    # Probe artifacts & recall snapshots
    probes = _glob_sorted(os.path.join(comp_dir, "*-probe_artifacts.json"))
    result["probe_snapshot_count"] = len(probes)
    recalls = _glob_sorted(os.path.join(comp_dir, "*-recall.jsonl"))
    result["recall_snapshot_count"] = len(recalls)

    return result


def extract_attack_surface_discovery(comp_dir: str) -> dict:
    result: dict = {}

    # surface.json (last = final)
    surface_path = _glob_latest(os.path.join(comp_dir, "*-surface.json"))
    if surface_path:
        sf = _read_json(surface_path)
        if sf and isinstance(sf, dict):
            result["surface"] = {
                "hosts_count": len(sf.get("discovered_hosts", [])),
                "tech_fingerprints_count": len(sf.get("tech_fingerprints", [])),
            }
    result["surface_iterations"] = len(_glob_sorted(os.path.join(comp_dir, "*-surface.json")))

    # subdomains.jsonl
    sd_path = _glob_latest(os.path.join(comp_dir, "*-subdomains.jsonl"))
    if sd_path:
        result["subdomains_count"] = _count_lines(sd_path)

    # hosts.jsonl (last)
    hosts_path = _glob_latest(os.path.join(comp_dir, "*-hosts.jsonl"))
    if hosts_path:
        result["hosts_count"] = _count_lines(hosts_path)
    result["hosts_iterations"] = len(_glob_sorted(os.path.join(comp_dir, "*-hosts.jsonl")))

    # origins.jsonl
    origins_path = _glob_latest(os.path.join(comp_dir, "*-origins.jsonl"))
    if origins_path:
        result["origins_count"] = _count_lines(origins_path)

    # services.jsonl
    svc_path = _glob_latest(os.path.join(comp_dir, "*-services.jsonl"))
    if svc_path:
        svcs = _read_jsonl(svc_path)
        ports = sorted(set(s.get("port", 0) for s in svcs if s.get("port")))
        result["services"] = {"count": len(svcs), "ports": ports}

    # portscan.nmap.xml
    nmap_path = _glob_latest(os.path.join(comp_dir, "*-portscan.nmap.xml"))
    if nmap_path:
        result["nmap_scan"] = _file_info(nmap_path)

    # techstack.jsonl
    tech_path = _glob_latest(os.path.join(comp_dir, "*-techstack.jsonl"))
    if tech_path:
        techs = _read_jsonl(tech_path)
        result["techstack"] = {
            "count": len(techs),
            "products": [t.get("product", "") for t in techs],
            "categories": list(set(c for t in techs for c in (t.get("categories") or []))),
        }

    # paths.jsonl
    paths_path = _glob_latest(os.path.join(comp_dir, "*-paths.jsonl"))
    if paths_path:
        result["paths_count"] = _count_lines(paths_path)

    # cves.jsonl
    cves_path = _glob_latest(os.path.join(comp_dir, "*-cves.jsonl"))
    if cves_path:
        cves = _read_jsonl(cves_path)
        result["cves"] = {
            "count": len(cves),
            "ids": list(set(c.get("cve_id", "") for c in cves if c.get("cve_id"))),
            "severity_distribution": _severity_dist(cves),
            "products": list(set(c.get("product", "") for c in cves if c.get("product"))),
        }

    # secrets.jsonl
    secrets_path = _glob_latest(os.path.join(comp_dir, "*-secrets.jsonl"))
    if secrets_path:
        secrets = _read_jsonl(secrets_path)
        result["secrets"] = {
            "count": len(secrets),
            "types": list(set(s.get("type", s.get("kind", "")) for s in secrets if s.get("type") or s.get("kind"))),
        }

    # js_findings.jsonl (last)
    js_path = _glob_latest(os.path.join(comp_dir, "*-js_findings.jsonl"))
    if js_path:
        js = _read_jsonl(js_path)
        result["js_findings"] = {
            "count": len(js),
            "severity_distribution": _severity_dist(js),
        }

    # cloud_assets.jsonl
    cloud_path = _glob_latest(os.path.join(comp_dir, "*-cloud_assets.jsonl"))
    if cloud_path:
        result["cloud_assets_count"] = _count_lines(cloud_path)

    # takeovers.jsonl
    takeover_path = _glob_latest(os.path.join(comp_dir, "*-takeovers.jsonl"))
    if takeover_path:
        result["takeovers_count"] = _count_lines(takeover_path)

    # findings.jsonl
    findings_path = _glob_latest(os.path.join(comp_dir, "*-findings.jsonl"))
    if findings_path:
        findings = _read_jsonl(findings_path)
        result["findings"] = {
            "count": len(findings),
            "severity_distribution": _severity_dist(findings),
        }

    # engagement_context.json
    ctx_path = _glob_latest(os.path.join(comp_dir, "*-engagement_context.json"))
    if ctx_path:
        ctx = _read_json(ctx_path)
        if ctx and isinstance(ctx, dict):
            result["engagement_context"] = {
                k: ctx[k] for k in ("engagement_id", "target", "mode", "customer")
                if k in ctx
            }

    return result


def extract_planner(comp_dir: str) -> dict:
    result: dict = {}

    # plan.json (last)
    plan_path = _glob_latest(os.path.join(comp_dir, "*-plan.json"))
    if plan_path:
        plan = _read_json(plan_path)
        if plan and isinstance(plan, dict):
            phases = plan.get("phases", [])
            all_tasks = []
            for p in phases:
                all_tasks.extend(p.get("tasks", []))
            owasp_cats = list(set(t.get("owasp", "") for t in all_tasks if t.get("owasp")))
            priority_dist = dict(Counter(t.get("priority", "unknown") for t in all_tasks))
            result["plan"] = {
                "phase_count": len(phases),
                "task_count": len(all_tasks),
                "owasp_categories": sorted(owasp_cats),
                "priority_distribution": priority_dist,
            }

    # plan.md
    plan_md = _glob_latest(os.path.join(comp_dir, "*-plan.md"))
    if plan_md:
        result["plan_md"] = _file_info(plan_md)

    # test_cases.jsonl
    tc_path = _glob_latest(os.path.join(comp_dir, "*-test_cases.jsonl"))
    if tc_path:
        tcs = _read_jsonl(tc_path)
        owasp_dist = dict(Counter(tc.get("owasp", "unknown") for tc in tcs))
        test_type_dist = dict(Counter(tc.get("test_type", "unknown") for tc in tcs))
        result["test_cases"] = {
            "count": len(tcs),
            "by_owasp": owasp_dist,
            "by_test_type": test_type_dist,
        }

    # coverage_ledger.json (last)
    cl_path = _glob_latest(os.path.join(comp_dir, "*-coverage_ledger.json"))
    if cl_path:
        cl = _read_json(cl_path)
        if cl and isinstance(cl, dict):
            summary = cl.get("summary", {})
            result["coverage_ledger"] = {
                "total_endpoints": summary.get("total_endpoints"),
                "total_cells": summary.get("total_cells"),
                "covered": summary.get("covered"),
                "justified_skip": summary.get("justified_skip"),
                "uncovered": summary.get("uncovered"),
                "roles": cl.get("roles", []),
            }

    result["coverage_ledger_iterations"] = len(_glob_sorted(os.path.join(comp_dir, "*-coverage_ledger.json")))

    # _workdir files
    wd = os.path.join(comp_dir, "_workdir")
    if os.path.isdir(wd):
        ep_catalog = _read_json(os.path.join(wd, "endpoint-catalog.json"))
        if ep_catalog:
            if isinstance(ep_catalog, list):
                result["endpoint_catalog_count"] = len(ep_catalog)
            elif isinstance(ep_catalog, dict):
                result["endpoint_catalog_count"] = len(ep_catalog.get("endpoints", []))
        if os.path.isfile(os.path.join(wd, "surface-brief.md")):
            result["surface_brief_exists"] = True

    return result


def extract_vulnerability_discovery(comp_dir: str) -> dict:
    result: dict = {}

    # ALL findings.jsonl batches merged
    all_findings: list[dict] = []
    for fpath in _glob_sorted(os.path.join(comp_dir, "*-findings.jsonl")):
        all_findings.extend(_read_jsonl(fpath))

    if all_findings:
        finding_ids = set()
        cwes: set[str] = set()
        owasp_cats: set[str] = set()
        targets: set[str] = set()
        verification_dist: dict[str, int] = Counter()

        for f in all_findings:
            fid = f.get("finding_id") or f.get("task_id")
            if fid:
                finding_ids.add(fid)
            cwe = f.get("cwe", "")
            if cwe:
                cwes.add(cwe)
            owasp = f.get("owasp", "")
            if owasp:
                owasp_cats.add(owasp.split(" ")[0] if " " in owasp else owasp)
            target = f.get("target", "")
            if target:
                targets.add(target)
            vs = f.get("verification_status", "unknown")
            verification_dist[vs] += 1

        result["findings"] = {
            "total_entries": len(all_findings),
            "unique_finding_ids": len(finding_ids),
            "severity_distribution": _severity_dist(all_findings),
            "owasp_categories": sorted(owasp_cats),
            "cwes": sorted(cwes),
            "unique_targets": len(targets),
            "verification_status": dict(verification_dist),
            "has_evidence": sum(1 for f in all_findings if f.get("evidence")),
            "has_reproduction": sum(1 for f in all_findings if f.get("reproduction")),
            "has_remediation": sum(1 for f in all_findings if f.get("remediation")),
        }

    result["finding_batches"] = len(_glob_sorted(os.path.join(comp_dir, "*-findings.jsonl")))

    return result


def extract_vulnerability_exploitation(comp_dir: str) -> dict:
    result: dict = {}

    # exploits.jsonl summary
    exploits_path = _glob_latest(os.path.join(comp_dir, "*-exploits.jsonl"))
    if exploits_path:
        exploits = _read_jsonl(exploits_path)
        verification_dist = dict(Counter(e.get("verification_status", "unknown") for e in exploits))
        result["exploits_summary"] = {
            "count": len(exploits),
            "verification_status": verification_dist,
            "finding_ids": [e.get("finding_id", "") for e in exploits],
        }

    # Individual exploit.json files
    exploit_jsons = _glob_sorted(os.path.join(comp_dir, "*.exploit.json"))
    if exploit_jsons:
        exploits_detail = []
        for ep in exploit_jsons:
            ed = _read_json(ep)
            if ed and isinstance(ed, dict):
                exploits_detail.append({
                    "finding_id": ed.get("finding_id", ""),
                    "kind": ed.get("kind", ""),
                    "destructive": ed.get("destructive", False),
                    "verification_status": ed.get("verification_status", ""),
                    "steps_count": len(ed.get("steps", [])),
                    "has_script": bool(ed.get("script_path")),
                })
        result["exploit_details"] = exploits_detail
        result["exploit_json_count"] = len(exploit_jsons)
        result["verified_poc_count"] = sum(1 for e in exploits_detail if e.get("verification_status") == "verified-poc")
        result["verified_exploit_count"] = sum(1 for e in exploits_detail if e.get("verification_status") == "verified-exploit")
        result["destructive_count"] = sum(1 for e in exploits_detail if e.get("destructive"))

    # exploit.md handoff docs
    exploit_mds = _glob_sorted(os.path.join(comp_dir, "*.exploit.md"))
    result["exploit_md_count"] = len(exploit_mds)

    # updates.jsonl
    updates_path = _glob_latest(os.path.join(comp_dir, "*-updates.jsonl"))
    if updates_path:
        result["updates_count"] = _count_lines(updates_path)

    # PoC scripts
    scripts_dir = os.path.join(comp_dir, "scripts")
    if os.path.isdir(scripts_dir):
        result["poc_script_count"] = _count_files(scripts_dir, ".sh")

    return result


def extract_hacker(comp_dir: str) -> dict:
    result: dict = {}

    hf_path = _glob_latest(os.path.join(comp_dir, "*-hacker_findings.jsonl"))
    if hf_path:
        findings = _read_jsonl(hf_path)
        cwes: set[str] = set()
        owasp_cats: set[str] = set()
        verification_dist: dict[str, int] = Counter()

        for f in findings:
            cwe = f.get("cwe", "")
            if cwe:
                cwes.add(cwe)
            owasp = f.get("owasp", "")
            if owasp:
                owasp_cats.add(owasp.split(" ")[0] if " " in owasp else owasp)
            vs = f.get("verification_status", "unknown")
            verification_dist[vs] += 1

        result["findings"] = {
            "count": len(findings),
            "severity_distribution": _severity_dist(findings),
            "cwes": sorted(cwes),
            "owasp_categories": sorted(owasp_cats),
            "verification_status": dict(verification_dist),
            "has_chain_opportunity": sum(1 for f in findings if f.get("chain_opportunity")),
        }

    # screenshots
    ss_dir = os.path.join(comp_dir, "screenshots")
    if os.path.isdir(ss_dir):
        total = 0
        for root, _dirs, files in os.walk(ss_dir):
            total += sum(1 for f in files if f.lower().endswith((".png", ".jpg", ".jpeg")))
        result["screenshot_count"] = total

    return result


def extract_vulnerability_chaining(comp_dir: str) -> dict:
    result: dict = {}

    # attack_chain.json
    ac_path = _glob_latest(os.path.join(comp_dir, "*-attack_chain.json"))
    if ac_path:
        ac = _read_json(ac_path)
        if ac and isinstance(ac, dict):
            objectives = ac.get("objectives", [])
            nodes = ac.get("nodes", [])
            result["attack_chain"] = {
                "objective_count": len(objectives),
                "objectives": [
                    {"id": o.get("id", ""), "kind": o.get("kind", ""), "label": o.get("label", "")}
                    for o in objectives
                ],
                "node_count": len(nodes),
                "node_kinds": dict(Counter(n.get("kind", "unknown") for n in nodes)),
            }

    # attack_chain.mermaid.md
    mermaid_path = _glob_latest(os.path.join(comp_dir, "*-attack_chain.mermaid.md"))
    if mermaid_path:
        result["mermaid_diagram"] = _file_info(mermaid_path)

    # chain_graph_analysis.json
    cga_path = _glob_latest(os.path.join(comp_dir, "*-chain_graph_analysis.json"))
    if cga_path:
        cga = _read_json(cga_path)
        if cga and isinstance(cga, dict):
            summary = cga.get("summary", cga)
            result["graph_analysis"] = {
                "node_count": summary.get("node_count"),
                "edge_count": summary.get("edge_count"),
                "objective_count": summary.get("objective_count"),
                "entry_count": summary.get("entry_count"),
                "choke_point_count": summary.get("choke_point_count"),
                "cluster_count": summary.get("cluster_count"),
                "dead_end_count": summary.get("dead_end_count"),
                "most_critical_node": summary.get("most_critical_node"),
            }

    # scored-chains.jsonl
    sc_path = _glob_latest(os.path.join(comp_dir, "*-scored-chains.jsonl"))
    if sc_path:
        chains = _read_jsonl(sc_path)
        result["scored_chains"] = {
            "count": len(chains),
            "top_chains": [
                {
                    "rank": c.get("rank"),
                    "impact": c.get("impact"),
                    "exploitability": c.get("exploitability"),
                    "weight": c.get("weight"),
                    "objective_id": c.get("objective_id", ""),
                    "speculative": c.get("speculative", False),
                    "origin": c.get("origin", ""),
                    "narrative": (c.get("narrative", "")[:200] + "...") if len(c.get("narrative", "")) > 200 else c.get("narrative", ""),
                }
                for c in sorted(chains, key=lambda x: x.get("rank", 999))[:5]
            ],
        }

    # objectives.jsonl
    obj_path = _glob_latest(os.path.join(comp_dir, "*-objectives.jsonl"))
    if obj_path:
        objs = _read_jsonl(obj_path)
        result["objectives"] = {
            "count": len(objs),
            "kinds": dict(Counter(o.get("kind", "unknown") for o in objs)),
        }

    # candidates.jsonl
    cand_path = _glob_latest(os.path.join(comp_dir, "*-candidates.jsonl"))
    if cand_path:
        result["candidates_count"] = _count_lines(cand_path)

    # pattern-chains.jsonl
    pc_path = _glob_latest(os.path.join(comp_dir, "*-pattern-chains.jsonl"))
    if pc_path:
        result["pattern_chains_count"] = _count_lines(pc_path)

    # synthesized-nodes.jsonl
    sn_path = _glob_latest(os.path.join(comp_dir, "*-synthesized-nodes.jsonl"))
    if sn_path:
        result["synthesized_nodes_count"] = _count_lines(sn_path)

    # strategist-response.json
    sr_path = _glob_latest(os.path.join(comp_dir, "*-strategist-response.json"))
    if sr_path:
        result["strategist_response_exists"] = True

    # strategist-chains.jsonl
    stc_path = _glob_latest(os.path.join(comp_dir, "*-strategist-chains.jsonl"))
    if stc_path:
        result["strategist_chains_count"] = _count_lines(stc_path)

    # workflow-nodes.jsonl
    wn_path = _glob_latest(os.path.join(comp_dir, "*-workflow-nodes.jsonl"))
    if wn_path:
        result["workflow_nodes_count"] = _count_lines(wn_path)

    # findings.jsonl (chaining phase findings)
    f_path = _glob_latest(os.path.join(comp_dir, "*-findings.jsonl"))
    if f_path and "scored-chains" not in f_path and "pattern-chains" not in f_path:
        result["chaining_findings_count"] = _count_lines(f_path)

    return result


def extract_reporting(comp_dir: str) -> dict:
    result: dict = {}

    # scored-findings.jsonl
    sf_path = os.path.join(comp_dir, "scored-findings.jsonl")
    if not os.path.isfile(sf_path):
        sf_path_glob = _glob_latest(os.path.join(comp_dir, "*-scored-findings.jsonl"))
        if sf_path_glob:
            sf_path = sf_path_glob
    if os.path.isfile(sf_path):
        findings = _read_jsonl(sf_path)
        merged_count = sum(1 for f in findings if f.get("_merged_ids"))
        total_merged_ids = sum(len(f.get("_merged_ids", [])) for f in findings)
        cvss_scores = [f.get("cvss_score") for f in findings if f.get("cvss_score") is not None]
        verification_dist = dict(Counter(f.get("verification_status", "unknown") for f in findings))
        severity_reconciled = sum(1 for f in findings if f.get("_severity_reconciled"))

        result["scored_findings"] = {
            "count": len(findings),
            "severity_distribution": _severity_dist(findings),
            "verification_status": verification_dist,
            "merged_finding_count": merged_count,
            "total_merged_ids": total_merged_ids,
            "cvss_scores": {
                "count": len(cvss_scores),
                "min": round(min(cvss_scores), 1) if cvss_scores else None,
                "max": round(max(cvss_scores), 1) if cvss_scores else None,
                "mean": round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else None,
            },
            "severity_reconciled_count": severity_reconciled,
            "has_exploit": sum(1 for f in findings if f.get("_exploit")),
            "has_chain_ranks": sum(1 for f in findings if f.get("_chain_ranks")),
        }

    # normalized-findings.jsonl
    nf_path = os.path.join(comp_dir, "normalized-findings.jsonl")
    if not os.path.isfile(nf_path):
        nf_path = _glob_latest(os.path.join(comp_dir, "*-normalized-findings.jsonl")) or nf_path
    if os.path.isfile(nf_path):
        result["normalized_findings_count"] = _count_lines(nf_path)

    # finding_groups.jsonl
    fg_path = os.path.join(comp_dir, "finding_groups.jsonl")
    if not os.path.isfile(fg_path):
        fg_path = _glob_latest(os.path.join(comp_dir, "*-finding_groups.jsonl")) or fg_path
    if os.path.isfile(fg_path):
        groups = _read_jsonl(fg_path)
        result["finding_groups"] = {
            "count": len(groups),
            "names": [g.get("group_name", g.get("name", "")) for g in groups][:20],
        }

    # findings/*.md advisories
    findings_dir = os.path.join(comp_dir, "findings")
    if os.path.isdir(findings_dir):
        result["advisory_count"] = _count_files(findings_dir, ".md")

    # Deliverable files
    deliverables = {}
    for name, path in [
        ("report_md", os.path.join(comp_dir, "report.md")),
        ("report_exec_md", os.path.join(comp_dir, "report.exec.md")),
        ("report_html", os.path.join(comp_dir, "exports", "report.html")),
        ("report_exec_html", os.path.join(comp_dir, "exports", "report.exec.html")),
        ("report_pdf", os.path.join(comp_dir, "exports", "report.pdf")),
        ("report_docx", os.path.join(comp_dir, "exports", "report.docx")),
        ("advisory_html", os.path.join(comp_dir, "advisories", "advisory-report.html")),
        ("findings_csv", os.path.join(comp_dir, "findings.csv")),
        ("sarif_bundle", os.path.join(comp_dir, "sarif-bundle.sarif")),
        ("compliance_section", os.path.join(comp_dir, "compliance-section.md")),
    ]:
        info = _file_info(path)
        if info:
            deliverables[name] = info
    if deliverables:
        result["deliverables"] = deliverables

    # jira.json
    jira = _read_json(os.path.join(comp_dir, "jira.json"))
    if jira:
        if isinstance(jira, dict):
            result["jira_issue_count"] = jira.get("issue_count", len(jira.get("issues", [])))
        elif isinstance(jira, list):
            result["jira_issue_count"] = len(jira)

    # defectdojo.json
    dd = _read_json(os.path.join(comp_dir, "defectdojo.json"))
    if dd:
        if isinstance(dd, dict):
            result["defectdojo_finding_count"] = dd.get("finding_count", len(dd.get("findings", [])))
        elif isinstance(dd, list):
            result["defectdojo_finding_count"] = len(dd)

    # proof-captures.jsonl
    pc_path = os.path.join(comp_dir, "proof-captures.jsonl")
    if os.path.isfile(pc_path):
        result["proof_captures_count"] = _count_lines(pc_path)

    # remediations.jsonl
    rem_path = os.path.join(comp_dir, "remediations.jsonl")
    if os.path.isfile(rem_path):
        result["remediations_count"] = _count_lines(rem_path)

    # severity-overrides.jsonl
    so_path = os.path.join(comp_dir, "severity-overrides.jsonl")
    if not os.path.isfile(so_path):
        so_path = _glob_latest(os.path.join(comp_dir, "*-severity-overrides.jsonl")) or so_path
    if os.path.isfile(so_path):
        result["severity_overrides_count"] = _count_lines(so_path)

    # screenshots
    ss_index = _read_json(os.path.join(comp_dir, "screenshots", "index.json"))
    if ss_index:
        total_ss = sum(len(v.get("screenshots", [])) for v in ss_index.values()) if isinstance(ss_index, dict) else 0
        result["screenshot_count"] = total_ss
    else:
        ss_dir = os.path.join(comp_dir, "screenshots")
        if os.path.isdir(ss_dir):
            total = 0
            for root, _dirs, files in os.walk(ss_dir):
                total += sum(1 for f in files if f.lower().endswith((".png", ".jpg", ".jpeg")))
            if total:
                result["screenshot_count"] = total

    # reporting-manifest.json
    rm = _read_json(os.path.join(comp_dir, "reporting-manifest.json"))
    if rm and isinstance(rm, dict):
        result["manifest"] = {
            "finding_count": rm.get("finding_count"),
            "severity_distribution": rm.get("severity_distribution"),
            "phases": rm.get("phases", {}),
            "engagement_mode": rm.get("engagement_mode"),
        }

    # render-manifest.json
    rendm = _read_json(os.path.join(comp_dir, "render-manifest.json"))
    if rendm and isinstance(rendm, dict):
        exports = rendm.get("exports", {})
        result["render_exports"] = {
            name: {"status": info.get("status", ""), "size_bytes": info.get("size_bytes")}
            for name, info in exports.items()
            if isinstance(info, dict)
        }

    return result


# ---------------------------------------------------------------------------
# Gates & Bench
# ---------------------------------------------------------------------------

def extract_gates(gates_dir: str) -> dict:
    result: dict = {}
    if not os.path.isdir(gates_dir):
        return result

    for fname in sorted(os.listdir(gates_dir)):
        fpath = os.path.join(gates_dir, fname)
        if not os.path.isfile(fpath):
            continue
        if fname.startswith("."):
            continue

        if fname.endswith(".PASS"):
            comp = fname[:-5]
            result[comp] = "PASS"
        elif fname.endswith(".FAIL"):
            comp = fname[:-5]
            result[comp] = "FAIL"
        elif fname.endswith(".progress"):
            comp = fname.replace(".progress", "")
            if comp not in result:
                progress_data = _read_json(fpath) or _read_text(fpath, 4096)
                if progress_data:
                    result.setdefault(comp + "_progress", progress_data)

    return result


def extract_bench(bench_dir: str) -> dict:
    result: dict = {}
    if not os.path.isdir(bench_dir):
        return result

    br = _read_json(os.path.join(bench_dir, "benchmark_results.json"))
    if br and isinstance(br, dict):
        # run_meta
        run_meta = br.get("run_meta", {})
        if run_meta:
            result["run_meta"] = {
                "mode": run_meta.get("mode"),
                "model": run_meta.get("model"),
                "model_observed": run_meta.get("model_observed"),
                "tier": run_meta.get("tier"),
            }

        # integrity
        integrity = br.get("integrity", {})
        if integrity:
            result["integrity"] = {
                "verdict": integrity.get("verdict"),
                "reasons": integrity.get("reasons", []),
            }

        # overall
        overall = br.get("overall", {})
        if overall:
            result["overall"] = {
                "total_cost": overall.get("total_cost"),
                "total_tokens": overall.get("total_tokens"),
                "pipeline_elapsed_s": overall.get("pipeline_elapsed_s"),
            }

        # pipeline_overhead
        overhead = br.get("pipeline_overhead", {})
        if overhead:
            result["pipeline_overhead"] = {
                "elapsed_s": overhead.get("elapsed_s"),
                "start_iso": overhead.get("start_iso"),
                "end_iso": overhead.get("end_iso"),
            }

        # per-component summary
        components = br.get("components", {})
        comp_summary = {}
        for comp_name, comp_data in components.items():
            if not isinstance(comp_data, dict):
                continue
            a = comp_data.get("A", {})
            c = comp_data.get("C", {})

            tokens = a.get("A1_tokens", {}).get("total", {})
            subagents = a.get("A2_subagents", {})
            compaction = a.get("A3_compaction", {})
            skills = a.get("A4_skills", {})
            tool_calls = a.get("A5_tool_calls", {})
            hooks = a.get("A6_hook_buckets", {})
            timing = a.get("A7_time", {})

            comp_summary[comp_name] = {
                "tokens": {
                    "input": tokens.get("input", 0),
                    "output": tokens.get("output", 0),
                    "cache_read": tokens.get("cache_read", 0),
                    "cache_write": tokens.get("cache_write", 0),
                },
                "subagent_count": subagents.get("count", 0),
                "compaction_total": compaction.get("total", 0),
                "skills_total": skills.get("total", 0),
                "skills_by_name": skills.get("by_skill", {}),
                "tool_calls_total": tool_calls.get("total", 0),
                "tool_errors": tool_calls.get("errors", 0),
                "tool_error_rate": tool_calls.get("error_rate"),
                "max_token_truncations": tool_calls.get("max_token_truncations", 0),
                "hook_blocks": hooks.get("blocks", 0),
                "elapsed_s": timing.get("elapsed_s") or timing.get("wall_s"),
                "cost": c.get("C3_cost"),
            }

        result["components"] = comp_summary

    # Per-component snapshot files
    snapshots = _glob_sorted(os.path.join(bench_dir, "*-*.json"))
    snapshots = [s for s in snapshots if os.path.basename(s) != "benchmark_results.json"]
    result["snapshot_count"] = len(snapshots)

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

EXTRACTORS = {
    "crawler": extract_crawler,
    "attack_surface_discovery": extract_attack_surface_discovery,
    "planner": extract_planner,
    "vulnerability_discovery": extract_vulnerability_discovery,
    "vulnerability_exploitation": extract_vulnerability_exploitation,
    "hacker": extract_hacker,
    "vulnerability_chaining": extract_vulnerability_chaining,
    "reporting": extract_reporting,
}


def extract_all(run_dir: str) -> dict:
    run_dir = os.path.abspath(run_dir)
    comp_dirs = _detect_layout(run_dir)

    result: dict = {
        "run_dir": run_dir,
        "layout": "direct" if any(os.path.dirname(v) == run_dir for v in comp_dirs.values()) else "artifact",
        "components_found": sorted(comp_dirs.keys()),
        "components": {},
    }

    for comp_name, comp_path in sorted(comp_dirs.items()):
        extractor = EXTRACTORS.get(comp_name)
        if extractor:
            try:
                result["components"][comp_name] = extractor(comp_path)
            except Exception as e:
                result["components"][comp_name] = {"_error": str(e)}

    # Gates
    gates_dir = _find_gates_dir(run_dir)
    if gates_dir:
        result["gates"] = extract_gates(gates_dir)

    # Bench
    bench_dir = _find_bench_dir(run_dir)
    if bench_dir:
        result["bench"] = extract_bench(bench_dir)

    return result


def main():
    ap = argparse.ArgumentParser(description="Extract per-component results from an AEGIS run")
    ap.add_argument("--run-dir", required=True, help="Path to the AEGIS run directory")
    ap.add_argument("--output", help="Write JSON to file (default: stdout with --json)")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    result = extract_all(args.run_dir)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {args.output}")
    elif args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        # Human-readable summary
        print(f"Run directory: {result['run_dir']}")
        print(f"Layout: {result['layout']}")
        print(f"Components found: {', '.join(result['components_found'])}")
        print()

        for comp_name, comp_data in result.get("components", {}).items():
            if comp_data.get("_error"):
                print(f"  {comp_name}: ERROR — {comp_data['_error']}")
                continue

            print(f"  {comp_name}:")
            _print_component_summary(comp_name, comp_data)
            print()

        gates = result.get("gates", {})
        if gates:
            print("Gates:")
            for comp, status in sorted(gates.items()):
                if not comp.endswith("_progress"):
                    print(f"  {comp}: {status}")
            print()

        bench = result.get("bench", {})
        if bench:
            print("Bench:")
            integrity = bench.get("integrity", {})
            if integrity:
                print(f"  Integrity: {integrity.get('verdict', 'unknown')}")
            overall = bench.get("overall", {})
            if overall:
                cost = overall.get("total_cost")
                if cost is not None:
                    print(f"  Total cost: ${cost:.2f}")
            for comp, cd in sorted(bench.get("components", {}).items()):
                t = cd.get("tokens", {})
                cost_str = f"  ${cd['cost']:.2f}" if cd.get("cost") is not None else ""
                print(f"  {comp}: tools={cd.get('tool_calls_total', 0)} "
                      f"tokens={t.get('output', 0):,}out{cost_str}")


def _print_component_summary(name: str, data: dict) -> None:
    if name == "crawler":
        inv = data.get("endpoints_inventory", {})
        if inv:
            print(f"    Endpoints: {inv.get('count', 0)} "
                  f"(auth={inv.get('auth_required', 0)}, "
                  f"no-auth={inv.get('auth_not_required', 0)})")
        rm = data.get("role_matrix", {})
        if rm:
            print(f"    Roles: {', '.join(rm.get('roles', []))}")
        fr = data.get("frontier", {})
        if fr:
            print(f"    Frontier: {fr.get('visited_count', 0)} visited, "
                  f"{fr.get('todo_count', 0)} todo")
        fl = data.get("inferred_flows", {})
        if fl:
            print(f"    Flows: {fl.get('count', 0)} — {', '.join(fl.get('names', [])[:5])}")
        ss = data.get("screenshots", {})
        if ss:
            print(f"    Screenshots: {ss.get('total', 0)} "
                  f"({', '.join(f'{r}={c}' for r, c in ss.get('per_role', {}).items())})")

    elif name == "attack_surface_discovery":
        sf = data.get("surface", {})
        if sf:
            print(f"    Hosts: {sf.get('hosts_count', 0)}, "
                  f"Tech: {sf.get('tech_fingerprints_count', 0)}")
        print(f"    Subdomains: {data.get('subdomains_count', 0)}, "
              f"Paths: {data.get('paths_count', 0)}")
        ts = data.get("techstack", {})
        if ts:
            print(f"    Techstack: {ts.get('count', 0)} — "
                  f"{', '.join(ts.get('products', [])[:8])}")
        cv = data.get("cves", {})
        if cv:
            print(f"    CVEs: {cv.get('count', 0)}")
        sec = data.get("secrets", {})
        if sec:
            print(f"    Secrets: {sec.get('count', 0)}")

    elif name == "planner":
        pl = data.get("plan", {})
        if pl:
            print(f"    Phases: {pl.get('phase_count', 0)}, "
                  f"Tasks: {pl.get('task_count', 0)}")
            print(f"    OWASP: {', '.join(pl.get('owasp_categories', [])[:8])}")
        tc = data.get("test_cases", {})
        if tc:
            print(f"    Test cases: {tc.get('count', 0)}")
        cl = data.get("coverage_ledger", {})
        if cl:
            print(f"    Coverage: {cl.get('covered', 0)}/{cl.get('total_cells', 0)} cells")

    elif name == "vulnerability_discovery":
        f = data.get("findings", {})
        if f:
            print(f"    Findings: {f.get('unique_finding_ids', 0)} unique "
                  f"(batches={data.get('finding_batches', 0)})")
            print(f"    Severity: {f.get('severity_distribution', {})}")
            print(f"    Verification: {f.get('verification_status', {})}")

    elif name == "vulnerability_exploitation":
        print(f"    Exploit JSONs: {data.get('exploit_json_count', 0)}, "
              f"MDs: {data.get('exploit_md_count', 0)}, "
              f"Scripts: {data.get('poc_script_count', 0)}")
        print(f"    Verified-PoC: {data.get('verified_poc_count', 0)}, "
              f"Verified-Exploit: {data.get('verified_exploit_count', 0)}")

    elif name == "hacker":
        f = data.get("findings", {})
        if f:
            print(f"    Findings: {f.get('count', 0)}")
            print(f"    Severity: {f.get('severity_distribution', {})}")
            print(f"    Has chain opportunity: {f.get('has_chain_opportunity', 0)}")

    elif name == "vulnerability_chaining":
        ac = data.get("attack_chain", {})
        if ac:
            print(f"    Objectives: {ac.get('objective_count', 0)}, "
                  f"Nodes: {ac.get('node_count', 0)}")
        ga = data.get("graph_analysis", {})
        if ga:
            print(f"    Edges: {ga.get('edge_count', 0)}, "
                  f"Choke points: {ga.get('choke_point_count', 0)}, "
                  f"Dead ends: {ga.get('dead_end_count', 0)}")
        sc = data.get("scored_chains", {})
        if sc:
            print(f"    Scored chains: {sc.get('count', 0)}")

    elif name == "reporting":
        sf = data.get("scored_findings", {})
        if sf:
            print(f"    Final findings: {sf.get('count', 0)}")
            print(f"    Severity: {sf.get('severity_distribution', {})}")
            cvss = sf.get("cvss_scores", {})
            if cvss.get("count"):
                print(f"    CVSS: min={cvss['min']}, max={cvss['max']}, "
                      f"mean={cvss['mean']}")
            print(f"    Merged: {sf.get('merged_finding_count', 0)} "
                  f"(total merged IDs: {sf.get('total_merged_ids', 0)})")
        d = data.get("deliverables", {})
        if d:
            print(f"    Deliverables: {', '.join(d.keys())}")
        m = data.get("manifest", {})
        if m:
            phases = m.get("phases", {})
            completed = sum(1 for v in phases.values() if v and "completed" in str(v).lower())
            print(f"    Phases completed: {completed}/{len(phases)}")

    else:
        for k, v in data.items():
            if isinstance(v, dict):
                print(f"    {k}: {len(v)} items")
            elif isinstance(v, list):
                print(f"    {k}: {len(v)} items")
            else:
                print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
