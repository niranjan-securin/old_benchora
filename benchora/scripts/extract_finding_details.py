#!/usr/bin/env python3
"""extract_finding_details.py — read finding.md files from reporting/findings/.

Parses YAML frontmatter and key markdown sections from each finding.md,
producing a dict keyed by finding_id with structured detail for each finding.

Usage:
    extract_finding_details.py --run-dir <path> [--json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys


def _parse_frontmatter(text: str) -> dict:
    """Extract YAML-like frontmatter between --- markers."""
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    if not m:
        return {}
    fm = {}
    for line in m.group(1).split("\n"):
        line = line.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if val.replace(".", "", 1).isdigit():
            try:
                val = float(val) if "." in val else int(val)
            except ValueError:
                pass
        fm[key] = val
    return fm


def _extract_section(text: str, *headings: str) -> str:
    """Extract content under a markdown ## heading, up to the next ## or end.

    Accepts several alias headings and returns the first that matches, so
    divergent finding.md templates populate the same index field. (Measured:
    sonnet-4-6/run2 uses "Affected Endpoints"/"How to Replicate" where the other
    8 runs use "Where"/"How to replicate".)
    """
    for heading in headings:
        pattern = rf"^##\s+{re.escape(heading)}.*?\n(.*?)(?=^##\s|\Z)"
        m = re.search(pattern, text, re.MULTILINE | re.DOTALL | re.IGNORECASE)
        if not m:
            pattern_loose = rf"^##\s+.*?{re.escape(heading)}.*?\n(.*?)(?=^##\s|\Z)"
            m = re.search(pattern_loose, text, re.MULTILINE | re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _all_sections(text: str) -> dict:
    """Every ## section in the file, verbatim. Nothing is dropped or capped."""
    out = {}
    for m in re.finditer(r"^##\s+(.+?)\s*\n(.*?)(?=^##\s|\Z)", text,
                         re.MULTILINE | re.DOTALL):
        out[m.group(1).strip()] = m.group(2).strip()
    return out


def _extract_endpoints_from_section(section_text: str) -> list[str]:
    """Pull endpoint URLs from the 'Where' section."""
    endpoints = []
    for line in section_text.split("\n"):
        line = line.strip()
        if not line:
            continue
        cleaned = re.sub(r"^[-*]\s*", "", line)
        cleaned = re.sub(r"^`", "", cleaned).rstrip("`")
        url_match = re.search(r"(https?://\S+|/\S+)", cleaned)
        if url_match:
            endpoints.append(url_match.group(1))
    return endpoints


def _truncate(text: str, max_len: int = 2000) -> str:
    """Deprecated and unused: finding.md content is now stored in full.
    Kept so any external caller keeps working."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def extract_finding_details(run_dir: str) -> dict:
    """Read all finding.md files and return structured details keyed by finding_id."""
    findings_dirs = sorted(glob.glob(
        os.path.join(run_dir, "**", "findings"), recursive=True
    ))

    finding_files = []
    for fd in findings_dirs:
        if os.path.isdir(fd):
            for f in sorted(os.listdir(fd)):
                if f.endswith(".md"):
                    finding_files.append(os.path.join(fd, f))

    if not finding_files:
        for pattern in ["findings/*.md", "**/findings/*.md"]:
            hits = sorted(glob.glob(os.path.join(run_dir, pattern), recursive=True))
            if hits:
                finding_files = hits
                break

    details = {}
    for fpath in finding_files:
        try:
            # newline="" disables universal-newline translation so raw_markdown is
            # byte-identical to disk (sonnet-4-6/run1 has 39 CRLF pairs that would
            # otherwise be silently rewritten to LF).
            with open(fpath, encoding="utf-8", errors="replace", newline="") as f:
                text = f.read()
        except OSError:
            continue

        if len(text) < 20:
            continue

        fm = _parse_frontmatter(text)
        fid = fm.get("finding_id", "")
        if not fid:
            fid = os.path.splitext(os.path.basename(fpath))[0]

        # Only strip a real YAML frontmatter block. The previous
        # text.find("---", 3) matched the first markdown table separator, which
        # ate the title/banner on files with no frontmatter.
        _fm_m = re.match(r"^---\s*\n.*?\n---[ \t]*(?:\n|$)", text, re.DOTALL)
        body = text[_fm_m.end():].strip() if _fm_m else text

        description = _extract_section(body, "What it is", "Summary", "Description")
        where_text = _extract_section(body, "Where", "Affected Endpoints",
                                     "Where (affected endpoints)")
        replication = _extract_section(body, "How to replicate", "How to Replicate",
                                       "Reproduction")
        impact = _extract_section(body, "What an attacker gains", "Impact",
                                  "Impact scenarios")
        remediation = _extract_section(body, "Remediation", "Fix")
        proof = _extract_section(body, "Proof", "Evidence")
        exploit_code = _extract_section(body, "Exploit code", "Exploit Code", "PoC")
        attempts = _extract_section(body, "Attempts")

        affected_eps = _extract_endpoints_from_section(where_text)

        details[fid] = {
            "finding_id": fid,
            "title": fm.get("title", ""),
            "severity": fm.get("severity", ""),
            "cvss_score": fm.get("cvss_score"),
            "cvss_vector": fm.get("cvss_vector", ""),
            "owasp": fm.get("owasp", ""),
            "cwe": fm.get("cwe", ""),
            "verification_status": fm.get("verification_status", ""),
            "component": fm.get("component", ""),
            "discovered_at": fm.get("discovered_at", ""),
            # Untruncated. These parsed sections are a convenience index;
            # raw_markdown below is the content of record.
            "description": description,
            "affected_endpoints": affected_eps,
            "replication_steps": replication,
            "impact": impact,
            "remediation": remediation,
            "proof_summary": proof,
            "exploit_code": exploit_code,
            "attempts": attempts,
            "sections": _all_sections(body),
            "raw_markdown": text,
            "raw_bytes": len(text.encode("utf-8")),
            "source_file": os.path.basename(fpath),
            "source_path": os.path.relpath(fpath, run_dir),
        }

    return {
        "finding_count": len(details),
        "findings": details,
    }


def main():
    ap = argparse.ArgumentParser(description="Extract finding details from finding.md files")
    ap.add_argument("--run-dir", required=True, help="Path to run artifacts directory")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    result = extract_finding_details(args.run_dir)

    if args.json:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Found {result['finding_count']} finding detail files")
        for fid, detail in result["findings"].items():
            print(f"  {fid}: {detail['title'][:80]} [{detail['severity']}]")


if __name__ == "__main__":
    main()
