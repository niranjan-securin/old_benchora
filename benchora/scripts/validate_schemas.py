#!/usr/bin/env python3
"""validate_schemas.py — validate component artifacts against expected schemas.

Checks that each component's output files exist and have the required structure.
Does NOT use JSON Schema validation (no jsonschema dependency) — uses lightweight
structural checks instead.

Usage:
    validate_schemas.py --run-dir <path> [--json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys


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
                    return []
    return out


def _find_file(base_dir: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        hits = sorted(glob.glob(os.path.join(base_dir, "**", pattern), recursive=True))
        if hits:
            return hits[-1]
    return None


COMPONENT_SCHEMAS = {
    "crawler": {
        "files": {
            "crawl_surface.json": {
                "type": "object",
                "required_keys": ["endpoints"],
                "endpoints_item_keys": ["url", "method"],
            },
        },
    },
    "attack_surface_discovery": {
        "files": {
            "surface.json": {
                "type": "object",
            },
        },
    },
    "sast": {
        "files": {
            "sast_findings.jsonl": {
                "type": "jsonl",
                "min_fields_per_item": 3,
            },
        },
    },
    "planner": {
        "files": {
            "test_cases.jsonl": {
                "type": "jsonl",
                "min_fields_per_item": 3,
                "expected_keys": ["id", "endpoint"],
            },
        },
    },
    "vulnerability_discovery": {
        "files": {
            "findings.jsonl": {
                "type": "jsonl",
                "min_fields_per_item": 4,
                "expected_keys": ["endpoint", "cwe"],
            },
        },
    },
    "vulnerability_exploitation": {
        "files": {
            "exploits.jsonl": {
                "type": "jsonl",
                "min_fields_per_item": 3,
            },
        },
    },
    "hacker": {
        "files": {
            "hacker_findings.jsonl": {
                "type": "jsonl",
                "min_fields_per_item": 3,
            },
        },
    },
    "vulnerability_chaining": {
        "files": {
            "attack_chain.json": {
                "type": "object_or_array",
            },
        },
    },
    "reporting": {
        "files": {
            "scored-findings.jsonl": {
                "type": "jsonl",
                "min_fields_per_item": 5,
                "expected_keys": ["finding_id", "severity"],
            },
        },
    },
}


def _validate_json_file(path: str, schema: dict) -> dict:
    """Validate a single JSON file against a lightweight schema."""
    data = _read_json(path)
    if data is None:
        return {"valid": False, "error": "File not found or invalid JSON", "path": path}

    expected_type = schema.get("type", "object")
    if expected_type == "object" and not isinstance(data, dict):
        return {"valid": False, "error": f"Expected object, got {type(data).__name__}", "path": path}
    if expected_type == "array" and not isinstance(data, list):
        return {"valid": False, "error": f"Expected array, got {type(data).__name__}", "path": path}

    errors = []

    if isinstance(data, dict):
        required = schema.get("required_keys", [])
        for key in required:
            if key not in data:
                errors.append(f"Missing required key: {key}")

    if errors:
        return {"valid": False, "errors": errors, "path": path}
    return {"valid": True, "path": path}


def _validate_jsonl_file(path: str, schema: dict) -> dict:
    """Validate a JSONL file."""
    items = _read_jsonl(path)
    if not items:
        if not os.path.exists(path):
            return {"valid": False, "error": "File not found", "path": path}
        return {"valid": False, "error": "Empty or invalid JSONL", "path": path}

    min_fields = schema.get("min_fields_per_item", 1)
    expected_keys = schema.get("expected_keys", [])
    errors = []

    for i, item in enumerate(items[:5]):
        if not isinstance(item, dict):
            errors.append(f"Line {i}: expected object, got {type(item).__name__}")
            continue
        if len(item) < min_fields:
            errors.append(f"Line {i}: only {len(item)} fields (need {min_fields})")
        for key in expected_keys:
            if key not in item:
                errors.append(f"Line {i}: missing expected key '{key}'")
                break

    if errors:
        return {"valid": False, "errors": errors[:5], "path": path, "item_count": len(items)}
    return {"valid": True, "path": path, "item_count": len(items)}


def validate_run(run_dir: str) -> dict:
    """Validate all component artifacts in a run directory."""
    results = {}
    valid_count = 0
    total_count = 0

    for component, spec in COMPONENT_SCHEMAS.items():
        comp_results = {}
        for filename, schema in spec["files"].items():
            path = _find_file(run_dir, [filename, f"*{filename}"])
            total_count += 1

            if not path:
                comp_results[filename] = {"valid": False, "error": "Not found"}
                continue

            file_type = schema.get("type", "object")
            if file_type == "jsonl":
                result = _validate_jsonl_file(path, schema)
            else:
                result = _validate_json_file(path, schema)

            comp_results[filename] = result
            if result.get("valid"):
                valid_count += 1

        results[component] = comp_results

    schema_pass_rate = valid_count / total_count if total_count > 0 else 0.0
    failed_components = [
        comp for comp, files in results.items()
        if not all(f.get("valid", False) for f in files.values())
    ]

    return {
        "run_dir": run_dir,
        "total_files": total_count,
        "valid_files": valid_count,
        "schema_pass_rate": round(schema_pass_rate, 4),
        "failed_components": failed_components,
        "by_component": results,
    }


def main():
    ap = argparse.ArgumentParser(description="Validate component artifact schemas")
    ap.add_argument("--run-dir", required=True, help="Path to run artifacts directory")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    result = validate_run(args.run_dir)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Schema validation: {result['valid_files']}/{result['total_files']} valid "
              f"({result['schema_pass_rate']:.0%})")
        if result["failed_components"]:
            print(f"Failed components: {result['failed_components']}")
        for comp, files in sorted(result["by_component"].items()):
            for fname, fresult in files.items():
                status = "OK" if fresult.get("valid") else "FAIL"
                detail = fresult.get("error") or fresult.get("errors", [""])[0] if not fresult.get("valid") else ""
                count = f" ({fresult['item_count']} items)" if "item_count" in fresult else ""
                print(f"  [{status}] {comp}/{fname}{count} {detail}")


if __name__ == "__main__":
    main()
