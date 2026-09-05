#!/usr/bin/env python3
"""evaluate_test_cases.py — JSONPath-based test case assertion engine.

Evaluates test cases defined in benchora test case JSON files against
actual AEGIS component output from a run directory.

Usage:
    evaluate_test_cases.py --run-dir <path> --test-cases <path> [--json] [--verbose]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from typing import Any


# ---------------------------------------------------------------------------
# File loading helpers
# ---------------------------------------------------------------------------

def _read_json(path: str) -> Any | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _read_jsonl(path: str) -> list[dict]:
    out: list[dict] = []
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


def _resolve_artifact(run_dir: str, pattern: str) -> list[str]:
    """Resolve a glob pattern relative to run_dir, return matching paths."""
    full = os.path.join(run_dir, pattern)
    hits = sorted(glob.glob(full, recursive=True))
    if not hits:
        norm = pattern.replace("/", os.sep)
        hits = sorted(glob.glob(os.path.join(run_dir, "**", os.path.basename(norm)), recursive=True))
    return hits


def _load_artifact(run_dir: str, pattern: str) -> tuple[Any, list[str]]:
    """Load artifact data from one or more files matching the pattern.

    Returns (data, paths) where data is:
    - For .jsonl: a list of all records across matching files
    - For .json with one match: the parsed object
    - For .json with multiple matches: a list of parsed objects
    - For .md files: a list of {"_path": path, "_content": text} dicts
    """
    paths = _resolve_artifact(run_dir, pattern)
    if not paths:
        return None, []

    if pattern.endswith(".jsonl"):
        records: list[dict] = []
        for p in paths:
            records.extend(_read_jsonl(p))
        return records, paths

    if pattern.endswith(".json"):
        # Use the last (most recent by timestamp) file
        return _read_json(paths[-1]), [paths[-1]]

    if pattern.endswith(".md"):
        items = []
        for p in paths:
            if os.path.exists(p):
                with open(p, encoding="utf-8", errors="replace") as f:
                    items.append({"_path": p, "_content": f.read()})
        return items, paths

    return None, paths


# ---------------------------------------------------------------------------
# Mini JSONPath evaluator
# ---------------------------------------------------------------------------

def _jsonpath(data: Any, path: str) -> Any:
    """Evaluate a subset of JSONPath against data.

    Supported patterns:
      $                              -> root
      $.field                        -> field access
      $.field.subfield               -> chained field access
      $[*]                           -> all items in array
      $.field[*]                     -> all items in array field
      $.field[*].subfield            -> subfield of each array item
      $.roles[admin,user,nurse]      -> specific named keys
      $[?(@.field)]                  -> filter: field exists and truthy
      $[?(@.field=='value')]         -> filter: field equals string
      $[?(@.field>=9)]               -> filter: numeric comparison
      $[?(@.field!=null)]            -> filter: not null
      $[?(@.field.length>=2)]        -> filter: array/string length
      $[?(@.field.length > 1)]       -> filter: with spaces
      $[?(@.a && @.b)]              -> filter: AND
      $[?(@.a || @.b)]              -> filter: OR
      $[?(@.field=='a' || @.field=='b')]  -> OR with equality
      $[?(@.a.b)]                   -> nested field existence
      $[?(@.a[0])]                  -> array index existence
    """
    if data is None:
        return None

    if path == "$":
        return data

    path = path.lstrip("$").lstrip(".")

    return _eval_path(data, path)


def _eval_path(data: Any, path: str) -> Any:
    if not path:
        return data

    # Handle filter expressions: [?(...)]
    filter_match = re.match(r'^\[\?\((.+?)\)\](.*)$', path)
    if filter_match:
        expr = filter_match.group(1)
        rest = filter_match.group(2).lstrip(".")
        items = data if isinstance(data, list) else []
        filtered = [item for item in items if _eval_filter(item, expr)]
        if rest:
            return _eval_path(filtered, rest)
        return filtered

    # Handle [*] - all items
    if path.startswith("[*]"):
        rest = path[3:].lstrip(".")
        if isinstance(data, list):
            if rest:
                return [_eval_path(item, rest) for item in data]
            return data
        if isinstance(data, dict):
            if rest:
                return [_eval_path(v, rest) for v in data.values()]
            return list(data.values())
        return []

    # Handle [key1,key2,...] - specific named keys
    bracket_match = re.match(r'^\[([a-zA-Z0-9_,\s]+)\](.*)$', path)
    if bracket_match:
        keys = [k.strip() for k in bracket_match.group(1).split(",")]
        rest = bracket_match.group(2).lstrip(".")
        if isinstance(data, dict):
            items = [data[k] for k in keys if k in data]
            if rest:
                return [_eval_path(item, rest) for item in items]
            return items
        return []

    # Field access - find next segment boundary
    dot_pos = path.find(".")
    bracket_pos = path.find("[")

    if dot_pos == -1 and bracket_pos == -1:
        if isinstance(data, dict):
            return data.get(path)
        return None

    if bracket_pos != -1 and (dot_pos == -1 or bracket_pos < dot_pos):
        field = path[:bracket_pos]
        rest = path[bracket_pos:]
        if field:
            if isinstance(data, dict):
                return _eval_path(data.get(field), rest)
            return None
        return _eval_path(data, rest)

    field = path[:dot_pos]
    rest = path[dot_pos + 1:]
    if isinstance(data, dict):
        return _eval_path(data.get(field), rest)
    return None


def _eval_filter(item: Any, expr: str) -> bool:
    """Evaluate a filter expression like @.field=='value' against an item."""
    if not isinstance(item, dict):
        return False

    # OR expressions
    if " || " in expr:
        parts = expr.split(" || ")
        return any(_eval_filter(item, p.strip()) for p in parts)

    # AND expressions
    if " && " in expr:
        parts = expr.split(" && ")
        return all(_eval_filter(item, p.strip()) for p in parts)

    expr = expr.strip()

    # Comparison: @.field==value, @.field>=value, @.field!=value, @.field>value
    cmp_match = re.match(
        r'^@\.(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+)$', expr
    )
    if cmp_match:
        field_path = cmp_match.group(1)
        op = cmp_match.group(2)
        raw_val = cmp_match.group(3).strip()

        actual = _resolve_at_path(item, field_path)

        # Parse the comparison value
        expected = _parse_literal(raw_val)

        return _compare(actual, op, expected)

    # Existence: @.field or @.field.subfield
    if expr.startswith("@."):
        field_path = expr[2:]
        val = _resolve_at_path(item, field_path)
        return val is not None and val != "" and val != [] and val != {}

    return False


def _resolve_at_path(item: dict, field_path: str) -> Any:
    """Resolve a dotted path like 'evidence.request' or 'steps.length' on an item."""
    parts = field_path.split(".")
    current = item
    for i, part in enumerate(parts):
        if part == "length" and i == len(parts) - 1:
            if isinstance(current, (list, str)):
                return len(current)
            return 0
        # Handle array index like [0]
        idx_match = re.match(r'^(.+?)\[(\d+)\]$', part)
        if idx_match:
            field_name = idx_match.group(1)
            idx = int(idx_match.group(2))
            if isinstance(current, dict):
                current = current.get(field_name)
            else:
                return None
            if isinstance(current, list) and idx < len(current):
                current = current[idx]
            else:
                return None
            continue
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


def _parse_literal(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw == "null":
        return None
    if raw == "true":
        return True
    if raw == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "==" and expected is None:
        return actual is None
    if op == "!=" and expected is None:
        return actual is not None
    if op == "==":
        return actual == expected
    if op == "!=":
        return actual != expected
    try:
        a = float(actual) if actual is not None else 0
        e = float(expected) if expected is not None else 0
        if op == ">=":
            return a >= e
        if op == "<=":
            return a <= e
        if op == ">":
            return a > e
        if op == "<":
            return a < e
    except (TypeError, ValueError):
        return False
    return False


# ---------------------------------------------------------------------------
# Assertion check functions
# ---------------------------------------------------------------------------

def _check_keys_contain(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", [])
    if not isinstance(data, dict):
        return {"passed": False, "evidence": f"Expected object, got {type(data).__name__}"}
    missing = [k for k in expected if k not in data]
    if missing:
        return {"passed": False, "evidence": f"Missing keys: {missing}. Present: {sorted(data.keys())[:15]}"}
    return {"passed": True, "evidence": f"All required keys present: {expected}"}


def _check_all_match(data: Any, assertion: dict) -> dict:
    field = assertion.get("field", "")
    expected = assertion.get("expected")
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    if not data:
        return {"passed": False, "evidence": "Empty list — nothing to check"}
    mismatches = []
    for i, item in enumerate(data):
        val = item.get(field) if isinstance(item, dict) else None
        if val != expected:
            mismatches.append(f"[{i}].{field}={val}")
    if mismatches:
        return {"passed": False, "evidence": f"Mismatches: {mismatches[:5]}"}
    return {"passed": True, "evidence": f"All {len(data)} items have {field}={expected}"}


def _check_unique_count_gte(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", 1)
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    unique = set()
    for v in data:
        if isinstance(v, (str, int, float, bool)):
            unique.add(v)
        elif isinstance(v, list):
            unique.update(str(x) for x in v)
    count = len(unique)
    return {
        "passed": count >= expected,
        "evidence": f"{count} unique values (need {expected}): {sorted(str(x) for x in list(unique)[:10])}",
    }


def _check_any_contains(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", "")
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    for v in data:
        if isinstance(v, str) and expected in v:
            return {"passed": True, "evidence": f"Found '{expected}' in '{v}'"}
    return {"passed": False, "evidence": f"No item contains '{expected}' (checked {len(data)} items)"}


def _check_count_gte(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", 1)
    if isinstance(data, list):
        count = len(data)
    elif isinstance(data, dict):
        count = len(data)
    elif data is not None:
        count = 1
    else:
        count = 0
    return {
        "passed": count >= expected,
        "evidence": f"Count: {count} (need {expected})",
    }


def _check_count_where_length_gte(data: Any, assertion: dict) -> dict:
    length = assertion.get("length", 2)
    expected = assertion.get("expected", 1)
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    qualifying = 0
    for v in data:
        if isinstance(v, (list, str)) and len(v) >= length:
            qualifying += 1
    return {
        "passed": qualifying >= expected,
        "evidence": f"{qualifying} items with length >= {length} (need {expected})",
    }


def _check_ratio_true_lte(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", 0.5)
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    if not data:
        return {"passed": True, "evidence": "Empty list — trivially passes"}
    true_count = sum(1 for v in data if v is True)
    ratio = true_count / len(data)
    return {
        "passed": ratio <= expected,
        "evidence": f"{true_count}/{len(data)} true ({ratio:.0%}, need <= {expected:.0%})",
    }


def _check_all_length_gte(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", 1)
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    if not data:
        return {"passed": False, "evidence": "Empty list"}
    short = []
    for i, v in enumerate(data):
        vlen = len(v) if isinstance(v, (str, list)) else 0
        if vlen < expected:
            short.append(f"[{i}] len={vlen}")
    if short:
        return {"passed": False, "evidence": f"{len(short)} items too short (need >= {expected}): {short[:5]}"}
    return {"passed": True, "evidence": f"All {len(data)} items have length >= {expected}"}


def _check_any_equals(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected")
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    for v in data:
        if v == expected:
            return {"passed": True, "evidence": f"Found {expected}"}
        if isinstance(v, list) and expected in v:
            return {"passed": True, "evidence": f"Found {expected} in nested list"}
    return {"passed": False, "evidence": f"'{expected}' not found in {len(data)} items"}


def _check_any_matches_regex(data: Any, assertion: dict) -> dict:
    pattern = assertion.get("expected", "")
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    try:
        regex = re.compile(pattern)
    except re.error as e:
        return {"passed": False, "evidence": f"Invalid regex: {e}"}
    for v in data:
        if isinstance(v, str) and regex.search(v):
            return {"passed": True, "evidence": f"Matched '{v[:80]}' against /{pattern}/"}
    return {"passed": False, "evidence": f"No match for /{pattern}/ in {len(data)} items"}


def _check_all_have_field(data: Any, assertion: dict) -> dict:
    field = assertion.get("field", "")
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    if not data:
        return {"passed": False, "evidence": "Empty list"}
    missing = 0
    for item in data:
        if not isinstance(item, dict):
            missing += 1
            continue
        val = item.get(field)
        if val is None or val == "" or val == [] or val == {}:
            missing += 1
    if missing:
        return {"passed": False, "evidence": f"{missing}/{len(data)} items missing field '{field}'"}
    return {"passed": True, "evidence": f"All {len(data)} items have '{field}'"}


def _check_count_matches_regex(data: Any, assertion: dict) -> dict:
    pattern = assertion.get("regex", "")
    expected = assertion.get("expected", 1)
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    try:
        regex = re.compile(pattern)
    except re.error as e:
        return {"passed": False, "evidence": f"Invalid regex: {e}"}
    matches = sum(1 for v in data if isinstance(v, str) and regex.search(v))
    return {
        "passed": matches >= expected,
        "evidence": f"{matches} items match /{pattern}/ (need {expected})",
    }


def _check_count_values_where(data: Any, assertion: dict) -> dict:
    field = assertion.get("field", "")
    value = assertion.get("value")
    expected = assertion.get("expected", 1)
    if isinstance(data, dict):
        items = list(data.values())
    elif isinstance(data, list):
        items = data
    else:
        return {"passed": False, "evidence": f"Expected dict or list, got {type(data).__name__}"}
    matching = 0
    for item in items:
        if isinstance(item, dict) and item.get(field) == value:
            matching += 1
    return {
        "passed": matching >= expected,
        "evidence": f"{matching} items with {field}={value} (need {expected})",
    }


def _check_gte(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", 0)
    if data is None:
        return {"passed": False, "evidence": "Value is null"}
    try:
        val = float(data)
    except (TypeError, ValueError):
        return {"passed": False, "evidence": f"Cannot compare: {data!r}"}
    return {
        "passed": val >= expected,
        "evidence": f"Value: {val} (need >= {expected})",
    }


def _check_unique_prefix_count_gte(data: Any, assertion: dict) -> dict:
    prefix_length = assertion.get("prefix_length", 3)
    expected = assertion.get("expected", 1)
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    prefixes = set()
    for v in data:
        if isinstance(v, str) and len(v) >= prefix_length:
            prefixes.add(v[:prefix_length])
        elif isinstance(v, list):
            for sub in v:
                if isinstance(sub, str) and len(sub) >= prefix_length:
                    prefixes.add(sub[:prefix_length])
    return {
        "passed": len(prefixes) >= expected,
        "evidence": f"{len(prefixes)} unique prefixes (need {expected}): {sorted(prefixes)[:10]}",
    }


def _check_file_exists(_data: Any, _assertion: dict, *, paths: list[str] | None = None) -> dict:
    if paths and len(paths) > 0:
        return {"passed": True, "evidence": f"File exists: {paths[0]}"}
    return {"passed": False, "evidence": "File not found"}


def _check_not_empty(data: Any, _assertion: dict) -> dict:
    if data is None or data == "" or data == [] or data == {}:
        return {"passed": False, "evidence": f"Value is empty: {data!r}"}
    return {"passed": True, "evidence": f"Value present: {str(data)[:80]}"}


def _check_field_exists(data: Any, _assertion: dict) -> dict:
    if data is None:
        return {"passed": False, "evidence": "Field does not exist"}
    return {"passed": True, "evidence": f"Field exists with value: {str(data)[:80]}"}


def _check_ratio_gte(data: Any, assertion: dict, *, artifact_data: Any = None) -> dict:
    expected = assertion.get("expected", 0.5)
    ratio_of = assertion.get("ratio_of", "$[*]")

    numerator = len(data) if isinstance(data, list) else (1 if data else 0)

    if artifact_data is not None and ratio_of:
        total_data = _jsonpath(artifact_data, ratio_of)
        denominator = len(total_data) if isinstance(total_data, list) else (1 if total_data else 0)
    else:
        denominator = numerator

    if denominator == 0:
        return {"passed": False, "evidence": "Denominator is 0 — no items to check"}

    ratio = numerator / denominator
    return {
        "passed": ratio >= expected,
        "evidence": f"{numerator}/{denominator} ({ratio:.0%}, need {expected:.0%})",
    }


def _check_any_in(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", [])
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    for v in data:
        if v in expected:
            return {"passed": True, "evidence": f"Found '{v}' (in expected set)"}
        if isinstance(v, list):
            for sub in v:
                if sub in expected:
                    return {"passed": True, "evidence": f"Found '{sub}' in nested list"}
    return {"passed": False, "evidence": f"None of {len(data)} items in {expected}"}


def _check_all_unique(data: Any, _assertion: dict) -> dict:
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    seen: set = set()
    dupes: list = []
    for v in data:
        key = str(v)
        if key in seen:
            dupes.append(key)
        seen.add(key)
    if dupes:
        return {"passed": False, "evidence": f"{len(dupes)} duplicates: {dupes[:5]}"}
    return {"passed": True, "evidence": f"All {len(data)} values unique"}


def _check_all_not_empty(data: Any, _assertion: dict) -> dict:
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    if not data:
        return {"passed": False, "evidence": "Empty list"}
    empty = []
    for i, v in enumerate(data):
        if v is None or v == "" or v == [] or v == {}:
            empty.append(i)
    if empty:
        return {"passed": False, "evidence": f"{len(empty)} empty values at indices: {empty[:10]}"}
    return {"passed": True, "evidence": f"All {len(data)} values non-empty"}


def _check_all_in(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected", [])
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    bad = []
    for i, v in enumerate(data):
        if v not in expected:
            bad.append(f"[{i}]={v}")
    if bad:
        return {"passed": False, "evidence": f"{len(bad)} values not in allowed set: {bad[:5]}"}
    return {"passed": True, "evidence": f"All {len(data)} values in {expected}"}


def _check_all_equal(data: Any, assertion: dict) -> dict:
    expected = assertion.get("expected")
    if not isinstance(data, list):
        return {"passed": False, "evidence": f"Expected list, got {type(data).__name__}"}
    if not data:
        return {"passed": False, "evidence": "Empty list"}
    bad = [i for i, v in enumerate(data) if v != expected]
    if bad:
        return {"passed": False, "evidence": f"{len(bad)} values != {expected} at indices: {bad[:10]}"}
    return {"passed": True, "evidence": f"All {len(data)} values equal {expected}"}


def _check_coverage_ratio_gte(data: Any, assertion: dict) -> dict:
    covered_field = assertion.get("covered_field", "covered")
    total_field = assertion.get("total_field", "total_cells")
    expected = assertion.get("expected", 0.8)

    if not isinstance(data, dict):
        return {"passed": False, "evidence": f"Expected object, got {type(data).__name__}"}

    covered = data.get(covered_field, 0)
    total = data.get(total_field, 0)

    if total == 0:
        return {"passed": False, "evidence": "Total is 0"}

    try:
        ratio = float(covered) / float(total)
    except (TypeError, ValueError):
        return {"passed": False, "evidence": f"Cannot compute ratio: {covered}/{total}"}

    return {
        "passed": ratio >= expected,
        "evidence": f"{covered}/{total} ({ratio:.1%}, need {expected:.0%})",
    }


CHECK_HANDLERS: dict[str, Any] = {
    "keys_contain": _check_keys_contain,
    "all_match": _check_all_match,
    "unique_count_gte": _check_unique_count_gte,
    "any_contains": _check_any_contains,
    "count_gte": _check_count_gte,
    "count_where_length_gte": _check_count_where_length_gte,
    "ratio_true_lte": _check_ratio_true_lte,
    "all_length_gte": _check_all_length_gte,
    "any_equals": _check_any_equals,
    "any_matches_regex": _check_any_matches_regex,
    "all_have_field": _check_all_have_field,
    "count_matches_regex": _check_count_matches_regex,
    "count_values_where": _check_count_values_where,
    "gte": _check_gte,
    "unique_prefix_count_gte": _check_unique_prefix_count_gte,
    "file_exists": _check_file_exists,
    "not_empty": _check_not_empty,
    "field_exists": _check_field_exists,
    "ratio_gte": _check_ratio_gte,
    "any_in": _check_any_in,
    "all_unique": _check_all_unique,
    "all_not_empty": _check_all_not_empty,
    "all_in": _check_all_in,
    "all_equal": _check_all_equal,
    "coverage_ratio_gte": _check_coverage_ratio_gte,
}


# ---------------------------------------------------------------------------
# Main evaluation logic
# ---------------------------------------------------------------------------

def evaluate_test_cases(run_dir: str, test_cases_path: str, verbose: bool = False) -> dict:
    tc_data = _read_json(test_cases_path)
    if not tc_data:
        return {"error": f"Test cases file not found: {test_cases_path}", "total": 0, "passed": 0}

    if not isinstance(tc_data, dict):
        return {"error": "Test cases file must be a JSON object", "total": 0, "passed": 0}

    component = tc_data.get("component", "unknown")
    area = tc_data.get("area", "unknown")
    area_name = tc_data.get("area_name", "")
    artifacts_map = tc_data.get("artifacts", {})
    test_cases = tc_data.get("test_cases", [])
    min_pass_rate = tc_data.get("min_pass_rate", 0.7)

    # Pre-load all artifacts
    loaded: dict[str, tuple[Any, list[str]]] = {}
    for key, pattern in artifacts_map.items():
        loaded[key] = _load_artifact(run_dir, pattern)

    results = []
    total_weight = 0
    passed_weight = 0

    for tc in test_cases:
        tc_id = tc.get("id", "unknown")
        name = tc.get("name", "")
        description = tc.get("description", "")
        weight = tc.get("weight", 1)
        assertion = tc.get("assertion", {})

        if not assertion:
            results.append({
                "id": tc_id, "name": name, "description": description,
                "status": "SKIP", "reason": "No assertion defined",
                "weight": weight,
            })
            continue

        file_key = assertion.get("file", "")
        jp = assertion.get("path", "$")
        check = assertion.get("check", "")

        handler = CHECK_HANDLERS.get(check)
        if not handler:
            results.append({
                "id": tc_id, "name": name, "description": description,
                "status": "SKIP", "reason": f"Unknown check type: {check}",
                "weight": weight,
            })
            continue

        artifact_data, artifact_paths = loaded.get(file_key, (None, []))

        if check == "file_exists":
            result = _check_file_exists(artifact_data, assertion, paths=artifact_paths)
        elif artifact_data is None:
            result = {"passed": False, "evidence": f"Artifact '{file_key}' not found in {run_dir}"}
        else:
            data = _jsonpath(artifact_data, jp)

            if check == "ratio_gte":
                result = _check_ratio_gte(data, assertion, artifact_data=artifact_data)
            else:
                result = handler(data, assertion)

        status = "PASS" if result["passed"] else "FAIL"
        total_weight += weight
        if result["passed"]:
            passed_weight += weight

        results.append({
            "id": tc_id,
            "name": name,
            "description": description,
            "status": status,
            "evidence": result.get("evidence", ""),
            "weight": weight,
        })

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    skipped = sum(1 for r in results if r["status"] == "SKIP")

    unweighted_rate = passed / total if total > 0 else 0.0
    weighted_rate = passed_weight / total_weight if total_weight > 0 else 0.0

    return {
        "component": component,
        "area": area,
        "area_name": area_name,
        "test_cases_file": test_cases_path,
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "pass_rate": round(unweighted_rate, 4),
        "weighted_pass_rate": round(weighted_rate, 4),
        "min_pass_rate": min_pass_rate,
        "meets_minimum": weighted_rate >= min_pass_rate,
        "results": results,
    }


def main():
    ap = argparse.ArgumentParser(description="Evaluate test cases against component output")
    ap.add_argument("--run-dir", required=True, help="Path to run artifacts directory")
    ap.add_argument("--test-cases", required=True, help="Path to test cases JSON file")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    ap.add_argument("--verbose", action="store_true", help="Show detailed evidence")
    args = ap.parse_args()

    result = evaluate_test_cases(args.run_dir, args.test_cases, verbose=args.verbose)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print(f"ERROR: {result['error']}")
        sys.exit(1)

    header = f"Component: {result['component']}"
    if result.get("area_name"):
        header += f"  |  Area {result['area']}: {result['area_name']}"
    print(header)
    print(f"Tests: {result['total']} total, {result['passed']} passed, {result['failed']} failed, {result['skipped']} skipped")
    print(f"Pass rate: {result['pass_rate']:.0%} (unweighted)  |  {result['weighted_pass_rate']:.0%} (weighted)")
    min_pr = result.get("min_pass_rate", 0)
    meets = result.get("meets_minimum", False)
    print(f"Minimum: {min_pr:.0%}  |  {'MEETS' if meets else 'BELOW'} threshold")
    print()

    for r in result["results"]:
        icon = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}.get(r["status"], "????")
        w = f" (w={r['weight']})" if r.get("weight", 1) != 1 else ""
        print(f"  [{icon}] {r['id']}: {r.get('name', '')}{w}")
        detail = r.get("evidence") or r.get("reason", "")
        if detail:
            print(f"         {detail}")


if __name__ == "__main__":
    main()
