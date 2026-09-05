#!/usr/bin/env python3
"""parse_transcript.py — extract token usage and metadata from Claude Code transcripts.

Standalone — no AEGIS imports. Reads .jsonl transcript files and extracts
token counts (4-way split), model, tool calls, errors, and timing.

Usage:
    parse_transcript.py --transcript <path.jsonl> [--json]
    parse_transcript.py --dir <transcripts_dir> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
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


def parse_transcript(path: str) -> dict:
    """Parse a single Claude Code .jsonl transcript."""
    entries = _read_jsonl(path)

    tokens = {
        "input": 0,
        "output": 0,
        "cache_write": 0,
        "cache_read": 0,
    }
    model = None
    turns = 0
    tool_calls = 0
    tool_errors = 0
    skills = defaultdict(int)
    agents = 0
    max_tokens_truncations = 0
    per_tool = defaultdict(lambda: {"calls": 0, "errors": 0})

    first_ts = None
    last_ts = None

    for entry in entries:
        entry_type = entry.get("type", "")
        ts = entry.get("timestamp") or entry.get("ts")

        if ts:
            if first_ts is None:
                first_ts = ts
            last_ts = ts

        if entry_type == "assistant":
            turns += 1
            usage = entry.get("usage") or entry.get("message", {}).get("usage") or {}
            tokens["input"] += usage.get("input_tokens", 0)
            tokens["output"] += usage.get("output_tokens", 0)
            tokens["cache_write"] += usage.get("cache_creation_input_tokens", 0)
            tokens["cache_read"] += usage.get("cache_read_input_tokens", 0)

            entry_model = (entry.get("message", {}).get("model")
                          or usage.get("model") or entry.get("model"))
            if entry_model and model is None:
                model = entry_model

            if usage.get("stop_reason") == "max_tokens":
                max_tokens_truncations += 1

        elif entry_type in ("tool_use", "tool_call"):
            tool_calls += 1
            tool_name = entry.get("name") or entry.get("tool_name") or "unknown"
            per_tool[tool_name]["calls"] += 1

            if tool_name == "Skill":
                skill_input = entry.get("input") or entry.get("tool_input") or {}
                skill_name = skill_input.get("skill", "unknown") if isinstance(skill_input, dict) else "unknown"
                skills[skill_name] += 1

            if tool_name == "Agent":
                agents += 1

        elif entry_type == "tool_result":
            is_error = entry.get("is_error", False) or entry.get("error", False)
            if is_error:
                tool_errors += 1
                tool_name = entry.get("name") or entry.get("tool_name") or "unknown"
                per_tool[tool_name]["errors"] += 1

    elapsed_ms = None
    if first_ts and last_ts:
        try:
            if isinstance(first_ts, (int, float)) and isinstance(last_ts, (int, float)):
                elapsed_ms = int((last_ts - first_ts) * 1000) if last_ts > 1e12 else int(last_ts - first_ts)
        except (TypeError, ValueError):
            pass

    return {
        "transcript": os.path.basename(path),
        "tokens": tokens,
        "model": model,
        "turns": turns,
        "tool_calls": tool_calls,
        "tool_errors": tool_errors,
        "skills": dict(skills),
        "agents": agents,
        "elapsed_ms": elapsed_ms,
        "max_tokens_truncations": max_tokens_truncations,
        "per_tool": {k: dict(v) for k, v in per_tool.items()},
    }


def parse_directory(transcripts_dir: str) -> dict:
    """Parse all transcripts in a directory, grouped by component."""
    components = {}
    totals = {
        "input": 0, "output": 0, "cache_write": 0, "cache_read": 0,
    }
    total_tool_calls = 0
    total_errors = 0
    total_turns = 0
    model = None

    if not os.path.isdir(transcripts_dir):
        return {"error": f"Not a directory: {transcripts_dir}"}

    for root, _dirs, files in os.walk(transcripts_dir):
        for fname in sorted(files):
            if not fname.endswith(".jsonl"):
                continue
            fpath = os.path.join(root, fname)
            result = parse_transcript(fpath)

            rel_dir = os.path.relpath(root, transcripts_dir)
            raw_component = rel_dir.split(os.sep)[0] if rel_dir != "." else "unknown"
            # Claude Code transcript dirs use mangled paths like
            # "-home-secadmin-AEGIS-Fixed-components-crawler" — extract
            # the last segment after "components-" as the real name.
            if "-components-" in raw_component:
                component = raw_component.rsplit("-components-", 1)[-1]
            else:
                component = raw_component

            if component not in components:
                components[component] = {
                    "tokens": {"input": 0, "output": 0, "cache_write": 0, "cache_read": 0},
                    "tool_calls": 0,
                    "tool_errors": 0,
                    "turns": 0,
                    "transcripts": [],
                }

            comp = components[component]
            for k in totals:
                comp["tokens"][k] += result["tokens"][k]
                totals[k] += result["tokens"][k]
            comp["tool_calls"] += result["tool_calls"]
            comp["tool_errors"] += result["tool_errors"]
            comp["turns"] += result["turns"]
            comp["transcripts"].append(result["transcript"])
            total_tool_calls += result["tool_calls"]
            total_errors += result["tool_errors"]
            total_turns += result["turns"]

            if result["model"] and model is None:
                model = result["model"]

    return {
        "directory": transcripts_dir,
        "model": model,
        "total_tokens": totals,
        "total_tool_calls": total_tool_calls,
        "total_errors": total_errors,
        "total_turns": total_turns,
        "by_component": components,
    }


def compute_cost(tokens: dict, prices: dict) -> float:
    """Compute cost from token counts and pricing."""
    cost = 0.0
    for token_type, price_key in [
        ("input", "input_per_million"),
        ("output", "output_per_million"),
        ("cache_write", "cache_write_per_million"),
        ("cache_read", "cache_read_per_million"),
    ]:
        count = tokens.get(token_type, 0)
        rate = prices.get(price_key)
        if count and rate is not None:
            cost += count * rate / 1_000_000
    return round(cost, 4)


def main():
    ap = argparse.ArgumentParser(description="Parse Claude Code transcripts for token usage")
    ap.add_argument("--transcript", default=None, help="Path to a single .jsonl transcript")
    ap.add_argument("--dir", default=None, help="Path to transcripts directory")
    ap.add_argument("--prices", default=None, help="Path to model_prices.json (for cost calculation)")
    ap.add_argument("--model", default=None,
                    help="Authoritative model id for PRICING. Without this the model is "
                         "auto-detected from the transcript, which mis-priced sonnet-4-6/run1 "
                         "at claude-opus-4-7 rates ($1853 instead of $371).")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    if not args.transcript and not args.dir:
        ap.error("Provide --transcript or --dir")

    if args.transcript:
        result = parse_transcript(args.transcript)
    else:
        result = parse_directory(args.dir)

    if args.prices and os.path.exists(args.prices):
        with open(args.prices, encoding="utf-8") as f:
            all_prices = json.load(f)
        observed = result.get("model", "")
        model_id = args.model or observed
        result["model_observed_in_transcript"] = observed
        result["model_used_for_pricing"] = model_id
        if args.model and observed and observed != args.model:
            result["model_pricing_mismatch"] = (
                f"transcript reports {observed!r}; priced as {args.model!r} (declared)")
        prices = all_prices.get(model_id, {})
        result["priced"] = bool(prices)
        if not prices:
            # benchora contract: missing data is null, never a silent zero.
            result["cost_usd"] = None
            result["cost_unpriced_reason"] = f"no rate card for {model_id!r} in model_prices.json"
        if prices:
            total_tokens = result.get("total_tokens") or result.get("tokens", {})
            result["cost_usd"] = compute_cost(total_tokens, prices)
            if "by_component" in result:
                for comp_data in result["by_component"].values():
                    comp_data["cost_usd"] = compute_cost(comp_data["tokens"], prices)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if args.transcript:
            r = result
            print(f"Transcript: {r['transcript']}")
            print(f"Model:      {r['model']}")
            print(f"Turns:      {r['turns']}")
            print(f"Tool calls: {r['tool_calls']} ({r['tool_errors']} errors)")
            t = r["tokens"]
            print(f"Tokens:     in={t['input']:,}  out={t['output']:,}  "
                  f"cache_w={t['cache_write']:,}  cache_r={t['cache_read']:,}")
        else:
            r = result
            print(f"Directory: {r['directory']}")
            print(f"Model:     {r['model']}")
            print(f"Components: {len(r['by_component'])}")
            t = r["total_tokens"]
            print(f"Total tokens: in={t['input']:,}  out={t['output']:,}  "
                  f"cache_w={t['cache_write']:,}  cache_r={t['cache_read']:,}")
            if "cost_usd" in r:
                print(f"Total cost: ${r['cost_usd']:.2f}")
            for comp_name, comp_data in sorted(r["by_component"].items()):
                ct = comp_data["tokens"]
                cost_str = f"  ${comp_data['cost_usd']:.2f}" if "cost_usd" in comp_data else ""
                print(f"  {comp_name}: in={ct['input']:,} out={ct['output']:,}{cost_str}")


if __name__ == "__main__":
    main()
