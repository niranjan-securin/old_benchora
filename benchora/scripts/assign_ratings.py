#!/usr/bin/env python3
"""assign_ratings.py — assign Leading/Strong/Adequate/Weak/Not viable ratings.

Takes all models' per-area scores (mean + stdev across 3 repeats) and assigns
ratings relative to the best performer.

Usage:
    assign_ratings.py --scores <all_models_scores.json> [--config <rating_scale.json>] [--json]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from statistics import mean, stdev


def compute_repeat_stats(repeat_scores: list[float | None]) -> dict:
    """Compute mean and stdev from repeat scores, filtering None values."""
    valid = [s for s in repeat_scores if s is not None]
    if not valid:
        return {"mean": None, "stdev": None, "n": 0}
    m = mean(valid)
    sd = stdev(valid) if len(valid) >= 2 else 0.0
    return {"mean": round(m, 4), "stdev": round(sd, 4), "n": len(valid)}


def assign_rating(
    model_score: float,
    model_spread: float,
    leader_score: float,
    leader_spread: float,
    runner_up_score: float | None,
    runner_up_spread: float | None,
    is_leader: bool,
    is_inverse: bool = False,
    has_structural_failure: bool = False,
) -> str:
    """Assign a rating to a single model for a single area.

    Args:
        model_score: This model's mean score for the area
        model_spread: This model's stdev across repeats
        leader_score: Best model's mean score
        leader_spread: Best model's stdev across repeats
        runner_up_score: Second-best model's score (None if only 1 model)
        runner_up_spread: Second-best model's stdev (None if only 1 model)
        is_leader: Whether this model is the leader
        is_inverse: True for cost (lower is better)
        has_structural_failure: True if component refusal or schema failure
    """
    if has_structural_failure:
        return "Not viable"

    if model_score is None or leader_score is None:
        return "Not viable"

    if leader_score == 0 and not is_inverse:
        return "Not viable"

    if is_inverse:
        if leader_score == 0:
            return "Not viable"
        ratio = leader_score / model_score if model_score > 0 else 0.0
    else:
        ratio = model_score / leader_score if leader_score > 0 else 0.0

    if is_leader:
        if runner_up_score is not None and runner_up_spread is not None:
            if is_inverse:
                margin = runner_up_score - leader_score
            else:
                margin = leader_score - runner_up_score
            if margin > runner_up_spread and runner_up_spread >= 0:
                return "Leading"
        return "Strong"

    if leader_spread > 0:
        if is_inverse:
            within_spread = abs(model_score - leader_score) <= leader_spread
        else:
            within_spread = abs(model_score - leader_score) <= leader_spread
        if within_spread:
            return "Strong"

    if ratio >= 0.6:
        return "Adequate"
    elif ratio >= 0.3:
        return "Weak"
    else:
        return "Not viable"


def assign_ratings_for_area(
    model_stats: dict[str, dict],
    area_key: str,
    is_inverse: bool = False,
    structural_failures: dict[str, list[str]] | None = None,
) -> dict[str, dict]:
    """Assign ratings for all models in a single area.

    Args:
        model_stats: {model_id: {"mean": float, "stdev": float}} for this area
        area_key: The area key (e.g. "1_recon")
        is_inverse: True for cost areas (lower is better)
        structural_failures: {model_id: [failed_component_names]}
    """
    structural_failures = structural_failures or {}

    valid_models = {
        m: s for m, s in model_stats.items()
        if s.get("mean") is not None
    }

    if not valid_models:
        return {m: {"rating": "Not viable", "reason": "No valid score"} for m in model_stats}

    if is_inverse:
        ranked = sorted(valid_models.keys(), key=lambda m: valid_models[m]["mean"])
    else:
        ranked = sorted(valid_models.keys(), key=lambda m: valid_models[m]["mean"], reverse=True)

    leader = ranked[0]
    leader_score = valid_models[leader]["mean"]
    leader_spread = valid_models[leader].get("stdev", 0.0) or 0.0
    runner_up = ranked[1] if len(ranked) > 1 else None
    runner_up_score = valid_models[runner_up]["mean"] if runner_up else None
    runner_up_spread = valid_models[runner_up].get("stdev", 0.0) if runner_up else None

    results = {}
    for model_id, stats in model_stats.items():
        has_failure = bool(structural_failures.get(model_id))
        is_leader = (model_id == leader)

        rating = assign_rating(
            model_score=stats.get("mean"),
            model_spread=stats.get("stdev", 0.0) or 0.0,
            leader_score=leader_score,
            leader_spread=leader_spread,
            runner_up_score=runner_up_score,
            runner_up_spread=runner_up_spread,
            is_leader=is_leader,
            is_inverse=is_inverse,
            has_structural_failure=has_failure,
        )

        results[model_id] = {
            "mean": stats.get("mean"),
            "stdev": stats.get("stdev"),
            "rating": rating,
            "rank": ranked.index(model_id) + 1 if model_id in ranked else len(ranked) + 1,
        }

    for model_id in model_stats:
        if model_id not in results:
            results[model_id] = {"mean": None, "stdev": None, "rating": "Not viable", "rank": len(ranked) + 1}

    return results


def compute_overall_ranking(
    area_ratings: dict[str, dict[str, dict]],
    weights: dict[str, float] | None = None,
) -> dict[str, dict]:
    """Compute overall model ranking from per-area ratings.

    Args:
        area_ratings: {area_key: {model_id: {"mean": float, "rating": str}}}
        weights: {area_key: weight} — defaults per plan
    """
    default_weights = {
        "1_recon": 1.0, "2_interaction": 1.0, "3_sast": 1.0,
        "4_vuln_analysis": 1.0, "5_exploitation": 1.0, "6_attack_path": 1.0,
        "7_business_logic": 1.0, "8_reporting": 1.0,
        "9_reliability": 1.5, "10_cost": 0.5, "11_reproducibility": 1.0,
    }
    weights = weights or default_weights

    all_models = set()
    for area_data in area_ratings.values():
        all_models.update(area_data.keys())

    RATING_SCORES = {
        "Leading": 1.0, "Strong": 0.8, "Adequate": 0.6, "Weak": 0.3, "Not viable": 0.0,
    }

    model_overalls = {}
    for model_id in all_models:
        weighted_sum = 0.0
        weight_total = 0.0

        for area_key, area_data in area_ratings.items():
            model_area = area_data.get(model_id, {})
            rating = model_area.get("rating", "Not viable")
            w = weights.get(area_key, 1.0)
            weighted_sum += RATING_SCORES.get(rating, 0.0) * w
            weight_total += w

        overall = weighted_sum / weight_total if weight_total > 0 else 0.0
        model_overalls[model_id] = round(overall, 4)

    ranked = sorted(model_overalls.keys(), key=lambda m: model_overalls[m], reverse=True)

    results = {}
    for rank, model_id in enumerate(ranked, 1):
        results[model_id] = {
            "overall_score": model_overalls[model_id],
            "rank": rank,
        }

    return results


def main():
    ap = argparse.ArgumentParser(description="Assign ratings to models across evaluation areas")
    ap.add_argument("--scores", required=True,
                    help="JSON file with {area_key: {model_id: {mean, stdev}}}")
    ap.add_argument("--config", default=None, help="Path to rating_scale.json")
    ap.add_argument("--json", action="store_true", help="Output as JSON")
    args = ap.parse_args()

    with open(args.scores, encoding="utf-8") as f:
        all_scores = json.load(f)

    area_ratings = {}
    inverse_areas = {"10_cost"}

    for area_key, model_stats in all_scores.items():
        is_inverse = area_key in inverse_areas
        area_ratings[area_key] = assign_ratings_for_area(
            model_stats, area_key, is_inverse=is_inverse
        )

    overall = compute_overall_ranking(area_ratings)

    output = {
        "area_ratings": area_ratings,
        "overall": overall,
    }

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print("Per-area ratings:")
        for area_key, models in area_ratings.items():
            print(f"\n  {area_key}:")
            for model_id, data in sorted(models.items(), key=lambda x: x[1].get("rank", 99)):
                print(f"    #{data['rank']} {model_id}: {data['rating']} "
                      f"(mean={data['mean']}, stdev={data['stdev']})")

        print("\nOverall ranking:")
        for model_id, data in sorted(overall.items(), key=lambda x: x[1]["rank"]):
            print(f"  #{data['rank']} {model_id}: {data['overall_score']:.4f}")


if __name__ == "__main__":
    main()
