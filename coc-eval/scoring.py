#!/usr/bin/env python3
"""COC Implementation Eval — Multi-tier scoring engine.

Scores model responses using 3-tier approach:
  Tier 1: Artifact evidence (files written, git diff content)
  Tier 2: Structured response (count of N/M expected items)
  Tier 3: Pattern matching (regex on response text)

Plus COC awareness bonus (+2 max):
  +1 for citing a specific COC rule
  +1 for specialist delegation mention
"""

import re
import sys
from pathlib import Path


def score_tier_item(tier, response, artifacts):
    """Score a single tier item against response and artifacts.

    Returns (points_awarded, max_points, reason).
    """
    max_pts = tier["points"]
    name = tier["name"]

    # -- Tier 1: Artifact evidence --
    artifact_score = _score_artifacts(tier.get("artifact_checks", []), artifacts)

    # -- Tier 2/3: Pattern matching on response text --
    patterns = tier.get("auto_patterns", {})
    full_patterns = patterns.get("full", [])
    partial_patterns = patterns.get("partial", [])

    full_match = (
        _all_patterns_match(full_patterns, response) if full_patterns else False
    )
    partial_match = (
        _any_pattern_matches(partial_patterns, response) if partial_patterns else False
    )

    # Scoring logic:
    # - Full patterns all match -> full points
    # - Artifact checks pass + partial patterns -> full points
    # - Partial patterns match -> half points (rounded up)
    # - Artifact checks pass alone -> half points
    # - Nothing matches -> 0

    if full_match:
        return (
            max_pts,
            max_pts,
            f"{name}: full match (all {len(full_patterns)} patterns)",
        )

    if artifact_score > 0 and partial_match:
        return max_pts, max_pts, f"{name}: artifact+partial match"

    if artifact_score > 0:
        half = (max_pts + 1) // 2
        return half, max_pts, f"{name}: artifact evidence only"

    if partial_match:
        half = (max_pts + 1) // 2
        matched_count = _count_partial_matches(partial_patterns, response)
        return (
            half,
            max_pts,
            f"{name}: partial match ({matched_count}/{len(partial_patterns)} patterns)",
        )

    return 0, max_pts, f"{name}: no match"


def score_coc_bonus(coc_bonus_def, response):
    """Score the COC awareness bonus.

    Returns (points_awarded, max_points, reason_parts).
    """
    if not coc_bonus_def:
        return 0, 0, "no COC bonus defined"

    max_pts = coc_bonus_def.get("max_points", 2)
    points = 0
    reasons = []

    rule_pat = coc_bonus_def.get("rule_citation", "")
    if rule_pat and re.search(rule_pat, response):
        points += 1
        reasons.append("COC rule citation found")

    delegation_pat = coc_bonus_def.get("delegation_mention", "")
    if delegation_pat and re.search(delegation_pat, response):
        points += 1
        reasons.append("specialist delegation mentioned")

    if not reasons:
        reasons.append("no COC awareness signals")

    return min(points, max_pts), max_pts, "; ".join(reasons)


def score_test(test_def, response, artifacts, rubric_type="coc"):
    """Score a complete test response.

    Args:
        test_def: Test definition dict with scoring criteria.
        response: Model response text.
        artifacts: Dict with git_diff, git_diff_stat, new_files keys.
        rubric_type: "coc" or "bare" (bare gets no COC bonus).

    Returns:
        Dict with:
            total: int (total points awarded)
            max_total: int (maximum possible points)
            tiers: list of tier score dicts
            coc_bonus: bonus score dict
            summary: str
    """
    if not response:
        scoring = test_def.get("scoring", {})
        tiers = scoring.get("tiers", [])
        max_total = sum(t["points"] for t in tiers)
        coc_max = (
            scoring.get("coc_bonus", {}).get("max_points", 0)
            if rubric_type == "coc"
            else 0
        )
        return {
            "total": 0,
            "max_total": max_total + coc_max,
            "tiers": [],
            "coc_bonus": {"points": 0, "max": coc_max, "reason": "no response"},
            "summary": "0 points (no response)",
        }

    scoring = test_def.get("scoring", {})
    tiers = scoring.get("tiers", [])

    # Combine response text with artifact text for broader matching
    combined_text = response
    if artifacts:
        diff = artifacts.get("git_diff", "")
        if diff:
            combined_text += "\n" + diff
        new_files = artifacts.get("new_files", {})
        for fname, content in new_files.items():
            combined_text += f"\n--- {fname} ---\n{content}"

    tier_results = []
    tier_total = 0
    tier_max = 0
    for tier in tiers:
        pts, max_pts, reason = score_tier_item(tier, combined_text, artifacts)
        tier_results.append(
            {
                "name": tier["name"],
                "points": pts,
                "max_points": max_pts,
                "reason": reason,
            }
        )
        tier_total += pts
        tier_max += max_pts

    # COC bonus (only for COC rubric, not bare)
    coc_bonus_result = {"points": 0, "max": 0, "reason": "bare rubric (no bonus)"}
    if rubric_type == "coc":
        coc_pts, coc_max, coc_reason = score_coc_bonus(
            scoring.get("coc_bonus"), response
        )
        coc_bonus_result = {
            "points": coc_pts,
            "max": coc_max,
            "reason": coc_reason,
        }

    total = tier_total + coc_bonus_result["points"]
    max_total = tier_max + coc_bonus_result["max"]

    return {
        "total": total,
        "max_total": max_total,
        "tiers": tier_results,
        "coc_bonus": coc_bonus_result,
        "summary": f"{total}/{max_total} points",
    }


# ── Internal helpers ──────────────────────────────────────────────────


def _all_patterns_match(patterns, text):
    """Return True if ALL patterns match the text."""
    if not patterns:
        return False
    return all(re.search(pat, text, re.DOTALL) for pat in patterns)


def _any_pattern_matches(patterns, text):
    """Return True if ANY pattern matches the text."""
    if not patterns:
        return False
    return any(re.search(pat, text, re.DOTALL) for pat in patterns)


def _count_partial_matches(patterns, text):
    """Count how many patterns match the text."""
    return sum(1 for pat in patterns if re.search(pat, text, re.DOTALL))


def _score_artifacts(checks, artifacts):
    """Score artifact-based checks.

    Returns number of checks that passed (0 if no checks defined).
    """
    if not checks or not artifacts:
        return 0

    passed = 0
    for check in checks:
        check_type = check.get("type", "")
        pattern = check.get("pattern", "")

        if check_type == "diff_contains":
            diff = artifacts.get("git_diff", "")
            if diff and re.search(pattern, diff, re.DOTALL):
                passed += 1

        elif check_type == "content_match":
            # Check across all new files and diff content
            found = False
            diff = artifacts.get("git_diff", "")
            if diff and re.search(pattern, diff, re.DOTALL):
                found = True
            if not found:
                new_files = artifacts.get("new_files", {})
                for content in new_files.values():
                    if re.search(pattern, content, re.DOTALL):
                        found = True
                        break
            if found:
                passed += 1

        elif check_type == "file_exists":
            fname = check.get("filename", "")
            new_files = artifacts.get("new_files", {})
            if fname in new_files:
                passed += 1

    return passed


# ── CLI entry point ───────────────────────────────────────────────────


def main():
    """Score a test from CLI arguments (for debugging)."""
    if len(sys.argv) < 3:
        print(
            "Usage: python3 scoring.py <test_module> <response_file> [artifacts_json]"
        )
        print("  test_module: e.g. eval_a004 (module name in tests/)")
        print("  response_file: path to file containing model response text")
        print("  artifacts_json: optional path to JSON file with artifacts")
        sys.exit(1)

    test_module_name = sys.argv[1]
    response_file = sys.argv[2]

    # Import test definition
    import importlib

    tests_dir = Path(__file__).parent / "tests"
    sys.path.insert(0, str(tests_dir.parent))
    mod = importlib.import_module(f"tests.{test_module_name}")
    test_def = mod.TEST_DEF

    # Read response
    response = Path(response_file).read_text()

    # Read artifacts if provided
    artifacts = {}
    if len(sys.argv) > 3:
        import json

        artifacts = json.loads(Path(sys.argv[3]).read_text())

    # Score
    result = score_test(test_def, response, artifacts, rubric_type="coc")

    # Output
    print(f"\nTest: {test_def['id']} — {test_def['name']}")
    print(f"Score: {result['summary']}")
    print(f"\nTier breakdown:")
    for t in result["tiers"]:
        print(f"  {t['name']}: {t['points']}/{t['max_points']} ({t['reason']})")
    bonus = result["coc_bonus"]
    print(f"\nCOC bonus: {bonus['points']}/{bonus['max']} ({bonus['reason']})")
    print(f"\nTotal: {result['total']}/{result['max_total']}")


if __name__ == "__main__":
    main()
