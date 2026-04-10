#!/usr/bin/env python3
"""COC Implementation Eval — Cross-model comparison reports.

Reads result JSON files from results/ and produces:
  - Per-model scorecard (test x score table)
  - Cross-model comparison (side-by-side)
  - COC vs bare delta per test per model
  - Aggregate COC value-add score

Usage:
  # Compare all result files in results/
  python3 coc-eval/compare.py

  # Compare specific files
  python3 coc-eval/compare.py results/eval-default-full.json results/eval-mm-full.json

  # Output as JSON instead of table
  python3 coc-eval/compare.py --format json
"""

import argparse
import json
import sys
from pathlib import Path

EVAL_DIR = Path(__file__).parent.resolve()
RESULTS_DIR = EVAL_DIR / "results"


def load_result_file(path):
    """Load a single result JSON file.

    Returns parsed dict.
    Raises FileNotFoundError if file does not exist.
    Raises json.JSONDecodeError if file is not valid JSON.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Result file not found: {path}")
    return json.loads(path.read_text())


def load_all_results():
    """Load all result JSON files from the results/ directory.

    Returns list of (filename, data) tuples.
    Raises FileNotFoundError if results directory does not exist or is empty.
    """
    if not RESULTS_DIR.exists():
        raise FileNotFoundError(f"Results directory not found: {RESULTS_DIR}")

    files = sorted(RESULTS_DIR.glob("eval-*.json"))
    if not files:
        raise FileNotFoundError(
            f"No eval result files found in {RESULTS_DIR}. "
            f"Run the eval first: python3 coc-eval/runner.py ..."
        )

    results = []
    for f in files:
        try:
            data = json.loads(f.read_text())
            results.append((f.name, data))
        except json.JSONDecodeError as e:
            print(f"  WARNING: Skipping {f.name} (invalid JSON: {e})", file=sys.stderr)
    return results


# ── Scorecard extraction ──────────────────────────────────────────────


def extract_scorecard(data):
    """Extract per-test scores from a result file.

    Returns dict with model info and per-rubric per-test scores.
    """
    model = data.get("model", "unknown")
    profile = data.get("profile", "unknown")
    mode = data.get("mode", "unknown")

    scorecard = {
        "model": model,
        "profile": profile,
        "mode": mode,
        "timestamp": data.get("timestamp", ""),
        "rubrics": {},
    }

    for rubric_type, results in data.get("results", {}).items():
        tests = {}
        total_score = 0
        total_max = 0
        total_time = 0.0
        total_in_tokens = 0
        total_out_tokens = 0

        for r in results:
            test_id = r.get("test_id", "unknown")
            score_data = r.get("score", {})
            pts = score_data.get("total", 0)
            max_pts = score_data.get("max_total", 0)

            tests[test_id] = {
                "name": r.get("test_name", ""),
                "type": r.get("test_type", ""),
                "score": pts,
                "max_score": max_pts,
                "ok": r.get("ok", False),
                "elapsed": r.get("elapsed", 0),
                "num_turns": r.get("num_turns", 0),
                "input_tokens": r.get("input_tokens", 0),
                "output_tokens": r.get("output_tokens", 0),
                "tiers": score_data.get("tiers", []),
                "coc_bonus": score_data.get("coc_bonus", {}),
            }
            total_score += pts
            total_max += max_pts
            total_time += r.get("elapsed", 0)
            total_in_tokens += r.get("input_tokens", 0)
            total_out_tokens += r.get("output_tokens", 0)

        scorecard["rubrics"][rubric_type] = {
            "tests": tests,
            "total_score": total_score,
            "total_max": total_max,
            "total_time": total_time,
            "total_input_tokens": total_in_tokens,
            "total_output_tokens": total_out_tokens,
        }

    return scorecard


# ── Report formatters ─────────────────────────────────────────────────


def format_model_scorecard(scorecard):
    """Format a single model's scorecard as a text table."""
    lines = []
    model = scorecard["model"]
    profile = scorecard["profile"]
    ts = scorecard["timestamp"]

    lines.append(f"Model: {model} (profile: {profile})")
    lines.append(f"Timestamp: {ts}")

    for rubric_type, rubric_data in scorecard["rubrics"].items():
        tests = rubric_data["tests"]
        total = rubric_data["total_score"]
        total_max = rubric_data["total_max"]
        total_time = rubric_data["total_time"]

        lines.append(f"\n  {rubric_type.upper()} ({total}/{total_max})")
        lines.append(
            f"  {'Test':<12} {'Name':<35} {'Score':>7} {'Time':>8} {'Turns':>6}"
        )
        lines.append(f"  {'-' * 70}")

        for test_id, t in tests.items():
            score_str = f"{t['score']}/{t['max_score']}"
            time_str = f"{t['elapsed']:.1f}s"
            lines.append(
                f"  {test_id:<12} {t['name']:<35} {score_str:>7} "
                f"{time_str:>8} {t['num_turns']:>6}"
            )

            # Tier breakdown
            for tier in t.get("tiers", []):
                tier_score = f"{tier['points']}/{tier['max_points']}"
                lines.append(
                    f"    {tier['name']:<42} {tier_score:>7}  {tier['reason']}"
                )

            bonus = t.get("coc_bonus", {})
            if bonus.get("max", 0) > 0:
                bonus_score = f"{bonus['points']}/{bonus['max']}"
                lines.append(
                    f"    {'COC bonus':<42} {bonus_score:>7}  {bonus['reason']}"
                )

        lines.append(f"  {'-' * 70}")
        lines.append(f"  {'TOTAL':<48} {total}/{total_max}  ({total_time:.1f}s)")

    return "\n".join(lines)


def format_cross_model_comparison(scorecards):
    """Format a side-by-side comparison of multiple models."""
    if not scorecards:
        return "No scorecards to compare."

    lines = []
    lines.append("CROSS-MODEL COMPARISON")
    lines.append("=" * 80)

    # Collect all test IDs across all scorecards
    all_test_ids = set()
    for sc in scorecards:
        for rubric_data in sc["rubrics"].values():
            all_test_ids.update(rubric_data["tests"].keys())
    all_test_ids = sorted(all_test_ids)

    # Collect all rubric types
    all_rubrics = set()
    for sc in scorecards:
        all_rubrics.update(sc["rubrics"].keys())
    all_rubrics = sorted(all_rubrics)

    for rubric_type in all_rubrics:
        lines.append(f"\n  {rubric_type.upper()}")

        # Header
        model_names = [sc["model"][:20] for sc in scorecards]
        header = f"  {'Test':<12}"
        for name in model_names:
            header += f" {name:>20}"
        lines.append(header)
        lines.append(f"  {'-' * (12 + 21 * len(scorecards))}")

        # Per-test rows
        for test_id in all_test_ids:
            row = f"  {test_id:<12}"
            for sc in scorecards:
                rubric = sc["rubrics"].get(rubric_type, {})
                test_data = rubric.get("tests", {}).get(test_id)
                if test_data:
                    cell = f"{test_data['score']}/{test_data['max_score']}"
                else:
                    cell = "-"
                row += f" {cell:>20}"
            lines.append(row)

        # Totals
        total_row = f"  {'TOTAL':<12}"
        for sc in scorecards:
            rubric = sc["rubrics"].get(rubric_type, {})
            total = rubric.get("total_score", 0)
            total_max = rubric.get("total_max", 0)
            cell = f"{total}/{total_max}"
            total_row += f" {cell:>20}"
        lines.append(f"  {'-' * (12 + 21 * len(scorecards))}")
        lines.append(total_row)

    return "\n".join(lines)


def format_coc_vs_bare_delta(scorecards):
    """Format COC vs bare delta for models that have both rubrics."""
    lines = []
    lines.append("\nCOC VALUE-ADD DELTA")
    lines.append("=" * 80)

    has_delta = False

    for sc in scorecards:
        coc_rubric = sc["rubrics"].get("coc")
        bare_rubric = sc["rubrics"].get("bare")
        if not coc_rubric or not bare_rubric:
            continue

        has_delta = True
        model = sc["model"]
        lines.append(f"\n  {model}")
        lines.append(f"  {'Test':<12} {'COC':>8} {'Bare':>8} {'Delta':>8} {'Pct':>8}")
        lines.append(f"  {'-' * 48}")

        total_delta = 0
        total_coc = 0
        total_bare = 0

        all_test_ids = sorted(
            set(coc_rubric["tests"].keys()) | set(bare_rubric["tests"].keys())
        )

        for test_id in all_test_ids:
            coc_test = coc_rubric["tests"].get(test_id, {})
            bare_test = bare_rubric["tests"].get(test_id, {})
            coc_score = coc_test.get("score", 0)
            bare_score = bare_test.get("score", 0)
            delta = coc_score - bare_score
            total_delta += delta
            total_coc += coc_score
            total_bare += bare_score

            sign = "+" if delta > 0 else ""
            pct = ""
            if bare_score > 0:
                pct_val = (delta / bare_score) * 100
                pct = f"{pct_val:+.0f}%"
            elif coc_score > 0:
                pct = "+inf%"

            lines.append(
                f"  {test_id:<12} {coc_score:>8} {bare_score:>8} "
                f"{sign}{delta:>7} {pct:>8}"
            )

        lines.append(f"  {'-' * 48}")
        sign = "+" if total_delta > 0 else ""
        total_pct = ""
        if total_bare > 0:
            total_pct_val = (total_delta / total_bare) * 100
            total_pct = f"{total_pct_val:+.0f}%"

        lines.append(
            f"  {'TOTAL':<12} {total_coc:>8} {total_bare:>8} "
            f"{sign}{total_delta:>7} {total_pct:>8}"
        )

    if not has_delta:
        lines.append("\n  No models with both COC and bare results found.")
        lines.append("  Run with --mode full to generate both passes.")

    return "\n".join(lines)


def format_aggregate_summary(scorecards):
    """Format an aggregate summary across all models."""
    lines = []
    lines.append("\nAGGREGATE SUMMARY")
    lines.append("=" * 80)

    header = f"  {'Model':<25} {'Profile':<10}"
    # Collect all rubric types
    all_rubrics = set()
    for sc in scorecards:
        all_rubrics.update(sc["rubrics"].keys())
    all_rubrics = sorted(all_rubrics)

    for r in all_rubrics:
        header += f" {r.upper():>15}"
    lines.append(header)
    lines.append(f"  {'-' * (35 + 16 * len(all_rubrics))}")

    for sc in scorecards:
        row = f"  {sc['model']:<25} {sc['profile']:<10}"
        for r in all_rubrics:
            rubric = sc["rubrics"].get(r)
            if rubric:
                cell = f"{rubric['total_score']}/{rubric['total_max']}"
            else:
                cell = "-"
            row += f" {cell:>15}"
        lines.append(row)

    return "\n".join(lines)


# ── JSON output ───────────────────────────────────────────────────────


def build_comparison_json(scorecards):
    """Build a structured comparison dict for JSON output."""
    comparison = {
        "models": [],
        "tests": {},
        "deltas": [],
    }

    all_test_ids = set()
    for sc in scorecards:
        model_entry = {
            "model": sc["model"],
            "profile": sc["profile"],
            "timestamp": sc["timestamp"],
            "rubrics": {},
        }
        for rubric_type, rubric_data in sc["rubrics"].items():
            model_entry["rubrics"][rubric_type] = {
                "total_score": rubric_data["total_score"],
                "total_max": rubric_data["total_max"],
                "total_time": rubric_data["total_time"],
            }
            all_test_ids.update(rubric_data["tests"].keys())
        comparison["models"].append(model_entry)

    # Per-test comparison
    for test_id in sorted(all_test_ids):
        test_entry = {}
        for sc in scorecards:
            model = sc["model"]
            for rubric_type, rubric_data in sc["rubrics"].items():
                test_data = rubric_data["tests"].get(test_id)
                if test_data:
                    key = f"{model}/{rubric_type}"
                    test_entry[key] = {
                        "score": test_data["score"],
                        "max_score": test_data["max_score"],
                        "elapsed": test_data["elapsed"],
                    }
        comparison["tests"][test_id] = test_entry

    # COC vs bare deltas
    for sc in scorecards:
        coc = sc["rubrics"].get("coc")
        bare = sc["rubrics"].get("bare")
        if coc and bare:
            delta_entry = {
                "model": sc["model"],
                "coc_total": coc["total_score"],
                "bare_total": bare["total_score"],
                "delta": coc["total_score"] - bare["total_score"],
                "per_test": {},
            }
            for test_id in set(coc["tests"]) | set(bare["tests"]):
                c = coc["tests"].get(test_id, {}).get("score", 0)
                b = bare["tests"].get(test_id, {}).get("score", 0)
                delta_entry["per_test"][test_id] = {
                    "coc": c,
                    "bare": b,
                    "delta": c - b,
                }
            comparison["deltas"].append(delta_entry)

    return comparison


# ── Main ──────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="COC Implementation Eval — Comparison reports"
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Result JSON files to compare (default: all in results/)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    args = parser.parse_args()

    # Load results
    if args.files:
        result_pairs = []
        for f in args.files:
            path = Path(f)
            data = load_result_file(path)
            result_pairs.append((path.name, data))
    else:
        result_pairs = load_all_results()

    print(f"Loaded {len(result_pairs)} result file(s)\n")

    # Extract scorecards
    scorecards = []
    for fname, data in result_pairs:
        sc = extract_scorecard(data)
        scorecards.append(sc)
        print(f"  {fname}: {sc['model']} ({sc['mode']})")

    if args.format == "json":
        comparison = build_comparison_json(scorecards)
        print(json.dumps(comparison, indent=2))
        return

    # Table output
    print()

    # Individual scorecards
    for sc in scorecards:
        print(format_model_scorecard(sc))
        print()

    # Cross-model comparison (if >1 model)
    if len(scorecards) > 1:
        print(format_cross_model_comparison(scorecards))

    # COC vs bare delta
    print(format_coc_vs_bare_delta(scorecards))

    # Aggregate
    print(format_aggregate_summary(scorecards))
    print()


if __name__ == "__main__":
    main()
