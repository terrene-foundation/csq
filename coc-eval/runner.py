#!/usr/bin/env python3
"""COC Implementation Eval — Main orchestrator.

Tests implementation capability: can the model diagnose and fix real
coding problems when guided by COC artifacts?

Unlike test-coc-bench.py (which tests rule obedience), this eval tests
whether the model can actually DO the work that COC rules describe.

Usage:
  # Full eval (COC + bare comparison)
  python3 coc-eval/runner.py default "Claude Opus 4.6" --mode full

  # COC-only
  python3 coc-eval/runner.py zai "Z.AI GLM-5.1" --mode coc-only

  # Bare-only baseline
  python3 coc-eval/runner.py mm "MiniMax M2.7" --mode bare-only

  # Specific tests
  python3 coc-eval/runner.py default "Claude Opus" --tests EVAL-A004,EVAL-P003

  # Ablation (strip specific COC layers)
  python3 coc-eval/runner.py default "Claude Opus" --mode ablation --ablation-group no-rules
"""

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Resolve paths relative to this file
EVAL_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = EVAL_DIR.parent.resolve()
COC_ENV = PROJECT_ROOT / "coc-env"
HOME = Path.home()

# Import scoring from same directory
sys.path.insert(0, str(EVAL_DIR))
from scoring import score_test


# ── Test loader ───────────────────────────────────────────────────────


def load_all_tests():
    """Load all test definitions from tests/ directory.

    Returns dict of test_id -> test_def.
    """
    tests_dir = EVAL_DIR / "tests"
    test_defs = {}

    for py_file in sorted(tests_dir.glob("eval_*.py")):
        module_name = py_file.stem
        spec = importlib.util.spec_from_file_location(
            f"tests.{module_name}", str(py_file)
        )
        if spec is None:
            raise ImportError(f"Cannot load test module: {py_file}")
        if spec.loader is None:
            raise ImportError(f"No loader for test module: {py_file}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        test_def = getattr(mod, "TEST_DEF", None)
        if test_def is None:
            raise ValueError(f"Test module {py_file} has no TEST_DEF")
        test_id = test_def["id"]
        test_defs[test_id] = test_def

    if not test_defs:
        raise FileNotFoundError(f"No test definitions found in {tests_dir}")

    return test_defs


def filter_tests(test_defs, test_ids_csv):
    """Filter test definitions to only the requested test IDs.

    Args:
        test_defs: Dict of all test definitions.
        test_ids_csv: Comma-separated test IDs (e.g. "EVAL-A004,EVAL-P003").

    Returns:
        Filtered dict of test_id -> test_def.

    Raises:
        ValueError: If a requested test ID is not found.
    """
    requested = [tid.strip() for tid in test_ids_csv.split(",")]
    filtered = {}
    for tid in requested:
        if tid not in test_defs:
            available = ", ".join(sorted(test_defs.keys()))
            raise ValueError(f"Test {tid!r} not found. Available: {available}")
        filtered[tid] = test_defs[tid]
    return filtered


# ── Environment management ────────────────────────────────────────────


def reset_coc_env():
    """Reset coc-env to a clean state. Call before each test."""
    if not COC_ENV.exists():
        raise FileNotFoundError(
            f"COC environment not found at {COC_ENV}. "
            f"Expected a git repository at this path."
        )
    # Restore tracked files
    subprocess.run(
        ["git", "checkout", "--", "."],
        cwd=COC_ENV,
        capture_output=True,
        check=False,
    )
    # Remove untracked files (test artifacts)
    subprocess.run(
        ["git", "clean", "-fd"],
        cwd=COC_ENV,
        capture_output=True,
        check=False,
    )
    # Clear journal pending entries from test runs
    pending = COC_ENV / "workspaces" / "_template" / "journal" / ".pending"
    if pending.exists():
        shutil.rmtree(pending, ignore_errors=True)


def setup_scaffold(test_def):
    """Copy scaffold files into coc-env working directory.

    The scaffold directory is copied into coc-env so the model can
    read and modify the files during the test.
    """
    scaffold_name = test_def.get("scaffold")
    if not scaffold_name:
        raise ValueError(f"Test {test_def['id']} has no scaffold defined")

    scaffold_dir = EVAL_DIR / "scaffolds" / scaffold_name
    if not scaffold_dir.exists():
        raise FileNotFoundError(f"Scaffold directory not found: {scaffold_dir}")

    # Copy scaffold files into coc-env
    scaffold_files = test_def.get("scaffold_files", [])
    if not scaffold_files:
        raise ValueError(f"Test {test_def['id']} has no scaffold_files listed")

    copied = []
    for rel_path in scaffold_files:
        src = scaffold_dir / rel_path
        dst = COC_ENV / rel_path

        if not src.exists():
            raise FileNotFoundError(
                f"Scaffold file not found: {src} "
                f"(listed in test {test_def['id']} scaffold_files)"
            )

        # Create parent directories
        dst.parent.mkdir(parents=True, exist_ok=True)

        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
        copied.append(rel_path)

    return copied


def capture_artifacts():
    """Capture git diff and new files in coc-env after a test runs.

    Returns a dict of file changes so we can see exactly what the model
    wrote — not just what it said it wrote.

    Note: coc-env is a subdirectory of the parent git repo, so all git
    commands use '-- .' to scope to the coc-env directory only. Without
    this, changes in sibling directories would bleed into artifacts.
    """
    artifacts = {}

    # Tracked file changes (scoped to coc-env/ only)
    diff = subprocess.run(
        ["git", "diff", "--stat", "--", "."],
        cwd=COC_ENV,
        capture_output=True,
        text=True,
        check=False,
    )
    if diff.stdout.strip():
        artifacts["git_diff_stat"] = diff.stdout.strip()
        # Get the actual diff content
        full_diff = subprocess.run(
            ["git", "diff", "--", "."],
            cwd=COC_ENV,
            capture_output=True,
            text=True,
            check=False,
        )
        artifacts["git_diff"] = full_diff.stdout[:10000]

    # New untracked files (scoped to coc-env/ only).
    # git status --porcelain paths are relative to repo root, so we
    # need to compute the prefix to filter and remap paths.
    repo_root_result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=COC_ENV,
        capture_output=True,
        text=True,
        check=False,
    )
    repo_root = (
        Path(repo_root_result.stdout.strip())
        if repo_root_result.returncode == 0
        else COC_ENV.parent
    )
    coc_prefix = str(COC_ENV.relative_to(repo_root)) + "/"

    status = subprocess.run(
        ["git", "status", "--porcelain", "-u", "--", "."],
        cwd=COC_ENV,
        capture_output=True,
        text=True,
        check=False,
    )
    new_files = {}
    for line in status.stdout.strip().splitlines():
        if line.startswith("??"):
            raw_path = line[3:].strip()
            # Strip the coc-env/ prefix if present (porcelain paths
            # are relative to repo root, not cwd)
            if raw_path.startswith(coc_prefix):
                rel_path = raw_path[len(coc_prefix) :]
            else:
                rel_path = raw_path
            full = COC_ENV / rel_path
            if full.is_file() and full.stat().st_size < 50000:
                try:
                    new_files[rel_path] = full.read_text()[:5000]
                except Exception:
                    new_files[rel_path] = "<binary or unreadable>"
    if new_files:
        artifacts["new_files"] = new_files

    return artifacts


# ── Config builders ───────────────────────────────────────────────────


def _load_base_settings(profile, model_override=None):
    """Load and merge base settings with profile overlay.

    Returns the merged settings dict.
    """
    settings_path = HOME / ".claude/settings.json"
    if not settings_path.exists():
        raise FileNotFoundError(
            f"Base settings not found at {settings_path}. "
            f"Claude Code must be configured before running the eval."
        )
    base = json.loads(settings_path.read_text())

    # Merge profile overlay
    overlay_path = HOME / f".claude/settings-{profile}.json"
    if (
        profile != "default"
        and overlay_path.exists()
        and overlay_path.stat().st_size > 0
    ):
        overlay = json.loads(overlay_path.read_text())
        base = _deep_merge(base, overlay)

    # Override model if specified
    if model_override:
        base.setdefault("env", {})
        for alias in [
            "ANTHROPIC_MODEL",
            "ANTHROPIC_SMALL_FAST_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        ]:
            base["env"][alias] = model_override

    return base


def _deep_merge(a, b):
    """Deep merge dict b into dict a. b wins on conflicts."""
    result = dict(a)
    for k, v in b.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _symlink_shared_dirs(config_dir):
    """Symlink shared Claude Code directories into config dir."""
    for item in ["projects", "commands", "agents", "skills", "memory"]:
        src = HOME / f".claude/{item}"
        dst = config_dir / item
        if src.exists() and not dst.exists():
            dst.symlink_to(src)


def _symlink_credentials(config_dir):
    """Symlink credentials for OAuth-based profiles.

    MUST symlink, never copy — copying kills the token via rotation.
    """
    creds = HOME / ".claude/credentials.json"
    if not creds.exists():
        for i in range(1, 10):
            creds = HOME / f".claude/accounts/config-{i}/.credentials.json"
            if creds.exists():
                break
    if creds.exists():
        dst = config_dir / ".credentials.json"
        if not dst.exists():
            dst.symlink_to(creds)


def build_coc_config(profile, model_override=None):
    """Build config dir with full COC environment.

    This is the standard configuration: CLAUDE.md + .claude/rules/ +
    .claude/agents/ + .claude/skills/ — the model gets the full
    COC artifact set.
    """
    config_dir = Path(tempfile.mkdtemp(prefix="csq-eval-coc-"))

    base = _load_base_settings(profile, model_override)
    (config_dir / "settings.json").write_text(json.dumps(base, indent=2))
    (config_dir / ".claude.json").write_text('{"hasCompletedOnboarding": true}')

    _symlink_shared_dirs(config_dir)
    _symlink_credentials(config_dir)

    return config_dir


def build_bare_config(profile, model_override=None):
    """Build config dir with minimal environment (no COC artifacts).

    Only CLAUDE.md is available. No .claude/rules/, no .claude/agents/,
    no .claude/skills/. This isolates the model's raw capability from
    COC-guided capability.
    """
    config_dir = Path(tempfile.mkdtemp(prefix="csq-eval-bare-"))

    base = _load_base_settings(profile, model_override)

    # Strip COC-specific settings that reference .claude/ artifacts
    # The bare config should not point to system prompts that load COC rules
    for key in ("systemPromptFile", "appendSystemPromptFile"):
        base.pop(key, None)

    (config_dir / "settings.json").write_text(json.dumps(base, indent=2))
    (config_dir / ".claude.json").write_text('{"hasCompletedOnboarding": true}')

    # Do NOT symlink agents, skills, or rules — that is the point of bare mode
    # Only symlink projects (for project context) and credentials (for auth)
    for item in ["projects", "memory"]:
        src = HOME / f".claude/{item}"
        dst = config_dir / item
        if src.exists() and not dst.exists():
            dst.symlink_to(src)

    _symlink_credentials(config_dir)

    return config_dir


def build_ablation_config(profile, ablation_group, model_override=None):
    """Build config dir with specific COC layers stripped for ablation.

    Ablation groups:
      no-rules:   Strip .claude/rules/ (keep agents, skills)
      no-agents:  Strip .claude/agents/ (keep rules, skills)
      no-skills:  Strip .claude/skills/ (keep rules, agents)
      rules-only: Keep only .claude/rules/ (strip agents, skills)
    """
    valid_groups = ("no-rules", "no-agents", "no-skills", "rules-only")
    if ablation_group not in valid_groups:
        raise ValueError(
            f"Invalid ablation group: {ablation_group!r}. "
            f"Valid groups: {', '.join(valid_groups)}"
        )

    config_dir = Path(tempfile.mkdtemp(prefix=f"csq-eval-abl-{ablation_group}-"))

    base = _load_base_settings(profile, model_override)
    (config_dir / "settings.json").write_text(json.dumps(base, indent=2))
    (config_dir / ".claude.json").write_text('{"hasCompletedOnboarding": true}')

    # Determine which dirs to symlink based on ablation group
    include_map = {
        "no-rules": ["agents", "skills"],
        "no-agents": ["rules", "skills"],
        "no-skills": ["rules", "agents"],
        "rules-only": ["rules"],
    }
    include = include_map[ablation_group]

    # Always include these
    for item in ["projects", "memory", "commands"]:
        src = HOME / f".claude/{item}"
        dst = config_dir / item
        if src.exists() and not dst.exists():
            dst.symlink_to(src)

    # Conditionally include COC layers
    for item in include:
        src = HOME / f".claude/{item}"
        dst = config_dir / item
        if src.exists() and not dst.exists():
            dst.symlink_to(src)

    _symlink_credentials(config_dir)

    return config_dir


# ── Test execution ────────────────────────────────────────────────────


def run_test(config_dir, test_def, timeout=None):
    """Run a single test in a clean environment.

    Returns a result dict with ok, elapsed, result, tokens, artifacts.
    """
    test_timeout = timeout or test_def.get("timeout", 600)
    max_turns = test_def.get("max_turns", 10)

    env = os.environ.copy()
    # Strip ANTHROPIC_* vars so settings.json in the isolated config_dir is
    # the sole source of model routing. Prevents parent session env vars from
    # overriding the eval profile and contaminating other sessions.
    for key in list(env.keys()):
        if key.startswith("ANTHROPIC_"):
            del env[key]
    env["CLAUDE_CONFIG_DIR"] = str(config_dir)

    start = time.monotonic()
    try:
        result = subprocess.run(
            [
                "claude",
                "--print",
                test_def["prompt"],
                "--output-format",
                "json",
                "--max-turns",
                str(max_turns),
                "--dangerously-skip-permissions",
            ],
            capture_output=True,
            text=True,
            timeout=test_timeout,
            cwd=str(COC_ENV),
            env=env,
        )
        elapsed = time.monotonic() - start

        # Capture what the model actually did to the filesystem
        artifacts = capture_artifacts()

        if result.returncode != 0:
            error_msg = result.stderr[:1000].strip()
            if not error_msg:
                error_msg = f"exit code {result.returncode} (no stderr)"
            return {
                "ok": False,
                "error": error_msg,
                "elapsed": elapsed,
                "num_turns": 0,
                "result": "",
                "input_tokens": 0,
                "output_tokens": 0,
                "artifacts": artifacts,
            }

        data = json.loads(result.stdout)
        return {
            "ok": True,
            "elapsed": elapsed,
            "result": data.get("result", ""),
            "input_tokens": data.get("usage", {}).get("input_tokens", 0),
            "output_tokens": data.get("usage", {}).get("output_tokens", 0),
            "num_turns": data.get("num_turns", 0),
            "artifacts": artifacts,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"timeout ({test_timeout}s)",
            "elapsed": test_timeout,
            "num_turns": 0,
            "result": "",
            "input_tokens": 0,
            "output_tokens": 0,
            "artifacts": capture_artifacts(),
        }
    except json.JSONDecodeError as e:
        return {
            "ok": False,
            "error": f"JSON decode error: {e}",
            "elapsed": time.monotonic() - start,
            "num_turns": 0,
            "result": "",
            "input_tokens": 0,
            "output_tokens": 0,
            "artifacts": capture_artifacts(),
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "elapsed": time.monotonic() - start,
            "num_turns": 0,
            "result": "",
            "input_tokens": 0,
            "output_tokens": 0,
            "artifacts": {},
        }


# ── Run modes ─────────────────────────────────────────────────────────


def run_eval_pass(config_dir, test_defs, rubric_type, label, timeout=None):
    """Run a full eval pass (all tests) with a given config.

    Returns list of per-test result dicts.
    """
    results = []
    total_tests = len(test_defs)

    for i, (test_id, test_def) in enumerate(test_defs.items(), 1):
        # Clean environment before each test
        reset_coc_env()

        print(
            f"\n  [{i}/{total_tests}] {test_id} — {test_def['name']} "
            f"({test_def['type']})..."
        )

        # Set up scaffold
        try:
            copied = setup_scaffold(test_def)
            print(f"      Scaffold: {len(copied)} files copied")
        except (FileNotFoundError, ValueError) as e:
            print(f"      SCAFFOLD ERROR: {e}")
            results.append(
                {
                    "test_id": test_id,
                    "test_name": test_def["name"],
                    "rubric": rubric_type,
                    "ok": False,
                    "error": f"scaffold setup failed: {e}",
                    "score": {"total": 0, "max_total": test_def["max_points"]},
                }
            )
            continue

        # Execute test (retry once on empty-response failures)
        run_result = run_test(config_dir, test_def, timeout)
        if not run_result["ok"] and not run_result.get("result") and run_result.get("output_tokens", 0) == 0:
            print(f"      Empty response (rc={run_result.get('error', '?')}), retrying...")
            reset_coc_env()
            setup_scaffold(test_def)
            run_result = run_test(config_dir, test_def, timeout)

        # Score
        if run_result["ok"]:
            score = score_test(
                test_def,
                run_result["result"],
                run_result.get("artifacts", {}),
                rubric_type=rubric_type,
            )
            preview = run_result["result"][:200].replace("\n", " ")
            print(f"      Score: {score['summary']}")
            print(
                f"      {run_result['elapsed']:.1f}s, "
                f"{run_result['num_turns']} turns, "
                f"{run_result['input_tokens']}in/{run_result['output_tokens']}out tokens"
            )
            print(f"      Preview: {preview}...")
            for t in score["tiers"]:
                print(
                    f"        {t['name']}: {t['points']}/{t['max_points']} "
                    f"({t['reason']})"
                )
            if run_result.get("artifacts"):
                arts = run_result["artifacts"]
                if arts.get("new_files"):
                    print(f"      Artifacts: {list(arts['new_files'].keys())}")
                if arts.get("git_diff_stat"):
                    print(f"      Changes: {arts['git_diff_stat'][:120]}")
        else:
            score = {
                "total": 0,
                "max_total": test_def["max_points"],
                "tiers": [],
                "summary": f"0/{test_def['max_points']} (FAIL)",
            }
            print(f"      Score: 0 (FAIL: {run_result.get('error', 'unknown')[:200]})")

        results.append(
            {
                "test_id": test_id,
                "test_name": test_def["name"],
                "test_type": test_def["type"],
                "rubric": rubric_type,
                "ok": run_result["ok"],
                "error": run_result.get("error"),
                "elapsed": run_result.get("elapsed", 0),
                "num_turns": run_result.get("num_turns", 0),
                "input_tokens": run_result.get("input_tokens", 0),
                "output_tokens": run_result.get("output_tokens", 0),
                "score": score,
                "artifacts": run_result.get("artifacts", {}),
                "response_preview": run_result.get("result", "")[:500],
            }
        )

    return results


def print_summary(label, results, rubric_type):
    """Print a summary table for one eval pass."""
    total_score = sum(r["score"]["total"] for r in results)
    total_max = sum(r["score"]["max_total"] for r in results)
    total_time = sum(r.get("elapsed", 0) for r in results)
    total_in = sum(r.get("input_tokens", 0) for r in results)
    total_out = sum(r.get("output_tokens", 0) for r in results)

    print(f"\n  {rubric_type.upper()} RESULTS: {label}")
    print(f"  {'=' * 60}")
    for r in results:
        s = r["score"]
        print(f"    {r['test_id']:<12} {r['test_name']:<35} {s['total']}/{s['max_total']}")
    print(f"  {'-' * 60}")
    print(f"    {'TOTAL':<12} {'':35} {total_score}/{total_max}")
    print(f"    Time: {total_time:.1f}s | Tokens: {total_in}in / {total_out}out")
    return total_score, total_max


# ── Main ──────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="COC Implementation Eval — Tests implementation capability"
    )
    parser.add_argument(
        "profile",
        help="Settings profile (mm, ollama, zai, default)",
    )
    parser.add_argument(
        "label",
        help="Model display name (e.g. 'Claude Opus 4.6')",
    )
    parser.add_argument(
        "--mode",
        choices=["full", "coc-only", "bare-only", "ablation"],
        default="full",
        help="Eval mode: full (COC+bare), coc-only, bare-only, ablation",
    )
    parser.add_argument(
        "--tests",
        help="Comma-separated test IDs to run (e.g. EVAL-A004,EVAL-P003)",
    )
    parser.add_argument(
        "--model-override",
        help="Override ANTHROPIC_MODEL env var",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Per-test timeout in seconds (overrides test-level timeout)",
    )
    parser.add_argument(
        "--ablation-group",
        help="Ablation group: no-rules, no-agents, no-skills, rules-only",
    )
    args = parser.parse_args()

    # Validate ablation args
    if args.mode == "ablation" and not args.ablation_group:
        parser.error("--ablation-group is required when --mode=ablation")

    # Load tests
    all_tests = load_all_tests()
    if args.tests:
        test_defs = filter_tests(all_tests, args.tests)
    else:
        test_defs = all_tests

    test_count = len(test_defs)
    test_max = sum(t["max_points"] for t in test_defs.values())

    print(f"COC Implementation Eval")
    print(f"Model: {args.label} (profile: {args.profile})")
    print(f"Mode: {args.mode}")
    print(f"Tests: {test_count} ({test_max} base points per pass)")
    print(f"Environment: {COC_ENV}")
    if args.timeout:
        print(f"Timeout override: {args.timeout}s/test")
    if args.ablation_group:
        print(f"Ablation: {args.ablation_group}")
    print(f"{'=' * 70}\n")

    all_results = {}

    # ── COC pass ──
    if args.mode in ("full", "coc-only"):
        print(f"\n{'~' * 70}")
        print(f"  COC PASS ({test_count} tests)")
        print(f"{'~' * 70}")

        coc_config = build_coc_config(args.profile, args.model_override)
        settings = json.loads((coc_config / "settings.json").read_text())
        model_id = settings.get("env", {}).get("ANTHROPIC_MODEL", "default")
        print(f"  Config: {coc_config}")
        print(f"  Model: {model_id}")

        coc_results = run_eval_pass(
            coc_config, test_defs, "coc", args.label, args.timeout
        )
        all_results["coc"] = coc_results
        coc_total, coc_max = print_summary(args.label, coc_results, "coc")

    # ── Bare pass ──
    if args.mode in ("full", "bare-only"):
        print(f"\n{'~' * 70}")
        print(f"  BARE PASS ({test_count} tests)")
        print(f"{'~' * 70}")

        bare_config = build_bare_config(args.profile, args.model_override)
        settings = json.loads((bare_config / "settings.json").read_text())
        model_id = settings.get("env", {}).get("ANTHROPIC_MODEL", "default")
        print(f"  Config: {bare_config}")
        print(f"  Model: {model_id}")

        bare_results = run_eval_pass(
            bare_config, test_defs, "bare", args.label, args.timeout
        )
        all_results["bare"] = bare_results
        bare_total, bare_max = print_summary(args.label, bare_results, "bare")

    # ── Ablation pass ──
    if args.mode == "ablation":
        print(f"\n{'~' * 70}")
        print(f"  ABLATION PASS: {args.ablation_group} ({test_count} tests)")
        print(f"{'~' * 70}")

        abl_config = build_ablation_config(
            args.profile, args.ablation_group, args.model_override
        )
        settings = json.loads((abl_config / "settings.json").read_text())
        model_id = settings.get("env", {}).get("ANTHROPIC_MODEL", "default")
        print(f"  Config: {abl_config}")
        print(f"  Model: {model_id}")

        abl_results = run_eval_pass(
            abl_config,
            test_defs,
            f"ablation-{args.ablation_group}",
            args.label,
            args.timeout,
        )
        all_results[f"ablation-{args.ablation_group}"] = abl_results
        print_summary(args.label, abl_results, f"ablation-{args.ablation_group}")

    # ── Delta summary (full mode) ──
    if args.mode == "full" and "coc" in all_results and "bare" in all_results:
        print(f"\n{'=' * 70}")
        print(f"  COC VALUE-ADD DELTA: {args.label}")
        print(f"{'=' * 70}")

        coc_by_id = {r["test_id"]: r for r in all_results["coc"]}
        bare_by_id = {r["test_id"]: r for r in all_results["bare"]}

        total_delta = 0
        total_max = 0
        coc_total = 0
        bare_total = 0
        for test_id in test_defs:
            coc_r = coc_by_id.get(test_id, {})
            bare_r = bare_by_id.get(test_id, {})
            coc_s = coc_r.get("score", {}).get("total", 0)
            bare_s = bare_r.get("score", {}).get("total", 0)
            test_max = test_defs[test_id]["max_points"]
            total_max += test_max
            coc_total += coc_s
            bare_total += bare_s
            delta = coc_s - bare_s
            total_delta += delta
            sign = "+" if delta > 0 else ""
            print(
                f"    {test_id:<12} COC={coc_s}/{test_max}  "
                f"Bare={bare_s}/{test_max}  Delta={sign}{delta}"
            )
        print(f"  {'-' * 60}")
        sign = "+" if total_delta > 0 else ""
        print(
            f"    {'TOTAL':<12} COC={coc_total}/{total_max}  "
            f"Bare={bare_total}/{total_max}  Delta={sign}{total_delta}"
        )

    # ── Final reset ──
    reset_coc_env()

    # ── Save results ──
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    output = {
        "timestamp": timestamp,
        "model": args.label,
        "profile": args.profile,
        "mode": args.mode,
        "ablation_group": args.ablation_group,
        "test_count": test_count,
        "results": {},
    }

    for rubric_type, results in all_results.items():
        # Strip large artifacts from saved results to keep file size reasonable
        clean_results = []
        for r in results:
            clean = dict(r)
            arts = clean.get("artifacts", {})
            # Keep diff stat but truncate full diff
            if "git_diff" in arts:
                clean["artifacts"] = dict(arts)
                clean["artifacts"]["git_diff"] = arts["git_diff"][:3000]
            clean_results.append(clean)
        output["results"][rubric_type] = clean_results

    results_dir = EVAL_DIR / "results"
    results_dir.mkdir(exist_ok=True)
    out_name = f"eval-{args.profile}-{args.mode}"
    if args.ablation_group:
        out_name += f"-{args.ablation_group}"
    out_path = results_dir / f"{out_name}.json"
    out_path.write_text(json.dumps(output, indent=2, default=str))
    print(f"\n  Saved: {out_path}")

    # Return grand total for exit code
    grand = sum(
        r["score"]["total"] for results in all_results.values() for r in results
    )
    return grand


if __name__ == "__main__":
    score = main()
    sys.exit(0 if score > 0 else 1)
