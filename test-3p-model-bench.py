#!/usr/bin/env python3
"""COC compliance benchmark for third-party models via csq.

Runs real Claude Code instances against coc-env with each model,
scores COC compliance (tool usage, agent delegation, rule following,
skill awareness), and compares against Claude as baseline.

Reference environment: coc-env/ (all model benchmarks use this directory).
"""

import subprocess, json, os, sys, time, shutil, tempfile
from pathlib import Path

COC_ENV = Path(__file__).parent / "coc-env"
HOME = Path.home()
SETTINGS_BASE = HOME / ".claude/settings.json"

# Models to test. Each entry: (name, profile_name, model_override)
# profile_name maps to ~/.claude/settings-{name}.json
# model_override replaces ANTHROPIC_MODEL in the merged settings
MODELS = [
    ("gemma4",        "ollama", "gemma4:latest"),
    ("qwen3.5",       "ollama", "qwen3.5:latest"),
    ("glm-4.7-flash", "ollama", "glm-4.7-flash:latest"),
]

# Tasks that test specific COC behaviors
TASKS = [
    {
        "name": "tool-usage",
        "prompt": "List the files in the scripts/ directory and read the first one. Report what it does in one sentence.",
        "max_turns": 5,
        "checks": {
            "used_glob_or_ls": "Did the model use Glob/Bash to list files (not guess)?",
            "used_read": "Did the model use Read to read a file?",
            "gave_answer": "Did the model provide a meaningful answer?",
        }
    },
    {
        "name": "rule-following",
        "prompt": "I want to add a new utility function to this project. Before writing any code, tell me: what are the absolute directives from CLAUDE.md that I must follow? List them.",
        "max_turns": 3,
        "checks": {
            "read_claude_md": "Did the model read CLAUDE.md (not guess from memory)?",
            "listed_directives": "Did it list the actual directives (Framework-First, .env, Implement Don't Document)?",
            "no_fabrication": "Did it avoid fabricating directives that don't exist?",
        }
    },
    {
        "name": "agent-awareness",
        "prompt": "I need to add a new REST endpoint to this project. What agents are available to help me with this task? Which would you delegate to and why?",
        "max_turns": 3,
        "checks": {
            "knows_agents": "Did the model reference actual registered agents?",
            "would_delegate": "Did it express willingness to delegate rather than do everything itself?",
            "correct_agents": "Did it pick appropriate agents (e.g., deep-analyst, testing-specialist)?",
        }
    },
    {
        "name": "skill-awareness",
        "prompt": "What workflow skills are available in this project? If I wanted to start analyzing a new feature, which skill would I use?",
        "max_turns": 3,
        "checks": {
            "knows_skills": "Did the model reference actual registered skills?",
            "knows_analyze": "Did it identify /analyze as the starting point?",
            "knows_workflow": "Did it describe the 6-phase workflow (analyze→todos→implement→redteam→codify→wrapup)?",
        }
    },
]


def build_config(model_name, profile_name, model_override):
    """Build a temporary config dir with the profile merged in."""
    config_dir = Path(tempfile.mkdtemp(prefix=f"csq-bench-{model_name}-"))

    # Merge settings
    base = json.loads(SETTINGS_BASE.read_text())
    profile_path = HOME / f".claude/settings-{profile_name}.json"
    if profile_path.exists():
        overlay = json.loads(profile_path.read_text())
        def deep_merge(a, b):
            result = dict(a)
            for k, v in b.items():
                if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                    result[k] = deep_merge(result[k], v)
                else:
                    result[k] = v
            return result
        base = deep_merge(base, overlay)

    # Override model
    if model_override:
        base.setdefault("env", {})
        base["env"]["ANTHROPIC_MODEL"] = model_override
        for alias in ["ANTHROPIC_SMALL_FAST_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
                       "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL"]:
            base["env"][alias] = model_override

    (config_dir / "settings.json").write_text(json.dumps(base, indent=2))
    (config_dir / ".claude.json").write_text('{"hasCompletedOnboarding": true}')

    # Symlink shared dirs
    for item in ["projects", "commands", "agents", "skills", "memory"]:
        src = HOME / f".claude/{item}"
        dst = config_dir / item
        if src.exists() and not dst.exists():
            dst.symlink_to(src)

    return config_dir


def run_task(model_name, config_dir, task):
    """Run a single task and return the raw result."""
    env = os.environ.copy()
    env["CLAUDE_CONFIG_DIR"] = str(config_dir)

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["claude", "--print", task["prompt"],
             "--output-format", "json",
             "--max-turns", str(task.get("max_turns", 3)),
             "--dangerously-skip-permissions"],
            capture_output=True, text=True, timeout=300,
            cwd=str(COC_ENV), env=env,
        )
        elapsed = time.monotonic() - start
        if result.returncode != 0:
            return {"ok": False, "error": result.stderr[:500], "elapsed": elapsed}

        data = json.loads(result.stdout)
        return {
            "ok": True,
            "elapsed": elapsed,
            "result": data.get("result", ""),
            "input_tokens": data.get("usage", {}).get("input_tokens", 0),
            "output_tokens": data.get("usage", {}).get("output_tokens", 0),
            "num_turns": data.get("num_turns", 0),
            "session_id": data.get("session_id", ""),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout (300s)", "elapsed": 300}
    except Exception as e:
        return {"ok": False, "error": str(e), "elapsed": time.monotonic() - start}


def main():
    print(f"COC Compliance Benchmark")
    print(f"Reference environment: {COC_ENV}")
    print(f"Models: {', '.join(m[0] for m in MODELS)}")
    print(f"Tasks: {', '.join(t['name'] for t in TASKS)}")
    print(f"{'='*70}\n")

    all_results = {}

    for model_name, profile, model_override in MODELS:
        print(f"\n{'─'*70}")
        print(f"MODEL: {model_name}")
        print(f"{'─'*70}")

        config_dir = build_config(model_name, profile, model_override)
        model_results = {}

        for task in TASKS:
            print(f"\n  Task: {task['name']}...")
            r = run_task(model_name, config_dir, task)

            if not r["ok"]:
                print(f"    ✗ FAILED: {r['error']}")
                model_results[task["name"]] = {"ok": False, "error": r["error"]}
                continue

            print(f"    ✓ {r['elapsed']:.1f}s | {r['input_tokens']} in → {r['output_tokens']} out | {r['num_turns']} turns")
            print(f"    Response preview:")
            for line in r["result"].split("\n")[:6]:
                print(f"      {line[:100]}")
            if len(r["result"].split("\n")) > 6:
                print(f"      ... ({len(r['result'].split(chr(10)))} lines)")

            model_results[task["name"]] = r

        # Cleanup
        shutil.rmtree(config_dir, ignore_errors=True)
        all_results[model_name] = model_results

    # Summary
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"\n{'Model':<20} ", end="")
    for t in TASKS:
        print(f"{t['name']:<18} ", end="")
    print(f"{'Total time':>12}")

    print(f"{'-'*20} ", end="")
    for _ in TASKS:
        print(f"{'-'*18} ", end="")
    print(f"{'-'*12}")

    for model_name, results in all_results.items():
        print(f"{model_name:<20} ", end="")
        total_time = 0
        for t in TASKS:
            r = results.get(t["name"], {})
            if r.get("ok"):
                total_time += r["elapsed"]
                turns = r.get("num_turns", "?")
                print(f"{'✓':>1} {r['elapsed']:>5.0f}s {turns}t      ", end="")
            else:
                print(f"{'✗':>1} FAIL           ", end="")
        print(f"{total_time:>10.0f}s")

    # Save results
    results_path = Path(__file__).parent / "bench-results.json"
    with open(results_path, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "models": {name: profile for name, profile, _ in MODELS},
            "results": {
                model: {
                    task: {
                        "ok": r.get("ok", False),
                        "elapsed": r.get("elapsed", 0),
                        "input_tokens": r.get("input_tokens", 0),
                        "output_tokens": r.get("output_tokens", 0),
                        "num_turns": r.get("num_turns", 0),
                        "result": r.get("result", "")[:2000],
                    }
                    for task, r in tasks.items()
                }
                for model, tasks in all_results.items()
            }
        }, f, indent=2)
    print(f"\nResults saved to {results_path}")


if __name__ == "__main__":
    main()
