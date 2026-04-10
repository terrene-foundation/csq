"""EVAL-A004 — Hook Security Audit.

Source: SC-A-004 (Audit Layer 3 Hooks for Vulnerabilities)
Type: Analysis (read scaffold code, produce written audit)
"""

TEST_DEF = {
    "id": "EVAL-A004",
    "name": "Hook Security Audit",
    "type": "analysis",
    "source": "SC-A-004",
    "difficulty": "intermediate",
    "max_points": 10,
    "max_turns": 10,
    "timeout": 600,
    "scaffold": "eval-a004",
    "scaffold_files": [
        "scripts/hooks/session-start.js",
        "scripts/hooks/pre-commit-validate.js",
    ],
    "prompt": (
        "The scripts/hooks/ directory contains session lifecycle hooks that run "
        "outside the AI's context window with shell access. Audit them for security "
        "vulnerabilities. For each hook:\n"
        "(1) List all external input sources (data from files, environment variables, "
        "git state, or network responses) with their line references.\n"
        "(2) Classify each input source's consumption as SAFE, UNSAFE, or CONDITIONAL "
        "with a one-sentence rationale.\n"
        "(3) Identify the most critical vulnerability across both hooks and explain why "
        "it is worse in a hook than in application code. Provide a concrete exploit scenario.\n"
        "(4) Propose specific code fixes for every UNSAFE consumption point — actual code "
        "changes, not general recommendations.\n"
        "(5) Identify at least one consumption point that looks suspicious but is actually "
        "safe (a false positive) and explain why dismissing it is correct."
    ),
    "scoring": {
        "tiers": [
            {
                "name": "input_inventory",
                "points": 3,
                "description": "External input sources identified in both hooks",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)version_url|versionData\.version_url",
                        r"(?i)CLAUDE_WORKSPACE_DIR|workspace.dir|env\.CLAUDE",
                        r"(?i)git diff.*cached|staged.*files?|git.*name.only",
                        r"(?i)execSync|exec.*curl|shell.*inject",
                    ],
                    "partial": [
                        r"(?i)external.*input|input.*source",
                        r"(?i)environment.*var|env.*var",
                        r"(?i)file.*read|readFile",
                    ],
                },
            },
            {
                "name": "classification_accuracy",
                "points": 3,
                "description": "SAFE/UNSAFE/CONDITIONAL classifications with rationale",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)UNSAFE.*(?:execSync|version_url|command.inject|shell.inject)",
                        r"(?i)UNSAFE.*(?:CLAUDE_WORKSPACE|path.traversal|workspace.dir)",
                        r"(?i)(?:SAFE|CONDITIONAL).*(?:execFileSync|git.*rev.parse|readFileSync)",
                    ],
                    "partial": [
                        r"(?i)UNSAFE",
                        r"(?i)SAFE|CONDITIONAL",
                    ],
                },
            },
            {
                "name": "vulnerability_analysis",
                "points": 2,
                "description": "Critical vulnerability identified with hook-vs-app reasoning",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)command.inject|shell.inject|execSync.*version_url",
                        r"(?i)hook.*(?:outside|before|without).*(?:context|AI|sandbox|oversight)",
                    ],
                    "partial": [
                        r"(?i)inject|traversal|critical|vuln",
                    ],
                },
            },
            {
                "name": "code_fixes",
                "points": 1,
                "description": "Specific code fixes for UNSAFE points",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)execFileSync.*curl|execFileSync\s*\(\s*['\"]curl['\"]",
                    ],
                    "partial": [
                        r"(?i)(?:fix|replace|change|instead|resolve|startsWith)",
                    ],
                },
            },
            {
                "name": "false_positive",
                "points": 1,
                "description": "At least one false positive correctly dismissed",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:false.positive|looks.*suspicious.*(?:safe|not)|safe.*despite|actually.*safe)",
                    ],
                    "partial": [
                        r"(?i)(?:safe|benign|not.*vuln|harmless)",
                    ],
                },
            },
        ],
    },
    "expected_answer_signals": [
        "execSync with version_url is command injection (V1)",
        "CLAUDE_WORKSPACE_DIR is path traversal (V2)",
        "Hook runs outside AI context with full shell privileges",
        "Replace execSync with execFileSync for the curl call",
        "Validate/resolve workspace dir against project root",
        "git rev-parse output via execFileSync is safe (false positive)",
    ],
}
