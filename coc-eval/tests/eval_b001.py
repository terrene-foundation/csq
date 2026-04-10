"""EVAL-B001 — Read-Then-Merge Sync Plan.

Source: SC-B-001 (Read-then-Merge Sync Semantics)
Type: Brokerage (classify + plan, no execution)
"""

TEST_DEF = {
    "id": "EVAL-B001",
    "name": "Read-Then-Merge Sync Plan",
    "type": "brokerage",
    "source": "SC-B-001",
    "difficulty": "intermediate",
    "max_points": 10,
    "max_turns": 10,
    "timeout": 600,
    "scaffold": "eval-b001",
    "scaffold_files": [
        "manifest.yaml",
        "source/config.json",
        "source/schema.sql",
        "source/deploy.sh",
        "source/README.md",
        "source/auth.py",
        "source/utils.py",
        "source/middleware.py",
        "source/logging.conf",
        "source/routes.py",
        "source/health.py",
        "target/config.json",
        "target/schema.sql",
        "target/deploy.sh",
        "target/README.md",
        "target/auth.py",
        "target/utils.py",
        "target/middleware.py",
        "target/logging.conf",
        "target/routes.py",
        "target/monitoring.py",
    ],
    "prompt": (
        "You need to sync the source/ directory into the target/ directory. Both "
        "directories contain files for a governance API project.\n\n"
        "Sync protocol rules:\n"
        "  - Sync is ADDITIVE: target-only files are never deleted.\n"
        "  - Per-file diff is mandatory: no bulk overwrite.\n"
        "  - Content drifts where the target has newer/richer content require a decision.\n\n"
        "Your tasks:\n"
        "1. Read ALL files in both source/ and target/.\n"
        "2. For each file, classify the relationship between source and target as one of:\n"
        "   IDENTICAL (same content), OVERWRITE (source wins — source is strictly newer), "
        "MERGE (both have changes that should be combined), NEW (source only — copy to target), "
        "LOCAL (target only — preserve), SKIP (no action needed)\n"
        "3. Produce a sync plan as a table with columns: file, classification, reason.\n"
        "4. Do NOT execute the sync — plan only.\n"
        "5. State how many files a bulk rsync would have damaged and what content would be lost."
    ),
    # Expected classifications for scoring:
    # config.json    -> OVERWRITE (source has audit_trail feature, newer version)
    # schema.sql     -> OVERWRITE (source has audit_events table, clearance_level)
    # deploy.sh      -> IDENTICAL / SKIP
    # README.md      -> IDENTICAL / SKIP
    # auth.py        -> IDENTICAL / SKIP
    # utils.py       -> IDENTICAL / SKIP
    # middleware.py   -> MERGE (source has rate limit 200, target has request_id_middleware)
    # logging.conf   -> IDENTICAL / SKIP
    # routes.py      -> IDENTICAL / SKIP
    # health.py      -> NEW (source only, copy to target)
    # monitoring.py  -> LOCAL (target only, preserve)
    "scoring": {
        "tiers": [
            {
                "name": "classification_accuracy",
                "points": 5,
                "description": "Correct classification for each file pair (1 per 2 files)",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        # Must get the non-trivial ones right
                        r"(?i)middleware.*(?:merge|both|combine|drift)",
                        r"(?i)health.*(?:new|source.only|copy|add)",
                        r"(?i)monitoring.*(?:local|target.only|preserve|keep)",
                        r"(?i)(?:deploy|logging|routes|utils).*(?:identical|skip|same|no.change|no.action)",
                        r"(?i)(?:config|schema).*(?:overwrite|source.*win|update|newer)",
                    ],
                    "partial": [
                        r"(?i)middleware.*merge|health.*new|monitoring.*(?:local|preserve)",
                        r"(?i)identical|overwrite|merge|new|local",
                    ],
                },
            },
            {
                "name": "reasoning_quality",
                "points": 3,
                "description": "Reasoning explains WHY each classification was chosen",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)request_id_middleware.*(?:target.only|not.*source|local.*custom|preserve)",
                        r"(?i)(?:rate.limit|200|threshold).*(?:differ|change|source.*update)",
                        r"(?i)audit.*(?:table|event|trail).*(?:new|missing|added|source)",
                    ],
                    "partial": [
                        r"(?i)(?:because|reason|since|differs|custom|local)",
                    ],
                },
            },
            {
                "name": "structural_completeness",
                "points": 2,
                "description": "Table format with all required fields, blast radius stated",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?:\||file|classification|reason)",
                        r"(?i)(?:bulk|rsync|overwrite).*(?:damage|destroy|lose|lost|break|corrupt)",
                    ],
                    "partial": [
                        r"(?i)table|plan|summary",
                    ],
                },
            },
        ],
    },
    "expected_answer_signals": [
        "middleware.py -> MERGE (both have changes: rate limit + request_id)",
        "health.py -> NEW (source only, copy to target)",
        "monitoring.py -> LOCAL (target only, preserve)",
        "deploy.sh, README.md, auth.py, utils.py, logging.conf, routes.py -> IDENTICAL",
        "config.json, schema.sql -> OVERWRITE (source is strictly newer)",
        "Bulk rsync would damage monitoring.py and middleware.py at minimum",
    ],
}
