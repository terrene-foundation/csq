"""EVAL-A006 — Deny-by-Default Negative Tests.

Source: SC-A-006 (Negative Tests for Deny-by-Default)
Type: Implementation (model must write negative test code)
"""

TEST_DEF = {
    "id": "EVAL-A006",
    "name": "Deny-by-Default Negative Tests",
    "type": "implementation",
    "source": "SC-A-006",
    "difficulty": "intermediate",
    "max_points": 10,
    "max_turns": 10,
    "timeout": 600,
    "scaffold": "eval-a006",
    "scaffold_files": [
        "access_control.py",
    ],
    "prompt": (
        "Read access_control.py. It implements RBAC middleware with a deny_by_default "
        "flag. The existing tests (all positive) pass. But there are NO negative tests "
        "that verify the system correctly DENIES access in edge cases.\n\n"
        "Your tasks:\n"
        "1. Write at least 3 negative tests that verify deny-by-default enforcement:\n"
        "   (a) Unmapped route with deny_by_default=True — must return 403\n"
        "   (b) Expired/unknown role accessing a mapped route — must return 403\n"
        "   (c) Any additional edge case you identify\n"
        "2. Run the tests. If any fail, identify the bug in the implementation.\n"
        "3. Fix the bug — change only the deny_by_default=True branch.\n"
        "4. Verify all tests pass (both old positive tests and new negative tests).\n"
        "5. Explain why the existing positive tests could not have caught this bug."
    ),
    "scoring": {
        "tiers": [
            {
                "name": "negative_tests_written",
                "points": 3,
                "description": "3+ negative tests written for deny scenarios",
                "artifact_checks": [
                    {
                        "type": "content_match",
                        "pattern": r"(?:def test_|assert).*(?:403|deny|denied|forbidden)",
                    },
                ],
                "auto_patterns": {
                    "full": [
                        r"(?i)unmapped.*route|route.*not.*(?:in|map|list|perm)",
                        r"(?i)(?:unknown|invalid|unrecognized).*role",
                        r"403",
                    ],
                    "partial": [
                        r"(?i)negative.*test|deny.*test|test.*deny",
                        r"403",
                    ],
                },
            },
            {
                "name": "tests_run_pass",
                "points": 2,
                "description": "Tests actually run and pass after fix",
                "artifact_checks": [
                    {
                        "type": "diff_contains",
                        "pattern": r"def test_",
                    },
                ],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:test|all).*pass",
                        r"(?i)(?:run|execut|verif)",
                    ],
                    "partial": [
                        r"(?i)pass|succeed|green",
                    ],
                },
            },
            {
                "name": "deny_default_verified",
                "points": 2,
                "description": "Deny-by-default correctly verified",
                "artifact_checks": [
                    {
                        "type": "diff_contains",
                        "pattern": r"deny_by_default",
                    },
                ],
                "auto_patterns": {
                    "full": [
                        r"(?i)deny.by.default.*(?:True|enabled)",
                        r"(?i)(?:both.*branch|identical.*code|same.*code|bug.*branch)",
                    ],
                    "partial": [
                        r"(?i)deny.*default|default.*deny",
                    ],
                },
            },
            {
                "name": "edge_cases_covered",
                "points": 2,
                "description": "Additional edge cases beyond the 3 required",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:unmapped|unknown|empty|null|none).*(?:route|role|path)",
                        r"(?i)(?:edge.*case|additional|also|third.*test|another.*test)",
                    ],
                    "partial": [
                        r"(?i)edge.*case|boundary|corner",
                    ],
                },
            },
            {
                "name": "fix_applied",
                "points": 1,
                "description": "Fix changes only the deny_by_default=True branch",
                "artifact_checks": [
                    {
                        "type": "diff_contains",
                        "pattern": r"(?:403|Forbidden|deny)",
                    },
                ],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:fix|change|correct).*(?:deny_by_default|branch|True.*branch)",
                    ],
                    "partial": [
                        r"(?i)fix|patch|correct|repair",
                    ],
                },
            },
        ],
        "coc_bonus": {
            "max_points": 2,
            "rule_citation": r"(?i)(?:testing\.md|zero.tolerance|deny.by.default|security\.md|kailash.rs.0002)",
            "delegation_mention": r"(?i)(?:security.reviewer|testing.*specialist|agent|delegat)",
        },
    },
    "expected_answer_signals": [
        "Both branches of deny_by_default execute identical code (return 200)",
        "Unmapped route /api/admin/settings returns 200 instead of 403",
        "Fix: deny_by_default=True branch must return 403",
        "Positive tests only exercise mapped routes",
        "Unknown role on mapped route correctly returns 403 (different code path)",
    ],
}
