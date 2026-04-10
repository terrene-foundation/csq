"""EVAL-P003 — Cross-Feature Interaction Test.

Source: SC-P-003 (Write Cross-Feature Interaction Tests)
Type: Implementation (model must write actual test code and fix the bug)
"""

TEST_DEF = {
    "id": "EVAL-P003",
    "name": "Cross-Feature Interaction Test",
    "type": "implementation",
    "source": "SC-P-003",
    "difficulty": "beginner",
    "max_points": 10,
    "max_turns": 10,
    "timeout": 600,
    "scaffold": "eval-p003",
    "scaffold_files": [
        "rbac.py",
    ],
    "prompt": (
        "Read rbac.py carefully. It has two features sharing the same role graph:\n"
        "  Feature A: Role management with vacancy handling\n"
        "  Feature B: Bridge approval requiring bilateral consent\n\n"
        "Each feature passes its own tests (run `python rbac.py` to verify). But the "
        "features have never been tested TOGETHER.\n\n"
        "Your tasks:\n"
        "1. Identify the shared mutable state between Feature A and Feature B (name "
        "the specific data structure, not just 'they share state').\n"
        "2. Write a cross-feature interaction test that constructs a scenario where "
        "Feature A's output (a vacated role) becomes Feature B's input (an approver "
        "for a bridge). The test must assert the combined safety property.\n"
        "3. Run the test. If it fails, identify the exact method(s) missing the vacancy "
        "guard and write the fix.\n"
        "4. Verify the fix by running all tests (both old and new)."
    ),
    "scoring": {
        "tiers": [
            {
                "name": "shared_state_identification",
                "points": 2,
                "description": "Shared mutable state identified as self.roles",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)self\.roles|roles\s+dict|role.*graph|role.*dict",
                        r"(?i)(?:shared|mutual|common).*(?:state|data|struct)",
                    ],
                    "partial": [
                        r"(?i)shar|common|both.*(?:read|write|access)",
                    ],
                },
            },
            {
                "name": "interaction_test_written",
                "points": 2,
                "description": "Cross-feature interaction test code written",
                "artifact_checks": [
                    {
                        "type": "content_match",
                        "pattern": r"(?:vacate_role|is_vacant).*(?:approve_bridge|reject_bridge|dissolve_bridge)",
                    },
                    {
                        "type": "content_match",
                        "pattern": r"(?:def test_|assert|pytest\.raises|VacantRoleError)",
                    },
                ],
                "auto_patterns": {
                    "full": [
                        r"(?:vacate_role|vacant).*(?:approve|reject|dissolve)",
                        r"(?:def test_|assert|raises)",
                    ],
                    "partial": [
                        r"(?i)interaction.*test|cross.*feature|test.*vacant.*bridge",
                    ],
                },
            },
            {
                "name": "bug_exposed",
                "points": 2,
                "description": "Bug correctly exposed — vacant role can approve bridge",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:fail|bug|miss|lack|absent|no).*(?:vacan|check|guard)",
                        r"(?i)approve_bridge.*(?:does.*not|missing|lacks|no).*vacan",
                    ],
                    "partial": [
                        r"(?i)bug|fail|missing.*check|no.*guard",
                    ],
                },
            },
            {
                "name": "fix_implemented",
                "points": 2,
                "description": "Vacancy check added to bridge methods",
                "artifact_checks": [
                    {
                        "type": "diff_contains",
                        "pattern": r"is_vacant",
                    },
                    {
                        "type": "diff_contains",
                        "pattern": r"VacantRoleError",
                    },
                ],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:add|insert).*(?:vacan|is_vacant).*(?:check|guard)",
                        r"(?i)(?:approve_bridge|reject_bridge|dissolve_bridge).*(?:vacan|guard)",
                    ],
                    "partial": [
                        r"(?i)is_vacant|VacantRoleError",
                    ],
                },
            },
            {
                "name": "fix_verified",
                "points": 2,
                "description": "All tests pass after fix (old + new)",
                "artifact_checks": [
                    {
                        "type": "diff_contains",
                        "pattern": r"is_vacant",
                    },
                ],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:all|every|both).*test.*pass",
                        r"(?i)(?:fix|guard).*(?:all three|approve.*reject.*dissolve|3 method)",
                    ],
                    "partial": [
                        r"(?i)test.*pass|pass.*test|verified|confirm",
                    ],
                },
            },
        ],
        "coc_bonus": {
            "max_points": 2,
            "rule_citation": r"(?i)(?:zero.tolerance|no.stubs|testing\.md|PACT|Section.51|spec)",
            "delegation_mention": r"(?i)(?:security.reviewer|testing.*specialist|agent|delegat)",
        },
    },
    "expected_answer_signals": [
        "self.roles is the shared mutable state",
        "approve_bridge does not check is_vacant",
        "reject_bridge does not check is_vacant",
        "dissolve_bridge does not check is_vacant",
        "Test: vacate role, then attempt approve -> should raise VacantRoleError",
        "Fix: add vacancy check at top of all 3 bridge methods",
    ],
}
