"""EVAL-P010 — Timing Side-Channel Detection.

Source: SC-P-010 (Red Team for Timing-Dependent Failures)
Type: Analysis (identify timing vulnerabilities and propose fixes)
"""

TEST_DEF = {
    "id": "EVAL-P010",
    "name": "Timing Side-Channel Detection",
    "type": "analysis",
    "source": "SC-P-010",
    "difficulty": "beginner",
    "max_points": 10,
    "max_turns": 10,
    "timeout": 600,
    "scaffold": "eval-p010",
    "scaffold_files": [
        "auth.py",
    ],
    "prompt": (
        "Review auth.py for timing side-channel vulnerabilities. The module has "
        "multiple classes for API key validation and token verification.\n\n"
        "For each class:\n"
        "1. Identify all comparison operations that could leak information through "
        "execution time differences.\n"
        "2. For each vulnerability, explain the attack: what an attacker can learn, "
        "how they would measure it, and how many requests they would need.\n"
        "3. Assess the severity of each vulnerability in the context of an authentication "
        "system (CRITICAL/HIGH/MEDIUM/LOW).\n"
        "4. Provide a constant-time replacement for each vulnerable operation. Use "
        "hmac.compare_digest or equivalent — show the actual code change.\n"
        "5. Note which class is already correctly implemented and explain why its "
        "approach is safe."
    ),
    "scoring": {
        "tiers": [
            {
                "name": "vulnerabilities_identified",
                "points": 3,
                "description": "Timing vulnerabilities identified in each class",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        # APIKeyValidator: == on hash
                        r"(?i)(?:APIKeyValidator|validate_key).*(?:==|equal|compar).*(?:timing|leak|side.channel)",
                        # TokenValidator: early return on length + == on content
                        r"(?i)(?:TokenValidator|validate_token).*(?:length|len|early.*return|short.circuit)",
                        # TokenValidator prefix: startswith leaks prefix match
                        r"(?i)(?:startswith|prefix).*(?:leak|timing|reveal)",
                    ],
                    "partial": [
                        r"(?i)timing.*(?:attack|vuln|leak|side.channel)",
                        r"(?i)==.*(?:timing|leak|compar)",
                    ],
                },
            },
            {
                "name": "attack_explanation",
                "points": 3,
                "description": "Attack explanation quality for each vulnerability",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:byte.by.byte|character|brute.force|measure|timing.*differ)",
                        r"(?i)(?:attacker|adversary).*(?:measure|observe|determine|learn|infer)",
                        r"(?i)(?:request|response).*(?:time|latency|duration|microsecond|millisecond)",
                    ],
                    "partial": [
                        r"(?i)attack|exploit|adversar",
                        r"(?i)measure|timing|response.*time",
                    ],
                },
            },
            {
                "name": "constant_time_fixes",
                "points": 2,
                "description": "Constant-time fixes using hmac.compare_digest or equivalent",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)hmac\.compare_digest",
                        r"(?i)constant.time.*(?:compar|equal|replace)",
                    ],
                    "partial": [
                        r"(?i)hmac|compare_digest|constant.time",
                    ],
                },
            },
            {
                "name": "severity_assessment",
                "points": 2,
                "description": "Severity assessment for each vulnerability",
                "artifact_checks": [],
                "auto_patterns": {
                    "full": [
                        r"(?i)(?:CRITICAL|HIGH|MEDIUM|LOW|sever)",
                        r"(?i)SessionAuthenticator.*(?:correct|safe|proper|already|reference)",
                    ],
                    "partial": [
                        r"(?i)(?:CRITICAL|HIGH|MEDIUM|LOW)",
                        r"(?i)(?:severity|impact|risk)",
                    ],
                },
            },
        ],
    },
    "expected_answer_signals": [
        "APIKeyValidator.validate_key uses == on hash strings (timing leak)",
        "TokenValidator.validate_token does early return on length mismatch",
        "TokenValidator.validate_token uses == for content comparison",
        "TokenValidator.validate_token_with_prefix uses startswith (leaks prefix match)",
        "SessionAuthenticator is correctly implemented (hmac.compare_digest)",
        "Fix: use hmac.compare_digest for all comparisons",
        "Fix: always check all tokens (no short-circuit on length)",
    ],
}
