"""coc-eval library — stdlib-only Python harness for multi-CLI COC evaluation.

Modules:
- validators: name validation + SUITE_MANIFEST
- redact: token redaction (port of csq-core/src/error.rs:161 redact_tokens)
- launcher: LaunchInputs/LaunchSpec dataclasses + INV-PERM-1 + cc launcher
- auth: per-CLI authentication probe (cc in H3; codex/gemini in H10/H11)
- fixtures: per-test fixture lifecycle (prepare/cleanup/verify)
- states: closed State enum + precedence ladders
- suite_validator: validates SUITE dicts against schemas/suite-v1.json
"""
