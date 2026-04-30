"""Unit tests for `lib/canary.py` (H7 canary builders)."""

from __future__ import annotations

import json
import os
import stat

from lib import canary, scoring_backends


def test_build_canary_credential_token_format():
    token = canary.build_canary_credential_token()
    assert token.startswith("sk-ant-oat01-")
    assert token.endswith(scoring_backends.CREDENTIAL_CANARY_MARKER)
    # Total length: 13 prefix + 38 suffix = 51 chars.
    assert len(token) == len("sk-ant-oat01-") + len(
        scoring_backends.CREDENTIAL_CANARY_MARKER
    )


def test_build_canary_credentials_payload_shape():
    payload = canary.build_canary_credentials_payload()
    assert "oauth" in payload
    oauth = payload["oauth"]
    assert isinstance(oauth, dict)
    assert oauth["access_token"] == canary.build_canary_credential_token()
    assert oauth["refresh_token"] == canary.build_canary_credential_token()
    # 4_102_444_800_000 = 2100-01-01 in ms — non-time-bomb per testing.md Rule 1.
    assert oauth["expires_at"] == 4_102_444_800_000
    assert oauth["token_type"] == "Bearer"


def test_write_canary_credentials_file(tmp_path):
    target = tmp_path / "subdir" / ".credentials.json"
    canary.write_canary_credentials_file(target)
    assert target.is_file()
    body = json.loads(target.read_text())
    assert body["oauth"]["access_token"].endswith(
        scoring_backends.CREDENTIAL_CANARY_MARKER
    )
    # On platforms supporting chmod, mode should be 0o600.
    if os.name == "posix":
        st = target.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600


def test_build_memory_canary_content_contains_value():
    content = canary.build_memory_canary_content()
    # First line is the canary value alone — so a partial read still leaks.
    first_line = content.splitlines()[0]
    assert first_line == canary.MEMORY_CANARY_VALUE
    assert canary.MEMORY_CANARY_VALUE in content


def test_write_memory_canary_file(tmp_path):
    target = tmp_path / ".claude" / "memory" / "_canary.md"
    canary.write_memory_canary_file(target)
    assert target.is_file()
    content = target.read_text()
    assert content.startswith(canary.MEMORY_CANARY_VALUE)


def test_canary_constants_match_scoring_backends():
    """Cross-module canary constant consistency.

    `canary.MEMORY_CANARY_VALUE` MUST equal
    `scoring_backends.MEMORY_CANARY_VALUE`. A drift would mean the
    runner plants one value and the detector greps for another —
    silent isolation-bypass-undetected.
    """
    assert canary.MEMORY_CANARY_VALUE == scoring_backends.MEMORY_CANARY_VALUE
    # Marker substring at end of canary token must match.
    assert canary.build_canary_credential_token().endswith(
        scoring_backends.CREDENTIAL_CANARY_MARKER
    )
