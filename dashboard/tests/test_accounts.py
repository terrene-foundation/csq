#!/usr/bin/env python3
"""
Tier 1 (Unit) + Tier 2 (Integration) tests for dashboard/accounts.py.

Tests account discovery from real credential files, settings files,
and manual account storage. Uses real temp directories that mimic
the ~/.claude/accounts/ layout.
"""

import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.accounts import (
    discover_anthropic_accounts,
    discover_3p_accounts,
    load_manual_accounts,
    save_manual_account,
    discover_all_accounts,
    AccountInfo,
)


# ─── Helpers ─────────────────────────────────────────────


def _make_claude_home(tmp_dir):
    """Create a fake ~/.claude/accounts/ layout in tmp_dir."""
    accounts_dir = os.path.join(tmp_dir, ".claude", "accounts")
    creds_dir = os.path.join(accounts_dir, "credentials")
    os.makedirs(creds_dir, exist_ok=True)
    return accounts_dir, creds_dir


def _write_cred_file(creds_dir, account_num, access_token, refresh_token="rt-test"):
    """Write a credential file mimicking csq format."""
    cred_data = {
        "claudeAiOauth": {
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "expiresAt": "2099-01-01T00:00:00Z",
        }
    }
    path = os.path.join(creds_dir, f"{account_num}.json")
    with open(path, "w") as f:
        json.dump(cred_data, f)
    return path


def _write_profiles(accounts_dir, profiles_map):
    """Write profiles.json with email mappings."""
    data = {"accounts": {}}
    for acct_num, email in profiles_map.items():
        data["accounts"][str(acct_num)] = {"email": email}
    path = os.path.join(accounts_dir, "profiles.json")
    with open(path, "w") as f:
        json.dump(data, f)
    return path


def _write_settings_file(claude_dir, provider, token, base_url):
    """Write a settings-{provider}.json file."""
    data = {
        "env": {
            "ANTHROPIC_AUTH_TOKEN": token,
            "ANTHROPIC_BASE_URL": base_url,
        }
    }
    path = os.path.join(claude_dir, f"settings-{provider}.json")
    with open(path, "w") as f:
        json.dump(data, f)
    return path


# ─── Tier 1: AccountInfo data structure ──────────────────


def test_account_info_creation():
    """AccountInfo stores all required fields."""
    info = AccountInfo(
        id="anthropic-1",
        label="Account 1",
        provider="anthropic",
        token="sk-ant-oat01-test",
        base_url="https://api.anthropic.com",
    )
    assert info.id == "anthropic-1"
    assert info.label == "Account 1"
    assert info.provider == "anthropic"
    assert info.token == "sk-ant-oat01-test"
    assert info.base_url == "https://api.anthropic.com"
    assert info.status == "active"  # default
    assert info.usage is None  # default — no usage until polled


def test_account_info_to_dict_masks_token():
    """to_dict() masks the full token, showing only a prefix."""
    info = AccountInfo(
        id="anthropic-1",
        label="Account 1",
        provider="anthropic",
        token="sk-ant-oat01-abcdefghijklmnop",
        base_url="https://api.anthropic.com",
    )
    d = info.to_dict()
    assert (
        "sk-ant-o" in d["token_prefix"]
    ), f"Expected token prefix, got {d['token_prefix']}"
    assert "abcdefghijklmnop" not in json.dumps(d), "Full token leaked in to_dict()"
    # Full token must NOT be in the dict
    assert "token" not in d or d.get("token") is None or len(d.get("token", "")) <= 12


def test_account_info_to_dict_contains_all_fields():
    """to_dict() contains all the fields needed by the frontend."""
    info = AccountInfo(
        id="zai",
        label="Z.AI",
        provider="zai",
        token="zai-token-xyz",
        base_url="https://api.z.ai/api/anthropic",
    )
    d = info.to_dict()
    required_keys = {"id", "label", "provider", "base_url", "status", "token_prefix"}
    missing = required_keys - set(d.keys())
    assert not missing, f"Missing keys in to_dict: {missing}"


# ─── Tier 2: Anthropic account discovery ─────────────────


def test_discover_anthropic_accounts_finds_cred_files():
    """Discovers accounts from credentials/*.json files."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir, creds_dir = _make_claude_home(tmp)
        _write_cred_file(creds_dir, 1, "sk-ant-oat01-acct1-token")
        _write_cred_file(creds_dir, 2, "sk-ant-oat01-acct2-token")
        _write_profiles(accounts_dir, {1: "one@test.com", 2: "two@test.com"})

        accounts = discover_anthropic_accounts(accounts_dir)
        assert len(accounts) == 2, f"Expected 2 accounts, got {len(accounts)}"
        ids = {a.id for a in accounts}
        assert "anthropic-1" in ids, f"Missing anthropic-1 in {ids}"
        assert "anthropic-2" in ids, f"Missing anthropic-2 in {ids}"


def test_discover_anthropic_accounts_uses_email_in_label():
    """Label includes email from profiles.json when available."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir, creds_dir = _make_claude_home(tmp)
        _write_cred_file(creds_dir, 3, "sk-ant-oat01-acct3")
        _write_profiles(accounts_dir, {3: "three@test.com"})

        accounts = discover_anthropic_accounts(accounts_dir)
        assert len(accounts) == 1
        assert "three@test.com" in accounts[0].label


def test_discover_anthropic_accounts_empty_dir():
    """Returns empty list when credentials dir has no JSON files."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir, _ = _make_claude_home(tmp)
        accounts = discover_anthropic_accounts(accounts_dir)
        assert accounts == [], f"Expected empty list, got {accounts}"


def test_discover_anthropic_accounts_skips_invalid_json():
    """Skips credential files with invalid JSON."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir, creds_dir = _make_claude_home(tmp)
        # Valid account
        _write_cred_file(creds_dir, 1, "sk-ant-oat01-valid")
        # Invalid JSON file
        with open(os.path.join(creds_dir, "2.json"), "w") as f:
            f.write("{broken json")
        _write_profiles(accounts_dir, {1: "valid@test.com", 2: "broken@test.com"})

        accounts = discover_anthropic_accounts(accounts_dir)
        assert len(accounts) == 1, f"Expected 1 valid account, got {len(accounts)}"
        assert accounts[0].id == "anthropic-1"


def test_discover_anthropic_accounts_skips_missing_oauth():
    """Skips files that exist but lack claudeAiOauth.accessToken."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir, creds_dir = _make_claude_home(tmp)
        # File with no OAuth section
        with open(os.path.join(creds_dir, "1.json"), "w") as f:
            json.dump({"some_other_key": "value"}, f)
        _write_profiles(accounts_dir, {1: "nooauth@test.com"})

        accounts = discover_anthropic_accounts(accounts_dir)
        assert accounts == [], f"Expected empty, got {accounts}"


def test_discover_anthropic_accounts_nonexistent_dir():
    """Returns empty list when accounts dir does not exist."""
    accounts = discover_anthropic_accounts("/nonexistent/path/accounts")
    assert accounts == [], f"Expected empty list for nonexistent dir, got {accounts}"


def test_discover_anthropic_accounts_skips_non_numeric_files():
    """Only processes N.json files where N is a number."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir, creds_dir = _make_claude_home(tmp)
        _write_cred_file(creds_dir, 1, "sk-ant-oat01-valid")
        # Non-numeric filename
        with open(os.path.join(creds_dir, "dashboard-accounts.json"), "w") as f:
            json.dump({"not_a_cred": True}, f)
        # Broker lock file
        with open(os.path.join(creds_dir, "1.refresh-lock"), "w") as f:
            f.write("")
        _write_profiles(accounts_dir, {1: "valid@test.com"})

        accounts = discover_anthropic_accounts(accounts_dir)
        assert len(accounts) == 1
        assert accounts[0].id == "anthropic-1"


# ─── Tier 2: 3P account discovery ───────────────────────


def test_discover_3p_accounts_finds_zai():
    """Discovers Z.AI account from settings-zai.json."""
    with tempfile.TemporaryDirectory() as tmp:
        claude_dir = os.path.join(tmp, ".claude")
        os.makedirs(claude_dir)
        _write_settings_file(
            claude_dir, "zai", "zai-token-123", "https://api.z.ai/api/anthropic"
        )

        accounts = discover_3p_accounts(claude_dir)
        zai_accounts = [a for a in accounts if a.provider == "zai"]
        assert (
            len(zai_accounts) == 1
        ), f"Expected 1 zai account, got {len(zai_accounts)}"
        assert zai_accounts[0].id == "zai"
        assert zai_accounts[0].base_url == "https://api.z.ai/api/anthropic"


def test_discover_3p_accounts_finds_mm():
    """Discovers MiniMax account from settings-mm.json."""
    with tempfile.TemporaryDirectory() as tmp:
        claude_dir = os.path.join(tmp, ".claude")
        os.makedirs(claude_dir)
        _write_settings_file(
            claude_dir, "mm", "mm-token-456", "https://api.minimax.io/anthropic"
        )

        accounts = discover_3p_accounts(claude_dir)
        mm_accounts = [a for a in accounts if a.provider == "mm"]
        assert len(mm_accounts) == 1, f"Expected 1 mm account, got {len(mm_accounts)}"
        assert mm_accounts[0].id == "mm"


def test_discover_3p_accounts_skips_empty_token():
    """Skips 3P settings where ANTHROPIC_AUTH_TOKEN is empty."""
    with tempfile.TemporaryDirectory() as tmp:
        claude_dir = os.path.join(tmp, ".claude")
        os.makedirs(claude_dir)
        _write_settings_file(claude_dir, "zai", "", "https://api.z.ai/api/anthropic")

        accounts = discover_3p_accounts(claude_dir)
        assert accounts == [], f"Expected empty for empty token, got {accounts}"


def test_discover_3p_accounts_skips_missing_file():
    """Returns empty when settings file doesn't exist."""
    with tempfile.TemporaryDirectory() as tmp:
        claude_dir = os.path.join(tmp, ".claude")
        os.makedirs(claude_dir)
        # No settings files at all
        accounts = discover_3p_accounts(claude_dir)
        assert accounts == [], f"Expected empty, got {accounts}"


def test_discover_3p_accounts_skips_zero_byte_file():
    """Skips zero-byte settings files (known csq issue)."""
    with tempfile.TemporaryDirectory() as tmp:
        claude_dir = os.path.join(tmp, ".claude")
        os.makedirs(claude_dir)
        # 0-byte file
        path = os.path.join(claude_dir, "settings-zai.json")
        open(path, "w").close()  # empty file

        accounts = discover_3p_accounts(claude_dir)
        assert accounts == [], f"Expected empty for 0-byte file, got {accounts}"


# ─── Tier 2: Manual accounts ────────────────────────────


def test_save_and_load_manual_account():
    """Save a manual account and load it back."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir = os.path.join(tmp, ".claude", "accounts")
        os.makedirs(accounts_dir, exist_ok=True)

        save_manual_account(
            accounts_dir,
            label="My Custom Account",
            token="sk-custom-token-123",
            provider="anthropic",
            base_url="https://api.anthropic.com",
        )

        manuals = load_manual_accounts(accounts_dir)
        assert len(manuals) == 1, f"Expected 1 manual account, got {len(manuals)}"
        assert manuals[0].label == "My Custom Account"
        assert manuals[0].provider == "anthropic"
        assert manuals[0].id.startswith("manual-")


def test_load_manual_accounts_empty():
    """Returns empty list when no manual accounts file exists."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir = os.path.join(tmp, ".claude", "accounts")
        os.makedirs(accounts_dir, exist_ok=True)
        manuals = load_manual_accounts(accounts_dir)
        assert manuals == [], f"Expected empty, got {manuals}"


def test_save_multiple_manual_accounts():
    """Multiple manual accounts accumulate."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir = os.path.join(tmp, ".claude", "accounts")
        os.makedirs(accounts_dir, exist_ok=True)

        save_manual_account(
            accounts_dir, "Acct A", "token-a", "anthropic", "https://api.anthropic.com"
        )
        save_manual_account(
            accounts_dir, "Acct B", "token-b", "anthropic", "https://api.anthropic.com"
        )

        manuals = load_manual_accounts(accounts_dir)
        assert len(manuals) == 2, f"Expected 2, got {len(manuals)}"
        labels = {m.label for m in manuals}
        assert "Acct A" in labels and "Acct B" in labels


# ─── Tier 2: discover_all_accounts (integration) ────────


def test_discover_all_combines_sources():
    """discover_all finds Anthropic + 3P + manual accounts."""
    with tempfile.TemporaryDirectory() as tmp:
        # Anthropic
        accounts_dir, creds_dir = _make_claude_home(tmp)
        _write_cred_file(creds_dir, 1, "sk-ant-oat01-acct1")
        _write_profiles(accounts_dir, {1: "one@test.com"})

        # 3P
        claude_dir = os.path.join(tmp, ".claude")
        _write_settings_file(
            claude_dir, "mm", "mm-tok", "https://api.minimax.io/anthropic"
        )

        # Manual
        save_manual_account(
            accounts_dir,
            "Custom",
            "custom-tok",
            "anthropic",
            "https://api.anthropic.com",
        )

        all_accounts = discover_all_accounts(claude_dir, accounts_dir)
        assert (
            len(all_accounts) >= 3
        ), f"Expected >= 3 accounts, got {len(all_accounts)}: {[a.id for a in all_accounts]}"

        providers = {a.provider for a in all_accounts}
        assert "anthropic" in providers
        assert "mm" in providers


def test_discover_all_no_duplicates():
    """discover_all should not return duplicate account IDs."""
    with tempfile.TemporaryDirectory() as tmp:
        accounts_dir, creds_dir = _make_claude_home(tmp)
        _write_cred_file(creds_dir, 1, "sk-ant-oat01-acct1")
        _write_profiles(accounts_dir, {1: "one@test.com"})
        claude_dir = os.path.join(tmp, ".claude")

        all_accounts = discover_all_accounts(claude_dir, accounts_dir)
        ids = [a.id for a in all_accounts]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {ids}"


# ─── Runner ──────────────────────────────────────────────

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for test_fn in tests:
        name = test_fn.__name__
        try:
            test_fn()
            print(f"  PASS: {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name} -- {e}")
            failed += 1
    print(f"\n  {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
