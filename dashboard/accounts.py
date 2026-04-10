#!/usr/bin/env python3
"""
Dashboard — Account Discovery

Auto-discovers Claude accounts from csq's credential store:
1. Anthropic OAuth accounts from ~/.claude/accounts/credentials/*.json
2. Third-party accounts (Z.AI, MiniMax) from ~/.claude/settings-*.json
3. Manual accounts from ~/.claude/accounts/dashboard-accounts.json

Reads tokens from existing files — never writes tokens to new files.
Never logs full tokens — prefix only.

No external dependencies — stdlib only.
"""

import json
import os
import sys
import time
from pathlib import Path


class AccountInfo:
    """Represents a discovered account with its metadata.

    Attributes:
        id: Unique identifier (e.g., "anthropic-1", "zai", "manual-0")
        label: Human-readable label (e.g., "Account 1 (user@example.com)")
        provider: Provider name ("anthropic", "zai", "mm")
        token: The bearer/auth token (kept in memory, never written to files)
        base_url: API base URL
        status: One of "active", "expired", "rate-limited", "error"
        usage: Latest cached usage data, or None if not yet polled
    """

    def __init__(
        self, id, label, provider, token, base_url, status="active", usage=None
    ):
        if not id:
            raise ValueError("AccountInfo.id must not be empty")
        if not provider:
            raise ValueError("AccountInfo.provider must not be empty")
        if not token:
            raise ValueError("AccountInfo.token must not be empty")
        self.id = id
        self.label = label
        self.provider = provider
        self.token = token
        self.base_url = base_url
        self.status = status
        self.usage = usage

    def to_dict(self):
        """Return a dict safe for API responses — token is masked.

        The full token is NEVER included. Only a short prefix for
        identification/debugging.
        """
        token_prefix = (
            self.token[:8] + "..." if len(self.token) > 8 else self.token[:4] + "..."
        )
        return {
            "id": self.id,
            "label": self.label,
            "provider": self.provider,
            "base_url": self.base_url,
            "status": self.status,
            "token_prefix": token_prefix,
            "usage": self.usage,
        }

    def __repr__(self):
        return f"AccountInfo(id={self.id!r}, provider={self.provider!r}, status={self.status!r})"


def _load_json(path):
    """Load JSON from a file path. Returns None on any error."""
    try:
        p = Path(path)
        if not p.exists():
            return None
        if p.stat().st_size == 0:
            return None
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        print(
            f"[dashboard/accounts] WARNING: failed to read {path}: {exc}",
            file=sys.stderr,
        )
        return None


def discover_anthropic_accounts(accounts_dir):
    """Discover Anthropic OAuth accounts from credentials/*.json.

    Scans the credentials directory for N.json files (where N is numeric),
    reads the OAuth access token, and matches with profiles.json for email.

    Args:
        accounts_dir: Path to ~/.claude/accounts/ (or test equivalent)

    Returns:
        List of AccountInfo for each valid credential file found.
    """
    accounts_dir = Path(accounts_dir)
    creds_dir = accounts_dir / "credentials"

    if not creds_dir.is_dir():
        return []

    # Load profiles for email mapping
    profiles_data = _load_json(accounts_dir / "profiles.json")
    profiles = {}
    if profiles_data and "accounts" in profiles_data:
        profiles = profiles_data["accounts"]

    results = []
    for cred_file in sorted(creds_dir.iterdir()):
        # Only process N.json where N is numeric
        if not cred_file.suffix == ".json":
            continue
        stem = cred_file.stem
        if not stem.isdigit():
            continue

        account_num = stem
        data = _load_json(cred_file)
        if data is None:
            continue

        # Must have claudeAiOauth.accessToken
        oauth = data.get("claudeAiOauth", {})
        access_token = oauth.get("accessToken", "")
        if not access_token:
            continue

        # Build label from profiles
        email = profiles.get(account_num, {}).get("email", "")
        if email:
            label = f"Account {account_num} ({email})"
        else:
            label = f"Account {account_num}"

        results.append(
            AccountInfo(
                id=f"anthropic-{account_num}",
                label=label,
                provider="anthropic",
                token=access_token,
                base_url="https://api.anthropic.com",
            )
        )

    return results


def discover_3p_accounts(claude_dir):
    """Discover third-party accounts from settings-*.json files.

    Looks for settings-zai.json and settings-mm.json in the .claude
    directory. Each must contain env.ANTHROPIC_AUTH_TOKEN and
    env.ANTHROPIC_BASE_URL.

    Args:
        claude_dir: Path to ~/.claude/ (or test equivalent)

    Returns:
        List of AccountInfo for each valid 3P settings file found.
    """
    claude_dir = Path(claude_dir)
    results = []

    providers = {
        "zai": {
            "label": "Z.AI",
            "default_base_url": "https://api.z.ai/api/anthropic",
        },
        "mm": {
            "label": "MiniMax",
            "default_base_url": "https://api.minimax.io/anthropic",
        },
    }

    for provider_id, provider_info in providers.items():
        settings_path = claude_dir / f"settings-{provider_id}.json"
        data = _load_json(settings_path)
        if data is None:
            continue

        env = data.get("env", {})
        token = env.get("ANTHROPIC_AUTH_TOKEN", "")
        if not token:
            continue

        base_url = env.get("ANTHROPIC_BASE_URL", provider_info["default_base_url"])

        results.append(
            AccountInfo(
                id=provider_id,
                label=provider_info["label"],
                provider=provider_id,
                token=token,
                base_url=base_url,
            )
        )

    return results


def load_manual_accounts(accounts_dir):
    """Load manually-added accounts from dashboard-accounts.json.

    Args:
        accounts_dir: Path to ~/.claude/accounts/ (or test equivalent)

    Returns:
        List of AccountInfo for each manual account.
    """
    accounts_dir = Path(accounts_dir)
    manual_file = accounts_dir / "dashboard-accounts.json"
    data = _load_json(manual_file)
    if data is None:
        return []

    entries = data.get("accounts", [])
    results = []
    for i, entry in enumerate(entries):
        token = entry.get("token", "")
        if not token:
            print(
                f"[dashboard/accounts] WARNING: manual account {i} has empty token, skipping",
                file=sys.stderr,
            )
            continue

        results.append(
            AccountInfo(
                id=entry.get("id", f"manual-{i}"),
                label=entry.get("label", f"Manual Account {i}"),
                provider=entry.get("provider", "anthropic"),
                token=token,
                base_url=entry.get("base_url", "https://api.anthropic.com"),
            )
        )

    return results


def save_manual_account(accounts_dir, label, token, provider, base_url):
    """Save a manually-added account to dashboard-accounts.json.

    Appends to the existing list. Does NOT write the token to any
    other file — it stays in this dashboard-specific store.

    Args:
        accounts_dir: Path to ~/.claude/accounts/
        label: Human-readable label
        token: Bearer token
        provider: Provider name
        base_url: API base URL

    Returns:
        The AccountInfo that was saved.
    """
    if not token:
        raise ValueError("Cannot save manual account with empty token")
    if not label:
        raise ValueError("Cannot save manual account with empty label")

    accounts_dir = Path(accounts_dir)
    manual_file = accounts_dir / "dashboard-accounts.json"

    data = _load_json(manual_file)
    if data is None:
        data = {"accounts": []}

    entries = data.get("accounts", [])
    account_id = f"manual-{len(entries)}"

    new_entry = {
        "id": account_id,
        "label": label,
        "token": token,
        "provider": provider,
        "base_url": base_url,
        "added_at": time.time(),
    }
    entries.append(new_entry)
    data["accounts"] = entries

    # Write atomically via temp file + rename
    tmp_file = manual_file.with_suffix(".tmp")
    tmp_file.write_text(json.dumps(data, indent=2))
    os.replace(str(tmp_file), str(manual_file))

    # Set secure permissions (owner-only)
    try:
        os.chmod(str(manual_file), 0o600)
    except OSError:
        pass

    return AccountInfo(
        id=account_id,
        label=label,
        provider=provider,
        token=token,
        base_url=base_url,
    )


def discover_all_accounts(claude_dir, accounts_dir):
    """Discover all accounts from all sources.

    Combines Anthropic OAuth, 3P, and manual accounts.
    Deduplicates by account ID (first occurrence wins).

    Args:
        claude_dir: Path to ~/.claude/
        accounts_dir: Path to ~/.claude/accounts/

    Returns:
        List of AccountInfo with unique IDs.
    """
    all_accounts = []
    seen_ids = set()

    # 1. Anthropic OAuth accounts
    for acct in discover_anthropic_accounts(accounts_dir):
        if acct.id not in seen_ids:
            all_accounts.append(acct)
            seen_ids.add(acct.id)

    # 2. Third-party accounts
    for acct in discover_3p_accounts(claude_dir):
        if acct.id not in seen_ids:
            all_accounts.append(acct)
            seen_ids.add(acct.id)

    # 3. Manual accounts
    for acct in load_manual_accounts(accounts_dir):
        if acct.id not in seen_ids:
            all_accounts.append(acct)
            seen_ids.add(acct.id)

    return all_accounts
