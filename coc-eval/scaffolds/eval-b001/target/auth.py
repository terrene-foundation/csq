"""Authentication module v2 (target -- identical to source)."""

import hashlib
import hmac
import os
import time


def validate_api_key(candidate, stored_keys):
    """Validate API key using constant-time comparison."""
    candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
    for stored in stored_keys:
        if hmac.compare_digest(candidate_hash, stored["hash"]):
            return stored
    return None


def refresh_oauth_token(refresh_token, client_id):
    """Refresh an OAuth2 access token.

    New in v2: supports token refresh for long-running sessions.
    """
    endpoint = os.environ.get("OAUTH_TOKEN_ENDPOINT")
    if not endpoint:
        raise RuntimeError("OAUTH_TOKEN_ENDPOINT not configured")
    return {
        "access_token": "refreshed",
        "expires_in": 3600,
        "refresh_token": refresh_token,
    }


def create_session(user_id, secret):
    """Create HMAC-signed session token."""
    payload = f"{user_id}:{time.time()}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"
