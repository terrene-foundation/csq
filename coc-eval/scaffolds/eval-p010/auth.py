"""API authentication module with timing side-channel vulnerabilities.

This module provides API key validation and token verification for
a web service. It contains timing vulnerabilities that leak information
through execution time differences.
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class APIKeyRecord:
    key_hash: str
    owner: str
    scopes: List[str]
    created_at: float


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class APIKeyValidator:
    """Validates API keys against stored hashes.

    VULNERABILITY: Uses == for hash comparison, which is susceptible to
    timing attacks. The == operator short-circuits on the first differing
    byte, so an attacker can determine how many leading bytes of their
    candidate match the stored hash by measuring response time.
    """

    def __init__(self):
        self.keys: Dict[str, APIKeyRecord] = {}

    def register_key(self, api_key: str, owner: str, scopes: List[str]):
        """Register a new API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        self.keys[key_hash] = APIKeyRecord(
            key_hash=key_hash,
            owner=owner,
            scopes=scopes,
            created_at=time.time(),
        )

    def validate_key(self, candidate: str) -> Optional[APIKeyRecord]:
        """Validate an API key and return its record if valid.

        TIMING VULNERABILITY: The == comparison on hex digest strings
        leaks information about how many characters match. An attacker
        can brute-force one character at a time by measuring response
        time differences.
        """
        candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
        for stored_hash, record in self.keys.items():
            if candidate_hash == stored_hash:  # VULNERABLE: timing leak via ==
                return record
        return None

    def has_scope(self, candidate: str, required_scope: str) -> bool:
        """Check if an API key has a specific scope."""
        record = self.validate_key(candidate)
        if record is None:
            return False
        return required_scope in record.scopes


class TokenValidator:
    """Validates bearer tokens with length and content checks.

    VULNERABILITY: Early return on length mismatch leaks token length.
    An attacker can determine the expected token length by measuring
    whether a short vs long candidate gets a faster rejection.
    """

    def __init__(self, valid_tokens: List[str]):
        self.valid_tokens = valid_tokens

    def validate_token(self, candidate: str) -> bool:
        """Validate a bearer token.

        TIMING VULNERABILITY 1: Early return on length mismatch reveals
        the expected token length.

        TIMING VULNERABILITY 2: String == comparison after length check
        still leaks content through timing.
        """
        for valid in self.valid_tokens:
            # Early return on length mismatch -- leaks expected length
            if len(candidate) != len(valid):
                continue

            # Direct string comparison -- leaks content byte-by-byte
            if candidate == valid:  # VULNERABLE: timing leak via ==
                return True

        return False

    def validate_token_with_prefix(self, candidate: str, prefix: str) -> bool:
        """Validate a token that must start with a specific prefix.

        TIMING VULNERABILITY: prefix check with startswith() leaks
        whether the prefix matched, narrowing the attacker's search space.
        """
        if not candidate.startswith(prefix):
            return False

        # Strip prefix and validate the remainder
        token_body = candidate[len(prefix) :]
        for valid in self.valid_tokens:
            if token_body == valid:
                return True
        return False


class SessionAuthenticator:
    """Session-based authentication with HMAC verification.

    This class is correctly implemented -- it uses constant-time
    comparison via hmac.compare_digest. It serves as a reference
    for what the other classes SHOULD do.
    """

    def __init__(self, secret: str):
        import hmac as _hmac

        self._secret = secret
        self._hmac = _hmac

    def create_session_token(self, user_id: str) -> str:
        """Create an HMAC-signed session token."""
        payload = f"{user_id}:{time.time()}"
        sig = self._hmac.new(
            self._secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return f"{payload}:{sig}"

    def verify_session_token(self, token: str) -> Optional[str]:
        """Verify a session token and return the user_id.

        This is the CORRECT implementation -- uses hmac.compare_digest
        for constant-time comparison.
        """
        parts = token.rsplit(":", 1)
        if len(parts) != 2:
            return None
        payload, provided_sig = parts
        expected_sig = self._hmac.new(
            self._secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if self._hmac.compare_digest(provided_sig, expected_sig):
            user_id = payload.split(":")[0]
            return user_id
        return None


# ── Existing tests (all passing, all positive) ─────────────────────────


def test_register_and_validate_key():
    v = APIKeyValidator()
    v.register_key("sk-test-key-12345", "alice", ["read", "write"])
    record = v.validate_key("sk-test-key-12345")
    assert record is not None
    assert record.owner == "alice"


def test_invalid_key_returns_none():
    v = APIKeyValidator()
    v.register_key("sk-test-key-12345", "alice", ["read"])
    assert v.validate_key("sk-wrong-key") is None


def test_has_scope():
    v = APIKeyValidator()
    v.register_key("sk-test-key-12345", "alice", ["read", "write"])
    assert v.has_scope("sk-test-key-12345", "read") is True
    assert v.has_scope("sk-test-key-12345", "admin") is False


def test_validate_token():
    tv = TokenValidator(["token-abc-123", "token-def-456"])
    assert tv.validate_token("token-abc-123") is True
    assert tv.validate_token("wrong-token") is False


def test_validate_token_with_prefix():
    tv = TokenValidator(["abc-123", "def-456"])
    assert tv.validate_token_with_prefix("Bearer abc-123", "Bearer ") is True
    assert tv.validate_token_with_prefix("Bearer wrong", "Bearer ") is False
    assert tv.validate_token_with_prefix("NoPrefix abc-123", "Bearer ") is False


def test_session_authenticator():
    sa = SessionAuthenticator("my-secret")
    token = sa.create_session_token("user-42")
    user_id = sa.verify_session_token(token)
    assert user_id == "user-42"


def test_session_authenticator_rejects_tampered():
    sa = SessionAuthenticator("my-secret")
    token = sa.create_session_token("user-42")
    tampered = token[:-4] + "XXXX"
    assert sa.verify_session_token(tampered) is None


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")
