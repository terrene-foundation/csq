"""Token redaction — Python port of `csq-core/src/error.rs:161 redact_tokens`.

Patterns covered:
1. Known OAuth prefixes (`sk-ant-oat01-`, `sk-ant-ort01-`) — always redacted.
2. Prefix-with-body tokens: `sk-` (≥20), `sess-` (≥20), `rt_` (≥20), `AIza` (≥30).
3. Long bare hex (≥32 chars).
4. JWT triple-segment (`eyJ<b64url>+.eyJ<b64url>+.<b64url>+`).
5. PEM blocks (`-----BEGIN ...-----...-----END ...-----`) — pre-pass.

Word-boundary guard (R1-HIGH-01): prefix patterns 1/2/4 only match when the
preceding char is NOT a key-body char. Prevents false positives like
`module_sk-1234567890123456789012345`. Python's naive `\\b` regex is INCORRECT
for this — we replicate Rust's `is_key_char` predicate manually.

Patterns are byte-pattern-based, NOT JSON-field-name-based. The redactor
catches token-shaped bytes wherever they appear; if a token is in
`error_description`, pattern-match catches it. If a non-token diagnostic phrase
is in `error_description`, it stays.
"""

from __future__ import annotations

# Mirror the Rust constants byte-for-byte for parity.
KNOWN_TOKEN_PREFIXES: tuple[str, ...] = ("sk-ant-oat01-", "sk-ant-ort01-")

TOKEN_PREFIXES_WITH_BODY: tuple[tuple[str, int], ...] = (
    ("sk-", 20),
    ("sess-", 20),
    ("rt_", 20),
    ("AIza", 30),
)

JWT_SEGMENT_MIN_BODY: int = 17
HEX_MIN_LEN: int = 32
REDACTED: str = "[REDACTED]"


def _is_key_char(c: str) -> bool:
    """ASCII alphanumeric + `-` + `_` (matches Rust `is_key_char`)."""
    return c.isascii() and (c.isalnum() or c == "-" or c == "_")


def _is_hex_char(c: str) -> bool:
    """ASCII hex digit (matches Rust `is_hex_char`)."""
    return c.isascii() and c in "0123456789abcdefABCDEF"


def redact_pem_blocks(s: str) -> str:
    """Replace every `-----BEGIN <tag>-----...-----END <tag>-----` block with `[REDACTED]`.

    Public so the test module can exercise it directly. Mirrors Rust's
    `redact_pem_blocks`. Permissive on tag (any reasonable PEM type).
    """
    BEGIN_MARKER = "-----BEGIN "
    END_MARKER = "-----END "
    if BEGIN_MARKER not in s:
        return s
    out: list[str] = []
    cursor = 0
    while cursor < len(s):
        rest = s[cursor:]
        begin_idx = rest.find(BEGIN_MARKER)
        if begin_idx < 0:
            out.append(rest)
            break
        out.append(rest[:begin_idx])
        after_begin = rest[begin_idx:]
        end_idx = after_begin.find(END_MARKER)
        if end_idx < 0:
            # Unterminated PEM: redact defensively.
            out.append(REDACTED)
            break
        after_end = after_begin[end_idx + len(END_MARKER) :]
        close_dash_idx = after_end.find("-----")
        consumed_after_end = (
            (close_dash_idx + 5) if close_dash_idx >= 0 else len(after_end)
        )
        out.append(REDACTED)
        cursor += begin_idx + end_idx + len(END_MARKER) + consumed_after_end
    return "".join(out)


def redact_tokens(s: str) -> str:
    """Replace token-like strings with [REDACTED].

    See module docstring for full pattern list. Output is byte-for-byte
    identical to `csq-core::error::redact_tokens` for the same input on the
    fixture set at `error.rs:686-1013`.
    """
    if not s:
        return s

    # Pre-pass: collapse PEM blocks first.
    s = redact_pem_blocks(s)

    chars = list(s)
    n = len(chars)
    out: list[str] = []
    i = 0

    while i < n:
        # Word-boundary guard: prefix patterns only match when prev char is NOT a key char.
        word_boundary = i == 0 or not _is_key_char(chars[i - 1])

        # --- Pattern 1: known OAuth token prefixes (always redact body) ---
        matched_known = False
        if word_boundary:
            for prefix in KNOWN_TOKEN_PREFIXES:
                plen = len(prefix)
                if i + plen <= n and "".join(chars[i : i + plen]) == prefix:
                    j = i + plen
                    while j < n and _is_key_char(chars[j]):
                        j += 1
                    out.append(REDACTED)
                    i = j
                    matched_known = True
                    break
        if matched_known:
            continue

        # --- Pattern 2: prefix-with-body tokens (sk-*, sess-*, rt_*, AIza*) ---
        matched_prefixed = False
        if word_boundary:
            for prefix, min_body in TOKEN_PREFIXES_WITH_BODY:
                plen = len(prefix)
                if i + plen > n:
                    continue
                if "".join(chars[i : i + plen]) != prefix:
                    continue
                j = i + plen
                while j < n and _is_key_char(chars[j]):
                    j += 1
                body_len = j - (i + plen)
                if body_len >= min_body:
                    out.append(REDACTED)
                    i = j
                    matched_prefixed = True
                    break
        if matched_prefixed:
            continue

        # --- Pattern 4 (BEFORE hex): JWT triple-segment ---
        # Three base64url segments separated by dots; each segment body must be
        # ≥ JWT_SEGMENT_MIN_BODY chars. Placed BEFORE hex because `eyJ...`
        # would be partially consumed by the hex match (`e` is a hex digit).
        if (
            word_boundary
            and i + 3 <= n
            and chars[i] == "e"
            and chars[i + 1] == "y"
            and chars[i + 2] == "J"
        ):
            seg1_body_start = i + 3
            j = seg1_body_start
            while j < n and _is_key_char(chars[j]):
                j += 1
            seg1_body_len = j - seg1_body_start
            if (
                seg1_body_len >= JWT_SEGMENT_MIN_BODY
                and j < n
                and chars[j] == "."
                and j + 4 <= n
                and chars[j + 1] == "e"
                and chars[j + 2] == "y"
                and chars[j + 3] == "J"
            ):
                seg2_body_start = j + 4
                k = seg2_body_start
                while k < n and _is_key_char(chars[k]):
                    k += 1
                seg2_body_len = k - seg2_body_start
                if seg2_body_len >= JWT_SEGMENT_MIN_BODY and k < n and chars[k] == ".":
                    seg3_start = k + 1
                    m = seg3_start
                    while m < n and _is_key_char(chars[m]):
                        m += 1
                    seg3_len = m - seg3_start
                    if seg3_len >= JWT_SEGMENT_MIN_BODY + 3:
                        out.append(REDACTED)
                        i = m
                        continue

        # --- Pattern 3: long bare hex string (≥32 hex chars) ---
        if _is_hex_char(chars[i]):
            j = i
            while j < n and _is_hex_char(chars[j]):
                j += 1
            if j - i >= HEX_MIN_LEN:
                out.append(REDACTED)
                i = j
                continue

        out.append(chars[i])
        i += 1

    return "".join(out)
