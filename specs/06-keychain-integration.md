# 06 Keychain Integration

Spec version: 1.1.0 | Status: DRAFT | Governs: macOS Keychain ownership + read fallback, service-name derivation parity, Linux/Windows fallback

---

## 6.0 Scope

This spec defines csq's interaction with platform credential stores. It is a consumer of spec 01 sections 1.3, 1.5, and 1.7, which describe Claude Code's own behavior. csq's job is to remain parity-compatible with CC so that CC's keychain-fallback read path finds what csq wrote.

## 6.1 macOS service-name derivation (MUST match CC)

**Spec 01 section 1.3** defines the formula CC uses:

```
Default dir (no CLAUDE_CONFIG_DIR):  "Claude Code-credentials"
Custom dir:                          "Claude Code-credentials-<sha256(dir)[:8]>"
```

The hash is computed over the RAW config dir path (NFC-normalized in macOS filesystem terms). csq MUST reproduce this formula exactly. Any divergence causes CC's keychain-fallback read to miss entries csq wrote, surfacing as "Not logged in" for accounts that are actually provisioned.

**Parity test:** csq's unit test suite has a golden-values test that hashes a fixed set of paths and compares to values computed from the formula above. Any CC update that changes the formula breaks this test and is caught before the csq build ships.

## 6.2 Keychain ownership (macOS)

csq does NOT write CC's credential keychain entries — `csq-core/src/credentials/keychain.rs` is read-only by design ("csq does NOT write to the keychain. CC owns its own keychain entries"). CC's `claude auth login` — which `csq login N` runs with `CLAUDE_CONFIG_DIR=config-<N>` (spec 03 §3.2) — writes the credential JSON to the generic-password entry via its own `security add-generic-password` shell-out (spec 01 section 1.7). csq READS that entry as a capture fallback (`credentials::keychain::read`, via the `security find-generic-password` CLI — deliberately NOT the `security-framework` crate, so the read cannot trigger an interactive keychain auth prompt) for the case where CC writes keychain-only and skips `.credentials.json`. The `security-framework` native API IS used elsewhere — for csq's own third-party secret vault (`csq-core/src/platform/secret/macos.rs`) — a separate namespace from CC's credential entries.

**Keychain entries are per-config-dir**:

- For each account N, CC's login writes to service `Claude Code-credentials-<sha256(config-<N> path)[:8]>`.
- For each handle dir `term-<pid>`, nothing writes a keychain entry. The handle dir's `.credentials.json` symlink resolves to the canonical credential file which CC reads directly; CC's keychain lookup uses service name `Claude Code-credentials-<sha256(term-<pid> path)[:8]>` which MAY not exist. When that keychain entry is missing, CC falls back to reading the symlinked file — which is exactly what we want.
- **Consequence:** handle dirs have NO keychain entries in the normal case. The per-handle hash namespace is a fallback that CC never needs to hit.

**Why no per-handle entries?** Each handle dir lives for the life of one `claude` process, often minutes to hours. A keychain entry per handle dir would accumulate hundreds of stale entries over time, all of which CC would read and cache at startup. The file-through-symlink path is faster, cleaner, and has no cleanup cost (symlinks disappear with the handle dir on sweep).

## 6.3 CC's 30-second cache and the csq swap latency bound

Spec 01 section 1.5 documents CC's per-process 30-second keychain read cache. This matters for csq swap's latency:

- When csq swap repoints the handle dir's `.credentials.json` symlink to a new account's file, CC's next `fs.stat` on `.credentials.json` follows the symlink and sees the new mtime. Cache is cleared, credentials re-read. **The read path goes through the secure-storage read which tries the keychain FIRST**.
- The keychain has its own 30-second per-process TTL. If this CC process read the keychain within the last 30 seconds (for whatever reason), it serves that cached value — which is for the OLD account, not the new one.
- **Result:** swap latency is effectively instant IF the csq swap writes the fresh credentials via the file path (symlink resolves → new file → mtime check → memoize cleared → next read hits plaintext fallback). If it writes only via keychain, the current terminal may see up to 30 seconds of stale reads.

**This is why csq swap is a symlink-repoint operation, not a keychain-write operation.** Repointing the symlink makes the change visible instantly through the file path. See spec 02 section 2.3.3 INV-04 for the normative statement.

## 6.4 Write-path guards

When csq writes canonical credentials (daemon refresher → `identities/<UUID>/credentials.json` via `credentials::file::save_canonical_for`; `csq login N` seed path):

1. **Atomic**: temp file + rename, owner permissions `0o600`.
2. **Subscription metadata preserved**: if the new tokens have `null` for `subscription_type` or `rate_limit_tier`, read the existing file and preserve non-null values. See spec 01 section 1.7 and `rules/account-terminal-separation.md` rule 4.
3. **No keychain mirror**: csq never writes the keychain (§6.2). CC's keychain entry holds whatever CC last wrote; the file path is authoritative for csq-managed refresh, and CC picks up fresh file content via the mtime check (spec 01 section 1.4).
4. **Secure file permissions**: `platform::fs::secure_file()` sets `0o600`. Windows is a no-op.

## 6.5 Linux and Windows

**Linux:** no keychain integration is required for the normal CC flow. CC on Linux uses the plaintext-file secure-storage backend directly. csq writes to the file with `0o600` and stops. A future `libsecret` integration is tracked but not in current scope.

**Windows:** named pipe IPC is pending; for credentials, plaintext file with ACLs via `secure_file()` is the current path. Windows Credential Manager integration is tracked but not in current scope.

## 6.6 Keychain cleanup on account deletion

When an account is deleted (via a `csq delete N` command, pending — not currently implemented):

1. Remove `config-<N>/`.
2. Delete the keychain entry via `security delete-generic-password -s "Claude Code-credentials-<hash>"`.
3. Remove `credentials/<N>.json`.
4. Remove profile entry in `profiles.json`.
5. Signal the daemon to stop refresh and polling for N.

## 6.6a Audit signing key entry

The `csq-audit-signing` keychain service stores signing key material for the audit trail (spec 12 §12.11). The entry payload has two accepted formats:

| Format   | When written   | Payload shape                                                                        |
| -------- | -------------- | ------------------------------------------------------------------------------------ |
| New JSON | Current        | `{"seed_hex":"<64hex>","signing_active_since_seq":<u64>,"signing_key_id":"<KeyId>"}` |
| Legacy   | Earlier builds | Bare 64-char lowercase hex string (the Ed25519 seed only)                            |

- Service name: `csq-audit-signing`
- Account: `<chain_id>` (the chain identifier from `chain.json`, NOT a config-dir hash)
- One entry per install (not per-account in the OAuth sense)

The new JSON format co-locates the signing cutoff inside the seed entry so that cutoff and key share fate — see spec 12 §12.11.3a for the rationale.

**Payload contract:**

- `#[serde(deny_unknown_fields)]` is enforced — future fields MUST bump to a versioned schema. Any JSON with an extra field is rejected by `load_from_keychain`.
- `seed_hex` is private-key material. The Rust struct does NOT derive `Debug`. Read paths zeroize the hex string after decoding. `load_embedded_cutoff` parses via `serde_json::Value` (not `SeedEntryPayload`) to avoid allocating `seed_hex` when only the non-secret fields are needed.

This entry is distinct from the OAuth credential entries documented in §6.1–§6.5.

## 6.7 Cross-references

- `specs/01-cc-credential-architecture.md` sections 1.3, 1.5, 1.7 — CC's own keychain behavior (authoritative).
- `specs/02-csq-handle-dir-model.md` section 2.3.3 — why swap is a symlink repoint, not a keychain write.
- `rules/security.md` — credential handling invariants, atomic writes, token redaction.
- `rules/account-terminal-separation.md` rule 4 — subscription-metadata preservation.
