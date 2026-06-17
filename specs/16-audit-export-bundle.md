# 16 — Audit Export Bundle

**Spec version:** 1.4.0
**Status:** Normative
**Governs:** `csq audit export` — the self-contained, cross-org-verifiable audit-bundle producer, the signed export cutoff (`CUTOFF.json`, §16.14), and the embedded `verify` script contract.

## 16.0 Scope

`csq audit export` packages the local audit chain (spec 12) into a single `.tar`
archive that an **external auditor** — on a machine with NO csq install — can
verify end-to-end. The bundle is the compliance deliverable: the auditor
extracts it, runs the embedded `./verify` script, and gets a `PASS:` / `FAIL:`
verdict.

In scope: single-chain export, the bundle shape, `BUNDLE.lock` / `BUNDLE.sig`
discipline, the `verify` script contract, the cross-org verifiability property,
and the `--rekor` graceful-degradation path.

Out of scope: multi-chain bundles, `csq audit import` (reading an external
bundle into a fresh install), live remote-pull from non-Rekor sinks, and
partial-range (`--since`/`--until`) export.

## 16.1 Authority chain

`csq audit export` is implemented by `csq_core::audit::export::export_bundle`
(`csq-core/src/audit/export.rs`), wired to the CLI by
`csq/src/cli/commands/audit.rs::handle_export` and the `AuditCmd::Export`
variant in `csq/src/cli/mod.rs`. It reuses the chain verifier (`verify_chain`,
spec 12 §12.10) for the mandatory pre-flight and the `LocalSigningKey` (spec 12
§12.9) for the genesis-anchored signature.

## 16.2 Bundle shape

```text
csq-audit-bundle-<chain_id>-<exp_id>.tar
├── chain.jsonl              verbatim on-disk chain records, in sequence
├── public_keys.json         { genesis, keys: { key_id -> raw_pubkey_hex } }
├── rotation_chain.json      { anchor_key_id, entries: [ {previous_key_id, new_key_id, rotation_reason} ] }
├── canonical_form_vectors/
│   ├── VERSION              the canonical-form version (== AUDIT_SCHEMA_VERSION)
│   └── vectors.json         golden (record_json -> canonical_hash) self-check vectors
├── CUTOFF.json              signed export cutoff (head snapshot + anchor ref) — §16.14
├── BUNDLE.lock              sorted-by-path "<sha256>  <relpath>" of every other file
├── BUNDLE.sig               Ed25519 signature over BUNDLE.lock by the genesis-anchored key
└── verify                   self-contained python3-stdlib verifier (mode 0o755)
```

- `<chain_id>` is the chain id (`chain.json::chain_id`, a CSPRNG ULID with no
  PII); `<exp_id>` is a fresh per-export ULID-shaped run id (`gen_run_id`).
- `rotation_chain.json`'s top-level key is `anchor_key_id` — the chain's
  genesis-ANCHORED head signing key (the `BUNDLE.sig` signer). For a chain that
  has rotated keys this is the HEAD key, not the original genesis key; the
  rotation history back to genesis lives in `entries`.
- The archive is an uncompressed POSIX **USTAR** `.tar` (see §16.8). Default
  output path: `csq-audit-bundle-<chain_id>-<exp_id>.tar` in the current
  working directory; the produced path is printed on stdout and echoed on
  stderr for discoverability.

## 16.3 `BUNDLE.lock` and `BUNDLE.sig` discipline

- `BUNDLE.lock` is the SHA-256 of every OTHER bundle file (not itself, not
  `BUNDLE.sig`), one `"<hash>  <relpath>\n"` line per file, sorted by path.
  Recomputing it on a fresh extraction yields the same digest.
- `BUNDLE.sig` is the raw 64-byte Ed25519 signature over `BUNDLE.lock`'s bytes,
  produced by the chain's **genesis-anchored signing key** — the chain's current
  active signing key in the head keychain slot (account = `chain_id`).

**BUNDLE.sig is self-verifying.** `BUNDLE.sig` MUST verify using ONLY the
bundle's own `public_keys.json[genesis]` entry. The verifier fetches NO external
key (no key server, no registry). The bundle is self-contained by construction:
introducing an external key dependency would break the "auditor has no csq
install" property and create a single point of failure.

### 16.3.1 Auditor obligation — confirm the genesis key out-of-band

**The bundle is self-attesting, and a PASS verdict does NOT establish
provenance.** Self-containment is the design goal (the auditor needs no csq
install, no key server), but it means an attacker who tampers with the chain,
re-signs `BUNDLE.lock` with _their own_ key, AND swaps
`public_keys.json[genesis]` to that key produces a bundle that PASSes
identically. The verify script cannot detect this from inside the bundle —
every internal check is consistent with the attacker's key.

**Auditor obligation:** obtain the `genesis` public key via an INDEPENDENT
channel (the operator's published key fingerprint, a key-transparency log, a
direct trusted exchange) and confirm it equals `public_keys.json[genesis]`
BEFORE trusting a PASS. The verify script prints a `NOTE:` line naming the
genesis key id on every PASS to make this obligation unmissable. A PASS without
the out-of-band genesis-key confirmation proves only INTERNAL CONSISTENCY, not
authenticity.

### 16.3.2 Chain completeness rests on BUNDLE.sig over BUNDLE.lock

The chain-walk checks (seq monotonicity, `prev_hash` links, per-record
signatures) detect insertion, reordering, and content tampering, but they
CANNOT detect a dropped TAIL: a verifier handed a truncated `chain.jsonl`
(records 0..k of an 0..n chain) sees a perfectly valid prefix and PASSes. The
ONLY defense against tail truncation is that `BUNDLE.lock` records the exact
SHA-256 of the full `chain.jsonl`, and `BUNDLE.sig` signs `BUNDLE.lock` with the
genesis-anchored key at export time — so any post-export truncation breaks the
per-file SHA-256 check (Step 3) or the `BUNDLE.sig` check (Step 2).

**Consequence:** verifying `chain.jsonl` in isolation (without the
`BUNDLE.lock` + `BUNDLE.sig` gate, or with a re-computed lock) is UNSAFE — it
cannot detect a dropped tail. The verify script always runs Steps 2–3 before
the chain walk for exactly this reason; an auditor MUST NOT bypass them.

## 16.4 `public_keys.json`

Maps every signing key referenced by a chain-record signature — plus the
genesis key and every rotation-chain key — to its raw 32-byte Ed25519 public key
(lowercase hex). The verifier independently derives `key_id` as
`"ed25519:" + sha256(raw_pubkey)` for EVERY key in the map (not only genesis)
and rejects the bundle if ANY key's `key_id` does not match its pubkey. This
closes a tamper vector where a non-genesis pubkey is swapped while its key_id is
left intact: every key that signs a record is derivation-checked before its
signature is trusted.

Export FAILS (refuses to produce a bundle) if any non-placeholder key referenced
by a record cannot be resolved to a pubkey from the head slot or a
`historical/<n>` slot — the bundle must be self-contained, so an un-retained
outgoing key is a hard error (remediation: retain outgoing keys via
`csq audit rotate-key`, per spec 12 §12.9.5).

## 16.5 `canonical_form_vectors/` — embedded, not referenced

**The corpus is embedded.** The bundle embeds golden vectors for the
canonical-form version active when the records were signed; it does NOT reference
an external corpus or a URL.

csq's "canonical form" is deterministic JSON: the record's fields in a FIXED
declaration order (matching `persist.rs::CanonicalView`), with `canonical_hash`
set to the 64-zero genesis sentinel and the `signature` field excluded, emitted
compactly (`serde_json::to_vec`, no whitespace). There is NO external corpus —
the canonical form is fully determined by csq's own serializer.

`vectors.json` embeds ONE golden vector per distinct record SHAPE present in the
exported chain — where a "shape" is the record's `payload.kind` (the
session-custody event kind: `CsqRun`, `OAuthRefresh`, `KeyRotate`,
`AccountSwap`, `AccountLogout`, `AccountMove`, and the anchor-outcome kinds).
Records of the same shape exercise the SAME canonical-form reproduction path, so
one vector per shape gates EVERY shape the verifier will encounter on real
records. Vectors are deduped by shape and capped at a sane bound
(`MAX_CANONICAL_FORM_VECTORS = 64`, comfortably above the event-kind space).

> **Why per-shape, not first-N:** an early implementation embedded the first
> 3 records only. A record SHAPE appearing at index ≥ 3 then had its
> canonical form NEVER self-checked — the verifier could mis-reproduce that
> shape's canonical form and silently mis-verify it. Gating every distinct shape
> closes that gap structurally.

```json
{
  "canonical_form_version": "2",
  "vectors": [
    {
      "name": "shape_0",
      "shape_key": "CsqRun",
      "record_json": "<verbatim on-disk line>",
      "canonical_hash": "<hex>"
    }
  ]
}
```

`record_json` is the VERBATIM on-disk record line (a JSON string), NOT a parsed
object — a round-trip through a JSON object backed by a sorted map would reorder
the `payload` enum's `{"kind","data"}` fields and diverge from the on-disk
bytes. `VERSION` holds the `canonical_form_version` value verbatim.

The `verify` script self-checks each vector
(`sha256(canonical_bytes(json.loads(record_json))) == canonical_hash`) BEFORE
trusting its canonical-form reproduction on any real chain record. If the
self-check fails, the script FAILs with a "cannot reproduce csq's canonical
form" message rather than silently mis-verifying.

## 16.6 The `verify` script contract

**Stdlib-only, runs with no csq.** The `verify` script is `#!/usr/bin/env
python3` and uses ONLY the Python 3 standard library (`hashlib`, `json`,
`base64`, `tarfile`, `urllib`). Ed25519 signature verification is a pure-Python
RFC 8032 implementation embedded in the script — neither the `cryptography` PyPI
package NOR the `openssl` CLI is required.

> **Why pure-Python Ed25519, not `openssl`:** macOS ships **LibreSSL** at
> `/usr/bin/openssl`, whose `pkeyutl` does NOT support Ed25519 (no `-rawin`,
> unsupported-algorithm error). An `openssl`-dependent verifier would FAIL on a
> stock macOS auditor machine. A pure-Python verifier is the only construction
> that runs identically on Linux (OpenSSL), macOS (LibreSSL), and Windows
> without any install step. This satisfies the "truly vanilla machine"
> requirement of the stdlib-only directive.

The script is cross-platform: the `#!/usr/bin/env python3` shebang is a Unix
convenience for `./verify`, but the verifier itself is pure Python-3 stdlib
and runs identically everywhere. A Windows auditor runs `python3 verify`
directly (the shebang is ignored). Consequently the Rust unit tests that
spawn the script via a hardened `PATH=/usr/bin:/bin` and shebang execution
are `#[cfg(unix)]`-gated — the gate is on the test's shell-isolation harness,
not on the artifact's portability; the producer-side bundle/lock/sig/vectors
tests run on every platform.

The script, run from the extracted bundle directory, performs in order:

1. **Required-files check** — all 8 entries present.
2. **`BUNDLE.sig` over `BUNDLE.lock`** via `public_keys.json[genesis]` — FAILs
   first (before any chain check) with
   `"BUNDLE.sig verification failed: bundle tamper detected at export-time
anchor key"` so a tampered `BUNDLE.lock` surfaces as a signature failure.
3. **Per-file SHA-256** vs `BUNDLE.lock` — FAILs with
   `"file <path> SHA-256 mismatch: bundle file <path> tampered after BUNDLE.sig
was created"`.
4. **`CUTOFF.json` signed-cutoff self-check** (§16.14) — `cutoff_version`
   is `1`; `key_id` equals `public_keys.json[genesis]`; the recomputed canonical
   cutoff hash equals the stored `cutoff_hash`; and the `signature` verifies
   against the genesis pubkey over the 32 raw bytes of `cutoff_hash` (same
   signing contract as chain records, spec 12 §12.10.8). The HEAD cross-check is
   deferred to step 6 (needs the walked chain head).
5. **`canonical_form_vectors` self-check** (§16.5).
6. **Chain integrity** — for each `chain.jsonl` record: seq monotonicity,
   `prev_hash` chain link, `canonical_hash` recompute, and the per-record
   Ed25519 signature (skipping the all-zeros placeholder key). The signing
   pre-image is the 32 raw bytes of the recomputed `canonical_hash` (the unified
   signing contract, spec 12 §12.10.8). Each FAIL names the failing
   record's `record_id` and the failure mode. Non-placeholder keys MUST be
   present in `public_keys.json` AND anchored in `rotation_chain.json`.
7. **`CUTOFF.json` head cross-check** (§16.14) — `latest_seq` /
   `latest_hash` MUST equal the walked chain HEAD's `seq` / `canonical_hash`
   (explicit tail-truncation / head-tamper detection); and when
   `latest_anchor_ref` is present, `chain.jsonl[ack_seq]` MUST be a
   `replication_ack` carrying the same `sink` + `sink_id`.
8. **`--rekor <url>` (optional)** — best-effort entry-existence check, §16.7.
9. **Verdict** — `PASS: chain verified end-to-end (N records, M key rotations, K
signed records; signed cutoff confirms head seq S)` (exit 0) followed by a
   `NOTE:` line restating the auditor obligation to confirm the genesis key
   out-of-band (§16.3.1); or `FAIL: <specific>` (exit 1). Environment errors
   (bad args) exit 2.

The next record's `prev_hash` is checked against the SHA-256 of the previous
record's canonical bytes computed WITH its real (stored) `canonical_hash` in
place — matching how csq's writer computes `prev_hash` from
`canonical_bytes_for(prev_record)`.

## 16.7 `--rekor` best-effort entry-EXISTENCE check (NOT an inclusion proof)

**This is NOT cryptographic inclusion-proof verification.** `./verify --rekor
<url>` performs a _best-effort Rekor entry-EXISTENCE check_ for records that
carry a `rekor_log_index` field. For each such record it fetches the named log
entry over stdlib `urllib`, parses the Rekor response, and structurally confirms
the entry's `hashedrekord` digest (`spec.data.hash.value`) equals the record's
`canonical_hash`. The check is a STRUCTURED field comparison, not a raw
substring scan — arbitrary blob content cannot satisfy it.

What it deliberately does NOT do:

- It does NOT verify a Merkle inclusion proof.
- It does NOT validate a signed tree head / checkpoint.
- It does NOT establish that the entry is committed to the log's Merkle tree.

So a PASS under `--rekor` means "an entry with this digest exists at the named
index on the queried Rekor instance," not "this record is cryptographically
proven to be in the transparency log."

- `--rekor` absent → `WARN: --rekor not passed; Rekor entry-existence check
skipped` and local verification still **PASS**es (exit 0).
- `--rekor` present but no record carries a `rekor_log_index` → `WARN: ... Rekor
entry-existence check skipped for this chain` and still **PASS**.
- `--rekor` present and an entry fails to fetch or does not reference the
  expected hash → **FAIL** (exit 1).

No Sigstore SDK is used — `urllib`, `json`, and `base64` (stdlib) only.

### 16.7.1 Future work — real inclusion-proof verification

Real Sigstore Rekor Merkle-inclusion-proof verification against a signed tree
head is future work, gated on a prerequisite that does not yet exist: csq's
Rekor sink does not currently emit `rekor_log_index` (or the inclusion-proof
material — log index, hashes, tree size, root hash, checkpoint) into chain
records. There is therefore no data to verify a proof against today.

Implementing a stdlib hand-rolled Merkle-inclusion-proof verifier now would be
both untestable (no real `rekor_log_index` data) and a re-implementation of an
upstream transparency-log proof verifier in stdlib Python. The honest
deliverable today is the entry-existence check above, labeled as such everywhere
it surfaces (verify script output, `--help`, this spec). When the Rekor sink
emits the proof material, this section is upgraded to inclusion-proof
verification and the verify script's wording changes accordingly.

## 16.8 Dependency footprint

`csq audit export` adds **ZERO new Rust crates**. `zstd`, `tar`, `flate2`, and
`zip` are NOT in csq's dependency tree. The bundle is an uncompressed POSIX
USTAR `.tar` produced by a hand-rolled writer (`export::tar`) using only `std`:
512-byte headers (octal numeric fields, `ustar\0` magic, computed checksum,
fixed `mtime = 4102444800` for determinism), content padded to 512-byte
boundaries, two zeroed trailing blocks. A plain `.tar` is universally
extractable (`tar xf`, Python stdlib `tarfile`) without any third-party tooling.

> **Trade-off (compression):** a `.tar.zst` would be smaller but `zstd` is not
> in the tree (a new dep) and not universally installed on a vanilla auditor
> machine. Audit chains are small JSONL; the size win does not justify a
> dependency that would also need an extraction tool the auditor may not have.
> Plain `.tar` wins on the "no install on the auditor's machine" property that
> is the whole point of the bundle.

## 16.9 Pre-flight verification

Before packaging, `export_bundle` runs `verify_chain` over the WHOLE local
chain (`record_limit = usize::MAX`). If the local chain does not verify, export
returns `ExportError::PreflightFailed` and writes NOTHING — a bundle that fails
locally cannot verify for an external auditor, so csq refuses to produce one.
Empty chains return `ExportError::EmptyChain`.

## 16.10 `--since` / `--until` (CLI-surface stability)

The `--since` and `--until` flags are accepted for forward-compatibility but the
bundle currently always exports the WHOLE local chain. This mirrors
`csq audit verify --since` being a documented no-op (spec 12 §12.10.5);
partial-range export requires a chain-link look-behind and is future work. The
flags neither narrow nor error today.

When either flag is set, `export_bundle` emits a `WARN:` line on stderr stating
the flags are accepted but NOT yet applied and that the whole chain is exported,
so the no-op is never silent.

## 16.11 Security

- The final bundle write uses the secret-file write pipeline (`unique_tmp_path →
write → secure_file → atomic_replace`) with `remove_file(&tmp)` on every failure
  branch (per the security spec §5a).
- Error messages are fixed-vocabulary and routed through `redact_tokens` at the
  CLI boundary — no token/path echo.
- The bundle contains audit records and PUBLIC keys only; private signing key
  material never leaves the keychain.

## 16.12 Implementation surface

- `csq-core/src/audit/export.rs` — `export_bundle`, `ExportError`,
  `ExportSummary`, the stdlib USTAR `tar` writer, canonical-form vectors,
  rotation-chain assembly.
- `csq-core/src/audit/cutoff.rs` — `build_cutoff_json`, `CutoffManifest`,
  `AnchorRef`, `CutoffError` (the signed export cutoff, §16.14).
- `csq-core/src/audit/export/verify.py.template` — the embedded `verify` script
  (shipped verbatim via `include_str!`).
- `csq/src/cli/commands/audit.rs::handle_export` — CLI handler.
- `csq/src/cli/mod.rs` — `AuditCmd::Export` variant + dispatch arm.

## 16.13 Cross-references

- **Spec 12 — csq Audit Trail** (`12-audit-trail.md`): §12.10 chain verifier
  reused for the export pre-flight; §12.10.8 the unified signing contract the
  `verify` script reproduces; §12.9 key custody (the genesis-anchored signing
  key); §12.18 the anchor driver that writes the `replication_ack` records the
  cutoff's `latest_anchor_ref` references.
- **Spec 15 — LedgerSink Trait and Reference-Impl Catalog**
  (`15-ledgersink-trait-and-sinks.md`): the Rekor sink for the `--rekor` path.
- The security spec §5a — bundle-write cleanup discipline.

## 16.14 `CUTOFF.json` — signed export cutoff

`csq audit export` embeds a `CUTOFF.json` carrying a signed snapshot of the
chain HEAD at export time, plus the most recent external-anchor reference. It is
the export-time tamper-evidence and makes **tail-truncation detection
explicit** — without it, a dropped tail is detected only implicitly via
`BUNDLE.lock`'s SHA-256 over the whole `chain.jsonl`; the cutoff pins
`(latest_hash, latest_seq)` in a signed artifact the verifier cross-checks
against the walked head.

### 16.14.1 Manifest shape

```json
{
  "cutoff_version": "1",
  "chain_id": "<chain_id>",
  "latest_hash": "<chain HEAD canonical_hash>",
  "latest_seq": <chain HEAD seq>,
  "latest_anchor_ref": { "sink": "rekor", "sink_id": "<id>", "ack_seq": <seq> },
  "export_ts": "<ISO-8601 UTC>",
  "cutoff_hash": "<sha256 of the canonical pre-image>",
  "key_id": "<genesis-anchored export key id>",
  "signature": "<hex Ed25519 over the 32 raw bytes of cutoff_hash>"
}
```

- `latest_anchor_ref` is `null` for a never-anchored chain. When present it
  references the most recent `replication_ack` chain record (the anchor driver's
  outcome record, spec 12 §12.18): `ack_seq` is that record's own `seq` — the
  chain-authoritative anchor evidence. The per-sink `anchor-state-<sink>.json`
  is NOT used (it is not in the bundle and is attacker-writable).
- `chain_id` binds the cutoff to its chain, closing cross-chain replay.
- **The verifier confirms the referenced ack EXISTS and matches**
  (`chain.jsonl[ack_seq]` is a `replication_ack` with the same `sink` +
  `sink_id`); it does NOT independently re-derive that this is the
  chain-rev-LATEST ack — an honest exporter always emits the rev-latest, but the
  cross-check's purpose is to bind the cutoff to a real anchor record in the
  bundled chain, not to enforce recency. Likewise a `null` `latest_anchor_ref`
  does NOT prove the chain was never anchored — an exporter holding the genesis
  key could emit `null` to omit the link. The authoritative anchor history is
  the set of `replication_ack` records in `chain.jsonl` (covered by
  `BUNDLE.lock`), which an auditor can scan directly. This parallels the §16.3.1
  self-attestation boundary: the cutoff proves what the (genesis-key-holding)
  exporter ASSERTED, anchored to records in the bundle, not an independent
  recency/completeness guarantee.

### 16.14.2 Signing contract — reuse, do not re-roll

The cutoff is signed by the **genesis-anchored export key** (the same key that
signs `BUNDLE.sig`) over the SAME contract as every chain record (spec 12
§12.10.8): `cutoff_hash = sha256(canonical_pre_image)`, then Ed25519 over the
**32 raw bytes** of `cutoff_hash`. The canonical pre-image is the manifest with
`cutoff_hash` forced to the 64-zero genesis sentinel and `signature` excluded,
compact JSON, fields in the declaration order shown above; `latest_anchor_ref`
is `null` or an ordered `{sink, sink_id, ack_seq}` (a typed struct — declaration
order, not key-sorted). An auditor reproduces the cutoff hash with the SAME
routine the embedded verifier already runs on chain records, so no new
verification machinery is introduced.

### 16.14.3 Defense layering

`CUTOFF.json` is covered by `BUNDLE.lock` (so `BUNDLE.sig` detects a post-export
swap) AND carries its own canonical-form signature (so the cutoff tuple is
reproducibly verifiable independent of the file manifest). The verifier checks
both: Step 4 (self-consistency: hash + signature) and Step 7 (HEAD cross-check +
anchor-ref cross-check) — see §16.6.

## Revisions

- 1.4.0 — Bundle shape stabilized at 8 entries (`chain.jsonl`,
  `public_keys.json`, `rotation_chain.json`, `canonical_form_vectors/`,
  `CUTOFF.json`, `BUNDLE.lock`, `BUNDLE.sig`, `verify`). Canonical-form vectors
  keyed on `payload.kind` per distinct record shape.
- 1.2.0 — Signed export cutoff. `CUTOFF.json` bundle entry carrying
  `(chain_id, latest_hash, latest_seq, latest_anchor_ref, export_ts)`, signed by
  the genesis-anchored export key over the 32 raw bytes of its canonical hash
  (the §12.10.8 contract, reused — NOT re-rolled). §16.14 (manifest shape;
  signing contract; defense layering — covered by BUNDLE.lock AND self-signed).
  `verify` script gained the cutoff self-check (version, key_id == genesis,
  recomputed cutoff_hash, signature) and the HEAD cross-check (explicit
  tail-truncation detection) plus the anchor-ref cross-check; PASS line reports
  the cutoff head seq.
- 1.1.1 — §16.6: documented that the `verify` script is cross-platform (pure
  Python-3 stdlib; the `#!/usr/bin/env python3` shebang is a Unix convenience —
  a Windows auditor runs `python3 verify` directly). The Rust unit tests that
  spawn the script via a hardened `PATH=/usr/bin:/bin` + shebang execution are
  `#[cfg(unix)]`-gated; the gate is on the test's shell-isolation harness, not
  the artifact's portability. The producer-side bundle/lock/sig/vectors tests
  stay platform-agnostic.
- 1.1.0 — Verifier hardening: relabeled `--rekor` from "inclusion-proof
  verification" to a best-effort entry-EXISTENCE check, explicitly NOT a
  cryptographic inclusion proof (§16.7), hardened from a raw-substring scan to a
  structured `spec.data.hash.value` field comparison; §16.7.1 documents real
  Merkle-inclusion-proof verification as future work gated on the Rekor sink
  emitting `rekor_log_index`. The canonical-form self-check now covers ONE vector
  per distinct record SHAPE in the chain, not just the first 3 records (§16.5).
  §16.3.1 documents the auditor obligation to confirm the genesis public key
  out-of-band before trusting a PASS (the bundle is self-attesting); the verify
  script prints a `NOTE:` line on every PASS. §16.3.2 documents that chain
  completeness (no tail truncation) rests entirely on `BUNDLE.sig` over
  `BUNDLE.lock`. §16.4: the verifier derivation-checks EVERY key in
  `public_keys.json` (`key_id == "ed25519:" + sha256(pubkey)`), not only genesis.
  §16.10: `--since`/`--until` now emit a WARN when set so the no-op is never
  silent.
- 1.0.0 — Initial spec. `csq audit export` verifiable-bundle producer + embedded
  stdlib-only `verify` script. Records the pure-Python Ed25519 decision (LibreSSL
  on macOS does not support Ed25519 via `openssl`), the zero-new-Rust-crate
  `.tar` decision, and the embedded canonical_form_vectors self-check.
