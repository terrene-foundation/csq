# Frozen hook-registry 1b contract

These fixtures derive from Git objects at emitter commit
`1e1416b4155e0c0614c6308ca9a7eccd84b45407`. Schema prose and the sample
emitter name are neutralized locally; their current byte identities are pinned
below. The canonicalization vectors retain their original bytes.

| Fixture | Immutable source | SHA-256 |
| --- | --- | --- |
| schema.json | .claude/hooks/hook-registry.schema.json | faf5ffe730c34919511a1bb49f224d3417b560936479742bc972ac62d92bea5d |
| sample.json | .claude/audit-fixtures/hook-registry/sample-trestle-base.manifest.json | c1d6b2e2d24d5eedeaa6ac003fd894e484be5775733c4b11d5fab1819edcaf2b |
| jcs-vectors.json | .claude/audit-fixtures/hook-registry/jcs-vectors.json | 8ca358b69de77d002a2c47dc671ef90e7dfb9d69079d581839f46d29cc1a9894 |

The sample is 408574 bytes and carries 87 registration rows for 69 hook files.
Its recomputed content hash is
`a64f2ee2fa178307e998ee9ad77891c87f9d7361e938664126e7cbc2bc9326c6`.
Reader tests assert these identities rather than regenerate the expected bytes.

The frozen validator is `.claude/hooks/lib/hook-registry-contract.js`; the
canonical primitive is `lib/jcs-canonicalize.js`, re-exported by `weft-jcs.js`.
All 15 frozen vectors exercise their required strict-parse/canonical layers.
The vectors qualify the frozen implementation outputs; they do not reproduce
the RFC appendix's vectors or certify all RFC 8785 behavior.

Dependencies declare the emitter's static local-require closure only. Shape and
content-hash acceptance cannot establish dependency completeness, source-byte
integrity, signer authority, execution, native activation or semantic equivalence.
Pin admission must verify the runtime entries and dependencies before rows, then
retain each exact entry/closure as immutable bytes rather than reopen source.
Runtime `entry_sha256` is defined but optional in this frozen schema; the reader
preserves absence and the verifier must refuse that unverifiable runtime.
Declared timeout exemptions are retained on admitted rows for operator visibility.
