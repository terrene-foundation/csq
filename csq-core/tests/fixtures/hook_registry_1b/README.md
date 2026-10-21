# Frozen Loom hook-registry 1b contract

These three fixtures are copied byte for byte from Git objects at Loom commit
`1e1416b4155e0c0614c6308ca9a7eccd84b45407`, not from its mutable worktree.

| Fixture | Immutable source | SHA-256 |
| --- | --- | --- |
| schema.json | .claude/hooks/hook-registry.schema.json | 8d202ab3d554b4f67af5407131d192b6d2d1b156a7c0e135544ae36d8c209c6d |
| sample.json | .claude/audit-fixtures/hook-registry/sample-trestle-base.manifest.json | ba28556537d7fd77c1361280a158e6918e8bd33a7cff29e2dc83894299ed199f |
| jcs-vectors.json | .claude/audit-fixtures/hook-registry/jcs-vectors.json | 8ca358b69de77d002a2c47dc671ef90e7dfb9d69079d581839f46d29cc1a9894 |

The sample is 408569 bytes and carries 87 registration rows for 69 hook files.
Its recomputed content hash is
`10a48bfb7f1faa41bf14472eeb39c7d61b036c347390277a108bd3e9271fe0c7`.
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
