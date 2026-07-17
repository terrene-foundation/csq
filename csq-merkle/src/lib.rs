//! RFC 6962 Merkle Tree — native, dependency-light implementation.
//!
//! This crate computes inclusion proofs, consistency proofs, and signed-tree-head
//! roots using a Certificate-Transparency-style Merkle tree exactly as specified
//! in [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962#section-2.1).
//! There is NO the enterprise edition / eatp dependency: the tree is built directly on
//! `sha2::Sha256`, the same SHA-256 primitive csq-core's signing path and
//! csq-ledger's checkpoint path use.
//!
//! # Why this is a standalone leaf crate (an internal ticket)
//!
//! The RFC 6962 verifier here was extracted OUT of `csq-ledger` so that BOTH
//! `csq-ledger` (the transparency-log server) AND `csq-core` (which needs to
//! VERIFY inclusion proofs the ledger returns) can depend on the SAME
//! verification code without a dependency cycle. `csq-ledger` already depends on
//! `csq-core`; a `csq-core → csq-ledger` edge (so csq-core could reach the
//! verifier) would be circular. A zero-dependency leaf that both crates depend
//! on breaks the cycle. `csq-ledger` re-exports this crate's symbols
//! (`pub use csq_merkle::…`) so its own callers and tests are unchanged.
//!
//! # Domain separation (RFC 6962 §2.1)
//!
//! The hash of an empty list is `SHA-256()` (the hash of the empty string).
//!
//! For a list with one entry (a leaf) the Merkle Tree Hash is:
//!
//! ```text
//! MTH({d0}) = SHA-256(0x00 || d0)
//! ```
//!
//! For n > 1, with `k` the largest power of two strictly less than `n`:
//!
//! ```text
//! MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//! ```
//!
//! The leaf prefix `0x00` and interior prefix `0x01` are the *domain
//! separation* that makes second-preimage attacks (presenting an interior
//! node as a leaf) infeasible.
//!
//! # Why we hold all leaf hashes in memory
//!
//! csq-ledger recomputes the tree from the persisted leaf-hash list on every
//! checkpoint and every inclusion-proof request. The leaf hashes (32 bytes
//! each) are cheap to hold: 1 million records = 32 MB. The authoritative bytes
//! live on disk (the storage layer); this module is the pure, side-effect-free
//! computation over an already-loaded leaf-hash slice.
//!
//! # Test vectors
//!
//! The unit tests at the bottom of this file verify the implementation against
//! the canonical RFC 6962 test vectors documented in the Certificate
//! Transparency reference implementation
//! (`google/certificate-transparency` `merkle_tree_test`), reproduced inline
//! so the suite is self-contained.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest.
pub type Hash = [u8; 32];

/// Leaf-hash domain-separation prefix (RFC 6962 §2.1).
const LEAF_PREFIX: u8 = 0x00;
/// Interior-node domain-separation prefix (RFC 6962 §2.1).
const NODE_PREFIX: u8 = 0x01;

/// Computes the RFC 6962 leaf hash: `SHA-256(0x00 || leaf_bytes)`.
///
/// `leaf_bytes` is the canonical serialization of the record being logged.
/// The `0x00` prefix prevents a malicious submitter from supplying bytes that
/// collide with an interior node.
#[must_use]
pub fn hash_leaf(leaf_bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(leaf_bytes);
    hasher.finalize().into()
}

/// Computes the RFC 6962 interior hash: `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The hash of an empty tree: `SHA-256()` (hash of the empty string),
/// per RFC 6962 §2.1.
#[must_use]
pub fn empty_root() -> Hash {
    Sha256::new().finalize().into()
}

/// Largest power of two strictly less than `n` (the RFC 6962 split point `k`).
///
/// Precondition: `n >= 2`. For `n == 2` this returns 1.
fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n >= 2, "split point only defined for n >= 2");
    // The highest set bit of (n-1) is the largest power of two < n for n>=2,
    // EXCEPT when n is itself a power of two, where we need k = n/2.
    // RFC 6962 defines k as the largest power of two STRICTLY less than n.
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Computes the Merkle Tree Hash (root) over `leaves` (a slice of leaf hashes),
/// per RFC 6962 §2.1.
///
/// `leaves` MUST already be leaf hashes (output of [`hash_leaf`]), not raw
/// record bytes. An empty slice yields [`empty_root`].
#[must_use]
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_below(n);
            let left = merkle_root(&leaves[..k]);
            let right = merkle_root(&leaves[k..]);
            hash_children(&left, &right)
        }
    }
}

/// Computes the RFC 6962 §2.1.1 audit path (inclusion proof) for the leaf at
/// index `m` in a tree of `leaves`.
///
/// Returns the ordered list of sibling hashes from the leaf level up to (but
/// excluding) the root. An empty path means the tree has exactly one leaf and
/// that leaf IS the root.
///
/// Returns `None` when `m >= leaves.len()` (no such leaf).
#[must_use]
pub fn inclusion_proof(leaves: &[Hash], m: usize) -> Option<Vec<Hash>> {
    if m >= leaves.len() {
        return None;
    }
    Some(path(leaves, m))
}

/// Recursive helper implementing PATH(m, D[n]) from RFC 6962 §2.1.1.
fn path(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    if n == 1 {
        // PATH(0, {d0}) = {}
        return Vec::new();
    }
    let k = largest_power_of_two_below(n);
    if m < k {
        // PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])
        let mut p = path(&leaves[..k], m);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        // PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k])
        let mut p = path(&leaves[k..], m - k);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// Verifies an RFC 6962 inclusion proof: reconstructs the root from
/// `leaf_hash` at index `m` in a tree of size `tree_size` using `proof`, and
/// returns `true` iff it equals `expected_root`.
///
/// This is the verifier any client (the daemon-side `CsqLedgerSink`, or the
/// csq-ledger server's own self-check) runs against a checkpoint. It is the
/// mirror of [`inclusion_proof`].
#[must_use]
pub fn verify_inclusion(
    leaf_hash: &Hash,
    m: usize,
    tree_size: usize,
    proof: &[Hash],
    expected_root: &Hash,
) -> bool {
    if m >= tree_size {
        return false;
    }
    match reconstruct_root_from_path(leaf_hash, m, tree_size, proof) {
        Some(root) => &root == expected_root,
        None => false,
    }
}

/// Reconstructs the root from a leaf hash and its audit path, following the
/// inverse of RFC 6962 §2.1.1 PATH. Returns `None` if the proof length does
/// not match the expected path length for `(m, tree_size)`.
fn reconstruct_root_from_path(
    leaf_hash: &Hash,
    m: usize,
    tree_size: usize,
    proof: &[Hash],
) -> Option<Hash> {
    // Walk the same recursive structure as `path`, consuming proof elements.
    fn go(node: &Hash, m: usize, n: usize, proof: &[Hash]) -> Option<(Hash, usize)> {
        if n == 1 {
            // Leaf level — empty path expected.
            return Some((*node, 0));
        }
        let k = largest_power_of_two_below(n);
        if m < k {
            // Left subtree contains the leaf; next proof element is the right
            // subtree root, appended LAST by `path`. We recurse left first,
            // then consume one proof element from the END of the remaining
            // slice. To keep indexing simple we consume from the front by
            // reversing the order: `path` pushes the sibling AFTER recursion,
            // so the sibling for THIS level is the LAST element of `proof`.
            let (sibling, rest) = proof.split_last()?;
            let (sub, consumed) = go(node, m, k, rest)?;
            Some((hash_children(&sub, sibling), consumed + 1))
        } else {
            let (sibling, rest) = proof.split_last()?;
            let (sub, consumed) = go(node, m - k, n - k, rest)?;
            Some((hash_children(sibling, &sub), consumed + 1))
        }
    }
    let (root, consumed) = go(leaf_hash, m, tree_size, proof)?;
    if consumed == proof.len() {
        Some(root)
    } else {
        None
    }
}

/// Computes the RFC 6962 §2.1.2 consistency proof between a tree of size
/// `m` (older) and a tree of size `n` (newer), where `0 < m <= n`.
///
/// Returns the ordered list of node hashes that prove the size-`m` tree is a
/// prefix of the size-`n` tree (append-only consistency). Returns `None` when
/// `m == 0` or `m > n`.
#[must_use]
pub fn consistency_proof(leaves: &[Hash], m: usize, n: usize) -> Option<Vec<Hash>> {
    if m == 0 || m > n || n > leaves.len() {
        return None;
    }
    if m == n {
        // Equal trees — empty consistency proof (RFC 6962: PROOF(m, D[m]) = {}).
        return Some(Vec::new());
    }
    Some(subproof(leaves, m, n, true))
}

/// Recursive helper implementing SUBPROOF(m, D[n], b) from RFC 6962 §2.1.2.
fn subproof(leaves: &[Hash], m: usize, n: usize, b: bool) -> Vec<Hash> {
    if m == n {
        if b {
            // The subtree is complete and identical — no node needed.
            Vec::new()
        } else {
            // SUBPROOF(m, D[m], false) = {MTH(D[m])}
            vec![merkle_root(&leaves[..m])]
        }
    } else {
        let k = largest_power_of_two_below(n);
        if m <= k {
            // SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
            let mut p = subproof(&leaves[..k], m, k, b);
            p.push(merkle_root(&leaves[k..n]));
            p
        } else {
            // SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])
            let mut p = subproof(&leaves[k..], m - k, n - k, false);
            p.push(merkle_root(&leaves[..k]));
            p
        }
    }
}

/// Verifies an RFC 6962 consistency proof: given the old root (`first_root`
/// at size `m`), the new root (`second_root` at size `n`), and `proof`,
/// returns `true` iff the proof demonstrates the old tree is a prefix of the
/// new tree.
///
/// This is a faithful port of the CT reference verifier. It reconstructs both
/// roots from the proof and checks both match.
#[must_use]
pub fn verify_consistency(
    m: usize,
    n: usize,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> bool {
    if m == 0 || m > n {
        return false;
    }
    if m == n {
        // Equal trees: proof must be empty and roots must match.
        return proof.is_empty() && first_root == second_root;
    }

    // RFC 6962 §2.1.2 verification algorithm (CT reference implementation).
    let mut proof = proof.to_vec();
    // If m is an exact power of two, the reference algorithm prepends the
    // first node implicitly (the old root itself).
    if m.is_power_of_two() {
        proof.insert(0, *first_root);
    }
    if proof.is_empty() {
        return false;
    }

    let mut fn_idx = m - 1;
    let mut sn = n - 1;
    while fn_idx & 1 == 1 {
        fn_idx >>= 1;
        sn >>= 1;
    }

    let mut iter = proof.iter();
    let Some(first) = iter.next() else {
        return false;
    };
    let mut fr = *first;
    let mut sr = *first;

    for c in iter {
        if sn == 0 {
            return false;
        }
        if fn_idx & 1 == 1 || fn_idx == sn {
            fr = hash_children(c, &fr);
            sr = hash_children(c, &sr);
            while fn_idx & 1 == 0 && fn_idx != 0 {
                fn_idx >>= 1;
                sn >>= 1;
            }
        } else {
            sr = hash_children(&sr, c);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }

    &fr == first_root && &sr == second_root && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string into a 32-byte hash (test helper).
    fn h(s: &str) -> Hash {
        let v = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    // ── RFC 6962 canonical test vectors ──────────────────────────────────────
    // Source: google/certificate-transparency reference implementation,
    // `merkle_tree_test.cc` `kSHA256EmptyTreeHash` + the 8-leaf inputs/roots.

    /// `test rfc6962_empty_tree_root_matches_vector`
    #[test]
    fn rfc6962_empty_tree_root_matches_vector() {
        // SHA-256 of the empty string.
        let expected = h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(merkle_root(&[]), expected);
        assert_eq!(empty_root(), expected);
    }

    /// The 8 canonical CT leaf inputs (raw bytes, hex) from the reference test.
    fn ct_leaf_inputs() -> Vec<Vec<u8>> {
        [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ]
        .iter()
        .map(|s| hex::decode(s).unwrap())
        .collect()
    }

    /// `test rfc6962_one_leaf_root_matches_vector`
    #[test]
    fn rfc6962_one_leaf_root_matches_vector() {
        // MTH({""}) = SHA-256(0x00) = leaf hash of empty input.
        let leaves: Vec<Hash> = ct_leaf_inputs()[..1].iter().map(|b| hash_leaf(b)).collect();
        let expected = h("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
        assert_eq!(merkle_root(&leaves), expected);
    }

    /// `test rfc6962_eight_leaf_root_matches_vector`
    #[test]
    fn rfc6962_eight_leaf_root_matches_vector() {
        let leaves: Vec<Hash> = ct_leaf_inputs().iter().map(|b| hash_leaf(b)).collect();
        // Canonical CT root for the 8 inputs above.
        let expected = h("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328");
        assert_eq!(merkle_root(&leaves), expected);
    }

    /// `test rfc6962_inclusion_proof_verifies_for_every_leaf`
    #[test]
    fn rfc6962_inclusion_proof_verifies_for_every_leaf() {
        let leaves: Vec<Hash> = ct_leaf_inputs().iter().map(|b| hash_leaf(b)).collect();
        let root = merkle_root(&leaves);
        for (m, leaf) in leaves.iter().enumerate() {
            let proof = inclusion_proof(&leaves, m).expect("proof exists");
            assert!(
                verify_inclusion(leaf, m, leaves.len(), &proof, &root),
                "inclusion proof failed for leaf {m}"
            );
        }
    }

    /// `test rfc6962_inclusion_proof_rejects_wrong_leaf`
    #[test]
    fn rfc6962_inclusion_proof_rejects_wrong_leaf() {
        let leaves: Vec<Hash> = ct_leaf_inputs().iter().map(|b| hash_leaf(b)).collect();
        let root = merkle_root(&leaves);
        let proof = inclusion_proof(&leaves, 3).expect("proof exists");
        // Use leaf 4's hash with leaf 3's proof — must fail.
        assert!(!verify_inclusion(
            &leaves[4],
            3,
            leaves.len(),
            &proof,
            &root
        ));
    }

    /// `test rfc6962_inclusion_proof_known_path_size_4`
    ///
    /// For a 4-leaf tree, PATH(1, D[4]) = { MTH({d0}), MTH(D[2:4]) }.
    #[test]
    fn rfc6962_inclusion_proof_known_path_size_4() {
        let inputs: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i]).collect();
        let leaves: Vec<Hash> = inputs.iter().map(|b| hash_leaf(b)).collect();
        let proof = inclusion_proof(&leaves, 1).expect("proof");
        assert_eq!(proof.len(), 2, "4-leaf path length for m=1 is 2");
        // First sibling = leaf 0's hash; second = root of [2,3].
        assert_eq!(proof[0], leaves[0]);
        assert_eq!(proof[1], merkle_root(&leaves[2..4]));
    }

    /// `test rfc6962_consistency_proof_verifies_known_pairs`
    #[test]
    fn rfc6962_consistency_proof_verifies_known_pairs() {
        let leaves: Vec<Hash> = ct_leaf_inputs().iter().map(|b| hash_leaf(b)).collect();
        for m in 1..=leaves.len() {
            for n in m..=leaves.len() {
                let old_root = merkle_root(&leaves[..m]);
                let new_root = merkle_root(&leaves[..n]);
                let proof = consistency_proof(&leaves, m, n).expect("proof exists");
                assert!(
                    verify_consistency(m, n, &old_root, &new_root, &proof),
                    "consistency proof failed for m={m} n={n}"
                );
            }
        }
    }

    /// `test rfc6962_consistency_proof_rejects_forked_tree`
    #[test]
    fn rfc6962_consistency_proof_rejects_forked_tree() {
        let leaves: Vec<Hash> = ct_leaf_inputs().iter().map(|b| hash_leaf(b)).collect();
        // Build a "forked" new tree where leaf 2 was rewritten — old tree is
        // NOT a prefix, so the genuine proof for (3,6) must reject the forged
        // old root.
        let mut forked = leaves.clone();
        forked[2] = hash_leaf(b"tampered");
        let forged_old_root = merkle_root(&forked[..3]);
        let new_root = merkle_root(&leaves[..6]);
        let proof = consistency_proof(&leaves, 3, 6).expect("proof");
        assert!(
            !verify_consistency(3, 6, &forged_old_root, &new_root, &proof),
            "consistency proof must reject a forked (non-prefix) old root"
        );
    }

    /// `test rfc6962_leaf_and_node_domain_separation`
    ///
    /// A leaf hash of bytes `X` MUST differ from an interior hash whose
    /// concatenated children equal `X` — the 0x00/0x01 prefix is the defense.
    #[test]
    fn rfc6962_leaf_and_node_domain_separation() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let interior = hash_children(&a, &b);
        // Construct the raw concatenation an attacker would present as a leaf.
        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&b);
        let leaf_of_concat = hash_leaf(&concat);
        assert_ne!(
            interior, leaf_of_concat,
            "domain separation broken: interior node collides with leaf"
        );
    }

    /// `test rfc6962_single_leaf_proof_is_empty_and_root_is_leaf`
    #[test]
    fn rfc6962_single_leaf_proof_is_empty_and_root_is_leaf() {
        let leaf = hash_leaf(b"only");
        let leaves = vec![leaf];
        assert_eq!(merkle_root(&leaves), leaf);
        let proof = inclusion_proof(&leaves, 0).expect("proof");
        assert!(proof.is_empty());
        assert!(verify_inclusion(&leaf, 0, 1, &proof, &leaf));
    }
}
