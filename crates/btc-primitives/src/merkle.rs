//! Merkle trees — how a block commits to its transactions in 32 bytes.
//!
//! A block header has room for exactly one hash to represent every transaction
//! in the block, however many there are. The merkle root is that hash: pair up
//! the transaction ids, hash each pair, and repeat until one hash is left.
//!
//! ```text
//!            root
//!          /      \
//!      h(1,2)      h(3,4)
//!      /    \      /    \
//!    tx1   tx2   tx3   tx4
//! ```
//!
//! This is what makes mining cheap to re-target. When the coinbase changes —
//! and it changes on every extranonce increment — only the leftmost path up the
//! tree has to be recomputed, not the whole thing. That path is the "merkle
//! branch", and it is what a Stratum server sends to its miners instead of the
//! full transaction list.
//!
//! # The odd-node quirk (CVE-2012-2459)
//!
//! When a level has an odd number of nodes, Bitcoin duplicates the last one to
//! make a pair. This was a mistake: it means two *different* transaction lists
//! can produce the same merkle root — append a duplicate of the final
//! transaction and the root is unchanged. In 2012 that was exploitable to make
//! nodes reject valid blocks.
//!
//! The rule cannot be changed without a hard fork, so Bitcoin Core instead
//! rejects any block containing duplicate transactions. We reproduce the
//! duplication faithfully, because a merkle root computed any other way simply
//! would not match what the network expects.

use crate::hash::Sha256dHash;

/// Computes the merkle root of a list of transaction ids.
///
/// Returns `None` for an empty list: a block always has at least a coinbase
/// transaction, so an empty list means something has already gone wrong
/// upstream, and inventing a root for it would hide the bug.
pub fn merkle_root(leaves: &[Sha256dHash]) -> Option<Sha256dHash> {
    if leaves.is_empty() {
        return None;
    }

    let mut level: Vec<Sha256dHash> = leaves.to_vec();

    while level.len() > 1 {
        // An odd level duplicates its last node — see the CVE note above.
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("level is non-empty"));
        }

        level = level.chunks_exact(2).map(|pair| combine(pair[0], pair[1])).collect();
    }

    Some(level[0])
}

/// Hashes two child nodes into their parent: `sha256d(left || right)`.
///
/// Both children go in as internal-order bytes, which is why [`Sha256dHash`]
/// exposes that ordering explicitly rather than leaving it to chance.
pub fn combine(left: Sha256dHash, right: Sha256dHash) -> Sha256dHash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left.as_internal_bytes());
    buf[32..].copy_from_slice(right.as_internal_bytes());
    Sha256dHash::hash(&buf)
}

/// Computes the merkle branch for the **first** leaf — the coinbase.
///
/// The branch is the sibling at each level of the path from the coinbase up to
/// the root. Given the branch, the root can be recomputed from any coinbase
/// transaction without knowing the other transactions at all, which is exactly
/// what makes Stratum work: the pool sends this list once, and the miner can
/// then vary its coinbase freely and still produce a valid header.
///
/// Returns an empty branch for a single-transaction block, where the coinbase
/// txid *is* the root.
pub fn coinbase_branch(leaves: &[Sha256dHash]) -> Vec<Sha256dHash> {
    let mut branch = Vec::new();
    let mut level: Vec<Sha256dHash> = leaves.to_vec();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("level is non-empty"));
        }

        // The coinbase is always at index 0, so its sibling is always index 1.
        branch.push(level[1]);

        level = level.chunks_exact(2).map(|pair| combine(pair[0], pair[1])).collect();
    }

    branch
}

/// Rebuilds a merkle root from the first leaf and its branch.
///
/// The inverse of [`coinbase_branch`]. Because the coinbase is always the
/// leftmost leaf, it is always the *left* child at every level, so the fold
/// never has to ask which side it is on.
pub fn root_from_coinbase_branch(coinbase: Sha256dHash, branch: &[Sha256dHash]) -> Sha256dHash {
    branch.iter().fold(coinbase, |acc, sibling| combine(acc, *sibling))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> Sha256dHash {
        Sha256dHash::hash(&[n])
    }

    #[test]
    fn single_leaf_is_its_own_root() {
        assert_eq!(merkle_root(&[leaf(1)]), Some(leaf(1)));
    }

    #[test]
    fn empty_has_no_root() {
        assert_eq!(merkle_root(&[]), None);
    }

    #[test]
    fn two_leaves_combine_directly() {
        assert_eq!(
            merkle_root(&[leaf(1), leaf(2)]),
            Some(combine(leaf(1), leaf(2)))
        );
    }

    /// Three leaves: the third is duplicated to pair with itself.
    #[test]
    fn odd_level_duplicates_last_node() {
        let expected = combine(combine(leaf(1), leaf(2)), combine(leaf(3), leaf(3)));
        assert_eq!(merkle_root(&[leaf(1), leaf(2), leaf(3)]), Some(expected));
    }

    /// The CVE itself, demonstrated: appending a duplicate of the last
    /// transaction leaves the root unchanged. This is why Bitcoin Core has to
    /// reject blocks with duplicate transactions separately.
    #[test]
    fn duplicate_last_leaf_collides() {
        let three = merkle_root(&[leaf(1), leaf(2), leaf(3)]);
        let four = merkle_root(&[leaf(1), leaf(2), leaf(3), leaf(3)]);
        assert_eq!(three, four, "the CVE-2012-2459 collision");
    }

    /// The branch must reproduce the root for every tree size, including the
    /// odd ones where duplication happens partway up.
    #[test]
    fn branch_reproduces_root_at_every_size() {
        for count in 1..=33u8 {
            let leaves: Vec<_> = (1..=count).map(leaf).collect();
            let branch = coinbase_branch(&leaves);

            assert_eq!(
                root_from_coinbase_branch(leaves[0], &branch),
                merkle_root(&leaves).expect("non-empty"),
                "branch failed for a tree of {count} leaves"
            );
        }
    }
}
