use hash::{Hashable, AsBytes, Algorithm};
use std::hash::Hasher;

/// Merkle Tree.
///
/// All leafs and nodes stored sequential.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleTree<T: AsBytes+Sized+Ord+Clone, A: Algorithm<T>> {
    data: Vec<T>,
    alg: A,
}

impl<T: AsBytes+Sized+Ord+Clone, A: Algorithm<T>+Hasher> MerkleTree<T, A> {
    /// Creates a new merkle tree evaluating hashes for the input data and
    /// the whole tree it self.
    pub fn new<U: Hashable<A>>(data: &[U], alg: A) -> MerkleTree<T, A> {
        let mut t: MerkleTree<T, A> = MerkleTree {
            data: Vec::with_capacity(data.len()),
            alg
        };

        for i in 0..data.len() {
            data[i].hash(&mut t.alg);
            t.data.push(t.alg.hash());
            t.alg.reset();
        }

        t
    }
}

