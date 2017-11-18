use hash::{Hashable, Algorithm};
use merkle_hash::MerkleHasher;
use std::hash::Hasher;

/// Merkle Tree.
///
/// All leafs and nodes stored sequential.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleTree<T: AsRef<[u8]>+Sized+Ord+Clone, A: Algorithm<T>> {
    data: Vec<T>,
    olen: usize,
    alg: A,
}

impl<T: AsRef<[u8]>+Sized+Ord+Clone, A: Algorithm<T>+Hasher> MerkleTree<T, A> {
    /// Creates a new merkle tree evaluating hashes for the input data and
    /// the whole tree it self.
    pub fn new<U: Hashable<A>>(data: &[U], alg: A) -> MerkleTree<T, A> {
        let mut t: MerkleTree<T, A> = MerkleTree {
            data: Vec::with_capacity(data.len()),
            olen: data.len(),
            alg
        };

        for i in 0..data.len() {
            data[i].hash(&mut t.alg);
            let h = t.alg.hash();

            t.data.push(t.alg.leaf(h));
            t.alg.reset();
        }

        t
    }

    /// Returns original number of elements the tree was built upon.
    pub fn olen(&self) -> usize {
        self.olen
    }
}

