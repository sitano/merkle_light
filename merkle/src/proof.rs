use hash::Algorithm;

/// Merkle tree inclusion proof for data element, for which item = Leaf(Hash(Data Item)).
///
/// Lemma layout:
///
/// ```text
/// [ h1 h22 h333 ... root ]
/// ```
///
/// Proof validation is positioned hash against lemma path to match root hash.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Proof<T: AsRef<[u8]> + Sized + Ord + Clone + Default> {
    lemma: Vec<T>,
    item: T,
    left: bool,
}

impl<T: AsRef<[u8]> + Sized + Ord + Clone + Default> Proof<T> {
    /// Creates new MT inclusion proof
    pub fn new(lemma: Vec<T>, item: T, left: bool) -> Proof<T> {
        Proof { lemma, item, left }
    }

    /// Verifies MT inclusion proof
    pub fn validate<A: Algorithm<T>>(&self, _: A) -> bool {
        unimplemented!()
    }
}
