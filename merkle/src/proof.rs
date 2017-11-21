use hash::Algorithm;
use merkle_hash::MerkleHasher;

/// Merkle tree inclusion proof for data element, for which item = Leaf(Hash(Data Item)).
///
/// Lemma layout:
///
/// ```text
/// [ item h1x h2y h3z ... root ]
/// ```
///
/// Proof validation is positioned hash against lemma path to match root hash.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Proof<T: AsRef<[u8]> + Sized + Ord + Clone + Default>(Vec<T>, bool);

impl<T: AsRef<[u8]> + Sized + Ord + Clone + Default> Proof<T> {
    /// Creates new MT inclusion proof
    pub fn new(lemma: Vec<T>, left: bool) -> Proof<T> {
        assert!(lemma.len() > 2);
        Proof(lemma, left)
    }

    /// Return proof target leaf
    pub fn item(&self) -> T {
        self.0.first().unwrap().clone()
    }

    /// Return tree root
    pub fn root(&self) -> T {
        self.0.last().unwrap().clone()
    }

    /// Verifies MT inclusion proof
    pub fn validate<A: Algorithm<T>>(&self, mut alg: A) -> bool {
        let size = self.0.len();
        if size < 2 {
            return false
        }

        let mut h = self.item();
        let mut side = self.1; // left == true
        let root = self.root();

        for i in 1 .. size-1 {
            alg.reset();
            match side {
                true => {
                    h = alg.node(h, self.0[i].clone());
                }
                false => {
                    h = alg.node(self.0[i].clone(), h);
                }
            }
            side = !side;
        }

        h == root
    }
}
