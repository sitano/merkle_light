use hash::Algorithm;
use std::fmt::Debug;

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
pub struct Proof<T: Ord + Clone + Default + Debug> {
    lemma: Vec<T>,
    path: Vec<bool>,
}

impl<T: Sized + Ord + Clone + Default + Debug> Proof<T> {
    /// Creates new MT inclusion proof
    pub fn new(hash: Vec<T>, path: Vec<bool>) -> Proof<T> {
        assert!(hash.len() > 2);
        assert_eq!(hash.len() - 2, path.len());
        Proof { lemma: hash, path }
    }

    /// Return proof target leaf
    pub fn item(&self) -> T {
        self.lemma.first().unwrap().clone()
    }

    /// Return tree root
    pub fn root(&self) -> T {
        self.lemma.last().unwrap().clone()
    }

    /// Verifies MT inclusion proof
    pub fn validate<A: Algorithm<T>>(&self, mut alg: A) -> bool {
        let size = self.lemma.len();
        if size < 2 {
            return false;
        }

        let mut h = self.item();

        for i in 1..size - 1 {
            alg.reset();
            h = match self.path[i - 1] {
                true => alg.node(h, self.lemma[i].clone()),
                false => alg.node(self.lemma[i].clone(), h),
            };
        }

        h == self.root()
    }
}
