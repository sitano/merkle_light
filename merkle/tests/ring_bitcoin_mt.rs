#![cfg(test)]
#![cfg(feature = "bitcoin")]

extern crate ring;
extern crate merkle_light;

use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::merkle::MerkleTree;
use ring::digest::{Context, SHA256};
use std::fmt;
use std::hash::Hasher;
use std::iter::FromIterator;

#[derive(Clone)]
struct RingBitcoinAlgorithm(Context);

impl RingBitcoinAlgorithm {
    fn new() -> RingBitcoinAlgorithm {
        RingBitcoinAlgorithm(Context::new(&SHA256))
    }
}

impl Default for RingBitcoinAlgorithm {
    fn default() -> RingBitcoinAlgorithm {
        RingBitcoinAlgorithm::new()
    }
}

impl Hasher for RingBitcoinAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

type RingSHA256Hash = [u8; 32];

impl Algorithm<RingSHA256Hash> for RingBitcoinAlgorithm {
    /// ring.Context is not reusable after finalization (finish(self)),
    /// and having hash(&self) requires first to clone() the context.
    /// The context can't be moved away out of the struct field to
    /// be created at site due to the semantics of Hasher trait:
    /// Hasher trait has to have a context to write states updates.
    ///
    /// someone should hack it somehow.
    ///
    /// or better change signature in `ring` library of `finish()` to
    /// be `finish(&mut self)` to mark state as finalized or reset it.
    fn hash(&mut self) -> RingSHA256Hash {
        let h1 = self.0.clone().finish();

        // double sha256
        let mut c = Context::new(&SHA256);
        c.update(h1.as_ref());

        let mut h = [0u8; 32];
        h.copy_from_slice(c.finish().as_ref());
        h
    }

    fn reset(&mut self) {
        self.0 = Context::new(&SHA256);
    }

    fn leaf<O: Hashable<Self>>(&mut self, leaf: O) {
        leaf.hash(self)
    }

    fn node(&mut self, left: RingSHA256Hash, right: RingSHA256Hash) {
        left.hash(self);
        right.hash(self);
    }
}

struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    fn new<T>(data: &'a T) -> HexSlice<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        HexSlice(data.as_ref())
    }
}

/// reverse order
impl<'a> fmt::Display for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let len = self.0.len();
        for i in 0..len {
            let byte = self.0[len - 1 - i];
            write!(f, "{:x}{:x}", byte >> 4, byte & 0xf)?;
        }
        Ok(())
    }
}

/// [](https://bitcoin.stackexchange.com/questions/5671/how-do-you-perform-double-sha-256-encoding)
#[test]
fn test_ring_bitcoin_leaf_hash() {
    let mut a = RingBitcoinAlgorithm::new();
    "hello".hash(&mut a);
    let h1 = a.hash();
    assert_eq!(
        format!("{}", HexSlice::new(h1.as_ref())),
        "503d8319a48348cdc610a582f7bf754b5833df65038606eb48510790dfc99595"
    );
}

/// [](http://chimera.labs.oreilly.com/books/1234000001802/ch07.html#merkle_trees)
#[test]
fn test_ring_bitcoin_node() {
    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    let mut h3 = [0u8; 32];
    h1[0] = 0x00;
    h2[0] = 0x11;
    h3[0] = 0x22;

    let mut a = RingBitcoinAlgorithm::new();
    let h11 = h1;
    let h12 = h2;
    let h13 = h3;
    let h21 = a.node(h11, h12);
    let h22 = a.node(h13, h13);
    let h31 = a.node(h21, h22);

    assert_eq!(
        format!("{}", HexSlice::new(h21.as_ref())),
        "32650049a0418e4380db0af81788635d8b65424d397170b8499cdc28c4d27006"
    );
    assert_eq!(
        format!("{}", HexSlice::new(h22.as_ref())),
        "30861db96905c8dc8b99398ca1cd5bd5b84ac3264a4e1b3e65afa1bcee7540c4"
    );
    assert_eq!(
        format!("{}", HexSlice::new(h31.as_ref())),
        "d47780c084bad3830bcdaf6eace035e4c6cbf646d103795d22104fb105014ba3"
    );

    let t: MerkleTree<RingSHA256Hash, RingBitcoinAlgorithm> =
        MerkleTree::from_iter(vec![h1, h2, h3]);
    assert_eq!(
        format!("{}", HexSlice::new(t.root().as_ref())),
        "d47780c084bad3830bcdaf6eace035e4c6cbf646d103795d22104fb105014ba3"
    );
}
