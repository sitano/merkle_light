#![cfg(test)]
#![cfg(feature = "ring")]

extern crate ring;
extern crate merkle_light;

use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::merkle::MerkleTree;
use std::hash::Hasher;
use ring::digest::{Context, SHA256};
use std::fmt;

#[derive(Clone)]
struct BitcoinAlgorithm(Context);

impl BitcoinAlgorithm {
    fn new() -> BitcoinAlgorithm {
        BitcoinAlgorithm(Context::new(&SHA256))
    }
}

impl Default for BitcoinAlgorithm {
    fn default() -> BitcoinAlgorithm {
        BitcoinAlgorithm::new()
    }
}

impl Hasher for BitcoinAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        0
    }
}

type Hash32 = [u8; 32];

impl Hashable<BitcoinAlgorithm> for Hash32 {
    fn hash(&self, state: &mut BitcoinAlgorithm) {
        state.write(self.as_ref())
    }
}

impl Algorithm<Hash32> for BitcoinAlgorithm {
    /// ring.Context is not reusable after finalization (finish(self)),
    /// and having hash(&self) requires first to clone() the context.
    /// The context can't be moved away out of the struct field to
    /// be created at site due to the semantics of Hasher trait:
    /// Hasher trait has to have a context to write states updates.
    #[inline]
    fn hash(&self) -> Hash32 {
        let h1 = self.0.clone().finish();

        // double sha256
        let mut c = Context::new(&SHA256);
        c.update(h1.as_ref());

        let mut h = [0u8; 32];
        h.copy_from_slice(c.finish().as_ref());
        h
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Context::new(&SHA256);
    }

    #[inline]
    fn write_t(&mut self, i: Hash32) {
        self.0.update(i.as_ref());
    }

    fn leaf(&mut self, leaf: Hash32) -> Hash32 {
        leaf
    }

    fn node(&mut self, left: Hash32, right: Hash32) -> Hash32 {
        // concat
        let mut c = Context::new(&SHA256);
        c.update(left.as_ref());
        c.update(right.as_ref());
        let h1 = c.finish();

        // double sha256
        c = Context::new(&SHA256);
        c.update(h1.as_ref());

        let mut h = [0u8; 32];
        h.copy_from_slice(c.finish().as_ref());
        h
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
fn test_bitcoin_leaf_hash() {
    let mut a = BitcoinAlgorithm::new();
    "hello".hash(&mut a);
    let h1 = a.hash();
    assert_eq!(
        format!("{}", HexSlice::new(h1.as_ref())),
        "503d8319a48348cdc610a582f7bf754b5833df65038606eb48510790dfc99595"
    );
}

/// [](http://chimera.labs.oreilly.com/books/1234000001802/ch07.html#merkle_trees)
#[test]
fn test_bitcoin_node() {
    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    let mut h3 = [0u8; 32];
    // can't hash 0 as h0 is 0 (neutral element)
    h1[0] = 0x11;
    h2[0] = 0x22;
    h3[0] = 0x33;

    let mut a = BitcoinAlgorithm::new();
    let h11 = h1;
    let h12 = h2;
    let h13 = h3;
    let h21 = a.node(h11, h12);
    let h22 = a.node(h13, h13);
    let h31 = a.node(h21, h22);

    assert_eq!(
        format!("{}", HexSlice::new(h21.as_ref())),
        "72e03f56a66ff1cdc70fb30bdd74e314cb9cedc1c4f3f934af5d966d489d7e98"
    );
    assert_eq!(
        format!("{}", HexSlice::new(h22.as_ref())),
        "c317ce23cf415aad7c7506322135ea47b423ef9e130676afa331ea93430463ea"
    );
    assert_eq!(
        format!("{}", HexSlice::new(h31.as_ref())),
        "fd75384c491592f4d431d76d83fe0d376afd5600476af29907622b9ce46b1c3c"
    );

    let t = MerkleTree::from_iter(vec![h1, h2, h3], a);
    assert_eq!(
        format!("{}", HexSlice::new(t.root().as_ref())),
        "fd75384c491592f4d431d76d83fe0d376afd5600476af29907622b9ce46b1c3c"
    );
}
