#![cfg(test)]
#![cfg(feature = "bitcoin")]

extern crate crypto;
extern crate merkle_light;

use std::fmt;
use std::hash::Hasher;
use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::merkle::MerkleTree;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

#[derive(Clone)]
struct CryptoBitcoinAlgorithm(Sha256);

impl CryptoBitcoinAlgorithm {
    fn new() -> CryptoBitcoinAlgorithm {
        CryptoBitcoinAlgorithm(Sha256::new())
    }
}

impl Default for CryptoBitcoinAlgorithm {
    fn default() -> CryptoBitcoinAlgorithm {
        CryptoBitcoinAlgorithm::new()
    }
}

impl Hasher for CryptoBitcoinAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

type CryptoSHA256Hash = [u8; 32];

impl Algorithm<CryptoSHA256Hash> for CryptoBitcoinAlgorithm {
    #[inline]
    fn hash(&mut self) -> CryptoSHA256Hash {
        let mut h = [0u8; 32];
        self.0.result(&mut h);

        // double sha256
        let mut c = Sha256::new();
        c.input(h.as_ref());
        c.result(&mut h);
        h
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }

    fn leaf<O: Hashable<Self>>(&mut self, leaf: O) {
        leaf.hash(self)
    }

    fn node(&mut self, left: CryptoSHA256Hash, right: CryptoSHA256Hash) {
        left.hash(self);
        right.hash(self);
    }
}

impl Hashable<CryptoBitcoinAlgorithm> for Vec<u8> {
    fn hash(&self, state: &mut CryptoBitcoinAlgorithm) {
        state.write(self.as_ref())
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
fn test_crypto_bitcoin_leaf_hash() {
    let mut a = CryptoBitcoinAlgorithm::new();
    "hello".hash(&mut a);
    let h1 = a.hash();
    assert_eq!(
        format!("{}", HexSlice::new(h1.as_ref())),
        "503d8319a48348cdc610a582f7bf754b5833df65038606eb48510790dfc99595"
    );
}

/// [](http://chimera.labs.oreilly.com/books/1234000001802/ch07.html#merkle_trees)
#[test]
fn test_crypto_bitcoin_node() {
    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    let mut h3 = [0u8; 32];
    h1[0] = 0x00;
    h2[0] = 0x11;
    h3[0] = 0x22;

    let mut a = CryptoBitcoinAlgorithm::new();
    let h11 = h1;
    let h12 = h2;
    let h13 = h3;
    let h21 = {
        a.reset();
        a.node(h11, h12);
        a.hash()
    };
    let h22 = {
        a.reset();
        a.node(h13, h13);
        a.hash()
    };
    let h31 = {
        a.reset();
        a.node(h21, h22);
        a.hash()
    };

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

    let t: MerkleTree<CryptoSHA256Hash, CryptoBitcoinAlgorithm> =
        MerkleTree::new([[h11, h12].concat(), [h13, h13].concat()].iter());
    assert_eq!(
        format!("{}", HexSlice::new(t.root().as_ref())),
        "d47780c084bad3830bcdaf6eace035e4c6cbf646d103795d22104fb105014ba3"
    );
}
