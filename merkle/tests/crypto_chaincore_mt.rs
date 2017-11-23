#![cfg(test)]
#![cfg(feature = "chaincore")]

extern crate crypto;
extern crate merkle_light;

use std::fmt;
use std::hash::Hasher;
use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::merkle::MerkleTree;
use crypto::sha3::{Sha3, Sha3Mode};
use crypto::digest::Digest;

#[derive(Clone)]
struct CryptoChainCoreAlgorithm(Sha3);

impl CryptoChainCoreAlgorithm {
    fn new() -> CryptoChainCoreAlgorithm {
        CryptoChainCoreAlgorithm(Sha3::new(Sha3Mode::Sha3_256))
    }
}

impl Default for CryptoChainCoreAlgorithm {
    fn default() -> CryptoChainCoreAlgorithm {
        CryptoChainCoreAlgorithm::new()
    }
}

impl Hasher for CryptoChainCoreAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        0
    }
}

type CryptoSHA256Hash = [u8; 32];

impl Hashable<CryptoChainCoreAlgorithm> for CryptoSHA256Hash {
    fn hash(&self, state: &mut CryptoChainCoreAlgorithm) {
        state.write(self.as_ref())
    }
}

impl Algorithm<CryptoSHA256Hash> for CryptoChainCoreAlgorithm {
    #[inline]
    fn hash(&mut self) -> CryptoSHA256Hash {
        let mut h = [0u8; 32];
        self.0.result(&mut h);
        h
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }

    #[inline]
    fn write_t(&mut self, i: CryptoSHA256Hash) {
        self.0.input(i.as_ref());
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

#[test]
fn test_crypto_chaincore_node() {
    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    let mut h3 = [0u8; 32];
    // can't hash 0 as h0 is 0 (neutral element)
    h1[0] = 0x11;
    h2[0] = 0x22;
    h3[0] = 0x33;

    let t = MerkleTree::from_iter(vec![h1, h2, h3], CryptoChainCoreAlgorithm::new());
    assert_eq!(
        format!("{}", HexSlice::new(t.root().as_ref())),
        "105a3b9e90ae49a8da2c0b0b47b32bce8ee9bfba2deabeafdfa888d17661967c"
    );
}
