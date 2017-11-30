#![cfg(feature = "crypto_bench")]

#![feature(test)]
#![feature(rand)]
#![feature(crypto)]

extern crate test;
extern crate rand;
extern crate crypto;
extern crate merkle_light;

use crypto::digest::Digest;
use crypto::sha2::Sha512;
use merkle_light::hash::Algorithm;
use merkle_light::merkle::MerkleTree;
use std::hash::Hasher;
use std::cmp::Ordering;
use test::Bencher;

#[derive(Copy, Clone)]
pub struct Hash512(pub [u8; 64]);

impl Default for Hash512 {
    fn default() -> Self {
        Hash512([0u8; 64])
    }
}

impl AsRef<[u8]> for Hash512 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl PartialOrd for Hash512 {
    #[inline]
    fn partial_cmp(&self, other: &Hash512) -> Option<Ordering> {
        PartialOrd::partial_cmp(&&self.0[..], &&other.0[..])
    }

    #[inline]
    fn lt(&self, other: &Hash512) -> bool {
        PartialOrd::lt(&&self.0[..], &&other.0[..])
    }

    #[inline]
    fn le(&self, other: &Hash512) -> bool {
        PartialOrd::le(&&self.0[..], &&other.0[..])
    }

    #[inline]
    fn ge(&self, other: &Hash512) -> bool {
        PartialOrd::ge(&&self.0[..], &&other.0[..])
    }

    #[inline]
    fn gt(&self, other: &Hash512) -> bool {
        PartialOrd::gt(&&self.0[..], &&other.0[..])
    }
}

impl Ord for Hash512 {
    #[inline]
    fn cmp(&self, other: &Hash512) -> Ordering {
        Ord::cmp(&&self.0[..], &&other.0[..])
    }
}

impl PartialEq for Hash512 {
    fn eq(&self, other: &Hash512) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for Hash512 {}

#[derive(Copy, Clone)]
struct A(Sha512);

impl A {
    fn new() -> A {
        A(Sha512::new())
    }
}

impl Default for A {
    fn default() -> Self {
        A::new()
    }
}

impl Hasher for A {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<Hash512> for A {
    #[inline]
    fn hash(&mut self) -> Hash512 {
        let mut h = [0u8; 64];
        self.0.result(&mut h);
        Hash512(h)
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}

#[bench]
fn bench_crypto_sha512_from_data_5(b: &mut Bencher) {
    let values = vec!["one", "two", "three", "four"];

    b.iter(|| MerkleTree::<Hash512, A>::from_data(values.clone()));
}

#[bench]
fn bench_crypto_sha512_from_data_5_proof(b: &mut Bencher) {
    let values = vec!["one", "two", "three", "four"];
    let tree: MerkleTree<Hash512, A> = MerkleTree::from_data(values.clone());

    b.iter(|| for i in 0..values.len() {
        let proof = tree.gen_proof(i);
        test::black_box(proof);
    });
}

#[bench]
fn bench_crypto_sha512_from_data_5_proof_check(b: &mut Bencher) {
    let values = vec!["one", "two", "three", "four"];
    let tree: MerkleTree<Hash512, A> = MerkleTree::from_data(values.clone());
    let proofs = (0..values.len())
        .map(|i| tree.gen_proof(i))
        .collect::<Vec<_>>();

    b.iter(|| for proof in &proofs {
        test::black_box(proof.validate::<A>());
    });
}
