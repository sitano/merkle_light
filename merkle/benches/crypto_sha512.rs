#![cfg(feature = "crypto_bench")]

#![feature(test)]
#![feature(rand)]
#![feature(crypto)]

mod hash512;

extern crate test;
extern crate rand;
extern crate crypto;
extern crate merkle_light;

use crypto::digest::Digest;
use crypto::sha2::Sha512;
use merkle_light::hash::Algorithm;
use merkle_light::merkle::MerkleTree;
use hash512::Hash512;
use std::hash::Hasher;
use test::Bencher;

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
fn bench_crypto_sha512(b: &mut Bencher) {
    let mut h = [0u8; 64];
    b.iter(|| {
        let mut x = Sha512::new();
        x.input("12345".as_ref());
        x.result(&mut h);
    });
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
