#![cfg(feature = "crypto_bench")]

#![feature(test)]
#![feature(rand)]

mod hash512;
mod ringx;

extern crate merkle_light;
extern crate test;
extern crate rand;

use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::merkle::MerkleTree;
use ringx::Context;
use ringx::SHA512;
use hash512::Hash512;
use std::hash::Hasher;
use std::iter::FromIterator;
use test::Bencher;

#[derive(Clone)]
struct B(Context);

impl B {
    fn new() -> B {
        B(Context::new(&SHA512))
    }
}

impl Default for B {
    fn default() -> Self {
        B::new()
    }
}

impl Hasher for B {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<Hash512> for B {
    #[inline]
    fn hash(&mut self) -> Hash512 {
        let mut h = [0u8; 64];
        h.copy_from_slice(self.0.finish().as_ref());
        Hash512(h)
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}

fn small_tree() -> Vec<Hash512> {
    ["one", "two", "three", "four"].iter().map(|x| {
        let mut a = B::new();
        Hashable::hash(x, &mut a);
        a.hash()
    }).collect::<Vec<Hash512>>()
}

#[bench]
fn bench_ringx_sha512(b: &mut Bencher) {
    b.iter(|| {
        let mut x = Context::new(&SHA512);
        x.update("12345".as_ref());
        x.finish();
    });
}

#[bench]
fn bench_ringx_sha512_from_data_5(b: &mut Bencher) {
    let values = small_tree();
    b.iter(|| MerkleTree::<Hash512, B>::from_iter(values.clone()));
}

#[bench]
fn bench_ringx_sha512_from_data_5_proof(b: &mut Bencher) {
    let values = small_tree();
    let tree: MerkleTree<Hash512, B> = MerkleTree::from_iter(values.clone());

    b.iter(|| for i in 0..values.len() {
        let proof = tree.gen_proof(i);
        test::black_box(proof);
    });
}

#[bench]
fn bench_ringx_sha512_from_data_5_proof_check(b: &mut Bencher) {
    let values = small_tree();
    let tree: MerkleTree<Hash512, B> = MerkleTree::from_iter(values.clone());
    let proofs = (0..values.len())
        .map(|i| tree.gen_proof(i))
        .collect::<Vec<_>>();

    b.iter(|| for proof in &proofs {
        test::black_box(proof.validate::<B>());
    });
}
