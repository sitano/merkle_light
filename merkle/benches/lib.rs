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
use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::merkle::MerkleTree;
use std::mem;
use std::ptr;
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
        0
    }
}

type Hash512 = [u64; 8];

impl Hashable<A> for Hash512 {
    fn hash(&self, state: &mut A) {
        for x in self {
            state.write_u64(*x)
        }
    }
}

impl Algorithm<Hash512> for A {
    #[inline]
    fn hash(&mut self) -> Hash512 {
        let mut h = [0u8; 64];
        self.0.result(&mut h);
        let mut r = [0u64; 8];
        read_u64v_be(&mut r, h.as_ref());
        r
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }

    #[inline]
    fn write_t(&mut self, i: Hash512) {
        for x in i.as_ref() {
            self.write_u64(*x)
        }
    }
}

fn read_u64v_be(dst: &mut [u64], input: &[u8]) {
    assert_eq!(dst.len() * 8, input.len());
    unsafe {
        let mut x: *mut u64 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: u64 = mem::uninitialized();
            ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 8);
            *x = u64::from_be(tmp);
            x = x.offset(1);
            y = y.offset(8);
        }
    }
}

#[bench]
fn bench_from_data_small(b: &mut Bencher) {
    let values = vec!["one", "two", "three", "four"];

    b.iter(|| MerkleTree::<Hash512, A>::from_data(values.clone()));
}

#[bench]
fn bench_from_data_small_proof(b: &mut Bencher) {
    let values = vec!["one", "two", "three", "four"];
    let tree: MerkleTree<Hash512, A> = MerkleTree::from_data(values.clone());

    b.iter(|| for i in 0..values.len() {
        let proof = tree.gen_proof(i);
        test::black_box(proof);
    });
}

#[bench]
fn bench_small_str_proof_check(b: &mut Bencher) {
    let values = vec!["one", "two", "three", "four"];
    let tree: MerkleTree<Hash512, A> = MerkleTree::from_data(values.clone());
    let proofs = (0..values.len())
        .map(|i| tree.gen_proof(i))
        .collect::<Vec<_>>();

    b.iter(|| for proof in &proofs {
        test::black_box(proof.validate::<A>());
    });
}
