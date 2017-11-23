//! light _Merkle Tree_ implementation.
//!
//! Merkle tree (MT) implemented as a full binary tree allocated as a vec
//! of statically sized hashes to give hashes more locality. MT specialized
//! to the extent of hashing algorithm and hash item, compatible to the
//! `std::hash::Hasher` and supports custom hash algorithms.
//! Implementation does not depend on any external crypto libraries,
//! and tries to be as performant, as possible.
//!
//! This tree implementation uses encoding scheme as in _Certificate Transparency_
//! [RFC 6962](https://tools.ietf.org/html/rfc6962):
//!
//! ```text
//! MTH({d(0)}) = ALG(0x00 || d(0)).
//! For n > 1, let k be the largest power of two smaller than n (i.e.,
//! k < n <= 2k).  The Merkle tree Hash of an n-element list D[n] is then
//! defined recursively as
//! MTH(D[n]) = ALG(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
//! ```
//!
//! Link: [](https://en.wikipedia.org/wiki/Merkle_tree)
//!
//! # Implementation choices
//!
//! Main idea was that the whole code must obtain specialization at compile
//! time, hashes must be fixed size arrays known at compile time, hash algorithm
//! must be interface (lib should not dep on crypto libs) and lib must somehow
//! mimic std Rust api.
//!
//! Standard way in Rust is to hash objects with a `std::hash::Hasher`, and mainly
//! that is the reason behind the choice of the abstractions:
//!
//! `Object : Hashable<H> -> Hasher + Algorithm <- Merkle Tree`
//!
//! Custom [`merkle::hash::Hashable`] trait allows implementations differ
//! from [`std::collection`] related hashes, different implementations for
//! different hashing algorithms / schemas and conforms object-safety trait rules.
//!
//! [`Algorithm`] complements [`Hasher`] to be reusable and follows the idea
//! that the result hash is a mapping of the data stream.
//!
//! [`Algorithm.hash`] had to change its signature to be `&mut self` (`&self`) because
//! most of the cryptographic digest algorithms breaks current state on finalization
//! into unusable. `ring` libra tho contains interfaces incompatible to
//! `start-update-finish-reset` lifecycle. It requires either `cloning()` its state
//! on finalization, or `Cell`-ing via unsafe.
//!
//! # Interface
//!
//! ```text
//! - build_tree (items) -> tree
//! - get_root -> hash
//! - gen_proof -> proof
//! - validate_proof (proof, leaf, root) -> bool
//! ```
//!
//! # Examples
//!
//! [`test_sip.rs`]: algorithm implementation example for std sip hasher, u64 hash items
//! [`test_xor128.rs`]: custom hash example xor128
//! [`test_cmh.rs`]: custom merkle hasher implementation example
//! [`crypto_bitcoin_mt.rs`]: bitcoin merkle tree using crypto lib
//! [`crypto_chaincore_mt.rs`]: chain core merkle tree using crypto lib
//! [`ring_bitcoin_mt.rs`]: bitcoin merkle tree using ring lib
//!
//! # Quick start
//!
//! ```
//! #![cfg(feature = "chaincore")]
//!
//! extern crate crypto;
//! extern crate merkle_light;
//!
//! fn main() {
//!     use std::fmt;
//!     use std::hash::Hasher;
//!     use merkle_light::hash::{Algorithm, Hashable};
//!     use merkle_light::merkle::MerkleTree;
//!     use crypto::sha3::{Sha3, Sha3Mode};
//!     use crypto::digest::Digest;
//!
//!     #[derive(Clone)]
//!     struct ExampleAlgorithm(Sha3);
//!
//!     impl ExampleAlgorithm {
//!         fn new() -> ExampleAlgorithm {
//!             ExampleAlgorithm(Sha3::new(Sha3Mode::Sha3_256))
//!         }
//!     }
//!
//!     impl Default for ExampleAlgorithm {
//!         fn default() -> ExampleAlgorithm {
//!             ExampleAlgorithm::new()
//!         }
//!     }
//!
//!     impl Hasher for ExampleAlgorithm {
//!         #[inline]
//!         fn write(&mut self, msg: &[u8]) {
//!             self.0.input(msg)
//!         }
//!
//!         #[inline]
//!         fn finish(&self) -> u64 {
//!             0
//!         }
//!     }
//!
//!     impl Hashable<ExampleAlgorithm> for [u8; 32] {
//!         fn hash(&self, state: &mut ExampleAlgorithm) {
//!             state.write(self.as_ref())
//!         }
//!     }
//!
//!     impl Algorithm<[u8; 32]> for ExampleAlgorithm {
//!         fn hash(&mut self) -> [u8; 32] {
//!             let mut h = [0u8; 32];
//!             self.0.result(&mut h);
//!             h
//!         }
//!
//!         fn reset(&mut self) {
//!             self.0.reset();
//!         }
//!
//!         fn write_t(&mut self, i: [u8; 32]) {
//!             self.0.input(i.as_ref());
//!         }
//!     }
//!
//!     let mut h1 = [0u8; 32];
//!     let mut h2 = [0u8; 32];
//!     let mut h3 = [0u8; 32];
//!     h1[0] = 0x11;
//!     h2[0] = 0x22;
//!     h3[0] = 0x33;
//!
//!     let t = MerkleTree::from_iter(vec![h1, h2, h3], ExampleAlgorithm::new());
//!     println!("{:?}", t.root());
//! }
//! ```

#![deny(
    missing_docs, unused_qualifications,
    missing_debug_implementations, missing_copy_implementations,
    trivial_casts, trivial_numeric_casts,
    unsafe_code, unstable_features,
    unused_import_braces
)]

#![cfg_attr(feature="nightly", allow(unstable_features))]

/// Hash infrastructure for items in Merkle tree.
pub mod hash;

/// Common implementations for [`Hashable`].
mod hash_impl;

/// Merkle tree inclusion proof
pub mod proof;

/// Merkle tree abstractions, implementation and algorithms.
pub mod merkle;

/// Tests XOR128.
#[cfg(test)]
mod test_xor128;

/// Tests SIP.
#[cfg(test)]
mod test_sip;

/// Tests for Merkle Hasher Customization
#[cfg(test)]
mod test_cmh;
