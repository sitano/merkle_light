//! Simple _Merkle Tree_ implementation.
//!
//! Merkle Tree (MT) implemented as a full binary tree allocated as vec
//! to give hashes more locality. Tree specialized to the extent
//! of hashing algorithm and Sized hash item, compatible to the
//! std::hash::Hasher and supports custom hash algorithms. Thus,
//! implementation does not depend on any external crypto libraries,
//! and tries to be as performant, as possible.
//!
//! This tree implementation uses encoding scheme as in _Certificate Transperency_
//! RFC 6962 (https://tools.ietf.org/html/rfc6962):
//!
//! ```
//! MTH({d(0)}) = ALG(0x00 || d(0)).
//! For n > 1, let k be the largest power of two smaller than n (i.e.,
//! k < n <= 2k).  The Merkle Tree Hash of an n-element list D[n] is then
//! defined recursively as
//! MTH(D[n]) = ALG(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
//! ```
//!
//! Link: https://en.wikipedia.org/wiki/Merkle_tree
//!
//! # Interface
//! - eval tree (items) -> tree
//! - get root -> hash
//! - get proof -> proof
//! - validate proof (tree, proof) -> result
//!
//! # Examples
//!
//! TODO

#![deny(
    missing_docs, unused_qualifications,
    missing_debug_implementations, missing_copy_implementations,
    trivial_casts, trivial_numeric_casts,
    unsafe_code, unstable_features,
    unused_import_braces
)]

mod hash;
pub use hash::Hash;
pub use hash::AsBytes;
pub use hash::Algorithm;

mod merkle;
// pub mod merkle::Tree;
