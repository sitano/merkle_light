#![deny(
    /*missing_docs, */unused_qualifications,
    missing_debug_implementations, missing_copy_implementations,
    trivial_casts, trivial_numeric_casts,
    unsafe_code, unstable_features,
    unused_import_braces
)]

//! Merkle Tree implementation.
//!
//! Implemented with std::hash and linearized tree.

mod hash;
pub use hash::Hash;
pub use hash::AsBytes;
pub use hash::Algorithm;

mod merkle;
// pub mod merkle::Tree;
