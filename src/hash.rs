pub use std::hash::Hash;
use std::hash::Hasher;

/// Extended std::hash::Hasher for crypto hashes
pub trait MHasher : Hasher {
    /// Read full hash result
    fn read_full(&self) -> [u8];
}

#[cfg(test)]
mod hash_test {
    use hash::MHasher;

    #[test]
    fn test_hasher_simple() {
        struct xor128 {
            data: [u8; 16],
            i: u64
        }

        impl Hasher for xor128 {

        }

        impl MHasher for xor128 {
            fn read_full(&self) -> [u8] {}
        }
    }
}
