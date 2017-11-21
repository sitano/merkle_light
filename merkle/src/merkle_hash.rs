use hash::{Algorithm, MerkleHasher};
use std::fmt::Debug;

/// MT leaf hash prefix
const LEAF: u8 = 0x00;

/// MT interior node hash prefix
const INTERIOR: u8 = 0x01;

impl<T, A> MerkleHasher<T> for A
where
    T: Ord + Clone + Default + Debug,
    A: Algorithm<T>,
{
    fn empty(&mut self) -> T {
        self.reset();
        self.hash()
    }

    fn leaf(&mut self, leaf: T) -> T {
        self.reset();
        self.write_u8(LEAF);
        self.write_t(leaf);
        self.hash()
    }

    fn node(&mut self, left: T, right: T) -> T {
        self.reset();
        self.write_u8(INTERIOR);
        self.write_t(left);
        self.write_t(right);
        self.hash()
    }
}
