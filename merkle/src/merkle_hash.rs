use hash::Algorithm;
use std::fmt::Debug;

/// MT leaf hash prefix
const LEAF: u8 = 0x00;

/// MT interior node hash prefix
const INTERIOR: u8 = 0x01;

/// MT hash helper
pub trait MerkleHasher<U, T>
where
    T: AsRef<[U]> + Sized + Ord + Clone,
{
    /// Returns digest of the empty thing.
    fn empty(&mut self) -> T;

    /// Returns the hash value for MT leaf (prefix 0x00).
    fn leaf(&mut self, leaf: T) -> T;

    /// Returns the hash value for MT interior node (prefix 0x01).
    fn node(&mut self, left: T, right: T) -> T;
}

impl<U, T, A> MerkleHasher<U, T> for A
where
    T: AsRef<[U]> + Ord + Clone + Default + Debug,
    A: Algorithm<U, T>,
{
    fn empty(&mut self) -> T {
        self.reset();
        self.hash()
    }

    fn leaf(&mut self, leaf: T) -> T {
        self.reset();
        self.write_u8(LEAF);
        self.write_u(leaf);
        self.hash()
    }

    fn node(&mut self, left: T, right: T) -> T {
        self.reset();
        self.write_u8(INTERIOR);
        self.write_u(left);
        self.write_u(right);
        self.hash()
    }
}
