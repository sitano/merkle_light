use hash::Algorithm;

/// MT leaf hash prefix
const LEAF: u8 = 0x00;

/// MT interior node hash prefix
const INTERIOR: u8 = 0x01;

/// MT hash helper
pub trait MerkleHasher<T>
where
    T: AsRef<[u8]> + Sized + Ord + Clone,
{
    /// Returns digest of the empty thing.
    fn empty(&mut self) -> T;

    /// Returns the hash value for MT leaf (prefix 0x00).
    fn leaf(&mut self, leaf: T) -> T;

    /// Returns the hash value for MT interior node (prefix 0x01).
    fn node(&mut self, left: T, right: T) -> T;
}

impl<T, A> MerkleHasher<T> for A
where
    T: AsRef<[u8]> + Sized + Ord + Clone,
    A: Algorithm<T>,
{
    fn empty(&mut self) -> T {
        self.reset();
        self.hash()
    }

    fn leaf(&mut self, leaf: T) -> T {
        self.reset();
        self.write_u8(LEAF);
        self.write(leaf.as_ref());
        self.hash()
    }

    fn node(&mut self, left: T, right: T) -> T {
        self.reset();
        self.write_u8(INTERIOR);
        self.write(left.as_ref());
        self.write(right.as_ref());
        self.hash()
    }
}
