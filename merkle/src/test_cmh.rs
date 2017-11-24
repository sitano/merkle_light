#![cfg(test)]

use hash::{Hashable, Algorithm};
use merkle::MerkleTree;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::iter::FromIterator;

type Item = u64;

/// Custom merkle hash util test
#[derive(Debug, Clone, Default)]
struct CMH(DefaultHasher);

impl CMH {
    pub fn new() -> CMH {
        CMH(DefaultHasher::new())
    }
}

impl Hasher for CMH {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.write(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }
}

impl Algorithm<Item> for CMH {
    #[inline]
    fn hash(&mut self) -> Item {
        self.finish()
    }

    #[inline]
    fn reset(&mut self) {
        *self = CMH::default()
    }

    #[inline]
    fn write_t(&mut self, i: Item) {
        self.write_u64(i)
    }

    #[inline]
    fn leaf(&mut self, leaf: Item) -> Item {
        leaf & 0xff
    }

    #[inline]
    fn node(&mut self, left: Item, right: Item) -> Item {
        self.reset();
        self.write_u8(1);
        self.write_t(left);
        self.write_u8(2);
        self.write_t(right);
        self.hash() & 0xffff
    }
}

#[test]
fn test_custom_merkle_hasher() {
    let mut a = CMH::new();
    let mt: MerkleTree<Item, CMH> = MerkleTree::from_iter([1, 2, 3, 4, 5].iter().map(|x| {
        a.reset();
        x.hash(&mut a);
        a.hash()
    }));

    assert_eq!(
        mt.as_slice()
            .iter()
            .take(mt.leafs())
            .filter(|&&x| x > 255)
            .count(),
        0
    );
    assert_eq!(mt.as_slice().iter().filter(|&&x| x > 65535).count(), 0);
}
