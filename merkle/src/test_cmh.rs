#![cfg(test)]

use hash::{Hashable, Algorithm, MTA};
use merkle::MerkleTree;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::iter::FromIterator;
use test_item::Item;

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
        <Hasher>::write(&mut self.0, msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }
}

impl Algorithm<Item> for CMH {
    #[inline]
    fn hash(&mut self) -> Item {
        Item(self.finish())
    }

    #[inline]
    fn reset(&mut self) {
        *self = CMH::default()
    }
}

trait CMHMTA {}

impl MTA<Item, CMH> for CMHMTA {
    /// Returns the hash value for MT leaf (prefix 0x00).
    #[inline(always)]
    fn leaf<O: Hashable<CMH>>(leaf: O) -> Item {
        let mut a = CMH::default();
        leaf.hash(&mut a);
        Item(a.hash().0 & 0xff)
    }

    /// Returns the hash value for MT interior node (prefix 0x01).
    #[inline(always)]
    fn node(left: Item, right: Item) -> Item {
        let mut a = CMH::default();
        a.write_u8(1u8);
        a.write(left.as_ref());
        a.write_u8(2u8);
        a.write(right.as_ref());
        Item(a.hash().0 & 0xffff)
    }
}

#[test]
fn test_custom_merkle_hasher() {
    let mut a = CMH::new();
    let mt: MerkleTree<Item, CMH, CMHMTA> = MerkleTree::from_iter([1, 2, 3, 4, 5].iter().map(|x| {
        a.reset();
        x.hash(&mut a);
        a.hash()
    }));

    assert_eq!(
        mt.as_slice()
            .iter()
            .take(mt.leafs())
            .filter(|&&x| x.0 > 255)
            .count(),
        0
    );
    assert_eq!(mt.as_slice().iter().filter(|&&x| x.0 > 65535).count(), 0);
}
