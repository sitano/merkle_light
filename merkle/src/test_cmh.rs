#![cfg(test)]

use hash::{Hashable, Algorithm};
use merkle::MerkleTree;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::iter::FromIterator;
use test_item::Item;

/// Custom merkle hash util test
#[derive(Debug, Clone, Default)]
struct CMH(DefaultHasher, u8);

impl CMH {
    pub fn new() -> CMH {
        CMH(DefaultHasher::new(), 0)
    }
}

impl Hasher for CMH {
    fn write(&mut self, msg: &[u8]) {
        <Hasher>::write(&mut self.0, msg)
    }

    fn finish(&self) -> u64 {
        self.0.finish()
    }
}

impl Algorithm<Item> for CMH {
    fn hash(&mut self) -> Item {
        Item(self.finish() & (if self.1 <= 1 { 0xff } else { 0xffff }))
    }

    fn reset(&mut self) {
        *self = CMH::default()
    }

    fn leaf<O: Hashable<Self>>(&mut self, leaf: O) {
        self.1 += 1;
        // e.g. no prefix
        leaf.hash(self);
    }

    fn node(&mut self, left: Item, right: Item) {
        self.1 += 2;
        // e.g. custom prefix
        self.write(&[1u8]);
        self.write(left.as_ref());
        self.write(&[2u8]);
        self.write(right.as_ref());
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
            .filter(|&&x| x.0 > 255)
            .count(),
        0
    );
    assert_eq!(mt.as_slice().iter().filter(|&&x| x.0 > 65535).count(), 0);
}
