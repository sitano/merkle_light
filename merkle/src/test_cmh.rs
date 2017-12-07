#![cfg(test)]

use hash::{Hashable, Algorithm,MTA};
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
    fn write(&mut self, msg: &[u8]) {
        <Hasher>::write(&mut self.0, msg)
    }

    fn finish(&self) -> u64 {
        self.0.finish()
    }
}

impl Algorithm<Item> for CMH {
    fn hash(&mut self) -> Item {
        Item(self.finish())
    }

    fn reset(&mut self) {
        *self = CMH::default()
    }
}

impl MTA<Item> for CMH {
    fn leaf<O: Hashable<Self>>(&mut self, leaf: O) where Self: Algorithm<Item> {
        unimplemented!()
        // Item(leaf.0 & 0xff)
    }

    fn node(&mut self, left: Item, right: Item) {
        unimplemented!()
        /*(self.reset();
        self.write(&[1u8]);
        self.write(left.as_ref());
        self.write(&[2u8]);
        self.write(right.as_ref());
        Item(self.hash().0 & 0xffff)*/
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
