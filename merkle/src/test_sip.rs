#![cfg(test)]

/*
use hash::Algorithm;
use merkle::MerkleTree;
use std::hash::Hasher;
use std::collections::hash_map::DefaultHasher;

TODO impl Algorithm<[u64; 1]> for DefaultHasher {
    fn hash(&self) -> Item {
        self.finish() as Item
    }

    fn reset(&mut self) {
        *self = DefaultHasher::default()
    }
}

#[test]
fn test_simple_tree() {
    let x = [1, 2, 3, 4, 5];
    let mt = MerkleTree::from_data(&x, DefaultHasher::new());
    format!("{:?}", mt)
}
*/
