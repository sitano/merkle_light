#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

use merkletree::merkle::get_merkle_tree_leafs;

#[bench]
fn bench_get_merkle_tree_leafs_1mib(b: &mut Bencher) {
    let sector_size = 1024 * 1024;
    let tree_size = 2 * (sector_size / 32) - 1;
    b.iter(|| black_box(get_merkle_tree_leafs(tree_size)))
}

#[bench]
fn bench_get_merkle_tree_leafs_256mib(b: &mut Bencher) {
    let sector_size = 1024 * 1024 * 256;
    let tree_size = 2 * (sector_size / 32) - 1;
    b.iter(|| black_box(get_merkle_tree_leafs(tree_size)))
}
