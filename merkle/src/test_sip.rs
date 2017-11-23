#![cfg(test)]

use hash::{Hashable, Algorithm};
use merkle::MerkleTree;
use merkle::next_pow2;
use merkle::log2_pow2;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

type Item = u64;

impl Algorithm<Item> for DefaultHasher {
    fn hash(&mut self) -> Item {
        self.finish()
    }

    fn reset(&mut self) {
        *self = DefaultHasher::default()
    }

    fn write_t(&mut self, i: Item) {
        self.write_u64(i)
    }
}

#[test]
fn test_simple_tree() {
    let answer: Vec<Vec<u64>> = vec![
        vec![
            18161131233134742049,
            15963407371316104707,
            8061613778145084206,
        ],
        vec![
            18161131233134742049,
            15963407371316104707,
            2838807777806232157,
            0,
            8061613778145084206,
            8605533607343419251,
            12698627859487956302,
        ],
        vec![
            18161131233134742049,
            15963407371316104707,
            2838807777806232157,
            4356248227606450052,
            8061613778145084206,
            6971098229507888078,
            452397072384919190,
        ],
        vec![
            18161131233134742049,
            15963407371316104707,
            2838807777806232157,
            4356248227606450052,
            5528330654215492654,
            0,
            0,
            0,
            8061613778145084206,
            6971098229507888078,
            7858164776785041459,
            0,
            452397072384919190,
            13691461346724970593,
            12928874197991182098,
        ],
        vec![
            18161131233134742049,
            15963407371316104707,
            2838807777806232157,
            4356248227606450052,
            5528330654215492654,
            11057097817362835984,
            0,
            0,
            8061613778145084206,
            6971098229507888078,
            6554444691020019791,
            0,
            452397072384919190,
            2290028692816887453,
            151678167824896071,
        ],
        vec![
            18161131233134742049,
            15963407371316104707,
            2838807777806232157,
            4356248227606450052,
            5528330654215492654,
            11057097817362835984,
            15750323574099240302,
            0,
            8061613778145084206,
            6971098229507888078,
            6554444691020019791,
            13319587930734024288,
            452397072384919190,
            15756788945533226834,
            8300325667420840753,
        ],
    ];
    for items in 2..8 {
        let mut a = DefaultHasher::new();
        let mt = MerkleTree::from_iter(
            [1, 2, 3, 4, 5, 6, 7, 8]
                .iter()
                .map(|x| {
                    a.reset();
                    x.hash(&mut a);
                    a.hash()
                })
                .take(items),
            DefaultHasher::new(),
        );

        assert_eq!(mt.leafs(), next_pow2(items));
        assert_eq!(mt.len(), 2 * next_pow2(items) - 1);
        assert_eq!(mt.olen(), items);
        assert_eq!(mt.height(), log2_pow2(mt.len() + 1));
        assert_eq!(mt.as_slice(), answer[items - 2].as_slice());

        for i in 0..mt.olen() {
            let p = mt.gen_proof(i);
            assert!(p.validate(DefaultHasher::new()));
        }
    }
}
