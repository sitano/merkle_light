#![cfg(feature = "crypto_bench")]

#![feature(test)]
#![feature(rand)]

mod ringx;

extern crate test;
extern crate rand;

use ringx::Context;
use ringx::SHA512;
use test::Bencher;

#[bench]
fn bench_ringx_sha512(b: &mut Bencher) {
    b.iter(|| {
        let mut x = Context::new(&SHA512);
        x.update("12345".as_ref());
        x.finish();
    });
}
