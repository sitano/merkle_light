# merkle_light_derive

[![Build Status](https://travis-ci.org/sitano/merkle_light.svg?branch=master&style=flat)](https://travis-ci.org/sitano/merkle_light)
[![Issues](http://img.shields.io/github/issues/sitano/merkle.svg?style=flat)](https://github.com/sitano/merkle_light/issues)
![License](https://img.shields.io/badge/license-bsd3-brightgreen.svg?style=flat)
[![Crates.io](https://img.shields.io/crates/v/merkle_light.svg)](https://crates.io/crates/merkle_light)

*merkle_light_derive* is a `#[derive(Hashable)]` helper implementation for the `merkle_light`, 
a lightweight Rust implementation of a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree).

## Documentation

Documentation is [available](https://sitano.github.io/merkle_light/merkle_light/index.html).

## Quick start

```
extern crate merkle_light;

#[macro_use]
extern crate merkle_light_derive;

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use merkle_light::hash::Hashable;

#[derive(Hashable, Debug)]
struct Foo {
    a: u8,
    b: u16,
    c: u32,
    d: u64,
    e: String,
    f: &'static str,
}

fn main() {
    let foo = Foo {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
        e: String::from("bar"),
        f: "bar",
    };

    let hr = &mut DefaultHasher::new();
    println!("{}, foo.hash(hr));
}
```

## Bug Reporting

Please report bugs either as pull requests or as issues in [the issue
tracker](https://github.com/sitano/merkle_light). *merkle* has a
**full disclosure** vulnerability policy. **Please do NOT attempt to report
any security vulnerability in this code privately to anybody.**

## License

See [LICENSE](LICENSE).
