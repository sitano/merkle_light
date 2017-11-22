# merkle

[![Build Status](https://travis-ci.org/sitano/merkle_light.svg?branch=master&style=flat)](https://travis-ci.org/sitano/merkle_light)
[![Issues](http://img.shields.io/github/issues/sitano/merkle.svg?style=flat)](https://github.com/sitano/merkle_light/issues)
![License](https://img.shields.io/badge/license-bsd3-brightgreen.svg?style=flat)
[![Crates.io](https://img.shields.io/crates/v/merkle_light.svg)](https://crates.io/crates/merkle_light)

*merkle* is a lightweight Rust implementation of a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree).

## Features

- external dependency agnostic
- `std::hash::Hasher` compatibility
- standard types hasher implementations
- `#[derive(Hashable)]` support for simple struct
- customizable merkle leaf/node hashing algorithm
- support for custom hash types without `AsRef[u8]` (e.g. [u8; 16], [u64; 4])
- customizable hashing algorithm
- linear memory layout, no nodes on heap
- buildable from iterator, objects or hashes
- SPV included

## Documentation

Documentation is [available](https://sitano.github.io/merkle_light/merkle_light/index.html).

## Bug Reporting

Please report bugs either as pull requests or as issues in [the issue
tracker](https://github.com/sitano/merkle_light). *merkle* has a
**full disclosure** vulnerability policy. **Please do NOT attempt to report
any security vulnerability in this code privately to anybody.**

## License

See [LICENSE](LICENSE).
