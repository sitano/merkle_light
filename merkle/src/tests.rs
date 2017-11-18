#![cfg(test)]

use hash::*;
use merkle::MerkleTree;
use std::fmt;
use std::hash::Hasher;

const SIZE:usize = 0x10;

#[derive(Debug, Copy, Clone)]
struct XOR128 {
    data: [u8; SIZE],
    i: usize
}

impl XOR128 {
    fn new() -> XOR128 {
        XOR128 {
            data: [0; SIZE],
            i: 0
        }
    }
}

impl Hasher for XOR128 {
    fn write(&mut self, bytes: &[u8]) {
        for x in bytes {
            self.data[self.i&(SIZE-1)] ^= *x;
            self.i +=1;
        }
    }

    fn finish(&self) -> u64 {
        let mut h : u64 = 0;
        let mut off : u64 = 0;
        for i in 0..8 {
            h |= (self.data[i] as u64) << off;
            off += 8;
        }
        h
    }
}

impl Algorithm<[u8; 16]> for XOR128 {
    fn hash(&self) -> [u8; 16] { self.data }

    fn reset(&mut self) { *self = XOR128::new(); }
}

impl fmt::UpperHex for XOR128 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            if let Err(e) = f.write_str("0x") {
                return Err(e)
            }
        }
        for b in self.data.as_ref() {
            if let Err(e) = write!(f, "{:02X}", b) {
                return Err(e)
            }
        }
        Ok(())
    }
}

#[test]
fn test_hasher_simple() {
    let mut h = XOR128::new();
    "1234567812345678".hash(&mut h);
    h.reset();
    String::from("1234567812345678").hash(&mut h);
    assert_eq!(format!("{:#X}", h), "0x31323334353637383132333435363738");
    String::from("1234567812345678").hash(&mut h);
    assert_eq!(format!("{:#X}", h), "0x00000000000000000000000000000000");
    String::from("1234567812345678").hash(&mut h);
    assert_eq!(format!("{:#X}", h), "0x31323334353637383132333435363738");
}

#[test]
fn test_st() {
    let x = [String::from("ars"), String::from("zxc")];
    let mt = MerkleTree::new(&x, XOR128::new());
    assert_eq!(format!("{:?}", mt), "MerkleTree { data: [[0, 97, 114, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 122, 120, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]], olen: 2, alg: XOR128 { data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], i: 0 } }");
    assert_eq!(mt.olen(), 2);
}
