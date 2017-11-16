pub trait Hash<T: AsBytes> {
    fn hash(&self) -> T;
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl AsBytes for [u8; 16] {
    fn as_bytes(&self) -> &[u8] {
        &self[..]
    }
}

impl Hash<[u8; 16]> for String {
    fn hash(&self) -> [u8; 16] {
        let mut x = [0u8; 16];
        x[0] = self.as_bytes()[0];
        x
    }
}

#[derive(Debug, Clone)]
struct MerkleTree<T> {
    data: Vec<T>,
}

impl<T : AsBytes> MerkleTree<T> {
    fn new<U : Hash<T>>(data: &[U]) -> MerkleTree<T> {
        MerkleTree {
            data: data.iter().map(|x: &U| x.hash()).collect(),
        }
    }
}

pub trait MerkleHash {
    fn hash(&self) -> &[u8];

    fn reset(&mut self);
}

#[cfg(test)]
mod hash_test {
    use super::MerkleHash;
    use super::MerkleTree;
    use std::fmt;
    use std::hash::{Hash,Hasher};

    const SIZE:usize = 0x10;

    struct Xor128 {
        data: [u8; SIZE],
        i: usize
    }

    impl Xor128 {
        fn new() -> Xor128 {
            Xor128 {
                data: [0; SIZE],
                i: 0
            }
        }
    }

    impl Hasher for Xor128 {
        fn write(&mut self, bytes: &[u8]) {
            for x in bytes {
                self.data[self.i&(SIZE-1)] ^= x;
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

    impl MerkleHash for Xor128 {
        fn hash(&self) -> &[u8] {
            &self.data[..]
        }

        fn reset(&mut self) {
            *self = Xor128::new();
        }
    }

    impl fmt::UpperHex for Xor128 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            if f.alternate() {
                if let Err(e) = f.write_str("0x") {
                    return Err(e)
                }
            }
            for b in self.hash() {
                if let Err(e) = write!(f, "{:02X}", b) {
                    return Err(e)
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_hasher_simple() {
        let mut h = Xor128::new();
        "1234567812345678".hash(&mut h);
        h.reset();
        String::from("1234567812345678").hash(&mut h);
        assert_eq!(format!("{:#X}", h), "0xCE323334353637383132333435363738");
        String::from("1234567812345678").hash(&mut h);
        assert_eq!(format!("{:#X}", h), "0xF6FC01070103010F090301070103010F");
        String::from("1234567812345678").hash(&mut h);
        assert_eq!(format!("{:#X}", h), "0xC1C4CF35323734393E3B303532373439");
    }

    #[test]
    fn test_st() {
        let x = [String::from("ars"), String::from("zxc")];
        let mt = MerkleTree::new(&x);
        println!("{:?}", mt);
        println!("{:?}", mt.data.len());
    }
}
