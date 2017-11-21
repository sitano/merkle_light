//! Hash infrastructure for items in Merkle Tree.

use std::hash::Hasher;
use std::fmt::Debug;

/// A hashable type.
///
/// Types implementing `Hashable` are able to be [`hash`]ed with an instance of
/// [`Hasher`].
///
/// ## Implementing `Hashable`
///
/// You can derive `Hashable` with `#[derive(Hashable)]` if all fields implement `Hashable`.
/// The resulting hash will be the combination of the values from calling
/// [`hash`] on each field.
///
/// ```
/// #[macro_use]
/// extern crate merkle_light_derive;
/// extern crate merkle_light;
/// use merkle_light::hash::Hashable;
///
/// fn main() {
///     #[derive(Hashable)]
///     struct Foo {
///         name: String,
///         country: String,
///     }
/// }
/// ```
///
/// If you need more control over how a value is hashed, you can of course
/// implement the `Hashable` trait yourself:
///
/// ```
/// extern crate merkle_light;
/// use merkle_light::hash::Hashable;
/// use std::hash::Hasher;
/// use std::collections::hash_map::DefaultHasher;
///
/// fn main() {
///    struct Person {
///        id: u32,
///        name: String,
///        phone: u64,
///    }
///
///    impl<H: Hasher> Hashable<H> for Person {
///        fn hash(&self, state: &mut H) {
///            self.id.hash(state);
///            self.name.hash(state);
///            self.phone.hash(state);
///        }
///    }
///
///    let foo = Person{
///        id: 1,
///        name: String::from("blah"),
///        phone: 2,
///    };
///
///    let hr = &mut DefaultHasher::new();
///    foo.hash(hr);
///    assert_eq!(hr.finish(), 7101638158313343130)
/// }
/// ```
///
/// ## `Hashable` and `Eq`
///
/// When implementing both `Hashable` and [`Eq`], it is important that the following
/// property holds:
///
/// ```text
/// k1 == k2 -> hash(k1) == hash(k2)
/// ```
///
/// In other words, if two keys are equal, their hashes must also be equal.
pub trait Hashable<H: Hasher> {
    /// Feeds this value into the given [`Hasher`].
    ///
    /// [`Hasher`]: trait.Hasher.html
    fn hash(&self, state: &mut H);

    /// Feeds a slice of this type into the given [`Hasher`].
    ///
    /// [`Hasher`]: trait.Hasher.html
    fn hash_slice(data: &[Self], state: &mut H)
    where
        Self: Sized,
    {
        for piece in data {
            piece.hash(state);
        }
    }
}

/// MT leaf hash prefix
const LEAF: u8 = 0x00;

/// MT interior node hash prefix
const INTERIOR: u8 = 0x01;

/// Hashing algorithm type.
///
/// Algorithm conforms standard [`Hasher`] trait and provides methods to return
/// hash and resetting current state.
///
/// T is a hash item must be of known size at compile time, globally ordered, with
/// default value as a neutral element of the hash space. Neutral element is
/// interpreted as 0 or nil and required for evaluation of merkle tree.
pub trait Algorithm<T>: Hasher
where
    T: Ord + Clone + Default + Debug,
{
    /// Writes a single `T` into this hasher.
    fn write_t(&mut self, i: T);

    /// Returns the hash value for the data stream written so far.
    fn hash(&self) -> T;

    /// Reset Hasher state.
    fn reset(&mut self);

    /// Returns digest of the empty thing.
    fn empty(&mut self) -> T {
        self.reset();
        self.hash()
    }

    /// Returns the hash value for MT leaf (prefix 0x00).
    fn leaf(&mut self, leaf: T) -> T {
        self.reset();
        self.write_u8(LEAF);
        self.write_t(leaf);
        self.hash()
    }

    /// Returns the hash value for MT interior node (prefix 0x01).
    fn node(&mut self, left: T, right: T) -> T {
        self.reset();
        self.write_u8(INTERIOR);
        self.write_t(left);
        self.write_t(right);
        self.hash()
    }
}
