//! Hash infrastructure for items in Merkle Tree.
//!
//! - TODO extract Alg utils into separate trait

use std::hash::Hasher;

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
/// ```text
/// #[derive(Hashable)]
/// struct Rustacean {
///     name: String,
///     country: String,
/// }
/// ```
///
/// If you need more control over how a value is hashed, you can of course
/// implement the `Hashable` trait yourself:
///
/// ```text
/// use hash::Hashable;
///
/// struct Person {
///     id: u32,
///     name: String,
///     phone: u64,
/// }
///
/// /// where SHA256 : std::hash::Hasher
/// impl Hashable<SHA256> for Person {
///     fn hash(&self, state: &mut SHA256) {
///         self.id.hash(state);
///         self.phone.hash(state);
///     }
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
    fn hash_state(&self, state: &mut H);

    /// Feeds a slice of this type into the given [`Hasher`].
    ///
    /// [`Hasher`]: trait.Hasher.html
    fn hash_slice_state(data: &[Self], state: &mut H)
        where Self: Sized
    {
        for piece in data {
            piece.hash_state(state);
        }
    }
}

/// Hashing algorithm type.
///
/// Algorithm conforms standard [`Hasher`] trait and provides methods to return
/// full length hash and reset current state.
pub trait Algorithm<T> : Hasher
    where T: AsRef<[u8]>+Sized+Ord+Clone {

    /// MT leaf hash prefix
    const LEAF : u8 = 0x00;

    /// MT interior node hash prefix
    const INTERIOR : u8 = 0x01;

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
        self.write_u8(Self::LEAF);
        self.write(leaf.as_ref());
        self.hash()
    }

    /// Returns the hash value for MT interior node (prefix 0x01).
    fn node(&mut self, left: T, right: T) -> T {
        self.reset();
        self.write_u8(Self::INTERIOR);
        self.write(left.as_ref());
        self.write(right.as_ref());
        self.hash()
    }
}
