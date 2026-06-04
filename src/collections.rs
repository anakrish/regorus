// Centralized collection aliases to allow easy backend swaps (hashbrown for no_std+alloc).
// A single BuildHasher is used everywhere so changing hashing strategy is localized.

#![allow(dead_code)]

use core::hash::Hasher;

pub type DefaultBuildHasher = hashbrown::DefaultHashBuilder;

pub type Map<K, V> = hashbrown::HashMap<K, V, DefaultBuildHasher>;
pub type Set<T> = hashbrown::HashSet<T, DefaultBuildHasher>;

// Optional deterministic iteration; enabled where needed.
pub type IndexMap<K, V> = indexmap::IndexMap<K, V, DefaultBuildHasher>;
pub type IndexSet<T> = indexmap::IndexSet<T, DefaultBuildHasher>;

pub const SMALL_OBJECT_INLINE: usize = 0;
pub const SMALL_SET_INLINE: usize = 0;

pub fn try_reserve_map<K: Eq + core::hash::Hash, V>(map: &mut Map<K, V>, additional: usize) -> Result<(), hashbrown::TryReserveError> {
    map.try_reserve(additional)
}

pub fn try_reserve_set<T: Eq + core::hash::Hash>(set: &mut Set<T>, additional: usize) -> Result<(), hashbrown::TryReserveError> {
    set.try_reserve(additional)
}

// ── FNV-1a hasher (deterministic, no_std-safe) ─────────────────────────
// Used exclusively for order-independent hash accumulation in Set/Object
// Hash impls.  Must produce the same hash for the same input every time;
// foldhash's random seed makes DefaultBuildHasher unsuitable here.

struct FnvHasher(u64);

impl FnvHasher {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001B3;

    fn new() -> Self {
        Self(Self::OFFSET_BASIS)
    }
}

impl Hasher for FnvHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= byte as u64;
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }
}

/// Hash a value into a deterministic u64.
///
/// This is used for order-independent hash accumulation (XOR) in the
/// `Hash` impls of `SetStorage` and `ObjectStore`.  It must be
/// deterministic across calls within the same process.
pub fn hash_with_builder<T: core::hash::Hash>(v: &T) -> u64 {
    let mut hasher = FnvHasher::new();
    v.hash(&mut hasher);
    hasher.finish()
}
