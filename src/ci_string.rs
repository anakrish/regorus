// Case-insensitive string for object keys. Uses Unicode lowercase (culture-insensitive)
// which matches C# InvariantCultureIgnoreCase semantics for ASCII inputs and the standard
// invariant fold for broader Unicode.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt;
use core::hash::{Hash, Hasher};

#[derive(Clone)]
pub struct CIString {
    orig: Arc<str>,
    fold: Arc<str>,
}

impl CIString {
    pub fn new<S: AsRef<str>>(s: S) -> Self {
        let orig: Arc<str> = s.as_ref().to_owned().into();
        let fold: Arc<str> = orig.to_lowercase().into();
        Self { orig, fold }
    }

    pub fn as_str(&self) -> &str {
        &self.orig
    }
}

impl PartialEq for CIString {
    fn eq(&self, other: &Self) -> bool {
        self.fold == other.fold
    }
}

impl Eq for CIString {}

impl Hash for CIString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fold.hash(state);
    }
}

impl fmt::Debug for CIString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CIString").field(&self.orig).finish()
    }
}

impl fmt::Display for CIString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.orig)
    }
}

impl AsRef<str> for CIString {
    fn as_ref(&self) -> &str {
        &self.orig
    }
}

impl From<&str> for CIString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for CIString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<Arc<str>> for CIString {
    fn from(value: Arc<str>) -> Self {
        let fold: Arc<str> = value.to_lowercase().into();
        Self { orig: value, fold }
    }
}
