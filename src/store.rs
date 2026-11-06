//! Where key values live. The operating system keychain will implement this same trait.

use crate::secret::Secret;
use std::fmt;

#[derive(Debug)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

pub trait Store {
    fn get(&self, name: &str) -> Result<Option<Secret>, StoreError>;
    fn put(&mut self, name: &str, value: &Secret) -> Result<(), StoreError>;
    fn delete(&mut self, name: &str) -> Result<(), StoreError>;
}
