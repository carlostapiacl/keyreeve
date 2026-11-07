//! The engine's view of the vault. Writing needs no fingerprint, so each write goes straight to the
//! vault's own tool, and is durable before the engine records the step.

use super::pending_name;
use crate::keys::{swap_key, MIN_SWAP_CHARS};
use crate::secret::Secret;
use crate::store::{Store, StoreError};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

fn store_error(what: &str) -> StoreError {
    StoreError(format!("the vault could not {what}"))
}

/// The engine's view of the vault. A sealed copy holds a whole file, so the key is swapped inside
/// its text, and the rest of the file stays as it was.
pub struct VaultStore {
    pub(super) tool: PathBuf,
    pub(super) key: String,
    pub(super) text: Zeroizing<String>,
    pub(super) current: Secret,
    pub(super) admin: Option<(String, Secret)>,
    pub(super) temporary: HashMap<String, Secret>,
}

impl VaultStore {
    /// Runs the vault's tool with a value on stdin. Its output is discarded.
    fn write(&self, name: &str, value: &str) -> Result<(), StoreError> {
        let mut child = Command::new(&self.tool)
            .args(["put", name])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| store_error("start"))?;
        let mut stdin = child.stdin.take().ok_or_else(|| store_error("start"))?;
        let wrote = stdin.write_all(value.as_bytes());
        drop(stdin);
        let status = child.wait().map_err(|_| store_error("save a key"))?;
        if wrote.is_err() || !status.success() {
            return Err(store_error("save a key"));
        }
        Ok(())
    }

    fn drop_temporary(&self, name: &str) -> Result<(), StoreError> {
        let status = Command::new(&self.tool)
            .args(["drop", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| store_error("start"))?;
        if !status.success() {
            return Err(store_error("remove a temporary copy"));
        }
        Ok(())
    }
}

/// A provider's answer ends up in your files, and some are read by a shell, so a "key" holding
/// `$(...)` would run there. Too short also fails, because it could not be swapped safely later.
pub(super) fn check_new_key(value: &str) -> Result<(), String> {
    if value.chars().count() < MIN_SWAP_CHARS {
        return Err("the new key is too short to handle safely".into());
    }
    let safe = value.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '/' | '=' | ':' | '~')
    });
    if !safe {
        return Err("the new key has characters a key should not have".into());
    }
    Ok(())
}

impl Store for VaultStore {
    fn get(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        if name == self.key {
            return Ok(Some(self.current.clone()));
        }
        if let Some((admin, value)) = &self.admin {
            if admin == name {
                return Ok(Some(value.clone()));
            }
        }
        Ok(self.temporary.get(name).cloned())
    }

    fn put(&mut self, name: &str, value: &Secret) -> Result<(), StoreError> {
        if name == self.key {
            let text = Zeroizing::new(swap_key(&self.text, self.current.expose(), value.expose()));
            self.write(name, &text)?;
            self.text = text;
            self.current = value.clone();
        } else {
            if name == pending_name(&self.key) {
                check_new_key(value.expose()).map_err(StoreError)?;
            }
            self.write(name, value.expose())?;
            self.temporary.insert(name.to_owned(), value.clone());
        }
        Ok(())
    }

    fn delete(&mut self, name: &str) -> Result<(), StoreError> {
        self.drop_temporary(name)?;
        self.temporary.remove(name);
        Ok(())
    }
}
