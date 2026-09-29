use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const KEYRING_SERVICE: &str = "gmxf";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub user: String,
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        let dir = dirs::config_dir().ok_or(Error::NoConfigDir)?.join("gmxf");
        Ok(dir.join("config.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let text = fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::NotLoggedIn
            } else {
                Error::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)?;
        write_private(&path, text.as_bytes())?;
        Ok(())
    }

    pub fn clear() -> Result<()> {
        let path = Self::path()?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Persistence for the long-lived session cookie.
pub trait SessionStore {
    fn load(&self) -> Result<SecretString>;
    fn save(&self, cookie: &SecretString) -> Result<()>;
    fn delete(&self) -> Result<()>;
}

/// Session cookie in the OS keyring, keyed by account name.
pub struct KeyringStore {
    user: String,
}

impl KeyringStore {
    pub fn new(user: impl Into<String>) -> Self {
        Self { user: user.into() }
    }

    fn entry(&self) -> Result<Entry> {
        Ok(Entry::new(KEYRING_SERVICE, &self.user)?)
    }
}

impl SessionStore for KeyringStore {
    fn load(&self) -> Result<SecretString> {
        match self.entry()?.get_password() {
            Ok(p) if !p.is_empty() => Ok(SecretString::from(p)),
            Ok(_) | Err(keyring::Error::NoEntry) => Err(Error::NotLoggedIn),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, cookie: &SecretString) -> Result<()> {
        Ok(self.entry()?.set_password(cookie.expose_secret())?)
    }

    fn delete(&self) -> Result<()> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}
