//! Settings (`~/.config/gmxf/config.toml`) and the webmail session (`~/.local/state/gmxf/session`).

use std::{
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// User settings; every key is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The GMX account, e.g. `name@gmx.de`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Shell command printing the password, e.g. `rbw get gmx.net name@gmx.de`. With it, an expired
    /// session is renewed without asking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_cmd: Option<String>,
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        Ok(dirs::config_dir()
            .ok_or(Error::NoConfigDir)?
            .join("gmxf/config.toml"))
    }

    /// The settings, or defaults when there is no config file yet.
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::path()?)
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::path()?)
    }

    fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| Error::Config {
                path: path.to_owned(),
                message: e.to_string(),
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let text = toml::to_string(self).map_err(|e| Error::Config {
            path: path.to_owned(),
            message: e.to_string(),
        })?;
        write_private(path, text.as_bytes())
    }
}

/// One secret, persisted somewhere.
pub trait SecretStore {
    fn load(&self) -> Result<SecretString>;
    fn save(&self, secret: &SecretString) -> Result<()>;
    fn delete(&self) -> Result<()>;
}

/// A secret in a file only the user can read. Used for the webmail session: it lives about an
/// hour and is renewed with `password_cmd`, so it does not need a keyring (which may be locked
/// when working over SSH).
pub struct FileStore(PathBuf);

impl FileStore {
    pub fn session() -> Result<Self> {
        Ok(Self(
            dirs::state_dir()
                .or_else(dirs::data_local_dir)
                .ok_or(Error::NoConfigDir)?
                .join("gmxf/session"),
        ))
    }
}

impl SecretStore for FileStore {
    fn load(&self) -> Result<SecretString> {
        match fs::read_to_string(&self.0) {
            Ok(s) if !s.trim().is_empty() => Ok(SecretString::from(s.trim().to_owned())),
            Ok(_) => Err(Error::NotLoggedIn),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(Error::NotLoggedIn),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, secret: &SecretString) -> Result<()> {
        write_private(&self.0, secret.expose_secret().as_bytes())
    }

    fn delete(&self) -> Result<()> {
        match fs::remove_file(&self.0) {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

/// Writes `bytes` readable only by the user, creating the directory (also private) if needed.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut dir = fs::DirBuilder::new();
    dir.recursive(true);
    let mut file = fs::OpenOptions::new();
    file.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        dir.mode(0o700);
        file.mode(0o600);
    }
    if let Some(parent) = path.parent() {
        dir.create(parent)?;
    }
    file.open(path)?.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("gmxf-store-{}-{name}", std::process::id()))
    }

    #[test]
    fn config_round_trips_and_defaults_when_missing() {
        let path = scratch("cfg").join("config.toml");
        assert_eq!(Config::load_from(&path).unwrap(), Config::default());
        let cfg = Config {
            email: Some("me@gmx.de".into()),
            password_cmd: Some("rbw get gmx.net me@gmx.de".into()),
        };
        cfg.save_to(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("email = \"me@gmx.de\"") && text.contains("password_cmd = "),
            "{text}"
        );
        assert_eq!(Config::load_from(&path).unwrap(), cfg);
        fs::write(&path, "emial = \"x\"\n").unwrap();
        assert!(
            Config::load_from(&path)
                .unwrap_err()
                .to_string()
                .contains("emial")
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn session_file_is_private_and_deletable() {
        let dir = scratch("session");
        let store = FileStore(dir.join("sub/session"));
        assert!(matches!(store.load(), Err(Error::NotLoggedIn)));
        store.save(&SecretString::from("sso=abc")).unwrap();
        assert_eq!(store.load().unwrap().expose_secret(), "sso=abc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join("sub/session")), 0o600);
            assert_eq!(mode(&dir.join("sub")), 0o700);
        }
        store.delete().unwrap();
        store.delete().unwrap();
        assert!(matches!(store.load(), Err(Error::NotLoggedIn)));
        let _ = fs::remove_dir_all(dir);
    }
}
