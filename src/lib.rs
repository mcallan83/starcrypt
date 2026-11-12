//! Create and extract Cryptomator-compatible vaults without mounting.
//!
//! Operations refuse existing destinations and leave source contents intact.
//! Reads may update filesystem access timestamps. See the project README for
//! metadata and Format 8 integrity limits.
use anyhow::{Context, Result, ensure};
use oxcrypt_core::vault::path::DirId;
use std::{collections::HashSet, path::Path};

mod archive;
mod archive_read;
mod create;
mod extract;
mod fsutil;
mod vault_read;

pub use archive::ArchiveFormat;

/// Copy a folder's contents into a new password-protected Format 8 vault.
/// The source must be a directory and the destination's parent must exist.
/// On macOS, volume-root sources exclude known filesystem housekeeping entries,
/// including Trash and document version history; each exclusion is reported to stderr.
pub fn create_vault(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    ensure!(!password.is_empty(), "Password cannot be empty");
    let source = source
        .as_ref()
        .canonicalize()
        .context("Cannot resolve source folder")?;
    ensure!(source.is_dir(), "Source must be a folder");
    let destination = fsutil::destination_path(destination.as_ref(), &source)?;
    create::create(&source, &destination, password)
}

/// Package a new encrypted vault folder into a ZIP or 7z archive.
/// Uses the same macOS volume-root exclusions as [`create_vault`].
/// The destination filename must end with `.zip` or `.7z`, matching the format.
/// Unpack the archive before opening it with Cryptomator or [`extract_vault`].
pub fn create_archive(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
    format: ArchiveFormat,
) -> Result<()> {
    format.validate_destination(destination.as_ref())?;
    ensure!(!password.is_empty(), "Password cannot be empty");
    let source = source
        .as_ref()
        .canonicalize()
        .context("Cannot resolve source folder")?;
    ensure!(source.is_dir(), "Source must be a folder");
    let destination = fsutil::destination_path(destination.as_ref(), &source)?;
    archive::create_archive(&source, &destination, password, format)
}

/// Decrypt a vault folder or a ZIP/7z containing one vault into a new folder. Detected failures remove partial output.
pub fn extract_vault(
    vault: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    ensure!(!password.is_empty(), "Password cannot be empty");
    let vault = vault
        .as_ref()
        .canonicalize()
        .context("Cannot resolve vault")?;
    let destination = fsutil::destination_path(destination.as_ref(), &vault)?;
    let staging;
    let vault = if vault.is_file() {
        staging = tempfile::Builder::new()
            .prefix("starcrypt-unpack-")
            .tempdir()?;
        archive_read::unpack(&vault, staging.path())
            .context("Cannot read archive as a Cryptomator vault")?
    } else {
        vault
    };
    let ops = vault_read::open_vault(&vault, password)
        .context("Cannot unlock Cryptomator vault: invalid vault or incorrect password")?;
    fsutil::new_output(&destination, || {
        extract::export(&ops, &DirId::root(), &destination, &mut HashSet::new())
    })
}
