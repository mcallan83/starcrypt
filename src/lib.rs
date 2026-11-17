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
mod decrypt;
mod encrypt;
mod extract;
mod fsutil;
mod progress;
mod recovery;
mod vault_read;

pub use archive::ArchiveFormat;
pub use progress::{Progress, ProgressSnapshot};

/// Copy a folder's contents into a new password-protected Format 8 vault.
/// The source must be a directory and the destination's parent must exist.
/// On macOS, volume-root sources exclude known filesystem housekeeping entries,
/// including Trash and document version history; each exclusion is reported to stderr.
pub fn create_vault(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    create_vault_with_progress(source, destination, password, &Progress::default())
}

/// Run the operation with an optional shared progress handle.
pub fn create_vault_with_progress(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
    progress: &Progress,
) -> Result<()> {
    ensure!(!password.is_empty(), "Password cannot be empty");
    let source = source
        .as_ref()
        .canonicalize()
        .context("Cannot resolve source folder")?;
    ensure!(source.is_dir(), "Source must be a folder");
    let destination = fsutil::destination_path(destination.as_ref(), &source)?;
    create::create_with_progress(&source, &destination, password, progress)
}

/// Package a new encrypted vault folder into a ZIP or 7z archive.
/// Uses the same macOS volume-root exclusions as [`create_vault`].
/// The explicit format determines the archive type, regardless of the filename.
/// Its UTF-8 filename stem becomes the internal vault folder name and must not
/// contain `:` or `\`.
/// Unpack the archive before opening it with Cryptomator or [`extract_vault`].
pub fn create_archive(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
    format: ArchiveFormat,
) -> Result<()> {
    create_archive_with_progress(source, destination, password, format, &Progress::default())
}

/// Run the operation with an optional shared progress handle.
pub fn create_archive_with_progress(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
    format: ArchiveFormat,
    progress: &Progress,
) -> Result<()> {
    ensure!(!password.is_empty(), "Password cannot be empty");
    let source = source
        .as_ref()
        .canonicalize()
        .context("Cannot resolve source folder")?;
    ensure!(source.is_dir(), "Source must be a folder");
    let destination = fsutil::destination_path(destination.as_ref(), &source)?;
    archive::create_archive(&source, &destination, password, format, progress)
}

/// Decrypt a vault folder or a ZIP/7z containing one vault into a new folder. Detected failures remove partial output.
pub fn extract_vault(
    vault: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    extract_vault_with_progress(vault, destination, password, &Progress::default())
}

/// Run the operation with an optional shared progress handle.
pub fn extract_vault_with_progress(
    vault: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
    progress: &Progress,
) -> Result<()> {
    ensure!(!password.is_empty(), "Password cannot be empty");
    let vault = vault
        .as_ref()
        .canonicalize()
        .context("Cannot resolve vault")?;
    let destination = fsutil::destination_path(destination.as_ref(), &vault)?;
    progress.phase("Preparing decryption");
    let staging;
    let vault = if vault.is_file() {
        staging = tempfile::Builder::new()
            .prefix("starcrypt-unpack-")
            .tempdir()?;
        progress.phase("Unpacking archive");
        archive_read::unpack(&vault, staging.path())
            .context("Cannot read archive as a Cryptomator vault")?
    } else {
        vault
    };
    progress.phase("Unlocking vault");
    let ops = vault_read::open_vault(&vault, password)
        .context("Cannot unlock Cryptomator vault: invalid vault or incorrect password")?;
    fsutil::new_output(&destination, || {
        progress.phase("Decrypting");
        extract::export(
            &ops,
            &DirId::root(),
            &destination,
            &mut HashSet::new(),
            progress,
        )
    })
}

/// Create a folder vault or archive and return its Cryptomator recovery phrase.
/// The phrase grants access without the password. Store it separately and securely.
/// Returns the phrase only after the complete destination has been saved successfully.
pub fn create_with_recovery_key(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &str,
    format: Option<ArchiveFormat>,
    progress: &Progress,
) -> Result<zeroize::Zeroizing<String>> {
    ensure!(!password.is_empty(), "Password cannot be empty");
    let source = source
        .as_ref()
        .canonicalize()
        .context("Cannot resolve source folder")?;
    ensure!(source.is_dir(), "Source must be a folder");
    let destination = fsutil::destination_path(destination.as_ref(), &source)?;
    let mut phrase = None;
    let key_ready = |key: &oxcrypt_core::crypto::keys::MasterKey| {
        phrase = Some(recovery::encode(key)?);
        Ok(())
    };
    if let Some(format) = format {
        let write = match format {
            ArchiveFormat::Zip => archive::write_zip,
            ArchiveFormat::SevenZip => archive::write_seven_zip,
        };
        archive::create_archive_with_key(
            &source,
            &destination,
            password,
            progress,
            write,
            key_ready,
        )?;
    } else {
        create::create_with_key(
            &source,
            &destination,
            password,
            fsutil::is_macos_volume_root(&source)?,
            progress,
            key_ready,
        )?;
    }
    phrase.context("Recovery key was not generated")
}
