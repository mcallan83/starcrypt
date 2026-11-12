//! Creation of standard password-protected Format 8 vaults.
use crate::fsutil::{copy_times, new_output, safe_name};
use anyhow::{Context, Result, bail, ensure};
use oxcrypt_core::{
    crypto::keys::MasterKey,
    fs::name::create_c9s_filename,
    vault::{
        config::{VaultConfig, create_vault_config},
        master_key::create_masterkey_file,
        operations::VaultOperations,
        path::DirId,
    },
};
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub(crate) fn create(source: &Path, destination: &Path, password: &str) -> Result<()> {
    ensure!(
        std::env::var_os("OXCRYPT_FAST_KDF").is_none(),
        "Unset OXCRYPT_FAST_KDF before creating vaults"
    );
    let volume_root = crate::fsutil::is_macos_volume_root(source)?;
    create_with_volume_policy(source, destination, password, volume_root)
}

fn create_with_volume_policy(
    source: &Path,
    destination: &Path,
    password: &str,
    volume_root: bool,
) -> Result<()> {
    new_output(destination, || {
        let key = MasterKey::random()?;
        let config = VaultConfig {
            jti: uuid::Uuid::new_v4().to_string(),
            format: 8,
            shortening_threshold: 220,
            ciphertext_dir: None,
            payload: None,
        };
        fs::write(
            destination.join("masterkey.cryptomator"),
            create_masterkey_file(&key, password)?,
        )?;
        fs::write(
            destination.join("vault.cryptomator"),
            root_key_config(&create_vault_config(&config, &key)?, &key)?,
        )?;
        let ops = VaultOperations::new(destination, key);
        let root = DirId::root();
        fs::create_dir_all(ops.calculate_directory_storage_path(&root)?)?;
        import(&ops, source, "", volume_root)?;
        finalize_shortened_names(destination, ops.shortening_threshold())
    })
}

// oxcrypt currently hashes the encrypted base64 name without the .c9r suffix.
// Cryptomator hashes and stores the complete name. Finalize only after import,
// because oxcrypt's write/path-lookup helpers still expect their original layout.
fn finalize_shortened_names(vault: &Path, threshold: usize) -> Result<()> {
    for shard in fs::read_dir(vault.join("d"))? {
        for storage in fs::read_dir(shard?.path())? {
            let storage = storage?.path();
            let metadata = fs::metadata(&storage)?;
            for entry in fs::read_dir(&storage)? {
                let entry = entry?;
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                let shortened = name.ends_with(".c9s");
                let full_name = if shortened {
                    let original = fs::read_to_string(path.join("name.c9s"))?;
                    if original.ends_with(".c9r") {
                        original
                    } else {
                        format!("{original}.c9r")
                    }
                } else if name.ends_with(".c9r") && name.len() > threshold {
                    name
                } else {
                    continue;
                };
                let destination = storage.join(format!("{}.c9s", create_c9s_filename(&full_name)));
                if shortened || entry.file_type()?.is_dir() {
                    let entry_metadata = fs::metadata(&path)?;
                    if path != destination {
                        ensure!(!destination.exists(), "Shortened filename collision");
                        fs::rename(&path, &destination)?;
                    }
                    fs::write(destination.join("name.c9s"), full_name)?;
                    copy_times(&destination, &entry_metadata)?;
                } else {
                    fs::create_dir(&destination)?;
                    fs::rename(&path, destination.join("contents.c9r"))?;
                    fs::write(destination.join("name.c9s"), full_name)?;
                }
            }
            copy_times(&storage, &metadata)?;
        }
    }
    Ok(())
}
fn root_key_config(token: &str, key: &MasterKey) -> Result<String> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.required_spec_claims.clear();
    let claims: serde_json::Value = key.validate_jwt(token, &validation)?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("masterkeyfile:masterkey.cryptomator".into());
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &key.create_jwt_encoding_key()?,
    )?)
}
fn import(ops: &VaultOperations, source: &Path, prefix: &str, volume_root: bool) -> Result<()> {
    let directory_metadata = fs::metadata(source)
        .with_context(|| format!("Cannot inspect source directory {}", source.display()))?;
    let entries = fs::read_dir(source)
        .with_context(|| format!("Cannot read source directory {}", source.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!("Cannot read entry in source directory {}", source.display())
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Non-UTF-8 filename: {}", entry.path().display()))?;
        if volume_root && prefix.is_empty() && is_volume_bookkeeping(&name) {
            eprintln!(
                "Skipping macOS volume housekeeping entry: {:?}",
                entry.path()
            );
            continue;
        }
        safe_name(&name)?;
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry
            .file_type()
            .with_context(|| format!("Cannot inspect source entry {}", entry.path().display()))?;
        if kind.is_dir() {
            ops.create_directory_by_path(&relative)?;
            import(ops, &entry.path(), &relative, volume_root)?;
        } else if kind.is_file() {
            let metadata = fs::metadata(entry.path()).with_context(|| {
                format!("Cannot inspect source file {}", entry.path().display())
            })?;
            let contents =
                Zeroizing::new(fs::read(entry.path()).with_context(|| {
                    format!("Cannot read source file {}", entry.path().display())
                })?);
            let encrypted = ops.write_by_path(&relative, &contents)?;
            // oxcrypt emits a tag-only chunk for empty files. CryptoFS expects
            // the authenticated 68-byte header alone, with no content chunks.
            if contents.is_empty() {
                fs::OpenOptions::new()
                    .write(true)
                    .open(&encrypted)?
                    .set_len(68)?;
            }
            copy_times(&encrypted, &metadata)?;
        } else if kind.is_symlink() {
            let metadata = fs::symlink_metadata(entry.path())?;
            let target = fs::read_link(entry.path())?;
            let target = target.to_str().context("Non-UTF-8 symlink target")?;
            ops.create_symlink_by_path(&relative, target)?;
            let (parent, name) = ops.resolve_parent_path(&relative)?;
            let info = ops
                .find_symlink(&parent, &name)?
                .context("Created symlink is missing")?;
            copy_times(&info.encrypted_path, &metadata)?;
        } else {
            bail!("Unsupported special file: {}", entry.path().display());
        }
    }
    let id = if prefix.is_empty() {
        DirId::root()
    } else {
        ops.resolve_path(prefix)?.0
    };
    copy_times(
        &ops.calculate_directory_storage_path(&id)?,
        &directory_metadata,
    )?;
    Ok(())
}

// Exact names only, at the selected volume root. See docs/macos-volumes.md.
fn is_volume_bookkeeping(name: &str) -> bool {
    matches!(
        name,
        ".DocumentRevisions-V100"
            | ".Spotlight-V100"
            | ".fseventsd"
            | ".TemporaryItems"
            | ".Trashes"
            | ".hotfiles.btree"
            | ".journal"
            | ".journal_info_block"
            | ".quota.user"
            | ".quota.group"
            | ".HFS+ Private Directory Data\r"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_volume_bookkeeping_is_excluded() {
        for name in [
            ".Trashes",
            ".DocumentRevisions-V100",
            ".TemporaryItems",
            ".Spotlight-V100",
            ".fseventsd",
            ".hotfiles.btree",
            ".journal",
            ".journal_info_block",
            ".quota.user",
            ".quota.group",
            ".HFS+ Private Directory Data\r",
        ] {
            assert!(is_volume_bookkeeping(name));
        }
        for name in [
            ".git",
            ".gitignore",
            ".DS_Store",
            "._document",
            "__MACOSX",
            ".AppleDouble",
            ".VolumeIcon.icns",
            ".metadata_never_index",
            "Backups.backupdb",
            "lost+found",
            ".Trashes-backup",
            ".DocumentRevisions-V100-notes",
        ] {
            assert!(!is_volume_bookkeeping(name));
        }
    }

    #[test]
    #[cfg(unix)]
    fn volume_policy_skips_protected_roots_but_preserves_nested_and_hidden_files() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fs::create_dir_all(source.join("nested/.Trashes"))?;
        fs::create_dir_all(source.join(".git"))?;
        fs::write(source.join("nested/.Trashes/keep"), b"nested user data")?;
        fs::write(source.join(".git/config"), b"hidden user data")?;
        fs::write(source.join("._document"), b"resource fork sidecar")?;
        fs::write(source.join("document"), b"document bytes")?;
        let restricted = source.join(".Trashes");
        fs::create_dir(&restricted)?;
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o300))?;
        let vault = temp.path().join("vault");
        let result = create_with_volume_policy(&source, &vault, "test password", true);
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o700))?;
        result?;
        let restored = temp.path().join("restored");
        crate::extract_vault(&vault, &restored, "test password")?;
        assert!(!restored.join(".Trashes").exists());
        for path in [
            "nested/.Trashes/keep",
            ".git/config",
            "._document",
            "document",
        ] {
            assert_eq!(fs::read(source.join(path))?, fs::read(restored.join(path))?);
        }
        // A different unreadable entry must still fail even with filtering enabled.
        let unreadable = source.join("private-document");
        fs::write(&unreadable, b"must never silently skip")?;
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0))?;
        let failed = temp.path().join("failed");
        let result = create_with_volume_policy(&source, &failed, "test password", true);
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600))?;
        assert!(result.unwrap_err().to_string().contains("private-document"));
        assert!(!failed.exists());
        Ok(())
    }
}
