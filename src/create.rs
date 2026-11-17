//! Creation of standard password-protected Format 8 vaults.
use crate::encrypt::EncryptionPool;
use crate::fsutil::{copy_times, new_output, safe_name};
use anyhow::{Context, Result, bail, ensure};
use oxcrypt_core::{
    crypto::keys::MasterKey,
    fs::name::{create_c9s_filename, encrypt_filename},
    vault::{
        config::{VaultConfig, create_vault_config},
        master_key::create_masterkey_file,
        operations::VaultOperations,
        path::DirId,
    },
};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

pub(crate) fn create_with_progress(
    source: &Path,
    destination: &Path,
    password: &str,
    progress: &crate::Progress,
) -> Result<()> {
    ensure!(
        std::env::var_os("OXCRYPT_FAST_KDF").is_none(),
        "Unset OXCRYPT_FAST_KDF before creating vaults"
    );
    let volume_root = crate::fsutil::is_macos_volume_root(source)?;
    create_impl(source, destination, password, volume_root, progress)
}

fn create_impl(
    source: &Path,
    destination: &Path,
    password: &str,
    volume_root: bool,
    progress: &crate::Progress,
) -> Result<()> {
    create_with_key(source, destination, password, volume_root, progress, |_| {
        Ok(())
    })
}

pub(crate) fn create_with_key(
    source: &Path,
    destination: &Path,
    password: &str,
    volume_root: bool,
    progress: &crate::Progress,
    key_ready: impl FnOnce(&MasterKey) -> Result<()>,
) -> Result<()> {
    ensure!(
        std::env::var_os("OXCRYPT_FAST_KDF").is_none(),
        "Unset OXCRYPT_FAST_KDF before creating vaults"
    );
    new_output(destination, || {
        progress.phase("Scanning source");
        let mut directories = HashMap::new();
        let (bytes, files) = scan_source(source, volume_root, &mut directories, progress)?;
        progress.totals(bytes, files);
        progress.phase("Preparing encryption");
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
        let date = time::OffsetDateTime::now_utc();
        fs::write(
            destination.join("readme.txt"),
            format!(
                "Cryptomator vault created by StarCrypt on {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z. Open it with Cryptomator or extract it with StarCrypt.\n\n\
                 https://github.com/mcallan83/starcrypt\n",
                date.year(),
                u8::from(date.month()),
                date.day(),
                date.hour(),
                date.minute(),
                date.second()
            ),
        )?;
        let ops = VaultOperations::new(destination, key);
        let root = DirId::root();
        fs::create_dir_all(ops.calculate_directory_storage_path(&root)?)?;
        progress.phase("Encrypting");
        crate::encrypt::with_pool(progress, |pool| {
            import(&ops, source, &root, volume_root, pool, &directories)
        })?;
        progress.phase("Finalizing vault");
        finalize_entries(destination, &ops)?;
        key_ready(ops.master_key())
    })
}

// oxcrypt currently hashes the encrypted base64 name without the .c9r suffix.
// Cryptomator hashes and stores the complete name. Finalize only after import,
// because oxcrypt's write/path-lookup helpers still expect their original layout.
fn finalize_entries(vault: &Path, ops: &VaultOperations) -> Result<()> {
    for shard in fs::read_dir(vault.join("d"))? {
        for storage in fs::read_dir(shard?.path())? {
            let storage = storage?.path();
            let metadata = fs::metadata(&storage)?;
            for entry in fs::read_dir(&storage)? {
                let entry = entry?;
                let path = entry.path();
                // Clients may read directory times from the named entry or its
                // marker instead of the separate ciphertext contents directory.
                // Do this before shortening so renames retain the same times.
                if entry.file_type()?.is_dir() && path.join("dir.c9r").is_file() {
                    let marker = path.join("dir.c9r");
                    let id = DirId::from_raw(fs::read_to_string(&marker)?.trim());
                    let metadata = fs::metadata(ops.calculate_directory_storage_path(&id)?)?;
                    copy_times(&marker, &metadata)?;
                    copy_times(&path, &metadata)?;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let shortened = name.ends_with(".c9s");
                let full_name = if shortened {
                    let original = fs::read_to_string(path.join("name.c9s"))?;
                    if original.ends_with(".c9r") {
                        original
                    } else {
                        format!("{original}.c9r")
                    }
                } else if name.ends_with(".c9r") && name.len() > ops.shortening_threshold() {
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

// New vaults need no temporary encrypted empty file before writing the actual
// header and chunks. Reserve the file exclusively in EncryptionPool instead.
fn file_destination(ops: &VaultOperations, id: &DirId, name: &str) -> Result<PathBuf> {
    let storage = ops.calculate_directory_storage_path(id)?;
    let full_name = format!(
        "{}.c9r",
        encrypt_filename(name, id.as_str(), ops.master_key())?
    );
    if full_name.len() > ops.shortening_threshold() {
        let container = storage.join(format!("{}.c9s", create_c9s_filename(&full_name)));
        fs::create_dir(&container)?;
        fs::write(container.join("name.c9s"), full_name)?;
        Ok(container.join("contents.c9r"))
    } else {
        Ok(storage.join(full_name))
    }
}
fn import(
    ops: &VaultOperations,
    source: &Path,
    id: &DirId,
    volume_root: bool,
    jobs: &EncryptionPool,
    directories: &HashMap<PathBuf, fs::Metadata>,
) -> Result<()> {
    let directory_metadata = directories
        .get(source)
        .context("Source directory changed after scanning")?;
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
        if volume_root && is_volume_bookkeeping(&name) {
            continue;
        }
        safe_name(&name)?;
        let kind = entry
            .file_type()
            .with_context(|| format!("Cannot inspect source entry {}", entry.path().display()))?;
        if kind.is_dir() {
            let child = ops.create_directory(id, &name)?;
            import(ops, &entry.path(), &child, false, jobs, directories)?;
        } else if kind.is_file() {
            let metadata = fs::metadata(entry.path()).with_context(|| {
                format!("Cannot inspect source file {}", entry.path().display())
            })?;
            // Prepare names serially so directory lookup never races with writes.
            let encrypted = file_destination(ops, id, &name)?;
            jobs.encrypt_file(ops, &entry.path(), &encrypted, metadata)?;
        } else if kind.is_symlink() {
            let metadata = fs::symlink_metadata(entry.path())?;
            let target = fs::read_link(entry.path())?;
            let target = target.to_str().context("Non-UTF-8 symlink target")?;
            ops.create_symlink(id, &name, target)?;
            let info = ops
                .find_symlink(id, &name)?
                .context("Created symlink is missing")?;
            copy_times(&info.encrypted_path, &metadata)?;
        } else {
            bail!("Unsupported special file: {}", entry.path().display());
        }
    }
    copy_times(
        &ops.calculate_directory_storage_path(id)?,
        directory_metadata,
    )?;
    Ok(())
}

// Save directory metadata before read_dir updates access times. Only directory
// metadata is retained; the scan neither reads file contents nor follows links.
fn scan_source(
    source: &Path,
    volume_root: bool,
    directories: &mut HashMap<PathBuf, fs::Metadata>,
    progress: &crate::Progress,
) -> Result<(u64, u64)> {
    let metadata = fs::metadata(source)
        .with_context(|| format!("Cannot inspect source directory {}", source.display()))?;
    directories.insert(source.to_owned(), metadata);
    let mut bytes = 0u64;
    let mut files = 0u64;
    for entry in fs::read_dir(source)
        .with_context(|| format!("Cannot read source directory {}", source.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Non-UTF-8 filename: {}", entry.path().display()))?;
        if volume_root && is_volume_bookkeeping(&name) {
            progress.message(format!(
                "Skipping macOS system file: {}",
                entry.path().display()
            ));
            continue;
        }
        safe_name(&name)?;
        let kind = entry.file_type()?;
        let (child_bytes, child_files) = if kind.is_dir() {
            scan_source(&entry.path(), false, directories, progress)?
        } else if kind.is_file() {
            (entry.metadata()?.len(), 1)
        } else if kind.is_symlink() {
            (0, 0)
        } else {
            bail!("Unsupported special file: {}", entry.path().display());
        };
        bytes = bytes
            .checked_add(child_bytes)
            .context("Source byte count overflow")?;
        files = files
            .checked_add(child_files)
            .context("Source file count overflow")?;
    }
    Ok((bytes, files))
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
    fn directory_times_cover_entries_markers_and_contents() -> Result<()> {
        use oxcrypt_core::vault::operations::DirEntry;
        use std::time::{Duration, UNIX_EPOCH};

        fn check(ops: &VaultOperations, id: &DirId, source: &Path) -> Result<()> {
            let expected = fs::metadata(source)?.modified()?;
            assert_eq!(
                fs::metadata(ops.calculate_directory_storage_path(id)?)?.modified()?,
                expected
            );
            for entry in crate::vault_read::strict_list(ops, id)? {
                if let DirEntry::Directory(info) = entry {
                    let child = source.join(&info.name);
                    let expected = fs::metadata(&child)?.modified()?;
                    for path in [
                        info.encrypted_path.clone(),
                        info.encrypted_path.join("dir.c9r"),
                    ] {
                        assert_eq!(fs::metadata(&path)?.modified()?, expected, "{path:?}");
                    }
                    check(ops, &info.directory_id, &child)?;
                }
            }
            Ok(())
        }

        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        let long = "d".repeat(180);
        // 147 bytes exercises the boundary where adding .c9r requires shortening.
        let boundary = "b".repeat(147);
        let paths = [
            "".to_owned(),
            "ordinary".into(),
            "ordinary/empty".into(),
            long.clone(),
            format!("{long}/nested"),
            boundary,
        ];
        for path in &paths {
            fs::create_dir_all(source.join(path))?;
        }
        fs::write(source.join("ordinary/data"), b"unchanged contents")?;
        for (index, path) in paths.iter().enumerate() {
            fs::File::open(source.join(path))?.set_times(fs::FileTimes::new().set_modified(
                UNIX_EPOCH + Duration::new(1_600_000_000 + index as u64, 123_456_789),
            ))?;
        }
        let vault = temp.path().join("vault");
        crate::create_vault(&source, &vault, "test password")?;
        let ops = VaultOperations::open(&vault, "test password")?;
        check(&ops, &DirId::root(), &source)?;
        let output = temp.path().join("output");
        crate::extract_vault(&vault, &output, "test password")?;
        for path in &paths {
            assert_eq!(
                fs::metadata(output.join(path))?.modified()?,
                fs::metadata(source.join(path))?.modified()?
            );
        }
        assert_eq!(
            fs::read(output.join("ordinary/data"))?,
            b"unchanged contents"
        );
        Ok(())
    }

    fn create_with_volume_policy(
        source: &Path,
        destination: &Path,
        password: &str,
        volume_root: bool,
    ) -> Result<()> {
        create_impl(
            source,
            destination,
            password,
            volume_root,
            &crate::Progress::default(),
        )
    }

    #[test]
    #[ignore = "manual release-mode throughput measurement; no password KDF"]
    fn processing_throughput() -> Result<()> {
        use std::time::Instant;
        for many_files in [false, true] {
            let temp = tempfile::tempdir()?;
            let source = temp.path().join("source");
            fs::create_dir(&source)?;
            if many_files {
                for directory in 0..20 {
                    let path = source.join(format!("directory-{directory}"));
                    fs::create_dir(&path)?;
                    for file in 0..50 {
                        fs::write(path.join(format!("file-{file}")), vec![42; 4096])?;
                    }
                }
            } else {
                let mut file = fs::File::create(source.join("large"))?;
                use std::io::Write;
                let block = vec![42; 1024 * 1024];
                for _ in 0..128 {
                    file.write_all(&block)?;
                }
            }
            for iteration in 0..3 {
                let vault = temp.path().join(format!("vault-{iteration}"));
                fs::create_dir(&vault)?;
                let ops = VaultOperations::new(&vault, MasterKey::random()?);
                fs::create_dir_all(ops.calculate_directory_storage_path(&DirId::root())?)?;
                let progress = crate::Progress::default();
                let mut directories = HashMap::new();
                let started = Instant::now();
                scan_source(&source, false, &mut directories, &progress)?;
                crate::encrypt::with_pool(&progress, |pool| {
                    import(&ops, &source, &DirId::root(), false, pool, &directories)
                })?;
                let encryption = started.elapsed();
                let output = temp.path().join(format!("output-{iteration}"));
                let started = Instant::now();
                crate::fsutil::new_output(&output, || {
                    crate::extract::export(
                        &ops,
                        &DirId::root(),
                        &output,
                        &mut std::collections::HashSet::new(),
                        &crate::Progress::default(),
                    )
                })?;
                eprintln!(
                    "many_files={many_files} run={iteration} encrypt_ms={:.1} extract_ms={:.1}",
                    encryption.as_secs_f64() * 1000.0,
                    started.elapsed().as_secs_f64() * 1000.0
                );
            }
        }
        Ok(())
    }

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
        let progress = crate::Progress::with_buffered_messages();
        let result = create_impl(&source, &vault, "test password", true, &progress);
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o700))?;
        result?;
        assert_eq!(progress.snapshot().total_files, Some(4));
        let expected_bytes = [
            "nested/.Trashes/keep",
            ".git/config",
            "._document",
            "document",
        ]
        .iter()
        .map(|path| fs::metadata(source.join(path)).unwrap().len())
        .sum::<u64>();
        assert_eq!(progress.snapshot().total_bytes, Some(expected_bytes));
        let messages = progress.drain_messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains(".Trashes"));
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
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o0))?;
        let failed = temp.path().join("failed");
        let result = create_with_volume_policy(&source, &failed, "test password", true);
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600))?;
        assert!(result.unwrap_err().to_string().contains("private-document"));
        assert!(!failed.exists());
        Ok(())
    }
}
