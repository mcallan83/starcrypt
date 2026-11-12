//! Strict archive extraction: never silently omit malformed ciphertext entries.
use crate::fsutil::safe_name;
use anyhow::{Context, Result, ensure};
use oxcrypt_core::{
    fs::name::create_c9s_filename,
    vault::{
        operations::{DirEntry, VaultOperations},
        path::DirId,
    },
};
use oxcrypt_core::{
    fs::name::decrypt_filename,
    vault::{
        config::CipherCombo,
        operations::{VaultDirectoryInfo, VaultFileInfo, VaultSymlinkInfo},
    },
};
use std::{
    fs,
    path::{Component, Path},
};

fn ordinary_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "Unexpected native symlink in encrypted vault: {}",
        path.display()
    );
    Ok(metadata)
}

pub(super) fn open_vault(vault: &Path, password: &str) -> Result<VaultOperations> {
    ensure!(
        ordinary_metadata(&vault.join("vault.cryptomator"))?.is_file(),
        "Vault configuration is not a regular file"
    );
    let config = fs::read_to_string(vault.join("vault.cryptomator"))?;
    let header = jsonwebtoken::decode_header(&config)?;
    let kid = header.kid.context("Missing master-key location")?;
    let path = Path::new(
        kid.strip_prefix("masterkeyfile:")
            .context("Only password-protected masterkeyfile vaults are supported")?,
    );
    ensure!(
        !path.as_os_str().is_empty()
            && path.components().all(|p| matches!(p, Component::Normal(_))),
        "Master-key location must be a relative path inside the vault"
    );
    let mut key_path = vault.to_path_buf();
    for component in path.components() {
        key_path.push(component);
        ordinary_metadata(&key_path)?;
    }
    ensure!(
        fs::metadata(key_path)?.is_file(),
        "Master key is not a regular file"
    );
    Ok(VaultOperations::open(vault, password)?)
}

pub(super) fn validate_file_size(size: u64, cipher: CipherCombo) -> Result<()> {
    let (header, overhead) = match cipher {
        CipherCombo::SivGcm => (68, 28),
        CipherCombo::SivCtrMac => (88, 48),
    };
    ensure!(size >= header, "Truncated encrypted file header");
    let remainder = (size - header) % (32 * 1024 + overhead);
    ensure!(
        remainder == 0 || remainder > overhead,
        "Incomplete encrypted file chunk"
    );
    Ok(())
}

pub(super) fn validate_file(ops: &VaultOperations, path: &Path, size: u64) -> Result<()> {
    let legacy_empty_size = match ops.cipher_combo() {
        CipherCombo::SivGcm => 96,
        CipherCombo::SivCtrMac => 136,
    };
    if size == legacy_empty_size {
        // Older oxcrypt builds wrote a tag-only empty chunk. Read these only
        // after authenticating that tag; the streaming reader otherwise skips
        // content authentication when its calculated plaintext length is zero.
        let content = ops
            .cipher_combo()
            .decrypt_file(&fs::read(path)?, ops.master_key())?;
        ensure!(content.content.is_empty(), "Invalid legacy empty file");
        Ok(())
    } else {
        validate_file_size(size, ops.cipher_combo())
    }
}

pub(super) fn strict_list(ops: &VaultOperations, id: &DirId) -> Result<Vec<DirEntry>> {
    let storage = ops.calculate_directory_storage_path(id)?;
    ensure!(
        ordinary_metadata(&storage)?.is_dir(),
        "Missing encrypted directory storage"
    );
    let mut entries = Vec::new();
    for entry in fs::read_dir(&storage)? {
        let entry = entry?;
        let path = entry.path();
        let encrypted_name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Non-UTF-8 ciphertext name"))?;
        if encrypted_name == "dirid.c9r" {
            continue;
        } // Optional recovery metadata.
        let shortened = encrypted_name.ends_with(".c9s");
        if !shortened && !encrypted_name.ends_with(".c9r") {
            continue;
        }
        let metadata = ordinary_metadata(&path)?;
        let full_name = if shortened {
            ensure!(metadata.is_dir(), "Shortened entry is not a directory");
            ensure!(
                ordinary_metadata(&path.join("name.c9s"))?.is_file(),
                "Missing shortened filename"
            );
            let original = fs::read_to_string(path.join("name.c9s"))?;
            // Also read the old oxcrypt layout, without creating it in new vaults.
            ensure!(
                encrypted_name == format!("{}.c9s", create_c9s_filename(&original)),
                "Shortened filename hash mismatch"
            );
            original
        } else {
            encrypted_name.clone()
        };
        let name =
            decrypt_filename(&full_name, id.as_str(), ops.master_key()).with_context(|| {
                format!("Cannot authenticate encrypted filename {}", path.display())
            })?;
        safe_name(&name)?;
        if metadata.is_file() {
            ensure!(!shortened, "Invalid shortened entry");
            entries.push(DirEntry::File(VaultFileInfo {
                name,
                encrypted_name,
                encrypted_path: path,
                encrypted_size: metadata.len(),
                is_shortened: false,
            }));
            continue;
        }
        ensure!(metadata.is_dir(), "Unsupported encrypted entry type");
        let mut markers = Vec::new();
        for marker in ["contents.c9r", "dir.c9r", "symlink.c9r"] {
            match fs::symlink_metadata(path.join(marker)) {
                Ok(metadata) => {
                    ensure!(
                        metadata.is_file() && !metadata.file_type().is_symlink(),
                        "Encrypted entry payload is not a regular file"
                    );
                    markers.push(marker);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        ensure!(
            markers.len() == 1,
            "Missing or ambiguous encrypted entry type: {}",
            path.display()
        );
        match markers[0] {
            "contents.c9r" => {
                ensure!(shortened, "File container lacks shortened name");
                let content_path = path.join("contents.c9r");
                entries.push(DirEntry::File(VaultFileInfo {
                    name,
                    encrypted_name,
                    encrypted_size: fs::metadata(&content_path)?.len(),
                    encrypted_path: content_path,
                    is_shortened: true,
                }));
            }
            "dir.c9r" => {
                let directory_id = fs::read_to_string(path.join("dir.c9r"))?;
                ensure!(!directory_id.is_empty(), "Empty child directory ID");
                entries.push(DirEntry::Directory(VaultDirectoryInfo {
                    name,
                    directory_id: DirId::from_raw(directory_id),
                    encrypted_path: path,
                    parent_directory_id: id.clone(),
                }));
            }
            "symlink.c9r" => {
                let encrypted_target = fs::read(path.join("symlink.c9r"))?;
                validate_file_size(encrypted_target.len() as u64, ops.cipher_combo())?;
                let decrypted = ops
                    .cipher_combo()
                    .decrypt_file(&encrypted_target, ops.master_key())?;
                let target = String::from_utf8(decrypted.content)?;
                ensure!(!target.contains('\0'), "Invalid symlink target");
                entries.push(DirEntry::Symlink(VaultSymlinkInfo {
                    name,
                    target,
                    encrypted_path: path,
                    is_shortened: shortened,
                }));
            }
            _ => unreachable!(),
        }
    }
    Ok(entries)
}
