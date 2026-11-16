//! Strict archive extraction: never silently omit malformed ciphertext entries.
use crate::fsutil::safe_name;
use anyhow::{Context, Result, ensure};
use oxcrypt_core::{
    fs::name::create_c9s_filename,
    vault::{
        config::validate_vault_claims,
        master_key::MasterKeyFile,
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
    io::Read,
    path::{Component, Path, PathBuf},
};

const MAX_METADATA_BYTES: u64 = 64 * 1024;
// Includes scrypt's V, B and T buffers with the dependency's fixed p = 1.
const MAX_SCRYPT_MEMORY: u64 = 256 * 1024 * 1024;

fn read_metadata(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_METADATA_BYTES,
        "Vault metadata exceeds the 64 KiB limit: {}",
        path.display()
    );
    Ok(bytes)
}

fn validate_master_key(key: &MasterKeyFile) -> Result<()> {
    let n = u32::try_from(key.scrypt_cost_param).unwrap_or(0);
    let r = u32::try_from(key.scrypt_block_size).unwrap_or(0);
    ensure!(
        n >= 2 && n.is_power_of_two(),
        "Invalid scryptCostParam: must be a power of two greater than one"
    );
    ensure!(r > 0, "Invalid scryptBlockSize: must be positive");
    ensure!(
        u64::from(n.ilog2()) < 16 * u64::from(r) && r < 0x4000_0000,
        "Invalid scrypt parameters"
    );
    let memory = u64::from(n)
        .checked_add(2)
        .and_then(|blocks| blocks.checked_mul(u64::from(r)))
        .and_then(|blocks| blocks.checked_mul(128))
        .context("Scrypt memory requirement overflow")?;
    ensure!(
        memory <= MAX_SCRYPT_MEMORY,
        "Scrypt resource limit exceeded: estimated working buffers require {memory} bytes (limit: {MAX_SCRYPT_MEMORY} bytes)"
    );
    ensure!(!key.scrypt_salt.is_empty(), "Missing scrypt salt");
    ensure!(
        key.primary_master_key.len() == 40 && key.hmac_master_key.len() == 40,
        "Invalid wrapped master-key length"
    );
    ensure!(key.version_mac.len() == 32, "Invalid version MAC length");
    Ok(())
}

fn ordinary_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "Unexpected native symlink in encrypted vault: {}",
        path.display()
    );
    Ok(metadata)
}

/// Check every component below the selected vault, not just the final directory:
/// symlink_metadata follows links in ancestors. Recheck on each traversal rather
/// than caching these checks. This is not atomic against concurrent replacement.
pub(super) fn storage_directory(
    ops: &VaultOperations,
    id: &DirId,
) -> Result<(PathBuf, fs::Metadata)> {
    let storage = ops.calculate_directory_storage_path(id)?;
    let relative = storage
        .strip_prefix(ops.vault_path())
        .context("Encrypted directory storage is outside the vault")?;
    let mut path = ops.vault_path().to_path_buf();
    let mut metadata = None;
    for component in relative.components() {
        ensure!(
            matches!(component, Component::Normal(_)),
            "Invalid encrypted directory storage path"
        );
        path.push(component);
        let current = ordinary_metadata(&path)?;
        ensure!(
            current.is_dir(),
            "Missing encrypted directory storage: {}",
            path.display()
        );
        metadata = Some(current);
    }
    Ok((
        storage,
        metadata.context("Empty encrypted directory storage path")?,
    ))
}

pub(super) fn open_vault(vault: &Path, password: &str) -> Result<VaultOperations> {
    ensure!(
        ordinary_metadata(&vault.join("vault.cryptomator"))?.is_file(),
        "Vault configuration is not a regular file"
    );
    let config = String::from_utf8(read_metadata(&vault.join("vault.cryptomator"))?)?;
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
        fs::metadata(&key_path)?.is_file(),
        "Master key is not a regular file"
    );
    let key: MasterKeyFile = serde_json::from_slice(&read_metadata(&key_path)?)
        .context("Invalid master-key metadata")?;
    validate_master_key(&key)?;
    // Unlock precisely the data validated above, without reopening metadata via
    // VaultOperations::open (which also interprets the key location differently).
    let master_key = key.unlock(password)?;
    let claims = validate_vault_claims(&config, &master_key)?;
    Ok(VaultOperations::with_options(
        vault,
        master_key,
        claims.shortening_threshold(),
        claims.cipher_combo().context("Unsupported vault cipher")?,
    ))
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
    let (storage, _) = storage_directory(ops, id)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use oxcrypt_core::{crypto::keys::MasterKey, vault::master_key::create_masterkey_file};

    #[test]
    fn scrypt_resource_boundaries_are_checked_without_deriving_keys() -> Result<()> {
        let mut key: MasterKeyFile = serde_json::from_str(&create_masterkey_file(
            &MasterKey::random()?,
            "test password",
        )?)?;
        for (n, r) in [(2, 1), (32768, 8), (131072, 8), (2, 524288)] {
            key.scrypt_cost_param = n;
            key.scrypt_block_size = r;
            validate_master_key(&key)?;
        }
        // Exactly 256 MiB of working buffers is accepted; the next block is not.
        key.scrypt_block_size = 524289;
        assert!(
            validate_master_key(&key)
                .unwrap_err()
                .to_string()
                .contains("Scrypt resource limit exceeded")
        );
        key.scrypt_cost_param = 1 << 30;
        key.scrypt_block_size = 1 << 29;
        assert!(
            validate_master_key(&key)
                .unwrap_err()
                .to_string()
                .contains("Scrypt memory requirement overflow")
        );
        key.scrypt_cost_param = 65536;
        key.scrypt_block_size = 1;
        assert!(
            validate_master_key(&key)
                .unwrap_err()
                .to_string()
                .contains("Invalid scrypt parameters")
        );
        Ok(())
    }
}
