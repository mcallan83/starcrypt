//! Streaming extraction of authenticated vault entries.
#[cfg(unix)]
use crate::fsutil::copy_symlink_times;
use crate::{
    decrypt::{self, Source},
    fsutil::{copy_times, safe_name},
    vault_read::{storage_directory, strict_list, validate_file},
};
use anyhow::{Context, Result, ensure};
use oxcrypt_core::{
    fs::streaming::VaultFileReaderSync,
    vault::{
        operations::{DirEntry, VaultOperations},
        path::DirId,
    },
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

pub(crate) fn export(
    ops: &VaultOperations,
    id: &DirId,
    destination: &Path,
    visited: &mut HashSet<String>,
    progress: &crate::Progress,
) -> Result<()> {
    progress.phase("Scanning vault");
    let mut directories = HashMap::new();
    let (bytes, files) = scan_vault(ops, id, &mut directories)?;
    progress.totals(bytes, files);
    progress.phase("Decrypting");
    decrypt::with_pool(ops, progress, |pool| {
        export_with_writer(
            ops,
            id,
            destination,
            visited,
            Some(&directories),
            &mut |source, path| pool.decrypt_file(source, path),
        )
    })
}
fn export_with_writer(
    ops: &VaultOperations,
    id: &DirId,
    destination: &Path,
    visited: &mut HashSet<String>,
    directories: Option<&HashMap<String, fs::Metadata>>,
    write_file: &mut impl FnMut(Source, &Path) -> Result<()>,
) -> Result<()> {
    let directory_metadata = match directories {
        Some(directories) => directories
            .get(id.as_str())
            .context("Vault changed after scanning")?
            .clone(),
        None => storage_directory(ops, id)?.1,
    };
    ensure!(
        visited.insert(id.as_str().to_owned()),
        "Vault contains a repeated directory ID"
    );
    for entry in strict_list(ops, id)? {
        safe_name(entry.name())?;
        let path = destination.join(entry.name());
        match entry {
            DirEntry::File(info) => {
                let metadata = fs::metadata(&info.encrypted_path)?;
                validate_file(ops, &info.encrypted_path, metadata.len())?;
                // Listing supplies the actual on-disk path, including standard
                // shortened names that oxcrypt's name-lookup helper miscalculates.
                let reader = VaultFileReaderSync::open_with_cipher(
                    &info.encrypted_path,
                    ops.master_key(),
                    ops.cipher_combo(),
                )?;
                write_file(
                    Source {
                        reader,
                        path: info.encrypted_path,
                        metadata,
                    },
                    &path,
                )?;
            }
            DirEntry::Directory(info) => {
                fs::create_dir(&path)?;
                export_with_writer(
                    ops,
                    &info.directory_id,
                    &path,
                    visited,
                    directories,
                    write_file,
                )?;
            }
            DirEntry::Symlink(info) => {
                #[cfg(unix)]
                {
                    let metadata = fs::metadata(&info.encrypted_path)?;
                    std::os::unix::fs::symlink(&info.target, &path)?;
                    copy_symlink_times(&path, &metadata)?;
                }
                #[cfg(not(unix))]
                anyhow::bail!("Symlink extraction is currently supported only on Unix");
            }
        }
    }
    copy_times(destination, &directory_metadata)?;
    Ok(())
}

// Filename/entry metadata only: content authentication still happens during
// export. Retain original directory timestamps before listing changes atimes.
fn scan_vault(
    ops: &VaultOperations,
    id: &DirId,
    directories: &mut HashMap<String, fs::Metadata>,
) -> Result<(u64, u64)> {
    ensure!(
        !directories.contains_key(id.as_str()),
        "Vault contains a repeated directory ID"
    );
    directories.insert(id.as_str().to_owned(), storage_directory(ops, id)?.1);
    let mut bytes = 0u64;
    let mut files = 0u64;
    for entry in strict_list(ops, id)? {
        let (child_bytes, child_files) = match entry {
            DirEntry::File(info) => {
                let header_size = match ops.cipher_combo() {
                    oxcrypt_core::vault::config::CipherCombo::SivGcm => 68,
                    oxcrypt_core::vault::config::CipherCombo::SivCtrMac => 88,
                };
                let size = if info.encrypted_size == header_size {
                    0
                } else {
                    oxcrypt_core::fs::streaming::encrypted_to_plaintext_size_for_cipher(
                        info.encrypted_size,
                        ops.cipher_combo(),
                    )
                    .context("Invalid encrypted file size")?
                };
                (size, 1)
            }
            DirEntry::Directory(info) => scan_vault(ops, &info.directory_id, directories)?,
            DirEntry::Symlink(_) => (0, 0),
        };
        bytes = bytes
            .checked_add(child_bytes)
            .context("Vault byte count overflow")?;
        files = files
            .checked_add(child_files)
            .context("Vault file count overflow")?;
    }
    Ok((bytes, files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_vault, fsutil::new_output, vault_read::open_vault};
    use std::io::Write;
    use zeroize::Zeroizing;
    #[test]
    #[cfg(unix)]
    fn disk_full_during_extraction_cleans_partial_output() -> Result<()> {
        struct FullWriter {
            file: fs::File,
            remaining: usize,
        }
        impl Write for FullWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
                }
                let count = bytes.len().min(self.remaining);
                let written = self.file.write(&bytes[..count])?;
                self.remaining -= written;
                Ok(written)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.file.flush()
            }
        }
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fs::create_dir(&source)?;
        let data = vec![42; 65_537];
        fs::write(source.join("payload"), &data)?;
        let vault = temp.path().join("vault");
        create_vault(&source, &vault, "test password")?;
        let ops = open_vault(&vault, "test password")?;
        let output = temp.path().join("output");
        let error = new_output(&output, || {
            export_with_writer(
                &ops,
                &DirId::root(),
                &output,
                &mut HashSet::new(),
                None,
                &mut |mut source, path| {
                    let file = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)?;
                    let plaintext = Zeroizing::new(source.reader.read_range(0, 65_537)?);
                    FullWriter {
                        file,
                        remaining: 100,
                    }
                    .write_all(&plaintext)?;
                    Ok(())
                },
            )
        })
        .unwrap_err();
        ensure!(
            error
                .downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())
                == Some(libc::ENOSPC)
        );
        ensure!(!output.exists());
        ensure!(fs::read(source.join("payload"))? == data);
        Ok(())
    }
}
