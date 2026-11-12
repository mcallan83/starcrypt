//! Streaming extraction of authenticated vault entries.
#[cfg(unix)]
use crate::fsutil::copy_symlink_times;
use crate::{
    fsutil::{copy_times, safe_name},
    vault_read::{strict_list, validate_file},
};
use anyhow::{Result, ensure};
use oxcrypt_core::{
    fs::streaming::VaultFileReaderSync,
    vault::{
        operations::{DirEntry, VaultOperations},
        path::DirId,
    },
};
use std::{collections::HashSet, fs, io::Write, path::Path};
use zeroize::Zeroizing;

pub(crate) fn export(
    ops: &VaultOperations,
    id: &DirId,
    destination: &Path,
    visited: &mut HashSet<String>,
) -> Result<()> {
    export_with_writer(ops, id, destination, visited, &mut |reader, path| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        copy_decrypted_file(reader, &mut file)
    })
}
fn copy_decrypted_file(reader: &mut VaultFileReaderSync, writer: &mut impl Write) -> Result<()> {
    let mut offset = 0;
    while offset < reader.plaintext_size() {
        let chunk = Zeroizing::new(reader.read_range(offset, 32 * 1024)?);
        ensure!(!chunk.is_empty(), "Unexpected end of encrypted file");
        writer.write_all(&chunk)?;
        offset += chunk.len() as u64;
    }
    writer.flush()?;
    Ok(())
}
fn export_with_writer(
    ops: &VaultOperations,
    id: &DirId,
    destination: &Path,
    visited: &mut HashSet<String>,
    write_file: &mut impl FnMut(&mut VaultFileReaderSync, &Path) -> Result<()>,
) -> Result<()> {
    let directory_metadata = fs::metadata(ops.calculate_directory_storage_path(id)?)?;
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
                let mut reader = VaultFileReaderSync::open_with_cipher(
                    &info.encrypted_path,
                    ops.master_key(),
                    ops.cipher_combo(),
                )?;
                write_file(&mut reader, &path)?;
                copy_times(&path, &metadata)?;
            }
            DirEntry::Directory(info) => {
                fs::create_dir(&path)?;
                export_with_writer(ops, &info.directory_id, &path, visited, write_file)?;
            }
            DirEntry::Symlink(info) => {
                #[cfg(unix)]
                {
                    let metadata = fs::metadata(&info.encrypted_path)?;
                    std::os::unix::fs::symlink(&info.target, &path)?;
                    copy_symlink_times(&path, &metadata)?;
                }
                #[cfg(not(unix))]
                bail!("Symlink extraction is currently supported only on Unix");
            }
        }
    }
    copy_times(destination, &directory_metadata)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create::create, fsutil::new_output, vault_read::open_vault};
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
        create(&source, &vault, "test password")?;
        let ops = open_vault(&vault, "test password")?;
        let output = temp.path().join("output");
        let error = new_output(&output, || {
            export_with_writer(
                &ops,
                &DirId::root(),
                &output,
                &mut HashSet::new(),
                &mut |reader, path| {
                    let file = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)?;
                    copy_decrypted_file(
                        reader,
                        &mut FullWriter {
                            file,
                            remaining: 100,
                        },
                    )
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
