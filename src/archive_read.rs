//! Unpack ciphertext into private staging; never trust archive entry paths.
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Unpacker<'a> {
    root: &'a Path,
    seen: HashSet<PathBuf>,
    times: Vec<(PathBuf, fs::FileTimes)>,
}
impl Unpacker<'_> {
    fn entry(
        &mut self,
        name: &str,
        directory: bool,
        input: &mut dyn io::Read,
        times: fs::FileTimes,
    ) -> Result<()> {
        let name = name.strip_suffix('/').unwrap_or(name);
        ensure!(!name.is_empty(), "Empty archive entry path");
        let mut relative = PathBuf::new();
        for component in name.split('/') {
            crate::fsutil::safe_name(component)?;
            ensure!(!component.contains(':'), "Unsafe archive entry path");
            relative.push(component);
        }
        ensure!(
            self.seen.insert(relative.clone()),
            "Duplicate archive entry: {name}"
        );
        let path = self.root.join(relative);
        if directory {
            fs::create_dir_all(&path)?;
        } else {
            fs::create_dir_all(path.parent().context("Missing archive entry parent")?)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            io::copy(input, &mut file)?;
        }
        self.times.push((path, times));
        Ok(())
    }
    fn finish(mut self) -> Result<()> {
        // Restore directories last, after children have been created.
        self.times
            .sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, times) in self.times {
            fs::File::open(path)?.set_times(times)?;
        }
        Ok(())
    }
}

pub(crate) fn unpack(source: &Path, root: &Path) -> Result<PathBuf> {
    let mut unpacker = Unpacker {
        root,
        seen: HashSet::new(),
        times: Vec::new(),
    };
    match source.extension().and_then(|extension| extension.to_str()) {
        Some("zip") => {
            let mut archive = zip::ZipArchive::new(fs::File::open(source)?)?;
            for index in 0..archive.len() {
                let mut entry = archive.by_index(index)?;
                if let Some(mode) = entry.unix_mode() {
                    let kind = mode & 0o170000;
                    ensure!(
                        kind == 0 || kind == 0o100000 || kind == 0o040000,
                        "Archive contains a symlink or special file"
                    );
                }
                let mut modified = None;
                let mut accessed = None;
                for field in entry.extra_data_fields() {
                    match field {
                        zip::extra_fields::ExtraField::ExtendedTimestamp(timestamp) => {
                            if modified.is_none() {
                                modified = timestamp
                                    .mod_time()
                                    .map(|value| UNIX_EPOCH + Duration::from_secs(value.into()));
                            }
                            if accessed.is_none() {
                                accessed = timestamp
                                    .ac_time()
                                    .map(|value| UNIX_EPOCH + Duration::from_secs(value.into()));
                            }
                        }
                        zip::extra_fields::ExtraField::Ntfs(timestamp) => {
                            modified = Some(SystemTime::from(sevenz_rust2::NtTime::new(
                                timestamp.mtime(),
                            )));
                            accessed = Some(SystemTime::from(sevenz_rust2::NtTime::new(
                                timestamp.atime(),
                            )));
                        }
                        _ => {}
                    }
                }
                if modified.is_none()
                    && let Some(timestamp) = entry.last_modified()
                {
                    let timestamp = time::PrimitiveDateTime::try_from(timestamp)?.assume_utc();
                    modified = Some(SystemTime::from(timestamp));
                }
                let mut times = fs::FileTimes::new();
                if let Some(modified) = modified {
                    times = times.set_modified(modified);
                }
                if let Some(accessed) = accessed {
                    times = times.set_accessed(accessed);
                }
                let name = entry.name()?.into_owned();
                let directory = entry.is_dir();
                unpacker.entry(&name, directory, &mut entry, times)?;
            }
        }
        Some("7z") => {
            let mut archive =
                sevenz_rust2::ArchiveReader::open(source, sevenz_rust2::Password::empty())?;
            archive.for_each_entries(|entry, input| {
                let result = (|| -> Result<()> {
                    let kind = (entry.windows_attributes >> 16) & 0o170000;
                    ensure!(
                        !entry.is_anti_item
                            && (!entry.has_windows_attributes
                                || ((kind == 0 || kind == 0o100000 || kind == 0o040000)
                                    && entry.windows_attributes & 0x400 == 0)),
                        "Archive contains a symlink, special file or anti-item"
                    );
                    let mut times = fs::FileTimes::new();
                    if entry.has_last_modified_date {
                        times = times.set_modified(entry.last_modified_date.into());
                    }
                    if entry.has_access_date {
                        times = times.set_accessed(entry.access_date.into());
                    }
                    unpacker.entry(&entry.name, entry.is_directory, input, times)
                })();
                result
                    .map(|()| true)
                    .map_err(|error| sevenz_rust2::Error::Other(error.to_string().into()))
            })?;
        }
        _ => anyhow::bail!("Expected a vault folder, .zip file or .7z file"),
    }
    unpacker.finish()?;
    let mut candidates = Vec::new();
    fn find(path: &Path, candidates: &mut Vec<PathBuf>) -> Result<()> {
        if path.join("vault.cryptomator").is_file() {
            candidates.push(path.to_owned());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                find(&entry.path(), candidates)?;
            }
        }
        Ok(())
    }
    find(root, &mut candidates)?;
    ensure!(
        candidates.len() == 1,
        "Archive must contain exactly one Cryptomator vault; found {}",
        candidates.len()
    );
    let vault = candidates.pop().unwrap();
    ensure!(
        vault.join("d").is_dir(),
        "Archive does not contain a valid Cryptomator vault: missing d directory"
    );
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_vault;
    use std::io::Write;

    fn fixture(path: &Path, seven_zip: bool, entries: &[(&str, &[u8])]) -> Result<()> {
        let file = fs::File::create(path)?;
        if seven_zip {
            let mut writer = sevenz_rust2::ArchiveWriter::new(file)?;
            for &(name, bytes) in entries {
                let entry = if name.ends_with('/') {
                    sevenz_rust2::ArchiveEntry::new_directory(name)
                } else {
                    sevenz_rust2::ArchiveEntry::new_file(name)
                };
                writer.push_archive_entry(entry, Some(io::Cursor::new(bytes)))?;
            }
            writer.finish()?;
        } else {
            let mut writer = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for &(name, bytes) in entries {
                if name.ends_with('/') {
                    writer.add_directory(name, options)?;
                } else {
                    writer.start_file(name, options)?;
                    writer.write_all(bytes)?;
                }
            }
            writer.finish()?;
        }
        Ok(())
    }

    #[test]
    fn rejects_non_vault_invalid_vault_and_unsafe_archives_without_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for (extension, seven_zip) in [("zip", false), ("7z", true)] {
            for (case, entries, message) in [
                (
                    "plain",
                    vec![("readme.txt", b"not a vault".as_slice())],
                    "exactly one Cryptomator vault",
                ),
                (
                    "fake",
                    vec![
                        ("vault.cryptomator", b"fake".as_slice()),
                        ("d/", b"".as_slice()),
                    ],
                    "invalid vault or incorrect password",
                ),
                (
                    "multiple",
                    vec![
                        ("a/vault.cryptomator", b"fake".as_slice()),
                        ("b/vault.cryptomator", b"fake".as_slice()),
                    ],
                    "exactly one Cryptomator vault",
                ),
                (
                    "traversal",
                    vec![("../escaped", b"escape".as_slice())],
                    "Unsafe",
                ),
                (
                    "absolute",
                    vec![("/escaped", b"escape".as_slice())],
                    "Unsafe",
                ),
                (
                    "backslash",
                    vec![("..\\escaped", b"escape".as_slice())],
                    "Unsafe",
                ),
            ] {
                let archive = temp.path().join(format!("{case}.{extension}"));
                fixture(&archive, seven_zip, &entries)?;
                let output = temp.path().join(format!("{case}-{extension}-output"));
                let error = extract_vault(&archive, &output, "password").unwrap_err();
                assert!(
                    format!("{error:#}").contains(message),
                    "Unexpected error: {error:#}"
                );
                assert!(!output.exists());
            }
            let broken = temp.path().join(format!("broken.{extension}"));
            fs::write(&broken, b"not an archive")?;
            assert!(extract_vault(&broken, temp.path().join("broken-output"), "password").is_err());
        }
        assert!(!temp.path().join("escaped").exists());
        Ok(())
    }

    #[test]
    fn extracts_compressed_archives_with_vault_at_archive_root() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fs::create_dir_all(source.join("empty"))?;
        fs::write(source.join("hello"), b"hello from a compressed vault")?;
        let vault = temp.path().join("vault");
        crate::create_vault(&source, &vault, "test password")?;
        fn collect(root: &Path, path: &Path, entries: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                let name = path
                    .strip_prefix(root)?
                    .to_str()
                    .unwrap()
                    .replace('\\', "/");
                if entry.file_type()?.is_dir() {
                    entries.push((format!("{name}/"), vec![]));
                    collect(root, &path, entries)?;
                } else {
                    entries.push((name, fs::read(path)?));
                }
            }
            Ok(())
        }
        let mut entries = Vec::new();
        collect(&vault, &vault, &mut entries)?;
        let borrowed = entries
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect::<Vec<_>>();
        for (extension, seven_zip) in [("zip", false), ("7z", true)] {
            let archive = temp.path().join(format!("compressed.{extension}"));
            fixture(&archive, seven_zip, &borrowed)?;
            let output = temp.path().join(format!("output-{extension}"));
            extract_vault(&archive, &output, "test password")?;
            assert_eq!(
                fs::read(output.join("hello"))?,
                b"hello from a compressed vault"
            );
            assert!(output.join("empty").is_dir());
        }
        Ok(())
    }

    #[test]
    fn rejects_native_symlinks_in_archives() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let zip = temp.path().join("link.zip");
        let mut writer = zip::ZipWriter::new(fs::File::create(&zip)?);
        writer.add_symlink(
            "link",
            "../outside",
            zip::write::SimpleFileOptions::default(),
        )?;
        writer.finish()?;
        let seven_zip = temp.path().join("link.7z");
        let mut writer = sevenz_rust2::ArchiveWriter::new(fs::File::create(&seven_zip)?)?;
        let mut entry = sevenz_rust2::ArchiveEntry::new_file("link");
        entry.has_windows_attributes = true;
        entry.windows_attributes = (0o120777 << 16) | 0x8000;
        writer.push_archive_entry(entry, Some(io::Cursor::new(b"../outside")))?;
        writer.finish()?;
        for archive in [zip, seven_zip] {
            let error = extract_vault(archive, temp.path().join("output"), "password").unwrap_err();
            assert!(format!("{error:#}").contains("symlink"));
            assert!(!temp.path().join("output").exists());
        }
        Ok(())
    }
}
