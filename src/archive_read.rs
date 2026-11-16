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
            crate::fsutil::safe_archive_component(component)?;
            relative.push(component);
        }
        ensure!(
            self.seen.insert(relative.clone()),
            "Duplicate archive entry: {name}"
        );
        let path = self.root.join(relative);
        if directory {
            fs::create_dir_all(&path)?;
            self.times.push((path, times));
        } else {
            fs::create_dir_all(path.parent().context("Missing archive entry parent")?)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            io::copy(input, &mut file)?;
            file.set_times(times)?;
        }
        Ok(())
    }
    fn finish(mut self) -> Result<()> {
        // Restore directories last, after children have been created.
        self.times
            .sort_by_cached_key(|(path, _)| std::cmp::Reverse(path.components().count()));
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
    match source
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
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
