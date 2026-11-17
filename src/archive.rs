//! Package encrypted vaults without staging any plaintext copies.
use anyhow::{Context, Result, ensure};
use std::{fs, io, path::Path};

#[derive(Clone, Copy, Debug)]
pub enum ArchiveFormat {
    Zip,
    SevenZip,
}

pub(crate) fn create_archive(
    source: &Path,
    destination: &Path,
    password: &str,
    format: ArchiveFormat,
    progress: &crate::Progress,
) -> Result<()> {
    create_archive_using_progress(source, destination, password, progress, |vault, file| {
        match format {
            ArchiveFormat::Zip => write_zip(vault, file),
            ArchiveFormat::SevenZip => write_seven_zip(vault, file),
        }
    })
}

fn create_archive_using_progress(
    source: &Path,
    destination: &Path,
    password: &str,
    progress: &crate::Progress,
    write: impl FnOnce(&Path, fs::File) -> Result<()>,
) -> Result<()> {
    create_archive_with_key(source, destination, password, progress, write, |_| Ok(()))
}

pub(crate) fn create_archive_with_key(
    source: &Path,
    destination: &Path,
    password: &str,
    progress: &crate::Progress,
    write: impl FnOnce(&Path, fs::File) -> Result<()>,
    key_ready: impl FnOnce(&oxcrypt_core::crypto::keys::MasterKey) -> Result<()>,
) -> Result<()> {
    let name = destination
        .file_stem()
        .and_then(|name| name.to_str())
        .context("Archive needs a UTF-8 filename")?;
    crate::fsutil::safe_archive_component(name)
        .context("Archive filename stem cannot be used as a safe internal vault folder name")?;
    let staging = tempfile::Builder::new()
        .prefix("starcrypt-vault-")
        .tempdir()?;
    let vault = staging.path().join(name);
    // Only ciphertext is staged: the archive contains an ordinary vault folder.
    crate::create::create_with_key(
        source,
        &vault,
        password,
        crate::fsutil::is_macos_volume_root(source)?,
        progress,
        key_ready,
    )?;
    progress.phase("Packaging archive");
    let parent = destination
        .parent()
        .context("Archive needs a parent directory")?;
    let archive = tempfile::Builder::new()
        .prefix("starcrypt-archive-")
        .tempfile_in(parent)?;
    write(&vault, archive.as_file().try_clone()?)?;
    archive.as_file().sync_all()?;
    archive
        .persist_noclobber(destination)
        .context("Cannot save archive; destination must not exist")?;
    Ok(())
}

fn visit(
    vault: &Path,
    mut add: impl FnMut(&Path, &str, &fs::Metadata) -> Result<()>,
) -> Result<()> {
    fn walk(
        path: &Path,
        name: &str,
        add: &mut impl FnMut(&Path, &str, &fs::Metadata) -> Result<()>,
    ) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir() || metadata.is_file(),
            "Unexpected special file in encrypted staging directory"
        );
        add(path, name, &metadata)?;
        if metadata.is_dir() {
            let mut entries = fs::read_dir(path)?.collect::<io::Result<Vec<_>>>()?;
            entries.sort_by_cached_key(|entry| entry.file_name());
            for entry in entries {
                let child = entry.file_name();
                let child = child.to_str().context("Non-UTF-8 encrypted filename")?;
                crate::fsutil::safe_archive_component(child)?;
                walk(&entry.path(), &format!("{name}/{child}"), add)?;
            }
        }
        Ok(())
    }
    let name = vault
        .file_name()
        .and_then(|name| name.to_str())
        .context("Invalid vault name")?;
    crate::fsutil::safe_archive_component(name)?;
    walk(vault, name, &mut add)
}

pub(crate) fn write_zip(vault: &Path, file: fs::File) -> Result<()> {
    let mut writer = zip::ZipWriter::new(file);
    visit(vault, |path, name, metadata| {
        let modified = metadata.modified()?;
        let datetime = time::OffsetDateTime::from(modified);
        let dos_time = zip::DateTime::try_from(time::PrimitiveDateTime::new(
            datetime.date(),
            datetime.time(),
        ))
        .unwrap_or_default();
        let mut options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            // Some extractors use only the standard field, especially for folders.
            .last_modified_time(dos_time)
            .large_file(metadata.len() >= u32::MAX as u64)
            .into_full_options();
        // Extended timestamp field: UTC modification time, independent of local timezone.
        if let Ok(seconds) = modified.duration_since(std::time::UNIX_EPOCH)
            && let Ok(seconds) = u32::try_from(seconds.as_secs())
        {
            let mut timestamp = vec![1];
            timestamp.extend_from_slice(&seconds.to_le_bytes());
            options.add_extra_field(0x5455, timestamp, false)?;
        }
        if metadata.is_dir() {
            writer.add_directory(format!("{name}/"), options)?;
        } else {
            writer.start_file(name, options)?;
            io::copy(&mut fs::File::open(path)?, &mut writer)?;
        }
        Ok(())
    })?;
    drop(writer.finish()?);
    Ok(())
}

pub(crate) fn write_seven_zip(vault: &Path, file: fs::File) -> Result<()> {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod};
    let mut writer = ArchiveWriter::new(file)?;
    // Ciphertext is incompressible; avoid spending CPU compressing it again.
    writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    visit(vault, |path, name, metadata| {
        let entry = ArchiveEntry::from_path(path, name.to_owned());
        let input = if metadata.is_file() {
            Some(fs::File::open(path)?)
        } else {
            None
        };
        writer.push_archive_entry(entry, input)?;
        Ok(())
    })?;
    drop(writer.finish()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn zip_standard_timestamps_preserve_files_and_directories() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let vault = temp.path().join("vault");
        fs::create_dir_all(vault.join("nested/empty"))?;
        fs::write(vault.join("nested/data"), b"ciphertext")?;
        let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_001);
        for name in ["nested/data", "nested/empty", "nested", ""] {
            fs::File::open(vault.join(name))?
                .set_times(fs::FileTimes::new().set_modified(modified))?;
        }
        let archive = temp.path().join("vault.zip");
        write_zip(&vault, fs::File::create(&archive)?)?;
        let mut archive = zip::ZipArchive::new(fs::File::open(archive)?)?;
        for name in [
            "vault/",
            "vault/nested/",
            "vault/nested/empty/",
            "vault/nested/data",
        ] {
            let entry = archive.by_name(name)?;
            let standard = time::PrimitiveDateTime::try_from(entry.last_modified().unwrap())?;
            // DOS time has two-second precision; the UTC extra field retains seconds.
            assert_eq!(
                standard.assume_utc().unix_timestamp(),
                1_600_000_000,
                "{name}"
            );
            assert!(
                entry.extra_data_fields().any(|field| matches!(
                    field,
                    zip::extra_fields::ExtraField::ExtendedTimestamp(timestamp)
                        if timestamp.mod_time() == Some(1_600_000_001)
                )),
                "Missing UTC modification time for {name}"
            );
        }
        Ok(())
    }

    fn create_archive_using(
        source: &Path,
        destination: &Path,
        password: &str,
        write: impl FnOnce(&Path, fs::File) -> Result<()>,
    ) -> Result<()> {
        create_archive_using_progress(
            source,
            destination,
            password,
            &crate::Progress::default(),
            write,
        )
    }

    #[test]
    fn invalid_internal_name_fails_before_source_access_or_packaging() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("backup:2026.zip");
        let error = create_archive_using(
            &temp.path().join("missing-source"),
            &destination,
            "test password",
            |_, _| panic!("Invalid archive name reached packaging"),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("Unsafe archive entry path"));
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(temp.path())?.count(), 0);
        Ok(())
    }
    #[test]
    #[cfg(unix)]
    #[ignore = "child process used only by abrupt_archive_process_termination_keeps_source"]
    fn archive_interruption_child() -> Result<()> {
        let root = PathBuf::from(std::env::var("STARCRYPT_INTERRUPT_ROOT")?);
        create_archive_using(
            &root.join("source"),
            &root.join("archive.zip"),
            "test password",
            |vault, mut file| {
                fs::write(
                    root.join("marker"),
                    vault.parent().unwrap().to_string_lossy().as_bytes(),
                )?;
                file.write_all(b"partial")?;
                file.flush()?;
                loop {
                    std::thread::park();
                }
            },
        )
    }
    #[test]
    #[cfg(unix)]
    fn abrupt_archive_process_termination_keeps_source() -> Result<()> {
        use std::os::unix::process::CommandExt;
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        fs::create_dir(root.join("source"))?;
        fs::write(
            root.join("source/payload"),
            b"source intact after process termination",
        )?;
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "archive::tests::archive_interruption_child",
                "--ignored",
            ])
            .env("STARCRYPT_INTERRUPT_ROOT", root)
            .process_group(0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !root.join("marker").is_file() && std::time::Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // SAFETY: the child was started in its own process group. Kill only that
        // disposable test group, including its archiver, so no process is orphaned.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGTERM);
        }
        let status = child.wait()?;
        ensure!(root.join("marker").is_file(), "Test archiver did not start");
        ensure!(!status.success());
        ensure!(
            !root.join("archive.zip").exists(),
            "Partial archive was published"
        );
        ensure!(
            fs::read(root.join("source/payload"))? == b"source intact after process termination"
        );
        // Abrupt process death cannot run RAII cleanup. Verify the abandoned staging
        // contains an encrypted vault, then remove only this test's staging folder.
        let staging = PathBuf::from(fs::read_to_string(root.join("marker"))?);
        ensure!(
            staging
                .canonicalize()?
                .starts_with(std::env::temp_dir().canonicalize()?)
        );
        ensure!(
            staging
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("starcrypt-vault-")
        );
        ensure!(staging.join("archive/vault.cryptomator").is_file());
        ensure!(!staging.join("archive/payload").exists());
        fs::remove_dir_all(staging)?;
        Ok(())
    }
    #[test]
    fn failed_writer_never_publishes_partial_archive() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("payload"), b"source must remain intact")?;
        let destination = temp.path().join("failed.zip");
        assert!(
            create_archive_using(&source, &destination, "test password", |_, mut file| {
                file.write_all(b"partial")?;
                anyhow::bail!("injected disk-full error")
            })
            .is_err()
        );
        assert!(!destination.exists());
        assert!(!fs::read_dir(temp.path())?.any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("starcrypt-archive-")
        }));
        assert_eq!(
            fs::read(source.join("payload"))?,
            b"source must remain intact"
        );
        Ok(())
    }
}
