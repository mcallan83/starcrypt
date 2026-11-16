use anyhow::Result;
use starcrypt::extract_vault;
use std::io::Write;
use std::{fs, io, path::Path};

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
            (
                "colon",
                vec![("backup:2026/vault.cryptomator", b"fake".as_slice())],
                "Unsafe archive entry path",
            ),
            (
                "empty-path",
                vec![("/", b"".as_slice())],
                "Empty archive entry path",
            ),
            (
                "empty-component",
                vec![("a//b", b"escape".as_slice())],
                "Unsafe",
            ),
            (
                "dot-component",
                vec![("a/./b", b"escape".as_slice())],
                "Unsafe",
            ),
            (
                "parent-component",
                vec![("a/../b", b"escape".as_slice())],
                "Unsafe",
            ),
            (
                "missing-storage",
                vec![("vault.cryptomator", b"fake".as_slice())],
                "missing d directory",
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
fn duplicate_and_anti_item_entries_are_rejected() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let duplicate = temp.path().join("duplicate.7z");
    fixture(&duplicate, true, &[("same", b"first"), ("same", b"second")])?;
    let output = temp.path().join("duplicate-output");
    let error = extract_vault(&duplicate, &output, "password").unwrap_err();
    assert!(format!("{error:#}").contains("Duplicate archive entry"));
    assert!(!output.exists());
    let anti = temp.path().join("anti.7z");
    let mut writer = sevenz_rust2::ArchiveWriter::new(fs::File::create(&anti)?)?;
    let mut entry = sevenz_rust2::ArchiveEntry::new_file("anti");
    entry.is_anti_item = true;
    writer.push_archive_entry(entry, None::<io::Cursor<Vec<u8>>>)?;
    writer.finish()?;
    let output = temp.path().join("anti-output");
    let error = extract_vault(&anti, &output, "password").unwrap_err();
    assert!(format!("{error:#}").contains("anti-item"), "{error:#}");
    assert!(!output.exists());
    Ok(())
}

#[test]
fn unsupported_archive_extensions_and_payload_crc_errors_leave_no_output() -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let temp = tempfile::tempdir()?;
    let unsupported = temp.path().join("archive.bin");
    fs::write(&unsupported, b"not an archive")?;
    let output = temp.path().join("unsupported-output");
    let error = extract_vault(&unsupported, &output, "password").unwrap_err();
    assert!(format!("{error:#}").contains("Expected a vault folder"));
    assert!(!output.exists());
    let zip = temp.path().join("corrupt.zip");
    let mut writer = zip::ZipWriter::new(fs::File::create(&zip)?);
    writer.start_file(
        "data",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    writer.write_all(b"original")?;
    writer.finish()?;
    let mut archive = zip::ZipArchive::new(fs::File::open(&zip)?)?;
    let offset = archive.by_index(0)?.data_start().unwrap();
    drop(archive);
    let mut file = fs::OpenOptions::new().read(true).write(true).open(&zip)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut byte = [0];
    file.read_exact(&mut byte)?;
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&byte)?;
    let output = temp.path().join("corrupt-output");
    assert!(extract_vault(&zip, &output, "password").is_err());
    assert!(!output.exists());
    Ok(())
}

#[test]
fn archive_timestamp_precision_matches_the_supported_formats() -> Result<()> {
    use std::time::{Duration, UNIX_EPOCH};
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("nested/empty"))?;
    let path = source.join("data");
    fs::write(&path, b"contents")?;
    for entry in [
        &path,
        &source.join("nested/empty"),
        &source.join("nested"),
        &source,
    ] {
        fs::File::open(entry)?.set_times(
            fs::FileTimes::new()
                .set_modified(UNIX_EPOCH + Duration::new(1_600_000_000, 123_456_789)),
        )?;
    }
    for (extension, format, nanos) in [
        ("zip", starcrypt::ArchiveFormat::Zip, 0),
        ("7z", starcrypt::ArchiveFormat::SevenZip, 123_456_700),
    ] {
        let archive = temp.path().join(format!("archive.{extension}"));
        starcrypt::create_archive(&source, &archive, "test password", format)?;
        let output = temp.path().join(format!("output-{extension}"));
        extract_vault(&archive, &output, "test password")?;
        for entry in ["data", "", "nested", "nested/empty"] {
            assert_eq!(
                fs::metadata(output.join(entry))?.modified()?,
                UNIX_EPOCH + Duration::new(1_600_000_000, nanos),
                "Timestamp precision changed for {extension}: {entry}"
            );
        }
        assert_eq!(fs::read(output.join("data"))?, b"contents");
    }
    Ok(())
}

#[test]
fn zip_timestamp_fields_are_restored_with_ntfs_precedence() -> Result<()> {
    use std::time::{Duration, UNIX_EPOCH};
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("data"), b"timestamp fixture")?;
    let vault = temp.path().join("vault");
    starcrypt::create_vault(&source, &vault, "test password")?;
    let mut entries = Vec::new();
    collect(&vault, &vault, &mut entries)?;
    for scheme in ["dos", "unix", "ntfs"] {
        let path = temp.path().join(format!("{scheme}.zip"));
        let mut writer = zip::ZipWriter::new(fs::File::create(&path)?);
        let mut options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2000, 2, 29, 12, 34, 56)?)
            .into_full_options();
        let (modified, _accessed) = if scheme == "dos" {
            (UNIX_EPOCH + Duration::from_secs(951_827_696), None)
        } else {
            let mut stamp = vec![3];
            stamp.extend_from_slice(&1_600_000_000u32.to_le_bytes());
            stamp.extend_from_slice(&1_600_000_100u32.to_le_bytes());
            options.add_extra_field(0x5455, stamp, false)?;
            if scheme == "unix" {
                (
                    UNIX_EPOCH + Duration::from_secs(1_600_000_000),
                    Some(UNIX_EPOCH + Duration::from_secs(1_600_000_100)),
                )
            } else {
                let modified = UNIX_EPOCH + Duration::new(1_600_000_200, 123_456_700);
                let accessed = UNIX_EPOCH + Duration::new(1_600_000_300, 987_654_300);
                let mut ntfs = vec![0; 4];
                ntfs.extend_from_slice(&1u16.to_le_bytes());
                ntfs.extend_from_slice(&24u16.to_le_bytes());
                for time in [modified, accessed, modified] {
                    let value = sevenz_rust2::NtTime::try_from(time)
                        .map_err(|_| anyhow::anyhow!("Invalid fixture timestamp"))?;
                    ntfs.extend_from_slice(&u64::from(value).to_le_bytes());
                }
                options.add_extra_field(0x000a, ntfs, false)?;
                (modified, Some(accessed))
            }
        };
        for (name, bytes) in &entries {
            if name.ends_with('/') {
                writer.add_directory(name, options.clone())?;
            } else {
                writer.start_file(name, options.clone())?;
                writer.write_all(bytes)?;
            }
        }
        writer.finish()?;
        let output = temp.path().join(format!("output-{scheme}"));
        extract_vault(&path, &output, "test password")?;
        let metadata = fs::metadata(output.join("data"))?;
        assert_eq!(metadata.modified()?, modified, "{scheme}");
        // Reading the staged ciphertext can update its access time before decryption.
        assert_eq!(fs::read(output.join("data"))?, b"timestamp fixture");
    }
    Ok(())
}

#[test]
fn extracts_compressed_archives_with_vault_at_archive_root() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("empty"))?;
    fs::write(source.join("hello"), b"hello from a compressed vault")?;
    let vault = temp.path().join("vault");
    starcrypt::create_vault(&source, &vault, "test password")?;
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
