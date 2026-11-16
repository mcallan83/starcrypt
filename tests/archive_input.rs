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
    starcrypt::create_vault(&source, &vault, "test password")?;
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
