use anyhow::{Result, ensure};

use starcrypt::{ArchiveFormat, create_archive, extract_vault};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[test]
#[cfg(target_os = "macos")]
fn archive_creation_does_not_write_to_source() -> Result<()> {
    use std::collections::BTreeMap;
    #[cfg(target_os = "macos")]
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[derive(Debug, PartialEq)]
    struct State {
        contents_or_target: Vec<u8>,
        // Access time is deliberately separate: read-only filesystem access
        // can update it. All other checked metadata must remain unchanged.
        metadata: Vec<i128>,
        xattrs: Vec<u8>,
    }
    type States = BTreeMap<PathBuf, State>;
    type AccessTimes = BTreeMap<PathBuf, (i64, i64)>;
    fn snapshot(root: &Path) -> Result<(States, AccessTimes)> {
        fn visit(
            root: &Path,
            path: &Path,
            states: &mut BTreeMap<PathBuf, State>,
            access: &mut BTreeMap<PathBuf, (i64, i64)>,
        ) -> Result<()> {
            let metadata = fs::symlink_metadata(path)?;
            let relative = path.strip_prefix(root)?.to_owned();
            access.insert(relative.clone(), (metadata.atime(), metadata.atime_nsec()));
            let mut attributes = vec![
                metadata.dev() as i128,
                metadata.ino() as i128,
                metadata.mode() as i128,
                metadata.nlink() as i128,
                metadata.uid() as i128,
                metadata.gid() as i128,
                metadata.size() as i128,
                metadata.mtime() as i128,
                metadata.mtime_nsec() as i128,
                metadata.ctime() as i128,
                metadata.ctime_nsec() as i128,
            ];
            #[cfg(target_os = "macos")]
            attributes.extend([
                metadata.st_birthtime() as i128,
                metadata.st_birthtime_nsec() as i128,
                metadata.st_flags() as i128,
            ]);
            let contents_or_target = if metadata.is_file() {
                fs::read(path)?
            } else if metadata.file_type().is_symlink() {
                use std::os::unix::ffi::OsStrExt;
                fs::read_link(path)?.as_os_str().as_bytes().to_vec()
            } else {
                Vec::new()
            };
            let xattrs = std::process::Command::new("/usr/bin/xattr")
                .args(["-s", "-l", "-x"])
                .arg(path)
                .output()?;
            ensure!(xattrs.status.success(), "Cannot inspect fixture attributes");
            states.insert(
                relative,
                State {
                    contents_or_target,
                    metadata: attributes,
                    xattrs: xattrs.stdout,
                },
            );
            if metadata.is_dir() {
                for entry in fs::read_dir(path)? {
                    visit(root, &entry?.path(), states, access)?;
                }
            }
            Ok(())
        }
        let mut states = BTreeMap::new();
        let mut access = BTreeMap::new();
        visit(root, root, &mut states, &mut access)?;
        Ok((states, access))
    }

    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("nested/empty"))?;
    fs::write(source.join("nested/read-only"), b"original source bytes")?;
    fs::set_permissions(
        source.join("nested/read-only"),
        fs::Permissions::from_mode(0o444),
    )?;
    fs::write(source.join("private"), b"private fixture")?;
    fs::set_permissions(source.join("private"), fs::Permissions::from_mode(0o600))?;
    let outside = temp.path().join("outside");
    fs::write(&outside, b"outside target must stay untouched")?;
    symlink("../outside", source.join("outside-link"))?;
    symlink("missing", source.join("dangling"))?;
    let attributes = std::process::Command::new("/usr/bin/xattr")
        .args(["-w", "com.example.archive-source-test", "unchanged"])
        .arg(source.join("private"))
        .status()?;
    ensure!(attributes.success(), "Cannot prepare fixture attributes");

    let (before, _) = snapshot(&source)?;
    // Capture access times after the initial snapshot has read the fixtures.
    let (_, access_before) = snapshot(&source)?;
    let outside_before = fs::symlink_metadata(&outside)?;
    let archive = temp.path().join("vault.zip");
    create_archive(&source, &archive, "test password", ArchiveFormat::Zip)?;
    create_archive(
        &source,
        temp.path().join("vault.7z"),
        "test password",
        ArchiveFormat::SevenZip,
    )?;
    let (after, access_after) = snapshot(&source)?;
    assert_eq!(before, after);
    let changed = access_before
        .iter()
        .filter(|(path, times)| access_after.get(*path) != Some(*times))
        .count();
    eprintln!(
        "Source content, links, permissions, ownership, file identity, extended attributes and non-access timestamps unchanged; {changed} access timestamps changed by reads."
    );
    assert!(create_archive(&source, &archive, "test password", ArchiveFormat::Zip).is_err());
    assert_eq!(before, snapshot(&source)?.0, "Failure path changed source");
    let outside_after = fs::symlink_metadata(&outside)?;
    assert_eq!(outside_before.atime(), outside_after.atime());
    assert_eq!(outside_before.atime_nsec(), outside_after.atime_nsec());
    assert_eq!(outside_before.mtime(), outside_after.mtime());
    assert_eq!(fs::read(outside)?, b"outside target must stay untouched");
    Ok(())
}
#[test]
fn zipped_encrypted_vault_round_trip() -> Result<()> {
    archived_encrypted_vault_round_trip(ArchiveFormat::Zip, false)
}
#[test]
fn seven_zip_encrypted_vault_round_trip() -> Result<()> {
    archived_encrypted_vault_round_trip(ArchiveFormat::SevenZip, false)
}
fn archived_encrypted_vault_round_trip(format: ArchiveFormat, external: bool) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("nested/empty"))?;
    let content = (0..100_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    fs::write(source.join("nested/café.bin"), &content)?;
    fs::write(source.join("zero"), [])?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("nested/café.bin", source.join("link"))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("missing", source.join("dangling"))?;
    let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    for path in [
        source.join("nested/café.bin"),
        source.join("zero"),
        source.join("nested"),
        source.join("nested/empty"),
        source.clone(),
    ] {
        fs::File::open(path)?.set_times(fs::FileTimes::new().set_modified(timestamp))?;
    }
    let archive = temp.path().join(match format {
        ArchiveFormat::Zip => "my vault.zip",
        ArchiveFormat::SevenZip => "my vault.7z",
    });
    create_archive(&source, &archive, "test password", format)?;
    let direct = temp.path().join("direct");
    extract_vault(&archive, &direct, "test password")?;
    assert_eq!(fs::read(direct.join("nested/café.bin"))?, content);
    assert_eq!(
        fs::metadata(direct.join("nested/café.bin"))?.modified()?,
        timestamp
    );
    for path in ["", "nested", "nested/empty"] {
        assert_eq!(
            fs::metadata(direct.join(path))?.modified()?,
            timestamp,
            "Direct extraction changed folder timestamp: {path}"
        );
    }
    assert!(direct.join("nested/empty").is_dir());
    assert!(extract_vault(&archive, temp.path().join("direct-wrong"), "wrong password").is_err());
    assert!(!temp.path().join("direct-wrong").exists());
    #[cfg(unix)]
    assert_eq!(
        fs::read_link(direct.join("link"))?,
        Path::new("nested/café.bin")
    );
    let unpacked = temp.path().join("unpacked");
    if external {
        let result = match format {
            ArchiveFormat::Zip => std::process::Command::new("unzip")
                .arg("-q")
                .arg(&archive)
                .arg("-d")
                .arg(&unpacked)
                .output()?,
            ArchiveFormat::SevenZip => std::process::Command::new("7zz")
                .args(["x", "-y", "-bd"])
                .arg(format!("-o{}", unpacked.display()))
                .arg(&archive)
                .output()?,
        };
        ensure!(
            result.status.success(),
            "External archive reader failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    } else {
        match format {
            ArchiveFormat::Zip => {
                zip::ZipArchive::new(fs::File::open(&archive)?)?.extract(&unpacked)?
            }
            ArchiveFormat::SevenZip => sevenz_rust2::decompress_file(&archive, &unpacked)?,
        }
    }
    let vault = unpacked.join("my vault");
    assert!(vault.join("vault.cryptomator").is_file());
    assert!(vault.join("masterkey.cryptomator").is_file());
    assert!(vault.join("d").is_dir());
    assert!(!vault.join("nested").exists());
    assert!(!vault.join("zero").exists());
    assert!(extract_vault(&vault, temp.path().join("wrong-password"), "wrong password").is_err());
    let output = temp.path().join("decrypted");
    extract_vault(&vault, &output, "test password")?;
    assert_eq!(fs::read(output.join("nested/café.bin"))?, content);
    assert!(output.join("nested/empty").is_dir());
    assert_eq!(fs::metadata(output.join("zero"))?.len(), 0);
    #[cfg(unix)]
    {
        assert_eq!(
            fs::read_link(output.join("link"))?,
            Path::new("nested/café.bin")
        );
        assert_eq!(
            fs::read_link(output.join("dangling"))?,
            Path::new("missing")
        );
    }
    // Independent extractors must restore archive entry timestamps so extraction
    // of the vault retains the source modification times.
    if external {
        for path in ["nested/café.bin", "zero", "", "nested", "nested/empty"] {
            assert_eq!(
                fs::metadata(output.join(path))?.modified()?,
                timestamp,
                "Timestamp changed for {path}"
            );
        }
    }
    let original_archive = fs::read(&archive)?;
    assert!(create_archive(&source, &archive, "test password", format).is_err());
    assert_eq!(fs::read(&archive)?, original_archive);
    Ok(())
}

#[test]
#[ignore = "independent compatibility check requires unzip and 7zz on PATH"]
fn external_readers_unpack_native_archives() -> Result<()> {
    archived_encrypted_vault_round_trip(ArchiveFormat::Zip, true)?;
    archived_encrypted_vault_round_trip(ArchiveFormat::SevenZip, true)
}
