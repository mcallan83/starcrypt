mod common;
use anyhow::{Result, ensure};
use common::*;
use oxcrypt_core::{
    fs::name::create_c9s_filename,
    vault::{operations::VaultOperations, path::DirId},
};
use starcrypt::{create_vault, extract_vault};
use std::{fs, path::Path};

#[test]
fn round_trip_and_wrong_password() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("nested/empty"))?;
    fs::write(source.join("nested/hello.txt"), "hello 🌎")?;
    fs::write(source.join("zero"), [])?;
    let large = (0..100_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    fs::write(source.join("multiple-chunks.bin"), &large)?;
    let modified = std::time::UNIX_EPOCH + std::time::Duration::new(1_600_000_000, 123_456_789);
    let accessed = std::time::UNIX_EPOCH + std::time::Duration::new(1_600_000_100, 987_654_321);
    let paths = [
        "nested/hello.txt",
        "zero",
        "multiple-chunks.bin",
        "nested/empty",
        "nested",
        "",
    ];
    for path in paths {
        fs::File::open(source.join(path))?.set_times(
            fs::FileTimes::new()
                .set_modified(modified)
                .set_accessed(accessed),
        )?;
    }
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    assert!(vault.join("masterkey.cryptomator").is_file());
    assert_eq!(
        jsonwebtoken::decode_header(&fs::read_to_string(vault.join("vault.cryptomator"))?)?
            .kid
            .as_deref(),
        Some("masterkeyfile:masterkey.cryptomator")
    );
    ensure!(VaultOperations::open(&vault, "wrong password").is_err());
    let ops = VaultOperations::open(&vault, "test password")?;
    assert_eq!(
        ops.find_file(&DirId::root(), "zero")?
            .unwrap()
            .encrypted_size,
        68
    );
    for path in ["nested/hello.txt", "zero", "multiple-chunks.bin"] {
        let (parent, name) = ops.resolve_parent_path(path)?;
        let info = ops.find_file(&parent, &name)?.unwrap();
        let metadata = fs::metadata(info.encrypted_path)?;
        assert_eq!(metadata.modified()?, modified);
        assert_eq!(metadata.accessed()?, accessed);
    }
    let output = temp.path().join("output");
    extract_vault(&vault, &output, "test password")?;
    for path in paths {
        let metadata = fs::metadata(output.join(path))?;
        assert_eq!(metadata.modified()?, modified, "mtime: {path}");
        assert_eq!(metadata.accessed()?, accessed, "atime: {path}");
    }
    assert_eq!(
        fs::read(output.join("nested/hello.txt"))?,
        fs::read(source.join("nested/hello.txt"))?
    );
    assert!(output.join("nested/empty").is_dir());
    assert_eq!(fs::metadata(output.join("zero"))?.len(), 0);
    assert_eq!(fs::read(output.join("multiple-chunks.bin"))?, large);
    assert!(extract_vault(&vault, &output, "test password").is_err());
    Ok(())
}
#[test]
fn standard_shortened_names_round_trip() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    let boundary = "b".repeat(147); // base64 name fits 220; .c9r suffix exceeds it.
    let long_directory = "d".repeat(180);
    fs::write(source.join(&boundary), b"boundary")?;
    fs::create_dir(source.join(&long_directory))?;
    fs::write(source.join(&long_directory).join("child"), b"nested")?;
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let ops = VaultOperations::open(&vault, "test password")?;
    let storage = ops.calculate_directory_storage_path(&DirId::root())?;
    for entry in fs::read_dir(storage)? {
        let path = entry?.path();
        let full_name = fs::read_to_string(path.join("name.c9s"))?;
        assert!(full_name.ends_with(".c9r"));
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            format!("{}.c9s", create_c9s_filename(&full_name))
        );
    }
    let output = temp.path().join("output");
    extract_vault(&vault, &output, "test password")?;
    assert_eq!(fs::read(output.join(boundary))?, b"boundary");
    assert_eq!(
        fs::read(output.join(long_directory).join("child"))?,
        b"nested"
    );
    Ok(())
}
#[test]
#[cfg(unix)]
fn symlinks_round_trip_without_following_targets() -> Result<()> {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("file"), b"hello")?;
    let timestamp_file = temp.path().join("timestamps");
    fs::write(&timestamp_file, [])?;
    let modified = std::time::UNIX_EPOCH + std::time::Duration::new(1_500_000_000, 123_456_789);
    let accessed = modified + std::time::Duration::from_secs(100);
    fs::File::open(&timestamp_file)?.set_times(
        fs::FileTimes::new()
            .set_modified(modified)
            .set_accessed(accessed),
    )?;
    let link_times = fs::metadata(&timestamp_file)?;
    let target_modified = fs::metadata(source.join("file"))?.modified()?;
    let long_link = "l".repeat(180);
    let links = [
        ("relative", "./file"),
        ("dangling", "missing"),
        ("directory", "."),
        ("outside", "../outside"),
        ("absolute", "/nonexistent/absolute-target"),
        (long_link.as_str(), "./file"),
    ];
    for (name, target) in links {
        symlink(target, source.join(name))?;
        copy_symlink_times(&source.join(name), &link_times)?;
    }
    assert_eq!(
        fs::metadata(source.join("file"))?.modified()?,
        target_modified
    );
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let output = temp.path().join("output");
    extract_vault(&vault, &output, "test password")?;
    for (name, target) in links {
        let metadata = fs::symlink_metadata(output.join(name))?;
        assert_eq!(metadata.modified()?, modified, "symlink mtime: {name}");
        assert_eq!(metadata.accessed()?, accessed, "symlink atime: {name}");
        assert!(
            fs::symlink_metadata(output.join(name))?
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(output.join(name))?, Path::new(target));
    }
    assert_eq!(fs::read(output.join("file"))?, b"hello");
    assert!(!temp.path().join("outside").exists());
    Ok(())
}
