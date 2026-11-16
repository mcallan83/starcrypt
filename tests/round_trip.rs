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
fn legacy_ctrmac_configuration_and_empty_files_are_supported() -> Result<()> {
    use oxcrypt_core::vault::config::CipherCombo;
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("child"))?;
    fs::write(source.join("empty"), [])?;
    fs::write(source.join("child/data"), vec![42; 1024 * 1024 + 19])?;
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let ops = VaultOperations::open(&vault, "test password")?;
    for name in ["empty", "child/data"] {
        let (parent, filename) = ops.resolve_parent_path(name)?;
        let path = ops.find_file(&parent, &filename)?.unwrap().encrypted_path;
        fs::write(
            path,
            CipherCombo::SivCtrMac.encrypt_file(&fs::read(source.join(name))?, ops.master_key())?,
        )?;
    }
    let token = fs::read_to_string(vault.join("vault.cryptomator"))?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.required_spec_claims.clear();
    let mut claims: serde_json::Value = ops.master_key().validate_jwt(&token, &validation)?;
    claims["cipherCombo"] = "SIV_CTRMAC".into();
    fs::write(
        vault.join("vault.cryptomator"),
        jsonwebtoken::encode(
            &jsonwebtoken::decode_header(&token)?,
            &claims,
            &ops.master_key().create_jwt_encoding_key()?,
        )?,
    )?;
    let output = temp.path().join("output");
    extract_vault(&vault, &output, "test password")?;
    compare_tree(&source, &output)?;
    let path = ops
        .find_file(&DirId::root(), "empty")?
        .unwrap()
        .encrypted_path;
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(path, bytes)?;
    let output = temp.path().join("invalid");
    ensure!(extract_vault(&vault, &output, "test password").is_err());
    ensure!(!output.exists());
    Ok(())
}

#[test]
fn legacy_shortened_names_and_unrelated_sidecars_are_supported() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    let name = "l".repeat(180);
    fs::write(source.join(&name), b"legacy short name")?;
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let ops = VaultOperations::open(&vault, "test password")?;
    let storage = ops.calculate_directory_storage_path(&DirId::root())?;
    let path = fs::read_dir(&storage)?.next().unwrap()?.path();
    let original = fs::read_to_string(path.join("name.c9s"))?;
    let legacy = original.strip_suffix(".c9r").unwrap();
    let destination = storage.join(format!("{}.c9s", create_c9s_filename(legacy)));
    fs::rename(&path, &destination)?;
    fs::write(destination.join("name.c9s"), legacy)?;
    fs::write(storage.join(".DS_Store"), b"unrelated Finder metadata")?;
    fs::write(
        storage.join("dirid.c9r"),
        b"optional recovery data is not a user file",
    )?;
    let output = temp.path().join("output");
    extract_vault(&vault, &output, "test password")?;
    compare_tree(&source, &output)?;
    Ok(())
}

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
    let key: serde_json::Value =
        serde_json::from_slice(&fs::read(vault.join("masterkey.cryptomator"))?)?;
    assert_eq!(key["scryptCostParam"], 32768);
    assert_eq!(key["scryptBlockSize"], 8);
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
    fs::create_dir(source.join(&long_directory).join(&long_directory))?;
    fs::write(
        source
            .join(&long_directory)
            .join(&long_directory)
            .join(&boundary),
        b"deep shortened file",
    )?;
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
    assert_eq!(fs::read(output.join(&boundary))?, b"boundary");
    assert_eq!(
        fs::read(output.join(&long_directory).join("child"))?,
        b"nested"
    );
    assert_eq!(
        fs::read(
            output
                .join(&long_directory)
                .join(&long_directory)
                .join(&boundary)
        )?,
        b"deep shortened file"
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

#[test]
fn parallel_creation_streams_chunk_boundaries() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("nested"))?;
    let sizes = [0, 1, 32_767, 32_768, 32_769, 65_536, 65_537, 2_000_003];
    for (index, size) in sizes.into_iter().cycle().take(48).enumerate() {
        let bytes = (0..size)
            .map(|n| ((n + index) % 251) as u8)
            .collect::<Vec<_>>();
        let name = if index % 2 == 0 {
            format!("nested/file-{index}")
        } else {
            format!("file-{index}")
        };
        fs::write(source.join(name), bytes)?;
    }
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let output = temp.path().join("output");
    extract_vault(&vault, &output, "test password")?;
    for index in 0..48 {
        let name = if index % 2 == 0 {
            format!("nested/file-{index}")
        } else {
            format!("file-{index}")
        };
        assert_eq!(
            fs::read(source.join(&name))?,
            fs::read(output.join(&name))?,
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn progress_counts_completed_plaintext_and_regular_files() -> Result<()> {
    use starcrypt::{Progress, create_vault_with_progress, extract_vault_with_progress};
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("empty-directory"))?;
    fs::write(source.join("empty"), [])?;
    fs::write(source.join("large"), vec![7; 2 * 1024 * 1024 + 19])?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(".", source.join("directory-link"))?;
    let vault = temp.path().join("vault");
    let encrypting = Progress::default();
    create_vault_with_progress(&source, &vault, "test password", &encrypting)?;
    assert_eq!(encrypting.snapshot().bytes, 2 * 1024 * 1024 + 19);
    assert_eq!(encrypting.snapshot().files, 2);
    assert_eq!(
        encrypting.snapshot().total_bytes,
        Some(2 * 1024 * 1024 + 19)
    );
    assert_eq!(encrypting.snapshot().total_files, Some(2));
    let decrypting = Progress::default();
    extract_vault_with_progress(
        &vault,
        temp.path().join("output"),
        "test password",
        &decrypting,
    )?;
    assert_eq!(decrypting.snapshot().bytes, encrypting.snapshot().bytes);
    assert_eq!(decrypting.snapshot().files, 2);
    assert_eq!(
        decrypting.snapshot().total_bytes,
        encrypting.snapshot().total_bytes
    );
    assert_eq!(decrypting.snapshot().total_files, Some(2));
    Ok(())
}
