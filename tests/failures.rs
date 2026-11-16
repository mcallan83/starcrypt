use anyhow::{Result, ensure};
use starcrypt::{ArchiveFormat, create_archive, create_vault};
use std::fs;

#[test]
fn malformed_master_key_metadata_exits_normally_without_output() -> Result<()> {
    use serde_json::json;
    use std::io::Write;
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("payload"), b"original")?;
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let key_path = vault.join("masterkey.cryptomator");
    let original = fs::read(&key_path)?;
    let baseline: serde_json::Value = serde_json::from_slice(&original)?;
    for (index, (field, value, message)) in [
        ("scryptCostParam", json!(0), "Invalid scryptCostParam"),
        ("scryptCostParam", json!(-1), "Invalid scryptCostParam"),
        ("scryptCostParam", json!(1), "Invalid scryptCostParam"),
        ("scryptCostParam", json!(3), "Invalid scryptCostParam"),
        (
            "scryptCostParam",
            json!(1 << 30),
            "Scrypt resource limit exceeded",
        ),
        (
            "scryptCostParam",
            json!(4294967296u64),
            "Invalid master-key metadata",
        ),
        ("scryptCostParam", json!(1.5), "Invalid master-key metadata"),
        (
            "scryptCostParam",
            json!("32768"),
            "Invalid master-key metadata",
        ),
        (
            "scryptCostParam",
            json!(null),
            "Invalid master-key metadata",
        ),
        ("scryptBlockSize", json!(0), "Invalid scryptBlockSize"),
        ("scryptBlockSize", json!(-1), "Invalid scryptBlockSize"),
        (
            "scryptBlockSize",
            json!(1 << 28),
            "Scrypt resource limit exceeded",
        ),
        (
            "scryptBlockSize",
            json!(i32::MAX),
            "Invalid scrypt parameters",
        ),
        (
            "primaryMasterKey",
            json!(""),
            "Invalid wrapped master-key length",
        ),
        ("versionMac", json!(""), "Invalid version MAC length"),
        ("scryptSalt", json!(""), "Missing scrypt salt"),
        (
            "scryptSalt",
            json!("not base64!"),
            "Invalid master-key metadata",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut key = baseline.clone();
        key[field] = value;
        fs::write(&key_path, serde_json::to_vec(&key)?)?;
        let output = temp.path().join(format!("output-{index}"));
        let mut child = Command::new(env!("CARGO_BIN_EXE_starcrypt"))
            .arg("extract")
            .arg(&vault)
            .arg(&output)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(b"test password\n")?;
        let result = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&result.stderr);
        ensure!(result.status.code() == Some(1), "Unexpected exit: {stderr}");
        ensure!(stderr.contains(message), "Expected {message}: {stderr}");
        ensure!(!stderr.contains("panicked"), "{stderr}");
        ensure!(!output.exists());
    }
    fs::write(&key_path, &original)?;
    let restored = temp.path().join("valid-output");
    starcrypt::extract_vault(&vault, &restored, "test password")?;
    ensure!(fs::read(restored.join("payload"))? == b"original");
    Ok(())
}

#[test]
fn oversized_vault_metadata_is_rejected_before_unlocking() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    for name in ["masterkey.cryptomator", "vault.cryptomator"] {
        let path = vault.join(name);
        let original = fs::read(&path)?;
        fs::write(&path, vec![b' '; 64 * 1024 + 1])?;
        let output = temp.path().join(format!("output-{name}"));
        let error = starcrypt::extract_vault(&vault, &output, "test password").unwrap_err();
        ensure!(format!("{error:#}").contains("Vault metadata exceeds the 64 KiB limit"));
        ensure!(!output.exists());
        fs::write(path, original)?;
    }
    Ok(())
}

#[test]
fn unsafe_internal_archive_names_are_rejected_without_output() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("payload"), b"original")?;
    for (extension, format) in [("zip", ArchiveFormat::Zip), ("7z", ArchiveFormat::SevenZip)] {
        let destination = temp.path().join(format!("backup:2026.{extension}"));
        let error = create_archive(&source, &destination, "test password", format).unwrap_err();
        ensure!(format!("{error:#}").contains("Unsafe archive entry path"));
        ensure!(error.to_string().contains("Archive filename stem"));
        ensure!(!destination.exists());
    }
    ensure!(fs::read(source.join("payload"))? == b"original");
    ensure!(fs::read_dir(temp.path())?.count() == 1);
    Ok(())
}

#[test]
#[cfg(unix)]
fn unreadable_source_fails_without_output_or_source_changes() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    let path = source.join("unreadable");
    fs::write(&path, b"do not change")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o0))?;
    // This test must run as the ordinary user, not root, to exercise EACCES.
    ensure!(
        fs::File::open(&path).is_err(),
        "Run unreadable-file test without root privileges"
    );
    let vault = temp.path().join("vault");
    let error = create_vault(&source, &vault, "test password").unwrap_err();
    ensure!(error.to_string().contains(&path.display().to_string()));
    ensure!(format!("{error:#}").contains("Permission denied"));
    ensure!(!vault.exists());
    let archive = temp.path().join("archive.zip");
    ensure!(create_archive(&source, &archive, "test password", ArchiveFormat::Zip).is_err());
    ensure!(!archive.exists());
    ensure!(fs::metadata(&path)?.permissions().mode() & 0o777 == 0);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    ensure!(fs::read(&path)? == b"do not change");
    Ok(())
}
#[test]
#[cfg(unix)]
fn destination_collisions_preserve_existing_paths() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("payload"), b"original")?;
    let existing = temp.path().join("existing");
    fs::create_dir(&existing)?;
    fs::write(existing.join("sentinel"), b"keep me")?;
    ensure!(create_vault(&source, &existing, "test password").is_err());
    ensure!(fs::read(existing.join("sentinel"))? == b"keep me");
    let target = temp.path().join("target");
    fs::write(&target, b"never overwrite")?;
    let link = temp.path().join("existing.zip");
    std::os::unix::fs::symlink(&target, &link)?;
    ensure!(create_archive(&source, &link, "test password", ArchiveFormat::Zip).is_err());
    ensure!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    ensure!(fs::read(&target)? == b"never overwrite");
    ensure!(fs::read(source.join("payload"))? == b"original");
    Ok(())
}

#[test]
#[cfg(unix)]
fn unreadable_volume_directory_reports_path_and_removes_output() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    let restricted = source.join(".Trashes");
    fs::create_dir(&restricted)?;
    fs::set_permissions(&restricted, fs::Permissions::from_mode(0o300))?;
    let vault = temp.path().join("vault");
    let result = create_vault(&source, &vault, "test password");
    // Restore permissions before assertions so the fixture can always be removed.
    fs::set_permissions(&restricted, fs::Permissions::from_mode(0o700))?;
    let error = result.unwrap_err();
    ensure!(
        error
            .to_string()
            .contains(&restricted.display().to_string())
    );
    ensure!(format!("{error:#}").contains("Permission denied"));
    ensure!(!vault.exists());
    Ok(())
}
