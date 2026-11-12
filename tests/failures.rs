use anyhow::{Result, ensure};
use starcrypt::{ArchiveFormat, create_archive, create_vault};
use std::fs;

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
fn archive_extension_must_match_format_before_processing_source() -> Result<()> {
    let temp = tempfile::tempdir()?;
    // A nonexistent source proves extension validation happens before source access.
    let source = temp.path().join("missing-source");
    let cli_source = temp.path().join("source");
    fs::create_dir(&cli_source)?;
    for (flag, filename, extension) in [("--zip", "vault.7z", "zip"), ("--7z", "vault.zip", "7z")] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_starcrypt"))
            .arg("create")
            .arg(&cli_source)
            .arg(temp.path().join(filename))
            .arg(flag)
            .stdin(std::process::Stdio::null())
            .output()?;
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains(&format!("Archive filename must end with .{extension}"))
        );
        assert!(!String::from_utf8_lossy(&result.stderr).contains("Vault password:"));
    }

    for (format, extension, names) in [
        (
            ArchiveFormat::Zip,
            "zip",
            ["vault", "vault.7z", "vault.zip.txt", "vault.ZIP"],
        ),
        (
            ArchiveFormat::SevenZip,
            "7z",
            ["vault", "vault.zip", "vault.7z.txt", "vault.7Z"],
        ),
    ] {
        for name in names {
            let destination = temp.path().join(name);
            let error = create_archive(&source, &destination, "test password", format).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("Archive filename must end with .{extension}")
            );
            assert!(!destination.exists());
        }
        format.validate_destination(&temp.path().join(format!("vault.{extension}")))?;
    }
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
