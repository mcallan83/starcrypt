use anyhow::{Result, ensure};
use starcrypt::create_vault;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

fn run(args: &[&std::ffi::OsStr], password: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starcrypt"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(password).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn piped_create_and_file_extract() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let vault = temp.path().join("vault");
    let restored = temp.path().join("restored");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("hello.txt"), b"hello").unwrap();
    // Preserve spaces, strip CRLF, and ignore subsequent lines.
    let output = run(
        &["create".as_ref(), source.as_os_str(), vault.as_os_str()],
        b" secret \r\nignored\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let password_file = temp.path().join("password.txt");
    fs::write(&password_file, b" secret ").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_starcrypt"))
        .arg("extract")
        .arg(&vault)
        .arg(&restored)
        .stdin(fs::File::open(password_file).unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(restored.join("hello.txt")).unwrap(), b"hello");
}

#[test]
fn empty_stdin_fails_without_creating_vault() {
    let temp = tempfile::tempdir().unwrap();
    for password in [b"".as_slice(), b"\n", b"\r\n"] {
        let vault = temp.path().join("vault");
        let output = run(
            &[
                "create".as_ref(),
                temp.path().as_os_str(),
                vault.as_os_str(),
            ],
            password,
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Password from stdin cannot be empty")
        );
        assert!(!vault.exists());
    }
}

#[test]
fn create_infers_format_and_honors_override() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("hello.txt"), b"hello").unwrap();
    for (index, (name, format, expected)) in [
        ("vault", None, "folder"),
        ("vault.zip", None, "zip"),
        ("vault.7z", None, "7z"),
        ("vault.ZIP", None, "zip"),
        ("vault.7Z", None, "7z"),
        ("folder.zip", Some("folder"), "folder"),
        ("archive.7z", Some("zip"), "zip"),
        ("archive.zip", Some("7z"), "7z"),
        ("archive", Some("zip"), "zip"),
    ]
    .into_iter()
    .enumerate()
    {
        let case = temp.path().join(format!("case-{index}"));
        fs::create_dir(&case).unwrap();
        let destination = case.join(name);
        let mut args = vec![
            "create".as_ref(),
            source.as_os_str(),
            destination.as_os_str(),
        ];
        if let Some(format) = format {
            args.push("--format".as_ref());
            args.push(format.as_ref());
        }
        let output = run(&args, b"secret\n");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if expected == "folder" {
            assert!(destination.join("vault.cryptomator").is_file());
        } else {
            let bytes = fs::read(&destination).unwrap();
            let magic: &[u8] = if expected == "zip" {
                b"PK\x03\x04"
            } else {
                b"7z\xbc\xaf\x27\x1c"
            };
            assert!(bytes.starts_with(magic));
        }
        // Give overrides a matching extension for extraction.
        let input = if format.is_some() && expected != "folder" {
            let renamed = temp.path().join(format!("renamed-{index}.{expected}"));
            fs::rename(&destination, &renamed).unwrap();
            renamed
        } else {
            destination
        };
        let restored = temp.path().join(format!("restored-{index}"));
        let output = run(
            &["extract".as_ref(), input.as_os_str(), restored.as_os_str()],
            b"secret\n",
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(restored.join("hello.txt")).unwrap(), b"hello");
    }
}

#[test]
fn malformed_master_key_metadata_exits_normally_without_output() -> Result<()> {
    use serde_json::json;
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
        let result = run(
            &["extract".as_ref(), vault.as_os_str(), output.as_os_str()],
            b"test password\n",
        );
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
