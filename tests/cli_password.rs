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
