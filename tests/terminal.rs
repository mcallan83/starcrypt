#![cfg(unix)]

use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

// A failed assertion or timeout must not leave a password prompt running.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn drain(master: &mut File, transcript: &mut Vec<u8>) -> io::Result<()> {
    let mut buffer = [0; 4096];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => transcript.extend_from_slice(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(libc::EIO) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
}
fn echo_disabled(terminal: &File) -> io::Result<bool> {
    let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: attributes is writable; tcgetattr initializes it on success.
    if unsafe { libc::tcgetattr(terminal.as_raw_fd(), attributes.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call initialized attributes.
    Ok(unsafe { attributes.assume_init() }.c_lflag & libc::ECHO == 0)
}
fn run_terminal(args: &[&OsStr], responses: &[(&str, &str)]) -> Result<(ExitStatus, String)> {
    let (mut master_fd, mut slave_fd) = (-1, -1);
    let mut size = libc::winsize {
        ws_row: 24,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: output pointers and window size are initialized and live for the call.
    if unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("Cannot create test terminal");
    }
    // SAFETY: successful openpty returned two distinct owned file descriptors.
    let (mut master, slave) =
        unsafe { (File::from_raw_fd(master_fd), File::from_raw_fd(slave_fd)) };
    // SAFETY: master_fd is a live descriptor; fcntl only changes its I/O flags.
    let flags = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_starcrypt"));
    command
        .args(args)
        .env("TERM", "xterm-256color")
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?));
    // SAFETY: the child hook calls only async-signal-safe libc operations, and
    // fd 0 is the slave PTY installed by Command before this hook runs.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = ChildGuard(command.spawn()?);
    drop(command);
    let control = slave.try_clone()?;
    drop(slave);
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut transcript = Vec::new();
    let (mut response, mut searched) = (0, 0);
    loop {
        ensure!(
            Instant::now() < deadline,
            "Terminal test timed out: {}",
            String::from_utf8_lossy(&transcript)
        );
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll refers to one initialized pollfd for a live descriptor.
        let result = unsafe { libc::poll(&mut poll, 1, 100) };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error().into());
        }
        drain(&mut master, &mut transcript)?;
        while let Some((prompt, reply)) = responses.get(response) {
            let tail = String::from_utf8_lossy(&transcript[searched..]);
            let Some(index) = tail.find(prompt) else {
                break;
            };
            // The prompt can precede disabling echo. Synchronize with terminal
            // mode instead of racing the prompt with synthetic input.
            if !echo_disabled(&control)? {
                break;
            }
            searched += index + prompt.len();
            master.write_all(reply.as_bytes())?;
            master.write_all(b"\n")?;
            response += 1;
        }
        if let Some(status) = child.0.try_wait()? {
            drain(&mut master, &mut transcript)?;
            ensure!(
                response == responses.len(),
                "CLI exited before all prompts: {}",
                String::from_utf8_lossy(&transcript)
            );
            return Ok((status, String::from_utf8_lossy(&transcript).into_owned()));
        }
        if poll.revents & libc::POLLNVAL != 0 {
            bail!("Test terminal closed unexpectedly");
        }
    }
}

#[test]
fn interactive_passwords_create_and_extract_without_echoing() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("hello"), b"terminal round trip")?;
    let vault = temp.path().join("vault");
    let secret = "terminal-only-test-password";
    let (status, transcript) = run_terminal(
        &["create".as_ref(), source.as_os_str(), vault.as_os_str()],
        &[("Vault password:", secret), ("Confirm password:", secret)],
    )?;
    ensure!(status.success(), "{transcript}");
    ensure!(!transcript.contains(secret), "Password was echoed");
    ensure!(transcript.contains("Created vault:"));
    let output = temp.path().join("output");
    let (status, transcript) = run_terminal(
        &["extract".as_ref(), vault.as_os_str(), output.as_os_str()],
        &[("Vault password:", secret)],
    )?;
    ensure!(status.success(), "{transcript}");
    ensure!(!transcript.contains(secret), "Password was echoed");
    ensure!(!transcript.contains("Confirm password:"));
    ensure!(fs::read(output.join("hello"))? == b"terminal round trip");
    Ok(())
}

#[test]
fn interactive_empty_and_mismatched_passwords_leave_no_vault() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    type PasswordCase = (
        &'static str,
        &'static [(&'static str, &'static str)],
        &'static str,
    );
    let cases: &[PasswordCase] = &[
        (
            "empty",
            &[("Vault password:", "")],
            "Password cannot be empty",
        ),
        (
            "mismatch",
            &[
                ("Vault password:", "first"),
                ("Confirm password:", "second"),
            ],
            "Passwords do not match",
        ),
    ];
    for (name, responses, expected) in cases {
        let vault = temp.path().join(name);
        let (status, transcript) = run_terminal(
            &["create".as_ref(), source.as_os_str(), vault.as_os_str()],
            responses,
        )?;
        ensure!(status.code() == Some(1), "{transcript}");
        ensure!(transcript.contains(expected), "{transcript}");
        ensure!(!vault.exists());
    }
    Ok(())
}
