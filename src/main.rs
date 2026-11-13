use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use starcrypt::{
    ArchiveFormat, Progress, create_archive_with_progress, create_vault_with_progress,
    extract_vault_with_progress,
};
use std::{
    io::{BufRead, IsTerminal, Write},
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
mod status;

#[derive(Parser)]
#[command(
    version,
    about = "Create and extract Cryptomator vaults. No mounting required."
)]
struct Cli {
    /// Suppress progress status on stderr.
    #[arg(long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a folder's contents into a new vault, leaving the source intact.
    Create {
        source: PathBuf,
        vault: PathBuf,
        /// Package the encrypted vault folder in a ZIP archive.
        #[arg(long, conflicts_with = "seven_zip")]
        zip: bool,
        /// Package the encrypted vault folder in a 7z archive.
        #[arg(long = "7z", conflicts_with = "zip")]
        seven_zip: bool,
    },
    /// Decrypt a vault folder or a ZIP/7z containing a vault into a new folder.
    Extract {
        vault: PathBuf,
        destination: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Create {
            source,
            vault,
            zip,
            seven_zip,
        } => {
            let source = source
                .canonicalize()
                .context("Cannot resolve source folder")?;
            ensure!(source.is_dir(), "Source must be a folder");
            let destination = vault;
            let format = if seven_zip {
                Some(ArchiveFormat::SevenZip)
            } else if zip {
                Some(ArchiveFormat::Zip)
            } else {
                None
            };
            if let Some(format) = format {
                format.validate_destination(&destination)?;
            }
            let password = password(true)?;
            with_status(cli.quiet, |progress| {
                if let Some(format) = format {
                    create_archive_with_progress(&source, &destination, &password, format, progress)
                } else {
                    create_vault_with_progress(&source, &destination, &password, progress)
                }
            })?;
            println!("Created vault: {}", destination.display());
        }
        Command::Extract { vault, destination } => {
            let vault = vault.canonicalize().context("Cannot resolve vault")?;
            let password = password(false)?;
            with_status(cli.quiet, |progress| {
                extract_vault_with_progress(&vault, &destination, &password, progress)
            })?;
            println!("Extracted to: {}", destination.display());
        }
    }
    Ok(())
}

fn password(confirm: bool) -> Result<Zeroizing<String>> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return password_from_reader(stdin.lock());
    }
    let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
    ensure!(!password.is_empty(), "Password cannot be empty");
    if confirm {
        let repeat = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        ensure!(*password == *repeat, "Passwords do not match");
    }
    Ok(password)
}

fn password_from_reader(mut reader: impl BufRead) -> Result<Zeroizing<String>> {
    let mut password = Zeroizing::new(String::new());
    reader
        .read_line(&mut password)
        .context("Cannot read password from stdin")?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    ensure!(!password.is_empty(), "Password from stdin cannot be empty");
    Ok(password)
}

// Keep terminal refreshes out of encryption/decryption workers. Redirected stderr
// receives occasional complete lines, with no terminal escape sequences.
fn with_status(quiet: bool, work: impl FnOnce(&Progress) -> Result<()>) -> Result<()> {
    let progress = Progress::with_buffered_messages();
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        let sender = sender;
        let progress = &progress;
        let reporter = scope.spawn(move || {
            let terminal = std::io::stderr().is_terminal();
            let started = Instant::now();
            let mut display = (!quiet && terminal).then(status::Display::new);
            let mut last_phase = "";
            let mut last_output = Instant::now();
            loop {
                let finished = match receiver.recv_timeout(Duration::from_millis(200)) {
                    Ok(success) => Some(success),
                    Err(mpsc::RecvTimeoutError::Timeout) => None,
                    Err(mpsc::RecvTimeoutError::Disconnected) => Some(false),
                };
                let snapshot = progress.snapshot();
                let messages = progress.drain_messages();
                if (!quiet && terminal)
                    || !messages.is_empty()
                    || finished.is_some()
                    || snapshot.phase != last_phase
                    || last_output.elapsed() >= Duration::from_secs(5)
                {
                    let line = status::line(&snapshot, finished, started.elapsed());
                    if let Some(display) = &mut display {
                        display.render(&snapshot, line, messages, finished);
                    } else {
                        let mut stderr = std::io::stderr().lock();
                        if !quiet {
                            let _ = writeln!(stderr, "{line}");
                        }
                        for message in messages {
                            let _ = writeln!(stderr, "{message}");
                        }
                        let _ = stderr.flush();
                    }
                    last_phase = snapshot.phase;
                    last_output = Instant::now();
                }
                if finished.is_some() {
                    break;
                }
            }
        });
        let result = work(progress);
        let _ = sender.send(result.is_ok());
        let _ = reporter.join();
        result
    })
}
