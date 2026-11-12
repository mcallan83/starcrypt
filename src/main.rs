use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use starcrypt::{ArchiveFormat, create_archive, create_vault, extract_vault};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Create and extract Cryptomator vaults. No mounting required."
)]
struct Cli {
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
    match Cli::parse().command {
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
            if let Some(format) = format {
                create_archive(&source, &destination, &password, format)?;
            } else {
                create_vault(&source, &destination, &password)?;
            }
            println!("Created vault: {}", destination.display());
        }
        Command::Extract { vault, destination } => {
            let vault = vault.canonicalize().context("Cannot resolve vault")?;
            let password = password(false)?;
            extract_vault(&vault, &destination, &password)?;
            println!("Extracted to: {}", destination.display());
        }
    }
    Ok(())
}

fn password(confirm: bool) -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
    ensure!(!password.is_empty(), "Password cannot be empty");
    if confirm {
        let repeat = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        ensure!(*password == *repeat, "Passwords do not match");
    }
    Ok(password)
}
