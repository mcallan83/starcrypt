# StarCrypt

<img src="docs/assets/icon.png" alt="StarCrypt icon" width="160">

StarCrypt is a fast, lightweight command-line tool for creating and extracting [Cryptomator](https://cryptomator.org/) encrypted vaults.

Cryptomator's desktop app provides a graphical way to work with vaults. On macOS, files in a vault are accessed through a mounted volume, typically via WebDAV or FUSE. That workflow can add overhead with large vaults and may not preserve original timestamps.

StarCrypt offers a complementary command-line workflow: it creates and extracts Cryptomator-compatible vaults directly, without mounting them, and while preserving file modification times. Multithreaded processing and low memory use make it well suited to large directories.

## Features

- **Cryptomator compatible** — Create standard vaults that work with the official Cryptomator application.
- **No mounting required** — Encrypt and decrypt entire directories directly from the command line.
- **Non-destructive** — Source file contents are never changed. File modification times are preserved in the vault and on extraction; reading source files may update their access times, depending on filesystem settings.
- **Fast and efficient** — Multithreaded encryption and decryption with minimal memory usage.
- **Archive support** — Create and extract encrypted vaults packaged as ZIP or 7z archives.
- **Automation-friendly** — No Java runtime, desktop application, or background services.

## Build

Requires Rust 1.95+ and Xcode Command Line Tools on macOS.

```sh
cargo build --release --locked
cargo test --locked
```

The executable is located at `target/release/starcrypt`. To install it on your PATH:

```sh
cargo install --path . --locked
```

## Usage

### Create a Vault

Standard Cryptomator vault:

```sh
starcrypt create ~/Documents/photos ~/Backups/photos-vault
```

ZIP archive:

```sh
starcrypt create ~/Documents/photos ~/Backups/photos-vault.zip
```

7z archive:

```sh
starcrypt create ~/Documents/photos ~/Backups/photos-vault.7z
```

The destination extension determines the format: `.zip` creates a ZIP archive, `.7z` creates a 7z archive (case-insensitive), and any other name creates a standard Cryptomator vault folder.

ZIP and 7z output package an encrypted Cryptomator vault into a single archive file. The archive is not separately encrypted or password-protected; encryption is provided by the vault itself. These formats change only how the vault is packaged, making it easier to store or transfer as one file rather than a folder of many files.

The archive filename stem becomes the folder name inside the archive. It must be UTF-8 and cannot contain `:` or `\`; incompatible names are rejected before encryption starts.

### Extract a Vault

Extraction detects the archive extension, so vault paths ending in `.zip` or `.7z` are automatically extracted from the archive before the vault is decrypted.

Standard Cryptomator vault:

```sh
starcrypt extract ~/Backups/photos-vault ~/Desktop/restored-photos
```

ZIP archive:

```sh
starcrypt extract ~/Backups/photos-vault.zip ~/Desktop/restored-photos
```

7z archive:

```sh
starcrypt extract ~/Backups/photos-vault.7z ~/Desktop/restored-photos
```

StarCrypt validates and unlocks the vault using its password.


### Automated Password Input

By default, StarCrypt prompts for a password when creating or extracting a vault. If stdin is piped or redirected, it reads the first line as the password instead, without prompting or confirmation. A trailing LF or CRLF is removed; other whitespace is preserved. Empty input is rejected.

```sh
# Read from a password file
starcrypt create ./photos ./vault < /secure/password.txt
starcrypt extract ./vault ./restored < /secure/password.txt

# Read directly from 1Password CLI
op read 'op://Private/StarCrypt/password' | starcrypt create ./photos ./vault
```

### Cryptomator Compatibility

Vaults created by StarCrypt can be opened in the official Cryptomator application.

For ZIP or 7z archives, manually unpack the archive first, then open the extracted `vault.cryptomator` file in Cryptomator.

See [compatibility](docs/compatibility.md) for more information.

## Temporary Storage

Archived vault operations use temporary disk space for encrypted data:

- **Creating:** Requires space for the temporary encrypted vault and final archive.
- **Extracting:** Requires space for the temporary unpacked encrypted vault and the restored output.
