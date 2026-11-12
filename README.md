# starcrypt

<img src="docs/assets/icon.png" alt="Starcrypt icon" width="160">

Create a password-protected Cryptomator vault from a local folder, or extract a
vault into a local folder. No mounting, FUSE, Java, or background service.

## Build

Install Rust 1.95 or newer and Xcode Command Line Tools on macOS, then run:

```sh
cargo build --release --locked
cargo test --locked
```

The executable is `target/release/starcrypt`. To install it on your PATH:

```sh
cargo install --path . --locked
```

## Use

```sh
starcrypt create ~/Documents/photos ~/Backups/photos-vault
starcrypt extract ~/Backups/photos-vault ~/Desktop/restored-photos
starcrypt create ~/Documents/photos ~/Backups/photos-vault.zip --zip
starcrypt create ~/Documents/photos ~/Backups/photos-vault.7z --7z
starcrypt extract ~/Backups/photos-vault.zip ~/Desktop/restored-photos
starcrypt extract ~/Backups/photos-vault.7z ~/Desktop/restored-photos
```

`create --zip` or `create --7z` encrypts the source into a normal Cryptomator
vault, then packages that **encrypted vault folder** into a ZIP or 7z archive.
The archive contains `photos-vault/` with
`vault.cryptomator`, `masterkey.cryptomator`, and the encrypted `d/` tree. Only
ciphertext is staged temporarily; the source stays intact. The temporary vault
is removed on success or ordinary errors. Allow space for the encrypted vault
and archive; interruption can leave temporary ciphertext.

`extract` accepts a vault folder or a `.zip`/`.7z` containing exactly one vault,
at the archive root or inside a folder. Archives are unpacked into private temporary
ciphertext storage and validated/unlocked with the vault password before plaintext
extraction. Archives without a valid supported vault, ambiguous multiple vaults,
corrupt archives, unsafe paths, and native archive symlinks are rejected. Temporary
ciphertext is removed on success or ordinary errors. Allow space for the unpacked
vault and plaintext output; abrupt interruption can leave temporary ciphertext.
The archive itself must not have a separate archive password. To open it in the
Cryptomator desktop app, unpack it first and open `vault.cryptomator`.

ZIP and 7z archives are written directly by Rust libraries; no external archiver
is required. Ciphertext is stored without recompression. ZIP timestamps have
whole-second precision. The output filename must end with `.zip` for `--zip`
or `.7z` for `--7z` (lowercase). The archive destination must not already exist. Choose
only one format flag. Without either flag, creation outputs a normal vault folder.
Both archive round-trip tests run with `cargo test --locked`.

Both commands prompt for a hidden password. Creation asks for confirmation.
Passwords are never command-line arguments. Creation copies the source folder's
**contents** into the vault root and leaves the originals in place.
Creation opens source files for reading only; it does not write, rename, delete,
chmod, or set timestamps on source entries. The filesystem can still update access
times as a consequence of reading. The source-preservation regression test checks
contents, link targets, identity, permissions, ownership, extended attributes, and
non-access timestamps for both successful archive creation and an existing-output
failure. Source files must remain unchanged by other processes during creation.

The destination must not exist, its parent must exist, and it must be outside the
source folder. Existing destinations are never merged or overwritten. Ordinary
errors remove incomplete output; interruption or power loss can leave partial
output, which you must remove before retrying. Do not change the source or vault
while a command is running.

On macOS, selecting a mounted volume root (including a mounted DMG) automatically
excludes known root-level macOS housekeeping entries, reporting each exclusion.
This includes Trash and the Versions database, so deleted items and older document
versions are not retained. Ordinary folders and other hidden files remain included;
other unreadable entries still fail the operation. See [macOS volume archiving](docs/macos-volumes.md)
for the exact list, research sources, and compatibility limits. Native resource
forks and extended attributes are not preserved; retain the DMG if full filesystem
fidelity is needed.

## Scope and status

- Uses [oxcrypt-core](https://github.com/agucova/oxcrypt) directly for Cryptomator
  format 8 encryption and decryption. No mount backends are dependencies.
- Includes nested and empty folders, hidden files, Unicode names, and empty files.
- Preserves symlinks as links, including relative, absolute, directory, and dangling
  links. Targets are stored verbatim without following them or copying their contents.
  Extraction recreates links on macOS/Unix and preserves their modification/access
  timestamps without following the links or updating their targets. As with regular
  files, creation dates and metadata-change times are not preserved.
- Rejects special files (such as sockets and FIFOs), non-UTF-8 names/targets, and
  unsafe entry names.
- Preserves file bytes, folder structure, and modification/access timestamps for
  regular files and directories during creation and extraction, including subsecond precision
  where supported by the filesystem. Timestamps are stored as filesystem metadata
  on the encrypted files and directory storage folders. Tools that copy, sync, or
  access the vault can change these timestamps (especially access times); extraction
  restores the vault's current metadata. macOS creation dates and metadata-change
  times are not preserved.
- Does not preserve permissions, extended attributes, Finder tags, resource forks,
  or hard links.
- Creation currently reads one entire file into memory. Extraction streams files.
- Direct dependencies use exact versions, and oxcrypt-core is pinned to a full
  Git commit. Keep `Cargo.lock` with the project: it locks all transitive versions
  and registry checksums. Use `--locked` when building, testing, or installing so
  Cargo refuses to change the dependency resolution.
- Release compilation, formatting validation, and included tests pass. Tests cover
  round-trip extraction (including multiple chunks and empty files), wrong passwords,
  timestamps, shortened names, existing destinations, and unsafe names.
- Desktop 1.19.6/WebDAV content interoperability was tested in both directions.
  Independent official Java tests also cover GCM/CTRMAC vaults, symlinks, Unicode
  passwords, chunk boundaries, corruption, and failure handling. See
  [docs/verification.md](docs/verification.md) for compatibility and limitations.
  Exact metadata parity and full cryptographic conformance are not claimed.
- Extraction fails on malformed encrypted entries rather than silently skipping
  them. It supports password-protected master-key files inside the vault; Hub
  vaults, external master-key paths, and native symlinks in the encrypted layout
  are not supported. Removing whole trailing chunks or complete files cannot be
  detected from Format 8 alone; preserve independent backup hashes if needed.

Before relying on this for backups, run the tests and verify both directions:
open a generated vault in Cryptomator, then extract a format 8 vault created by
Cryptomator and compare the restored files. Keep your originals until verified.

## Development and releases

Application code is split into `src/create.rs`, `src/extract.rs`, `src/archive.rs`,
`src/vault_read.rs`, and `src/fsutil.rs`. `src/lib.rs` exposes the validated public
API; `src/main.rs` handles CLI arguments and password prompts. Module unit tests
exercise private failure paths, while `tests/*.rs` exercises the public API.
Independent Java and manual desktop comparison tools live under `tests/interop/`.

See [release instructions](docs/releasing.md) for checks, binary archives, and
checksums; [interoperability setup](tests/interop/README.md) for the optional JDK
suite. Starcrypt is [MIT licensed](LICENSE).
