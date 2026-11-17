# Working on StarCrypt

StarCrypt is a Rust CLI and library for creating and extracting Cryptomator
vaults without mounting them. It targets macOS and preserves file contents and
modification times. It creates Format 8 `SIV_GCM` vaults and reads `SIV_GCM` and
legacy `SIV_CTRMAC` vaults, including vaults packaged as ZIP or 7z.

## Project map

- `src/lib.rs`: public API and operation orchestration.
- `src/main.rs`, `src/status.rs`: CLI, password input, and terminal presentation.
- `src/create.rs`, `src/extract.rs`: directory traversal and vault entry handling.
- `src/encrypt.rs`, `src/decrypt.rs`: bounded parallel streaming workers.
- `src/vault_read.rs`: vault validation and unlocking.
- `src/archive.rs`, `src/archive_read.rs`: archive creation and untrusted input extraction.
- `src/fsutil.rs`: path validation, exclusive output creation, cleanup, and timestamps.
- `src/progress.rs`: shared progress state; keep terminal rendering in the CLI.
- `tests/`: public API and CLI integration tests; shared helpers in `tests/common/`.
- `tests/interop/reference/`: frozen official-library fixtures and provenance.
- `docs/testing.md`, `docs/compatibility.md`, `docs/macos-volumes.md`,
  `docs/releasing.md`: testing conventions, supported behavior, and release workflow.

Read the relevant implementation and documentation before changing behavior.
Keep changes focused and follow existing Rust patterns. Keep internal helpers
private; do not expand the public API solely to make tests easier.

## Safety and compatibility invariants

- Never overwrite an existing destination or modify source contents. Reserve
  outputs exclusively and preserve cleanup of incomplete output on failures.
- Treat vault metadata, filenames, archive paths, and encrypted storage as
  untrusted. Preserve path traversal checks, native symlink rejection in encrypted
  storage paths, metadata size limits, and password-derivation resource limits.
- Preserve authenticated reads and corruption rejection. Do not bypass checks to
  accept malformed fixtures or make compatibility tests pass.
- Reuse established cryptographic primitives and the pinned `oxcrypt-core`
  dependency. Changes to the vault format, key derivation, nonces, chunk layout,
  authentication, or dependency revision need explicit rationale and targeted
  regression coverage. Preserve the Cryptomator-specific adaptations in this repo.
- Keep passwords out of logs, command-line arguments, and committed files.
  Preserve zeroizing password storage. CLI stdin reads one line, removes only a
  trailing LF/CRLF, preserves other whitespace, and rejects empty passwords.
- Keep processing streaming with bounded queues and memory. Avoid collecting
  entire file contents or plaintext batches for the whole operation in memory.
- Preserve encrypted user symlinks without following their targets. Unsupported
  entries and read errors must fail visibly rather than silently omit user data.
- macOS volume housekeeping exclusions apply only to exact names at actual mount
  roots, with each exclusion reported. See `docs/macos-volumes.md`; do not broaden
  this into general hidden-file filtering or permission-error suppression.
- Do not claim preservation of permissions, ownership, extended attributes, or
  other unsupported metadata. Keep compatibility claims aligned with
  `docs/compatibility.md`, including Format 8 integrity limitations.

## Build and validation

Use Rust 1.95 or newer (edition 2024), plus Xcode Command Line Tools on macOS.
Keep dependency pins and `Cargo.lock` intact unless dependency changes are part
of the task. Use locked Cargo commands from the repository root.

```sh
cargo check --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

Run focused checks while iterating, then formatting, Clippy, and the regular test
suite for Rust changes. Run a release build for release or build-related changes.
For documentation or editor configuration changes, validate the changed files
and referenced commands; a full Rust build is usually unnecessary. Report what
actually ran, any failures, and checks blocked by missing tools or dependencies.

```sh
# Unit tests
cargo test --locked --lib --bin starcrypt
# One integration target (use an existing file under tests/)
cargo test --locked --test cli
# Optional independent archive-reader check; needs unzip and 7zz
cargo test --locked --test archive external_readers_unpack_native_archives -- --ignored
# Optional manual throughput diagnostic
cargo test --release --locked processing_throughput -- --ignored --nocapture
```

Do not run all ignored tests indiscriminately: some are subprocess fixtures,
optional compatibility checks, or manual diagnostics. The default suite needs
neither Java nor the Cryptomator desktop app.

Some docs reference optional interoperability launchers such as
`tests/interop/run.py`. Verify that the referenced scripts exist in the checkout
before using them; missing tooling is not a passing compatibility check. Follow
`tests/interop/README.md` for prerequisites when the tooling is available.

## Testing changes

Add regression tests for changed behavior, especially data loss, malformed input,
authentication, cleanup, and filesystem boundaries. Put private implementation
tests beside the code and end-to-end tests under `tests/`. Use fresh
`tempfile::TempDir` instances and disposable public passwords. Avoid global
working-directory/environment mutations and real user vaults. Keep real password
work factors in encryption tests; use deterministic metadata fixtures when no
actual key derivation is needed. Run permission tests as an ordinary user.

Preserve the frozen archives in `tests/interop/reference/` and their provenance.
Do not regenerate them merely to fix a failure. Intentional regeneration belongs
in a new directory with the producer versions and hashes recorded.

## Releases and generated files

`scripts/package-release.sh` builds a local host-architecture macOS package and
checksum under `dist/`; it refuses existing output. It also accepts an installed
macOS Rust target. Packaging does not publish or sign a release. Follow
`docs/releasing.md` for release preparation; do not publish as part of routine
development.

Do not commit `target/`, `dist/`, verification output, caches, generated Java
classes, real passwords, or private vault data. Preserve unrelated user changes.
Update the relevant docs when CLI behavior, supported formats, limitations, or
development commands change.
