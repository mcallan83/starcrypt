# Preparing a release

Starcrypt targets macOS. Build prerequisites are Rust **1.95 or newer** and Xcode
Command Line Tools. The executable does not require Rust, Python, or Java at runtime.
ZIP and 7z are written by Rust libraries; neither requires an external executable.

## Checks

Run from the project root as an ordinary user:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

The default test command includes ZIP and 7z archive tests. It needs neither Java
nor Cryptomator. Formatting, Clippy, and release compilation are separate checks;
`cargo test` does not run them.

See [testing](testing.md) for the unit/integration test layout and commands for
running individual targets.

For independent archive-reader compatibility, install `unzip` and `7zz`, then run:

```sh
cargo test --locked --test archive external_readers_unpack_native_archives -- --ignored
```

For independent Cryptomator compatibility, install a full JDK 26 and Cryptomator
and follow [the interoperability setup](../tests/interop/README.md):

```sh
python3 tests/interop/run.py
```

That launcher generates fixtures, checks interoperability in both directions,
runs the default Rust suite, and builds the release executable. It does not run
the independent archive-reader test, formatting, or Clippy. Missing tools must
not count as passing checks. Desktop UI/WebDAV checks are manual and are not
covered by either command. See [compatibility and limitations](compatibility.md).

Build the release executable separately when running only the Rust suite:

```sh
cargo build --release --locked
```

## Version

Update `Cargo.toml` for the intended version, then update the
root package entry in `Cargo.lock` by running `cargo check`. Keep all dependency
pins unchanged unless dependency upgrades are intentional.

## Binary archive

Create a host-architecture release package:

```sh
scripts/package-release.sh
```

For another installed macOS Rust target:

```sh
scripts/package-release.sh x86_64-apple-darwin
```

This creates `dist/starcrypt-VERSION-TARGET.tar.gz` and a `.sha256` checksum, refusing
existing output. The archive contains the executable, README, MIT license,
compatibility documentation, and the test setup guide. It excludes source
fixtures, disposable test-password files, compiler output, caches, and Python/Java
test tools. Packaging does
not publish a release. Artifacts are unsigned; signing/notarization is not configured.

Inspect and verify the generated package:

```sh
cd dist
shasum -a 256 -c starcrypt-VERSION-TARGET.tar.gz.sha256
```

The checksum file records the archive basename, so run that check from `dist/` or
pass the checksum's contents to your preferred verification tool from that folder.

## Source archive

Inspect the source package allowlist:

```sh
cargo package --list --locked
```

Generated directories (`target/`, `dist/`, and verification results) are ignored and
excluded from the source package. The pinned oxcrypt dependency comes from Git, so
the current manifest is intended for Git/source distribution rather than publishing
to crates.io. `cargo publish` would require a registry dependency strategy and valid
release metadata; this workflow does not publish to crates.io.
