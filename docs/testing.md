# Testing

StarCrypt follows the [Rust Book's test organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html):
unit tests beside the implementation, integration tests under `tests/`, and
shared integration helpers under `tests/common/mod.rs`.

## Unit tests

Keep focused tests of private functions, worker scheduling, and injected failures
inside a `#[cfg(test)] mod tests` at the end of the relevant source module.
Keep test-only helpers inside that module too. These tests and helpers are not
compiled into normal builds.

Examples include filename validation, chunk scheduling, source mutation checks,
KDF parameter validation, progress formatting, and disk-full injection. Tests
that simulate a volume-root policy stay beside creation code because they need
private hooks; they do not require mounting a real volume.

Use deterministic fixtures when testing validation rules. Do not derive password
keys merely to construct metadata for a validation-only test. Tests exercising
actual encryption continue to use the real cryptographic implementation.

Run unit tests with:

```sh
cargo test --locked --lib --bin starcrypt
```

## Integration tests

Use the public `starcrypt` API or the compiled CLI for complete workflows:

| Target | Coverage |
| --- | --- |
| `archive` | Archive creation, round trips, source preservation |
| `archive_input` | Archive input validation, malformed paths, compressed input |
| `cli` | Password input, exit behavior, format inference and overrides |
| `corruption` | Tampering rejection, symlink boundaries, incomplete-output cleanup |
| `failures` | Library errors, resource limits, collisions, permission failures |
| `round_trip` | Contents, names, timestamps, symlinks, progress |

Cargo discovers these targets automatically. Test helpers such as tree comparison
belong in `tests/common/mod.rs`, rather than as a top-level helper `.rs` file that
Cargo would treat as another integration target. Private helpers used by only one
target can remain in that file.

CLI tests use `env!("CARGO_BIN_EXE_starcrypt")` to locate Cargo's compiled binary.
They send test passwords through stdin and inspect the exit status and output.
Do not make internal implementation details public just to test them externally.

Run one integration target with:

```sh
cargo test --locked --test cli
cargo test --locked --test archive_input
```

## Isolation and optional checks

Use a fresh `tempfile::TempDir` for each test or independent fixture. Avoid global
working-directory or environment changes, and give subprocesses their own
environment when needed. Platform-specific filesystem tests use `#[cfg(unix)]`
or `#[cfg(target_os = "macos")]`. Run permission tests as an ordinary user.
Using `?` or `unwrap` for test setup is normal; assertions should make the expected
behavior and failures clear.

The ignored `create::tests::processing_throughput` function is a manual diagnostic
of private processing paths, excluding the password KDF. It is not a correctness
test or a statistical benchmark. Run it explicitly in release mode:

```sh
cargo test --release --locked processing_throughput -- --ignored --nocapture
```

The ignored archive child-process function is a subprocess fixture invoked by its
parent interruption test, not a standalone test to run manually.

Interoperability tests and their organization are unchanged. See
[release checks](releasing.md#checks) for the Java/Cryptomator and external archive
reader checks.

## Routine checks

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

The default suite does not run ignored interoperability tests, the subprocess
fixture on its own, or the manual throughput diagnostic.
