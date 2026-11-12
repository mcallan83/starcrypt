# Compatibility and limitations

Starcrypt creates Format 8 `SIV_GCM` vaults and reads `SIV_GCM` and legacy
`SIV_CTRMAC` vaults. ZIP and 7z archives use native Rust libraries.

## Test coverage

The default Rust suite covers round trips, wrong passwords, chunk boundaries,
shortened names, encrypted symlinks, corruption rejection, destination collisions,
source preservation, archive extraction, and cleanup after failures or termination.
Optional checks use official Cryptomator Java libraries and independent archive
readers. See [release checks](releasing.md#checks) for commands and
[interoperability setup](../tests/interop/README.md) for prerequisites.

Manual testing with Cryptomator 1.19.6 over WebDAV verified file contents
in both directions. Desktop UI and mount behavior require separate manual checks;
the Java suite does not exercise them.

## Limitations

- Format 8 cannot detect deletion of complete files or whole trailing chunks
  without a separate trusted inventory or backup hashes.
- Extraction does not restore permissions, ownership, creation dates, extended
  attributes, hard links, or sparse allocation. Some mount backends omit symlinks.
- Abrupt termination can leave temporary encrypted staging directories.
- Disk-full behavior is tested with injected failures, rather than filling a disk.
- Interoperability tests are not a cryptographic audit or proof of full Format 8
  conformance. Hub vaults, recovery tools, every KDF configuration, cloud sync,
  and all mount backends are outside this coverage.
- Starcrypt targets macOS; Windows and Linux behavior has not been validated.
