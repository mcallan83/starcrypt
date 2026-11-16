"""Disposable interoperability fixtures; contains no real user data."""
import os
import random

RANDOM_SEED = 0x53544152


def fixture(root):
    root.mkdir(parents=True, exist_ok=False)
    # Cover both the 32 KiB format chunks and Starcrypt's 1 MiB worker batches.
    for size in [0, 1, 32767, 32768, 32769, 65535, 65536, 65537, 98304,
                 1048575, 1048576, 1048577, 2097171]:
        (root / f'bytes-{size}.bin').write_bytes(bytes((i * 17 + 3) % 251 for i in range(size)))
    for name in ['nested/empty', 'directory-' + 'd' * 180]:
        (root / name).mkdir(parents=True)
    (root / 'nested/café 日本語 🌎.txt').write_text('Unicode file payload 🌎\n')
    (root / ('directory-' + 'd' * 180) / 'child.txt').write_text('nested long directory\n')
    deep = root / ('directory-' + 'd' * 180) / ('nested-' + 'n' * 180)
    deep.mkdir()
    (deep / ('file-' + 'f' * 180)).write_text('deep shortened path\n')
    (root / ('n' * 147)).write_text('shortening boundary\n')
    (root / ('long-' + 'l' * 180)).write_text('long name\n')
    # Sweep both sides of the Format 8 shortening threshold using ASCII and UTF-8.
    for length in range(144, 151):
        (root / ('a' * length)).write_bytes(b'ASCII name boundary\n')
    for length in range(70, 75):
        (root / ('é' * length)).write_bytes(b'UTF-8 name boundary\n')
    (root / '.hidden').write_bytes(b'hidden\n')
    (root / ' leading and trailing spaces ').write_bytes(b'spaces\n')
    # A fixed seed makes a failed mixed-data case reproducible.
    rng = random.Random(RANDOM_SEED)
    mixed = root / 'seeded-mixed-data'
    mixed.mkdir()
    for index in range(32):
        size = rng.choice([0, 1, 32767, 32768, 32769, rng.randrange(1, 131073)])
        (mixed / f'{index:02d}-{rng.getrandbits(64):016x}-🌎').write_bytes(rng.randbytes(size))
    for name, target in [('relative-link', 'bytes-32769.bin'), ('dangling-link', 'missing'),
                         ('directory-link', 'nested'), ('parent-link', '..'),
                         ('absolute-link', '/nonexistent/starcrypt-reference'),
                         ('link-' + 's' * 180, 'nested/café 日本語 🌎.txt')]:
        os.symlink(target, root / name)


    # Milliseconds are portable across Java filesystem providers. Apply last so
    # creating children cannot perturb directory modification times.
    for path in [*root.rglob('*'), root]:
        os.utime(path, ns=(1_600_000_100_987_000_000, 1_600_000_000_123_000_000),
                 follow_symlinks=False)
