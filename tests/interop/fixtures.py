"""Disposable interoperability fixtures; contains no real user data."""
import os


def fixture(root):
    root.mkdir(parents=True, exist_ok=False)
    for size in [0, 1, 32767, 32768, 32769, 65535, 65536, 65537, 98304]:
        (root / f'bytes-{size}.bin').write_bytes(bytes((i * 17 + 3) % 251 for i in range(size)))
    for name in ['nested/empty', 'directory-' + 'd' * 180]:
        (root / name).mkdir(parents=True)
    (root / 'nested/café 日本語 🌎.txt').write_text('Unicode file payload 🌎\n')
    (root / ('directory-' + 'd' * 180) / 'child.txt').write_text('nested long directory\n')
    (root / ('n' * 147)).write_text('shortening boundary\n')
    (root / ('long-' + 'l' * 180)).write_text('long name\n')
    for name, target in [('relative-link', 'bytes-32769.bin'), ('dangling-link', 'missing'),
                         ('directory-link', 'nested'), ('parent-link', '..'),
                         ('absolute-link', '/nonexistent/starcrypt-reference'),
                         ('link-' + 's' * 180, 'nested/café 日本語 🌎.txt')]:
        os.symlink(target, root / name)

