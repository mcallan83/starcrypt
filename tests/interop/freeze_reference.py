#!/usr/bin/env python3
"""Generate small, frozen official-release fixtures; never run during normal tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jdk-home', type=Path, required=True)
    parser.add_argument('--cryptofs', type=Path, required=True)
    parser.add_argument('--cryptolib', type=Path, required=True)
    parser.add_argument('--support-jars', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / 'source'
        (source / 'nested/empty').mkdir(parents=True)
        for name, content in [('empty', b''), ('boundary', bytes(i % 251 for i in range(32769))),
                              ('nested/café 🌎', b'official historical fixture\n'),
                              ('long-' + 'x' * 180, b'shortened filename\n')]:
            (source / name).write_bytes(content)
        os.symlink('nested/café 🌎', source / 'relative-link')
        for path in [*source.rglob('*'), source]:
            os.utime(path, ns=(1600000000123000000, 1600000000123000000), follow_symlinks=False)
        classes = root / 'classes'
        classes.mkdir()
        jars = [args.cryptofs.resolve(), args.cryptolib.resolve(), *[
            path.resolve() for path in sorted(args.support_jars.glob('*.jar'))
            if not path.name.startswith(('cryptofs-', 'cryptolib-', 'cryptomator-'))]]
        classpath = os.pathsep.join(map(str, [classes, *jars]))
        subprocess.run([str(args.jdk_home / 'bin/javac'), '--enable-preview', '--release', '26', '-cp', classpath,
                        '-d', str(classes), str(Path(__file__).with_name('StarcryptOracle.java'))], check=True)
        password = root / 'password'
        password.write_text('historical-public-test-password')
        cases = []
        for name, scheme in [('gcm', 'SIV_GCM'), ('ctrmac', 'SIV_CTRMAC')]:
            vault = root / name
            oracle = [str(args.jdk_home / 'bin/java'), '--enable-preview', '-cp', classpath, 'StarcryptOracle']
            report = args.output / (name + '-oracle.json')
            subprocess.run([*oracle, 'create', str(vault), str(source), scheme, str(password), str(report)], check=True)
            subprocess.run([*oracle, 'verify', str(vault), str(source), scheme, str(password), str(report)], check=True)
            archive = args.output / (name + '.zip')
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as writer:
                for path in sorted(vault.rglob('*')):
                    writer.write(path, path.relative_to(vault).as_posix())
            cases.append({'archive': archive.name, 'scheme': scheme, 'password': password.read_text(),
                          'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()})
        manifest = {'format': 8, 'producer': [args.cryptofs.name, args.cryptolib.name], 'cases': cases,
                    'generator_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                         for path in [Path(__file__), Path(__file__).with_name('StarcryptOracle.java')]},
                    'libraries_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in jars}}
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
