#!/usr/bin/env python3
"""Compile the Java oracle and run disposable, independent interoperability tests."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from fixtures import RANDOM_SEED, fixture

PROJECT = Path(__file__).resolve().parents[2]


def jdk_tools(home):
    if home:
        javac, java = Path(home) / 'bin/javac', Path(home) / 'bin/java'
    else:
        javac, java = shutil.which('javac'), shutil.which('java')
    if not javac or not java:
        raise RuntimeError('JDK 26 is required for interoperability tests. Set JAVA_HOME or use --jdk-home.')
    try:
        version = subprocess.run([str(javac), '-version'], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError('Cannot run javac. Set JAVA_HOME to a full JDK 26 installation.') from error
    if version.returncode or not re.search(r'javac 26(?:\.|\s|$)', version.stdout + version.stderr):
        raise RuntimeError('A full JDK 26 (java and javac) is required; the desktop runtime alone is insufficient. '
                           'Set JAVA_HOME or pass --jdk-home. See tests/interop/README.md.')
    return str(javac), str(java)


def run(command, root, label, env=None, expected_success=True, expected_error=None, cwd=PROJECT):
    started = time.monotonic()
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired as error:
        def decoded(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        (root / (label + '.log')).write_text(decoded(error.stdout) + decoded(error.stderr) + '\nTIMED OUT\n')
        save_stage(root, {'name': label, 'pass': False, 'exit_code': None,
                          'seconds': round(time.monotonic() - started, 3), 'error': 'timeout'})
        raise RuntimeError(f'{label}: timed out after 600 seconds') from error
    except OSError as error:
        (root / (label + '.log')).write_text(str(error) + '\n')
        save_stage(root, {'name': label, 'pass': False, 'exit_code': None,
                          'seconds': round(time.monotonic() - started, 3), 'error': str(error)})
        raise RuntimeError(f'{label}: cannot launch command: {error}') from error
    output = result.stdout + result.stderr
    (root / (label + '.log')).write_text(output)
    failure = None
    if (result.returncode == 0) != expected_success:
        failure = f'unexpected exit status {result.returncode}'
    if expected_success and 'Invalid cipher text file size' in output:
        failure = 'official implementation reported invalid ciphertext geometry'
    if expected_error and expected_error not in output:
        failure = 'failed for an unexpected reason'
    record = {'name': label, 'pass': failure is None, 'exit_code': result.returncode,
              'seconds': round(time.monotonic() - started, 3)}
    if failure:
        record['error'] = failure
    save_stage(root, record)
    if failure:
        print(output, file=sys.stderr)
        raise RuntimeError(f'{label}: {failure}')
    print(f'{label}: PASS', flush=True)
    return record


def save_stage(root, record):
    path = root / 'summary.json'
    previous = json.loads(path.read_text()) if path.exists() else {'checks': []}
    checks = [*previous['checks'], record]
    path.write_text(json.dumps({'pass': False, 'status': 'running' if record['pass'] else 'failed',
                               'checks': checks}, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New results directory (must not exist)')
    parser.add_argument('--jdk-home', type=Path, default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--cryptomator-app', type=Path, default=Path('/Applications/Cryptomator.app'))
    args = parser.parse_args()
    # Preflight before creating any fixtures or output.
    for tool in ['7zz', 'unzip']:
        if not shutil.which(tool):
            raise RuntimeError(f'{tool} is required for independent archive interoperability checks')
    javac, java = jdk_tools(args.jdk_home)
    app = args.cryptomator_app.resolve() / 'Contents/app'
    jars = sorted((app / 'mods').glob('*.jar')) + sorted(app.glob('*.jar'))
    if not any(path.name.startswith('cryptofs-') for path in jars):
        raise RuntimeError('Cryptomator libraries not found; set --cryptomator-app to an installed macOS app.')
    root = (args.output or PROJECT / 'verification-results' /
            datetime.now(timezone.utc).strftime('run-%Y%m%d-%H%M%S')).resolve()
    root.mkdir(parents=True, exist_ok=False)
    try:
        classes = root / 'classes'
        classes.mkdir()
        classpath = os.pathsep.join(map(str, [classes, *jars]))
        results = [run([javac, '--enable-preview', '--release', '26', '-cp', classpath,
                        '-d', str(classes), str(Path(__file__).with_name('StarcryptOracle.java'))], root, 'compile-oracle')]
        jar_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in jars if path.name.startswith(('cryptofs-', 'cryptolib-', 'cryptomator-'))}
        (root / 'reference-libraries.json').write_text(json.dumps(jar_hashes, indent=2) + '\n')
        fixture(root / 'source')
        source_files = [path for path in (root / 'source').rglob('*') if path.is_file() and not path.is_symlink()]
        fingerprints = {str(path.relative_to(PROJECT)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in [*sorted((PROJECT / 'src').glob('*.rs')), PROJECT / 'Cargo.toml', PROJECT / 'Cargo.lock',
                                     *sorted(Path(__file__).parent.glob('*.py')), Path(__file__).with_name('StarcryptOracle.java'),
                                     PROJECT / 'tests/official_reference.rs']}
        (root / 'run-info.json').write_text(json.dumps({
            'started_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
            'jdk_home': str(Path(java).parent.parent), 'fixture_random_seed': RANDOM_SEED,
            'regular_files': len(source_files), 'plaintext_bytes': sum(path.stat().st_size for path in source_files),
            'source_sha256': fingerprints}, indent=2) + '\n')
        case_values = [
            ('java-gcm', 'SIV_GCM', 'reference-café-🌎'),
            ('java-ctrmac', 'SIV_CTRMAC', 'reference-café-🌎'),
            ('java-nfd', 'SIV_GCM', unicodedata.normalize('NFD', 'café-🌎-normalization')),
            ('java-long', 'SIV_GCM', 'long-public-test-password-' * 120),
        ]
        cases = []
        oracle = [java, '--enable-preview', '-Djava.awt.headless=true', '-cp', classpath, 'StarcryptOracle']
        for name, scheme, password in case_values:
            password_file = root / (name + '-password.txt')
            password_file.write_text(password)
            cases.append({'name': name, 'scheme': scheme, 'password_file': password_file.name,
                          'alternate_password': unicodedata.normalize('NFD' if name == 'java-gcm' else 'NFC', password)})
            results.append(run([*oracle, 'create', str(root / name), str(root / 'source'), scheme,
                                str(password_file), str(root / (name + '.json'))], root, name))
        (root / 'cases.json').write_text(json.dumps(cases, indent=2, ensure_ascii=False) + '\n')
        env = dict(os.environ, STARCRYPT_VERIFICATION_DIR=str(root))
        results.append(run(['cargo', 'test', '--test', 'official_reference', '--locked', '--offline',
                            'official_java_reference_', '--', '--ignored', '--nocapture', '--test-threads=1'],
                           root, 'rust-official-reference', env))
        for case in cases:
            name = case['name']
            results.append(run([*oracle, 'verify', str(root / ('starcrypt-' + name)), str(root / 'source'),
                                'SIV_GCM', str(root / case['password_file']),
                                str(root / ('official-reads-' + name + '.json'))], root, 'official-reads-' + name))
        # Package Java vaults with an independent implementation, not Starcrypt's
        # archive writer. ZIP timestamp precision is checked at its portable limit.
        for extension in ['zip', '7z']:
            results.append(run(['7zz', 'a', '-t' + extension, str(root / ('external-java.' + extension)), '.'],
                               root, 'external-package-' + extension, cwd=root / 'java-gcm'))
            unpacked = root / ('external-unpacked-' + extension)
            if extension == 'zip':
                command = ['unzip', '-q', str(root / 'starcrypt.zip'), '-d', str(unpacked)]
            else:
                command = ['7zz', 'x', '-y', str(root / 'starcrypt.7z'), '-o' + str(unpacked)]
            results.append(run(command, root, 'external-unpack-' + extension))
            password = root / 'archive-password.txt'
            password.write_text('archive-test-password')
            # Creation puts the vault under the destination's stem.
            results.append(run([*oracle, 'verify-zip' if extension == 'zip' else 'verify', str(unpacked / 'starcrypt'), str(root / 'source'),
                                'SIV_GCM', str(password), str(root / ('official-archive-' + extension + '.json'))],
                               root, 'official-archive-' + extension))
        for name, scheme in [('gcm', 'SIV_GCM'), ('ctrmac', 'SIV_CTRMAC')]:
            shutil.copytree(root / ('starcrypt-java-gcm' if name == 'gcm' else 'java-ctrmac'),
                            root / ('editable-' + name))
            shutil.copytree(root / 'source', root / ('edited-source-' + name), symlinks=True)
            results.append(run([*oracle, 'edit', str(root / ('editable-' + name)), str(root / ('edited-source-' + name)),
                                scheme, str(root / 'java-gcm-password.txt'), str(root / ('edited-' + name + '.json'))],
                               root, 'official-edit-' + name))
            # A fresh process reopens the modified vault: cached writes cannot mask faults.
            results.append(run([*oracle, 'verify', str(root / ('editable-' + name)), str(root / ('edited-source-' + name)),
                                scheme, str(root / 'java-gcm-password.txt'), str(root / ('reopened-' + name + '.json'))],
                               root, 'official-reopen-' + name))
        results.append(run(['cargo', 'test', '--test', 'official_reference', '--locked', '--offline',
                            'official_java_modified_and_archived_vaults', '--', '--ignored', '--nocapture'],
                           root, 'rust-modified-and-archived', env))
        corruptions = json.loads((root / 'rust-reference-corruption.json').read_text())
        for case in corruptions:
            label = 'official-rejects-' + case['name']
            results.append(run([*oracle, 'reject-corrupt', str(root / case['vault']), str(root / 'source'),
                                case['scheme'], str(root / case['password_file']),
                                str(root / (label + '.json'))], root, label))
        for case in json.loads((root / 'metadata-corruption.json').read_text()):
            results.append(run([*oracle, 'verify', str(root / case['vault']), str(root / 'source'),
                                case['scheme'], str(root / 'java-gcm-password.txt'), str(root / (case['vault'] + '.json'))],
                               root, 'official-rejects-' + case['vault'], expected_success=False,
                               expected_error=case['expected_exception']))
        for name, vault, scheme, reason in [
                ('scheme', 'java-gcm', 'SIV_CTRMAC', 'Cipher scheme mismatch'),
                ('key-id', 'unexpected-key-id', 'SIV_GCM', 'Unexpected key identifier')]:
            results.append(run([*oracle, 'verify', str(root / vault), str(root / 'source'), scheme,
                                str(root / 'java-gcm-password.txt'), str(root / ('must-not-pass-' + name + '.json'))],
                               root, 'oracle-rejects-' + name, expected_success=False, expected_error=reason))
        wrong = root / 'wrong-password.txt'
        wrong.write_text('incorrect-disposable-test-password')
        results.append(run([*oracle, 'verify', str(root / 'starcrypt-java-gcm'), str(root / 'source'),
                            'SIV_GCM', str(wrong), str(root / 'must-not-be-created.json')], root,
                           'official-wrong-password', expected_success=False, expected_error='InvalidPassphraseException'))
        results.append(run(['cargo', 'test', '--locked', '--offline'], root, 'automated-tests', env))
        results.append(run(['cargo', 'build', '--release', '--locked', '--offline'], root, 'release-build', env))
        (root / 'summary.json').write_text(json.dumps({'pass': True, 'status': 'complete', 'checks': results,
            'limits': ['Uses official Java libraries, not the desktop UI wizard.',
                       'Disk-full errors are fault-injected; the host disk is not filled.',
                       'Removing complete trailing chunks/files is not detectable from Format 8 alone.',
                       'This is interoperability testing, not a security audit.']}, indent=2) + '\n')
        print(f'Verification complete. Reports: {root}')
    except Exception as error:
        summary_path = root / 'summary.json'
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else {'checks': []}
        summary.update({'pass': False, 'status': 'failed', 'error': str(error)})
        summary_path.write_text(json.dumps(summary, indent=2) + '\n')
        raise


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f'Interoperability tests: {error}', file=sys.stderr)
        sys.exit(1)
