#!/usr/bin/env python3
"""Compile the Java oracle and run disposable, independent interoperability tests."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unicodedata
from fixtures import fixture

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


def run(command, root, label, env=None, expected_success=True, expected_error=None):
    result = subprocess.run(command, cwd=PROJECT, env=env, capture_output=True, text=True, timeout=600)
    output = result.stdout + result.stderr
    (root / (label + '.log')).write_text(output)
    if (result.returncode == 0) != expected_success:
        print(output, file=sys.stderr)
        raise RuntimeError(f'{label}: unexpected exit status {result.returncode}')
    if expected_success and 'Invalid cipher text file size' in output:
        raise RuntimeError(f'{label}: official implementation reported invalid ciphertext geometry')
    if expected_error and expected_error not in output:
        raise RuntimeError(f'{label}: failed for an unexpected reason')
    print(f'{label}: PASS', flush=True)
    return {'name': label, 'pass': True, 'exit_code': result.returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New results directory (must not exist)')
    parser.add_argument('--jdk-home', type=Path, default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--cryptomator-app', type=Path, default=Path('/Applications/Cryptomator.app'))
    args = parser.parse_args()
    # Preflight before creating any fixtures or output.
    javac, java = jdk_tools(args.jdk_home)
    app = args.cryptomator_app.resolve() / 'Contents/app'
    jars = sorted((app / 'mods').glob('*.jar')) + sorted(app.glob('*.jar'))
    if not any(path.name.startswith('cryptofs-') for path in jars):
        raise RuntimeError('Cryptomator libraries not found; set --cryptomator-app to an installed macOS app.')
    root = (args.output or PROJECT / 'verification-results' /
            datetime.now(timezone.utc).strftime('run-%Y%m%d-%H%M%S')).resolve()
    root.mkdir(parents=True, exist_ok=False)
    classes = root / 'classes'
    classes.mkdir()
    classpath = os.pathsep.join(map(str, [classes, *jars]))
    results = [run([javac, '--enable-preview', '--release', '26', '-cp', classpath,
                    '-d', str(classes), str(Path(__file__).with_name('StarcryptOracle.java'))], root, 'compile-oracle')]
    jar_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in jars if path.name.startswith(('cryptofs-', 'cryptolib-', 'cryptomator-'))}
    (root / 'reference-libraries.json').write_text(json.dumps(jar_hashes, indent=2) + '\n')
    fixture(root / 'source')
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
                        'official_java_reference_interoperability', '--', '--ignored', '--nocapture'],
                       root, 'rust-official-reference', env))
    for case in cases:
        name = case['name']
        results.append(run([*oracle, 'verify', str(root / ('starcrypt-' + name)), str(root / 'source'),
                            'SIV_GCM', str(root / case['password_file']),
                            str(root / ('official-reads-' + name + '.json'))], root, 'official-reads-' + name))
    wrong = root / 'wrong-password.txt'
    wrong.write_text('incorrect-disposable-test-password')
    results.append(run([*oracle, 'verify', str(root / 'starcrypt-java-gcm'), str(root / 'source'),
                        'SIV_GCM', str(wrong), str(root / 'must-not-be-created.json')], root,
                       'official-wrong-password', expected_success=False, expected_error='InvalidPassphraseException'))
    results.append(run(['cargo', 'test', '--locked', '--offline'], root, 'automated-tests', env))
    results.append(run(['cargo', 'test', '--test', 'archive', '--locked', '--offline',
                        'seven_zip_encrypted_vault_round_trip'], root, 'seven-zip-round-trip', env))
    results.append(run(['cargo', 'build', '--release', '--locked', '--offline'], root, 'release-build', env))
    (root / 'summary.json').write_text(json.dumps({'pass': True, 'checks': results,
        'limits': ['Uses official Java libraries, not the desktop UI wizard.',
                   'Disk-full errors are fault-injected; the host disk is not filled.',
                   'Removing complete trailing chunks/files is not detectable from Format 8 alone.',
                   'This is interoperability testing, not a security audit.']}, indent=2) + '\n')
    print(f'Verification complete. Reports: {root}')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f'Interoperability tests: {error}', file=sys.stderr)
        sys.exit(1)
