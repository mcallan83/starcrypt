#!/usr/bin/env python3
"""Disposable fixtures and read-only comparisons for desktop interoperability."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import unicodedata


def fixture(root):
    root.mkdir(parents=True, exist_ok=False)
    (root / "nested/empty").mkdir(parents=True)
    long_directory = "directory-" + "d" * 180
    (root / long_directory).mkdir()
    files = {
        "hello.txt": b"Cryptomator interoperability test\n",
        "nested/日本語 café 🌎.txt": "Unicode contents: café 日本語 🌎\n".encode(),
        "empty.bin": b"",
        "multi-chunk.bin": bytes(range(256)) * 1025,
        ".hidden": b"hidden\n",
        "executable.sh": b"#!/bin/sh\nprintf 'fixture only\\n'\n",
        "private-key-placeholder": b"TEST DATA ONLY - NOT A REAL PRIVATE KEY\n",
        "long-" + "a" * 180 + ".txt": b"shortened encrypted filename\n",
        "attributed.txt": b"file with a test extended attribute\n",
        long_directory + "/inside.txt": b"file inside a shortened directory\n",
        "t" * 147: b"name at shortening boundary\n",
    }
    for name, content in files.items():
        (root / name).write_bytes(content)
    os.chmod(root / "executable.sh", 0o755)
    os.chmod(root / "private-key-placeholder", 0o600)
    os.chmod(root / "nested", 0o750)
    subprocess.run(["/usr/bin/xattr", "-w", "com.example.starcrypt-test", "test-xattr", str(root / "attributed.txt")], check=True)
    links = {
        "relative-link": "./hello.txt", "dangling-link": "does-not-exist",
        "directory-link": "nested", "parent-link": "..",
        "absolute-link": "/nonexistent/starcrypt-compatibility-test",
        "long-link-" + "b" * 180: "./hello.txt",
    }
    for name, target in links.items():
        os.symlink(target, root / name)
    os.link(root / "hello.txt", root / "hard-link.txt")
    with (root / "sparse.bin").open("wb") as stream:
        stream.seek(1024 * 1024)
        stream.write(b"end")
    # Apply times after all contents, including directory contents, are created.
    paths = list(root.rglob("*")) + [root]
    for path in paths:
        os.utime(path, ns=(1_600_000_100_987654321, 1_600_000_000_123456789), follow_symlinks=False)


def snapshot(root):
    entries = {}
    def visit(path, relative):
        metadata = path.lstat()  # Capture before reading, and never traverse symlinks.
        kind = "symlink" if stat.S_ISLNK(metadata.st_mode) else "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
        record = {
            "type": kind, "mode": oct(stat.S_IMODE(metadata.st_mode)),
            "mtime_ns": metadata.st_mtime_ns, "atime_ns": metadata.st_atime_ns,
            "uid": metadata.st_uid, "gid": metadata.st_gid,
            "birthtime": getattr(metadata, "st_birthtime", None),
            "hardlink_count": metadata.st_nlink if kind == "file" else None,
            "allocated_bytes": metadata.st_blocks * 512 if kind == "file" else None,
        }
        try:
            names = subprocess.check_output(["/usr/bin/xattr", "-s", str(path)], stderr=subprocess.PIPE).decode().splitlines()
            record["xattrs"] = {name: hashlib.sha256(subprocess.check_output(
                ["/usr/bin/xattr", "-s", "-p", name, str(path)], stderr=subprocess.PIPE)).hexdigest() for name in names}
        except (OSError, subprocess.CalledProcessError) as error:
            record["xattrs_error"] = str(error)
        if kind == "symlink":
            record["target"] = os.readlink(path)
        elif kind == "file":
            record["size"] = metadata.st_size
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            record["sha256"] = digest.hexdigest()
        key = unicodedata.normalize("NFC", relative)
        if key in entries:
            raise ValueError(f"Normalized filename collision: {relative}")
        entries[key] = record
        if kind == "directory":
            for child in sorted(path.iterdir()):
                visit(child, str(child.relative_to(root)))
    visit(root, ".")
    return entries


def compare(expected, actual):
    content, metadata = [], []
    for path in sorted(expected.keys() | actual.keys()):
        if path not in expected or path not in actual:
            content.append({"path": path, "issue": "unexpected" if path not in expected else "missing"})
            continue
        for key in expected[path].keys() | actual[path].keys():
            left, right = expected[path].get(key), actual[path].get(key)
            if left != right:
                issue = {"path": path, "field": key, "expected": left, "actual": right}
                (content if key in {"type", "size", "sha256", "target"} else metadata).append(issue)
    return {"content_pass": not content, "content_differences": content, "metadata_differences": metadata,
            "note": "Access times can change during inspection; allocation and ownership depend on the filesystem. Names are compared in NFC."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fixture").add_argument("path", type=Path)
    snap = commands.add_parser("snapshot")
    snap.add_argument("path", type=Path)
    snap.add_argument("output", type=Path)
    diff = commands.add_parser("compare")
    diff.add_argument("expected", type=Path)
    diff.add_argument("actual", type=Path)
    diff.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "fixture":
        fixture(args.path)
        print(f"Created fixture: {args.path}")
    elif args.command == "snapshot":
        args.output.write_text(json.dumps(snapshot(args.path), indent=2, ensure_ascii=False) + "\n")
        print(f"Saved snapshot: {args.output}")
    else:
        result = compare(json.loads(args.expected.read_text()), json.loads(args.actual.read_text()))
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(f"Content: {'PASS' if result['content_pass'] else 'FAIL'}; metadata differences: {len(result['metadata_differences'])}")
        raise SystemExit(0 if result["content_pass"] else 1)


if __name__ == "__main__":
    main()
