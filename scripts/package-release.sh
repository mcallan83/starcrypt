#!/usr/bin/env bash
# Build and package a local macOS release. Does not publish or sign anything.
set -euo pipefail

project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
release_target="${1:-$(rustc -vV | awk '/^host: / { print $2 }')}"
case "$release_target" in
  aarch64-apple-darwin|x86_64-apple-darwin) ;;
  *) printf 'Unsupported release target: %s\n' "$release_target" >&2; exit 1 ;;
esac
release_version="$(cargo metadata --format-version 1 --no-deps --locked | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
release_name="starcrypt-${release_version}-${release_target}"
release_output="$project_root/dist/$release_name.tar.gz"
if [[ -e "$release_output" || -e "$release_output.sha256" ]]; then
  printf 'Release output already exists: %s\n' "$release_output" >&2
  exit 1
fi
if [[ $# -gt 0 ]]; then
  cargo build --release --locked --target "$release_target"
  release_binary="target/$release_target/release/starcrypt"
else
  cargo build --release --locked
  release_binary="target/release/starcrypt"
fi
mkdir -p dist
release_stage="$(mktemp -d "$project_root/dist/.starcrypt-package.XXXXXX")"
trap 'rm -rf "$release_stage"' EXIT
mkdir -p "$release_stage/$release_name/docs" "$release_stage/$release_name/tests/interop"
cp "$release_binary" "$release_stage/$release_name/starcrypt"
chmod 755 "$release_stage/$release_name/starcrypt"
cp README.md LICENSE "$release_stage/$release_name/"
cp docs/verification.md "$release_stage/$release_name/docs/"
cp docs/releasing.md "$release_stage/$release_name/docs/"
cp tests/interop/README.md "$release_stage/$release_name/tests/interop/"
COPYFILE_DISABLE=1 tar -czf "$release_output" -C "$release_stage" "$release_name"
(cd dist && shasum -a 256 "$release_name.tar.gz" > "$release_name.tar.gz.sha256")
printf 'Created %s\nCreated %s.sha256\n' "$release_output" "$release_output"
