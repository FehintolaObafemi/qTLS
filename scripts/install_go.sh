#!/usr/bin/env bash
# Install the pinned Go toolchain into $QTLS_GO_ROOT (default ./.go) from the go.dev
# tarball, checked against a SHA-256 table. It builds the MTC WG's Go demo, the
# independent oracle of the `go`-marked tests (scripts/mtc_demo.py --build-only,
# specs.md D34). qTLS itself never uses Go. Keep GO_VERSION and the table in sync
# with scripts/mtc_demo.py (tests/test_scripts.py checks this).
#
# QTLS_GO_TARBALL=<file> installs from a local copy instead of downloading; the
# hash check is the same.
set -euo pipefail

GO_VERSION="go1.27.4"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
platform="${QTLS_GO_PLATFORM:-$os-$arch}"
# From https://go.dev/dl/?mode=json&include=all, each checked against a download.
case "$platform" in
  darwin-arm64) GO_SHA256="91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4" ;;
  linux-amd64) GO_SHA256="7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840" ;;
  *) echo "no pinned $GO_VERSION tarball for $platform" >&2; exit 1 ;;
esac

DEST="${QTLS_GO_ROOT:-$PWD/.go}"
INFO="$DEST/INSTALL_INFO"
export GOTOOLCHAIN=local  # never let `go` fetch a different toolchain

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if [[ -f "$INFO" ]] && [[ "$(cat "$INFO")" == "$GO_VERSION $platform $GO_SHA256" ]] && [[ -x "$DEST/bin/go" ]] \
  && "$DEST/bin/go" version | grep -q "^go version $GO_VERSION "; then
  echo "Go $GO_VERSION already installed in $DEST"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if [[ -n "${QTLS_GO_TARBALL:-}" ]]; then
  cp "$QTLS_GO_TARBALL" "$tmp/go.tgz"
else
  curl -fsSL --retry 3 -o "$tmp/go.tgz" "https://go.dev/dl/$GO_VERSION.$platform.tar.gz"
fi
actual="$(sha256 "$tmp/go.tgz")"
if [[ "$actual" != "$GO_SHA256" ]]; then
  echo "$GO_VERSION.$platform.tar.gz has sha256 $actual, expected $GO_SHA256" >&2
  exit 1
fi

mkdir -p "$tmp/go"
tar -xzf "$tmp/go.tgz" -C "$tmp/go" --strip-components=1
"$tmp/go/bin/go" version | grep -q "^go version $GO_VERSION " || { echo "the tarball isn't $GO_VERSION" >&2; exit 1; }
rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
mv "$tmp/go" "$DEST"
echo "$GO_VERSION $platform $GO_SHA256" > "$INFO"
echo "installed Go $GO_VERSION ($platform) into $DEST"
