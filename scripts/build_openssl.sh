#!/usr/bin/env bash
# Build the OpenSSL command-line tool at a pinned commit, with pinned flags,
# into $QTLS_OPENSSL_PREFIX. It is the independent TLS stack the interop and
# x509 oracle tests run against (tests/openssl_tools.py, the `openssl` marker).
# qTLS itself never links it. Keep OPENSSL_TAG and OPENSSL_SHA in sync with
# tests/openssl_tools.py (tests/test_environment.py checks this).
set -euo pipefail

OPENSSL_TAG="openssl-3.6.3"
OPENSSL_SHA="aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f"
# A static CLI (no-shared): nothing on the host's library path can stand in for it.
CONFIGURE_FLAGS=(no-shared no-docs no-tests --libdir=lib)

: "${QTLS_OPENSSL_PREFIX:?set QTLS_OPENSSL_PREFIX (e.g. \$PWD/.openssl)}"
mkdir -p "$QTLS_OPENSSL_PREFIX"
QTLS_OPENSSL_PREFIX="$(cd "$QTLS_OPENSSL_PREFIX" && pwd -P)"
INFO="$QTLS_OPENSSL_PREFIX/BUILD_INFO"
BIN="$QTLS_OPENSSL_PREFIX/bin/openssl"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

header() {
  echo "tag=$OPENSSL_TAG"
  echo "sha=$OPENSSL_SHA"
  echo "configure_flags=${CONFIGURE_FLAGS[*]}"
}

# Up to date only if tag, commit and flags match AND the binary has the recorded SHA-256.
if [[ -f "$INFO" ]] && [[ "$(head -n 3 "$INFO")" == "$(header)" ]] && [[ -x "$BIN" ]] \
  && [[ "$(sha256 "$BIN")" == "$(sed -n 's/^bin_sha256=//p' "$INFO")" ]]; then
  echo "OpenSSL $OPENSSL_TAG already built in $QTLS_OPENSSL_PREFIX"
  exit 0
fi
rm -f "$INFO"

src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$OPENSSL_TAG" \
  https://github.com/openssl/openssl "$src/openssl"
actual="$(git -C "$src/openssl" rev-parse HEAD)"
if [[ "$actual" != "$OPENSSL_SHA" ]]; then
  echo "OpenSSL tag $OPENSSL_TAG resolved to $actual, expected $OPENSSL_SHA" >&2
  exit 1
fi

jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
(cd "$src/openssl" && ./Configure "${CONFIGURE_FLAGS[@]}" "--prefix=$QTLS_OPENSSL_PREFIX" \
  "--openssldir=$QTLS_OPENSSL_PREFIX/ssl" >/dev/null && make -j"$jobs" >/dev/null && make install_sw >/dev/null)

"$BIN" version | grep -q "^OpenSSL ${OPENSSL_TAG#openssl-} " || { echo "built binary reports $("$BIN" version)" >&2; exit 1; }

{
  header
  echo "bin_sha256=$(sha256 "$BIN")"
  echo "host=$(uname -sm)"
} > "$INFO"
echo "built OpenSSL $OPENSSL_TAG ($OPENSSL_SHA) into $QTLS_OPENSSL_PREFIX"
