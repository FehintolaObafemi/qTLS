#!/usr/bin/env bash
# Build liboqs at a pinned commit, with pinned flags, into $OQS_INSTALL_PATH.
#
# liboqs-python ships no native library. If it can't find one at import time it
# clones and builds whatever it likes, or calls SystemExit. qTLS never lets that
# happen: this script is the only supported way to provide liboqs, and
# qtls.crypto verifies BUILD_INFO (tag, commit, flags, library SHA-256) before
# it imports `oqs`. Keep LIBOQS_TAG, LIBOQS_SHA and CMAKE_FLAGS in sync with
# qtls/crypto.py (tests/test_environment.py checks this).
set -euo pipefail

LIBOQS_TAG="0.16.0"
LIBOQS_SHA="5a1a854b0dc9f2141bdc771c555ee60c37950183"
# OQS_USE_OPENSSL=OFF: don't link the host's libcrypto, which is neither pinned
# nor recorded. OQS_DIST_BUILD=ON: portable build with runtime CPU dispatch.
CMAKE_FLAGS=(
  -DCMAKE_BUILD_TYPE=Release
  -DBUILD_SHARED_LIBS=ON
  -DCMAKE_INSTALL_LIBDIR=lib
  -DOQS_BUILD_ONLY_LIB=ON
  -DOQS_DIST_BUILD=ON
  -DOQS_USE_OPENSSL=OFF
)

: "${OQS_INSTALL_PATH:?set OQS_INSTALL_PATH (e.g. \$PWD/.oqs)}"
mkdir -p "$OQS_INSTALL_PATH"
OQS_INSTALL_PATH="$(cd "$OQS_INSTALL_PATH" && pwd -P)"
INFO="$OQS_INSTALL_PATH/BUILD_INFO"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

header() {
  echo "tag=$LIBOQS_TAG"
  echo "sha=$LIBOQS_SHA"
  echo "cmake_flags=${CMAKE_FLAGS[*]}"
}

# Up to date only if tag, commit and flags match AND the recorded library is
# present with the recorded SHA-256.
if [[ -f "$INFO" ]] && [[ "$(head -n 3 "$INFO")" == "$(header)" ]]; then
  lib="$(sed -n 's/^lib=//p' "$INFO")"
  want="$(sed -n 's/^lib_sha256=//p' "$INFO")"
  if [[ -n "$lib" && -f "$OQS_INSTALL_PATH/$lib" && "$(sha256 "$OQS_INSTALL_PATH/$lib")" == "$want" ]]; then
    echo "liboqs $LIBOQS_TAG already built in $OQS_INSTALL_PATH"
    exit 0
  fi
fi
rm -f "$INFO"

src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$LIBOQS_TAG" \
  https://github.com/open-quantum-safe/liboqs "$src/liboqs"
actual="$(git -C "$src/liboqs" rev-parse HEAD)"
if [[ "$actual" != "$LIBOQS_SHA" ]]; then
  echo "liboqs tag $LIBOQS_TAG resolved to $actual, expected $LIBOQS_SHA" >&2
  exit 1
fi

cmake -S "$src/liboqs" -B "$src/build" "${CMAKE_FLAGS[@]}" \
  "-DCMAKE_INSTALL_PREFIX=$OQS_INSTALL_PATH" >/dev/null
cmake --build "$src/build" --parallel 4 >/dev/null
cmake --install "$src/build" >/dev/null

# The real file behind lib/liboqs.{so,dylib}, relative to the install path.
for link in "$OQS_INSTALL_PATH/lib/liboqs.so" "$OQS_INSTALL_PATH/lib/liboqs.dylib"; do
  if [[ -e "$link" ]]; then
    # CMake installs relative symlinks within lib/ (liboqs.so -> liboqs.so.9 -> ...).
    target="$link"
    while [[ -L "$target" ]]; do target="$(dirname "$target")/$(readlink "$target")"; done
    lib="lib/$(basename "$target")"
    break
  fi
done
: "${lib:?liboqs shared library not found after install}"

{
  header
  echo "lib=$lib"
  echo "lib_sha256=$(sha256 "$OQS_INSTALL_PATH/$lib")"
  echo "host=$(uname -sm)"
} > "$INFO"
echo "built liboqs $LIBOQS_TAG ($LIBOQS_SHA) into $OQS_INSTALL_PATH"
