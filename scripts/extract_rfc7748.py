"""Extract the X25519 test vectors from RFC 7748 into JSON.

Usage:
    python scripts/extract_rfc7748.py <rfc7748.txt> tests/vectors/rfc7748/x25519.json

Takes §5.2 (two scalar-multiplication vectors, and the 1- and 1,000-iteration
results; the 1,000,000-iteration one is skipped as too slow) and §6.1 (the
Diffie-Hellman example). X448 is not used by qTLS and is not extracted.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HEX64 = re.compile(r"^\s+([0-9a-f]{64})\s*$")


def value_after(lines: list[str], start: int, label: str) -> tuple[str, int]:
    """Return the 64-hex-digit value on the line after the next `label` line."""
    for i in range(start, len(lines)):
        if lines[i].strip() == label:
            m = HEX64.match(lines[i + 1])
            if not m:
                raise ValueError(f"no 32-byte value after {label!r} at line {i + 1}")
            return m.group(1), i + 2
    raise ValueError(f"{label!r} not found after line {start}")


def main(src: Path, dst: Path) -> None:
    raw = src.read_bytes()
    lines = raw.decode().splitlines()
    # §5.2: the X25519 block runs from "X25519:" to "X448:".
    start = next(i for i, l in enumerate(lines) if l.startswith("5.2.  Test Vectors"))
    x25519 = next(i for i in range(start, len(lines)) if lines[i].strip() == "X25519:")
    vectors = []
    pos = x25519
    for _ in range(2):
        scalar, pos = value_after(lines, pos, "Input scalar:")
        u, pos = value_after(lines, pos, "Input u-coordinate:")
        out, pos = value_after(lines, pos, "Output u-coordinate:")
        vectors.append({"scalar": scalar, "u": u, "output": out})
    it = next(i for i in range(pos, len(lines)) if lines[i].strip() == "X25519:")
    one, p = value_after(lines, it, "After one iteration:")
    thousand, _ = value_after(lines, p, "After 1,000 iterations:")
    dh = next(i for i, l in enumerate(lines) if l.startswith("6.1.  Curve25519"))
    a, p = value_after(lines, dh, "Alice's private key, a:")
    a_pub, p = value_after(lines, p, "Alice's public key, X25519(a, 9):")
    b, p = value_after(lines, p, "Bob's private key, b:")
    b_pub, p = value_after(lines, p, "Bob's public key, X25519(b, 9):")
    k, _ = value_after(lines, p, "Their shared secret, K:")
    doc = {
        "source": "RFC 7748 §5.2 and §6.1, https://www.rfc-editor.org/rfc/rfc7748.txt",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "scalar_mult": vectors,
        "iterations": {"1": one, "1000": thousand},
        "dh": {"alice_private": a, "alice_public": a_pub, "bob_private": b, "bob_public": b_pub, "shared": k},
    }
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"{dst}: {len(vectors)} scalar-mult vectors, 2 iteration vectors, 1 DH vector")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
