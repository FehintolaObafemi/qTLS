#!/usr/bin/env python3
"""Record OpenSSL talking to OpenSSL, as a second independent oracle (docs/PLAN.md Phase 2e).

For each case, an ``openssl s_client`` and ``openssl s_server`` (the pinned
build, scripts/build_openssl.sh) run a TLS 1.3 handshake through a recording
relay, exchange one line each way, and close. The suite, group and signature
scheme are pinned to what qTLS supports. The chain is qTLS's own fixture chain
(qtls/configs.py), and everything the tests need is vendored with it, so the
capture stays valid when the fixtures change:

    tests/vectors/openssl/<case>/client.bin    bytes the client sent, in order
    tests/vectors/openssl/<case>/server.bin    bytes the server sent, in order
    tests/vectors/openssl/<case>/keylog.txt    OpenSSL's SSLKEYLOGFILE output (client side)
    tests/vectors/openssl/<case>/root.der      the trust anchor
    tests/vectors/openssl/<case>/key.pem       the server's leaf key (test fixture only)
    tests/vectors/openssl/<case>/meta.json     OpenSSL version, arguments, time, SHA-256 of each file

Usage: QTLS_OPENSSL=.openssl/bin/openssl scripts/capture_openssl.py
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import openssl_tools as ot  # noqa: E402

from qtls import configs  # noqa: E402

UTC = dt.timezone.utc
NOT_BEFORE = dt.datetime(2026, 1, 1, tzinfo=UTC)
NOW = NOT_BEFORE + dt.timedelta(days=30)
OUT = ROOT / "tests" / "vectors" / "openssl"
# The unfragmented cases turn middlebox compatibility off, as qTLS does (specs.md D16),
# so their sizes compare like with like. The fragmented ones keep OpenSSL's
# default (a session id and ChangeCipherSpec records) to exercise that framing too.
NO_MIDDLEBOX = ("-no_middlebox",)
CASES = {
    "A": (configs.CONFIG_A, "ecdsa_secp256r1_sha256", NO_MIDDLEBOX),
    "A-frag1024": (configs.CONFIG_A, "ecdsa_secp256r1_sha256", ("-max_send_frag", "1024")),
    "B65": (configs.config_b("ML-DSA-65"), "mldsa65", NO_MIDDLEBOX),
    "B65-frag1024": (configs.config_b("ML-DSA-65"), "mldsa65", ("-max_send_frag", "1024")),
}
CLIENT_LINE = b"hello from openssl s_client\n"
SERVER_LINE = b"hello from openssl s_server\n"


def capture(binary: str, name: str) -> None:
    cfg, sigalg, extra = CASES[name]
    _, server_cfg, chain = configs.endpoints(cfg, not_before=NOT_BEFORE, now=NOW)
    out = OUT / name
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        pki = ot.write_pki(Path(tmp), chain, server_cfg.signing_key)
        server_args = ("-groups", ot.GROUP, "-num_tickets", "2", *extra)
        server, port = ot.s_server(binary, pki, Path(tmp) / "server.keylog", *server_args)
        with server:
            relay = ot.Relay(("127.0.0.1", port))
            client_args = ("-groups", ot.GROUP, "-sigalgs", sigalg, *extra)
            client = ot.s_client(binary, relay.port, pki, NOW, out / "keylog.txt", *client_args)
            with client:
                server.wait_for(rb"CIPHER is")
                client.write(CLIENT_LINE)
                server.wait_for(CLIENT_LINE)
                server.write(SERVER_LINE)
                client.wait_for(SERVER_LINE)
                client.finish()  # stdin EOF: s_client sends close_notify
            server.finish()
            relay.join()
        (out / "client.bin").write_bytes(bytes(relay.from_client))
        (out / "server.bin").write_bytes(bytes(relay.from_server))
        (out / "root.der").write_bytes(chain.root_der)
        (out / "key.pem").write_bytes(pki.key.read_bytes())
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.name != "meta.json"}
    meta = {
        "openssl": subprocess.run([binary, "version"], capture_output=True, text=True, check=True).stdout.strip(),
        "case": name, "config": cfg.name, "now": NOW.isoformat(), "server_name": "qtls.test",
        "suite": ot.SUITE, "group": ot.GROUP, "sigalg": sigalg,
        "s_server": list(server_args), "s_client": list(client_args), "sha256": files,
    }  # fmt: skip
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"{name}: client {len(relay.from_client)} B, server {len(relay.from_server)} B")


def write_source() -> None:
    """tests/vectors/<dir>/SOURCE pins every vendored file (tests/test_environment.py)."""
    lines = [
        "document: TLS 1.3 handshakes between OpenSSL 3.6.3 s_client and s_server (docs/PLAN.md Phase 2e)",
        "source sha256: recorded per case in <case>/meta.json",
        "regenerate: QTLS_OPENSSL=.openssl/bin/openssl python scripts/capture_openssl.py",
        "oracle: independent (another TLS stack)",
    ]
    for path in sorted(p for p in OUT.rglob("*") if p.is_file() and p.name != "SOURCE"):
        lines.append(f"sha256 {path.relative_to(OUT)}: {hashlib.sha256(path.read_bytes()).hexdigest()}")
    (OUT / "SOURCE").write_text("\n".join(lines) + "\n")


def main() -> None:
    binary, why = ot.locate()
    if binary is None:
        sys.exit(why)
    if not ot.is_pinned_build(binary):  # SOURCE and the tests name the pinned version
        sys.exit(f"{binary} isn't the pinned {ot.OPENSSL_TAG} build; run scripts/build_openssl.sh")
    for name in CASES:
        capture(binary, name)
    write_source()


if __name__ == "__main__":
    main()
