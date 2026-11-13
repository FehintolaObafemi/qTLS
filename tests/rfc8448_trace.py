"""RFC 8448 §3 trace access for tests (not a test module).

Only expected *outputs* should be read from here in key-schedule tests; inputs
come from qtls (see tests/test_keyschedule.py).
"""

from __future__ import annotations

import json
from pathlib import Path

EVENTS = json.loads(
    (Path(__file__).parent / "vectors" / "rfc8448" / "simple_1rtt.json").read_text()
)["events"]


def h(s: str) -> bytes:
    return bytes.fromhex(s)


def event(actor: str, step: str, nth: int = 0) -> dict[str, str]:
    matches = [e["values"] for e in EVENTS if e["actor"] == actor and e["step"] == step]
    return matches[nth]


def message(actor: str, name: str) -> bytes:
    """A handshake message (header ‖ body) as the RFC lists it."""
    article = "an" if name[0] in "AEIOU" else "a"
    return h(event(actor, f"construct {article} {name} handshake message")[name])


CH = message("client", "ClientHello")
SH = message("server", "ServerHello")
EE = message("server", "EncryptedExtensions")
CERT = message("server", "Certificate")
CV = message("server", "CertificateVerify")
SFIN = message("server", "Finished")
CFIN = message("client", "Finished")
NST = message("server", "NewSessionTicket")

CLIENT_X25519_PUBLIC = h(event("client", "create an ephemeral x25519 key pair")["public key"])
SERVER_X25519_PUBLIC = h(event("server", "create an ephemeral x25519 key pair")["public key"])
