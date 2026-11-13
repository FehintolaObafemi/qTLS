"""Independent RFC oracles: X25519 (RFC 7748), the TLS 1.3 key schedule and
record protection primitives (RFC 8448 §3), and deterministic ECDSA (RFC 6979).

RFC 8448 is used here only through injected inputs (keys, secrets, messages):
its handshake negotiates X25519 and RSA-PSS, which qTLS's own handshake
deliberately doesn't (specs.md D16).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from qtls import crypto

VECTORS = Path(__file__).parent / "vectors"
X25519 = json.loads((VECTORS / "rfc7748" / "x25519.json").read_text())
RFC8448 = json.loads((VECTORS / "rfc8448" / "simple_1rtt.json").read_text())["events"]


def h(s: str) -> bytes:
    return bytes.fromhex(s)


def event(actor: str, step: str, nth: int = 0) -> dict:
    matches = [e["values"] for e in RFC8448 if e["actor"] == actor and e["step"] == step]
    return matches[nth]


# --------------------------------------------------------------------------- #
# RFC 7748
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("vector", X25519["scalar_mult"], ids=["5.2-a", "5.2-b"])
def test_x25519_scalar_mult(vector: dict) -> None:
    """Non-clamped scalars and a u-coordinate with the high bit set (RFC 7748 §5.2)."""
    key = crypto.x25519_from_private_bytes(h(vector["scalar"]))
    assert key.exchange(h(vector["u"])) == h(vector["output"])


def test_x25519_iterations() -> None:
    k = u = (9).to_bytes(32, "little")
    for i in range(1, 1001):
        k, u = crypto.x25519_from_private_bytes(k).exchange(u), k
        if i == 1:
            assert k == h(X25519["iterations"]["1"])
    assert k == h(X25519["iterations"]["1000"])


def test_x25519_diffie_hellman() -> None:
    dh = X25519["dh"]
    alice = crypto.x25519_from_private_bytes(h(dh["alice_private"]))
    bob = crypto.x25519_from_private_bytes(h(dh["bob_private"]))
    assert alice.public_key == h(dh["alice_public"])
    assert bob.public_key == h(dh["bob_public"])
    assert alice.exchange(bob.public_key) == bob.exchange(alice.public_key) == h(dh["shared"])
    assert alice.private_bytes() == h(dh["alice_private"])


@pytest.mark.parametrize("bad", [bytes(31), bytes(33)], ids=["31", "33"])
def test_x25519_private_key_length(bad: bytes) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.x25519_from_private_bytes(bad)
    with pytest.raises(TypeError):
        crypto.x25519_from_private_bytes("x" * 32)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# RFC 8448 §3
# --------------------------------------------------------------------------- #


def test_rfc8448_x25519_key_exchange() -> None:
    client = event("client", "create an ephemeral x25519 key pair")
    server = event("server", "create an ephemeral x25519 key pair")
    c = crypto.x25519_from_private_bytes(h(client["private key"]))
    s = crypto.x25519_from_private_bytes(h(server["private key"]))
    assert c.public_key == h(client["public key"])
    assert s.public_key == h(server["public key"])
    ikm = h(event("server", 'extract secret "handshake"')["IKM"])
    assert c.exchange(s.public_key) == s.exchange(c.public_key) == ikm


EXTRACTS = [e for e in RFC8448 if "salt" in e["values"] and e["values"].get("secret")]
EXPANDS = [e for e in RFC8448 if "PRK" in e["values"] and "info" in e["values"]]
KEY_DERIVATIONS = [e for e in RFC8448 if "key info" in e["values"]]


def test_rfc8448_coverage() -> None:
    assert len(EXTRACTS) == 3  # early, handshake, master
    assert len(EXPANDS) >= 12
    assert len(KEY_DERIVATIONS) == 4


@pytest.mark.parametrize("e", EXTRACTS, ids=[e["step"] for e in EXTRACTS])
def test_rfc8448_hkdf_extract(e: dict) -> None:
    v = e["values"]
    assert crypto.hkdf_extract(h(v["salt"]), h(v["IKM"])) == h(v["secret"])


@pytest.mark.parametrize("e", EXPANDS, ids=[f'{e["actor"]}: {e["step"]}' for e in EXPANDS])
def test_rfc8448_hkdf_expand(e: dict) -> None:
    v = e["values"]
    out = crypto.hkdf_expand(h(v["PRK"]), h(v["info"]), len(h(v["expanded"])))
    assert out == h(v["expanded"])


@pytest.mark.parametrize("e", KEY_DERIVATIONS, ids=[f'{e["actor"]}: {e["step"]}' for e in KEY_DERIVATIONS])
def test_rfc8448_traffic_key_and_iv(e: dict) -> None:
    """HKDF-Expand at 16 and 12 bytes, not just 32."""
    v = e["values"]
    assert crypto.hkdf_expand(h(v["PRK"]), h(v["key info"]), 16) == h(v["key expanded"])
    assert crypto.hkdf_expand(h(v["PRK"]), h(v["iv info"]), 12) == h(v["iv expanded"])


def test_rfc8448_empty_transcript_hash() -> None:
    derived = event("server", 'derive secret for handshake "tls13 derived"')
    assert crypto.sha256().digest() == h(derived["hash"])


def test_rfc8448_server_finished() -> None:
    """Transcript SHA-256 over CH..CertificateVerify, then HMAC with the finished key."""
    messages = [
        event("client", "construct a ClientHello handshake message")["ClientHello"],
        event("server", "construct a ServerHello handshake message")["ServerHello"],
        event("server", "construct an EncryptedExtensions handshake message")["EncryptedExtensions"],
        event("server", "construct a Certificate handshake message")["Certificate"],
        event("server", "construct a CertificateVerify handshake message")["CertificateVerify"],
    ]
    transcript = crypto.sha256()
    for m in messages:
        transcript.update(h(m))
    snapshot = transcript.copy()
    fin = event("server", 'calculate finished "tls13 finished"')
    assert crypto.hmac_sha256(h(fin["expanded"]), transcript.digest()) == h(fin["finished"])
    assert snapshot.digest() == transcript.digest()  # digest() doesn't consume the state
    finished_msg = event("server", "construct a Finished handshake message")["Finished"]
    assert h(finished_msg)[4:] == h(fin["finished"])


# (record step, nth occurrence, key step, key actor, sequence number, inner content type)
RECORDS = [
    ("server", "send handshake record", 1, "server", "derive write traffic keys for handshake data", 0, 0x16),
    # Client record #0 is the plaintext ClientHello; #1 is its protected Finished.
    ("client", "send handshake record", 1, "server", "derive read traffic keys for handshake data", 0, 0x16),
    ("server", "send handshake record", 2, "server", "derive write traffic keys for application data", 0, 0x16),
    ("client", "send application_data record", 0, "client", "derive write traffic keys for application data", 0, 0x17),
    ("server", "send application_data record", 0, "server", "derive write traffic keys for application data", 1, 0x17),
    ("client", "send alert record", 0, "client", "derive write traffic keys for application data", 1, 0x15),
    ("server", "send alert record", 0, "server", "derive write traffic keys for application data", 2, 0x15),
]


@pytest.mark.parametrize("record", RECORDS, ids=[f"{r[0]} {r[1]} #{r[2]}" for r in RECORDS])
def test_rfc8448_record_protection(record: tuple) -> None:
    """AES-128-GCM seal reproduces the RFC's protected record byte for byte; open inverts it."""
    actor, step, nth, key_actor, key_step, seq, content_type = record
    rec = event(actor, step, nth)
    keys = event(key_actor, key_step)
    full = h(rec["complete record"])
    header, body = full[:5], full[5:]
    nonce = (int.from_bytes(h(keys["iv expanded"]), "big") ^ seq).to_bytes(12, "big")
    aead = crypto.aead_key(h(keys["key expanded"]))
    plaintext = h(rec["payload"]) + bytes([content_type])
    assert aead.seal(nonce, plaintext, header) == body
    assert aead.open(nonce, body, header) == plaintext


# --------------------------------------------------------------------------- #
# RFC 6979 A.2.5 (P-256, SHA-256)
# --------------------------------------------------------------------------- #

RFC6979_X = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
RFC6979_PUB = (
    "04"
    "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
    "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
)
RFC6979_SIGS = {
    b"sample": (
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ),
    b"test": (
        "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    ),
}


@pytest.mark.parametrize("message", sorted(RFC6979_SIGS), ids=lambda m: m.decode())
def test_ecdsa_rfc6979_deterministic_signature(message: bytes) -> None:
    key = crypto.sig_generate("ECDSA-P256-SHA256", "openssl", seed=h(RFC6979_X))
    assert key.public_key == h(RFC6979_PUB)
    assert key.seed == h(RFC6979_X)
    r, s = RFC6979_SIGS[message]
    assert key.sign(message, seed=b"") == encode_dss_signature(int(r, 16), int(s, 16))
