"""An independent observer of a seeded handshake (not a test module).

It re-derives everything from RFC 8446 §4 and §7 and RFC 10024 with raw
``qtls.crypto`` primitives and its own parsing: it never imports
``qtls.handshake``, ``qtls.hybrid``, ``qtls.keyschedule``, ``qtls.record`` or
``qtls.messages``. Given the seed and the bytes each side put on the wire, it

* rebuilds both sides' ephemeral keys from the seed (``seeded_bytes`` is
  re-implemented here from its specification) and checks the key shares are
  laid out as RFC 10024 says, and the hybrid secret is ML-KEM ‖ X25519;
* re-derives every secret at the transcript point RFC 8446 names;
* decrypts every record in both directions and checks message order;
* checks both Finished values and verifies CertificateVerify with the
  leaf's key over the server context string;
* optionally checks the connections' keylogs against its own secrets.

A bug both endpoints share (a wrong transcript point, label or layout) still
completes a handshake between them, but fails here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from qtls import crypto, x509

HASH_LEN = 32
ZEROS = bytes(HASH_LEN)
GROUP = 0x11EC
MLKEM = "ML-KEM-768"
EK_LEN, CT_LEN = 1184, 1088
CV_CONTEXT = b"TLS 1.3, server CertificateVerify"
SCHEMES = {0x0403: "ECDSA-P256-SHA256", 0x0904: "ML-DSA-44", 0x0905: "ML-DSA-65", 0xFE50: "Falcon-512"}
HANDSHAKE, ALERT, APP_DATA, CCS = 22, 21, 23, 20
CH, SH, EE, CERT, CV, FIN, NST = 1, 2, 8, 11, 15, 20, 4


class OracleMismatch(AssertionError):
    pass


def expect(ok: bool, what: str) -> None:
    if not ok:
        raise OracleMismatch(what)


# ---- the seeded stream, from its specification ---------------------------- #


def seeded(seed: bytes, role: str, label: str, index: int, n: int) -> bytes:
    head = b"qtls handshake rng v1" + len(seed).to_bytes(2, "big") + seed + role.encode() + b"\x00" + label.encode() + b"\x00"
    out, block = b"", 0
    while len(out) < n:
        out += crypto.sha256(head + index.to_bytes(4, "big") + block.to_bytes(4, "big")).digest()
        block += 1
    return out[:n]


# ---- RFC 8446 §7.1 --------------------------------------------------------- #


def expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return crypto.hkdf_expand(secret, info, length)


def h(data: bytes) -> bytes:
    return crypto.sha256(data).digest()


def derive(secret: bytes, label: bytes, messages: bytes) -> bytes:
    return expand_label(secret, label, h(messages), HASH_LEN)


class _Opener:
    """RFC 8446 §5.2-5.3 record decryption with its own sequence number."""

    def __init__(self, secret: bytes) -> None:
        self.key = expand_label(secret, b"key", b"", 16)
        self.iv = expand_label(secret, b"iv", b"", 12)
        self.aead = crypto.aead_key(self.key)
        self.seq = 0

    def open(self, rec: bytes) -> tuple[int, bytes]:
        expect(rec[0] == APP_DATA, f"protected record has outer type {rec[0]}")
        nonce = (int.from_bytes(self.iv, "big") ^ self.seq).to_bytes(12, "big")
        self.seq += 1
        try:
            inner = self.aead.open(nonce, rec[5:], rec[:5])
        except crypto.AeadFailure:
            raise OracleMismatch("a record doesn't decrypt under the oracle's key") from None
        body = inner.rstrip(b"\x00")
        return body[-1], body[:-1]


def split(wire: bytes) -> list[bytes]:
    out, pos = [], 0
    while pos < len(wire):
        n = int.from_bytes(wire[pos + 3 : pos + 5], "big")
        out.append(wire[pos : pos + 5 + n])
        pos += 5 + n
    expect(pos == len(wire), "wire bytes don't end on a record boundary")
    return out


def parse_messages(stream: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos + 4 <= len(stream):
        n = int.from_bytes(stream[pos + 1 : pos + 4], "big")
        if pos + 4 + n > len(stream):
            break
        out.append((stream[pos], stream[pos : pos + 4 + n]))
        pos += 4 + n
    return out


def extensions(block: bytes) -> dict[int, bytes]:
    out, pos = {}, 0
    while pos < len(block):
        t = int.from_bytes(block[pos : pos + 2], "big")
        n = int.from_bytes(block[pos + 2 : pos + 4], "big")
        out[t] = block[pos + 4 : pos + 4 + n]
        pos += 4 + n
    return out


def client_hello_fields(raw: bytes) -> tuple[bytes, dict[int, bytes]]:
    body = raw[4:]
    random = body[2:34]
    pos = 34
    pos += 1 + body[pos]  # session id
    pos += 2 + int.from_bytes(body[pos : pos + 2], "big")  # suites
    pos += 1 + body[pos]  # compression
    return random, extensions(body[pos + 2 :])


def server_hello_fields(raw: bytes) -> tuple[bytes, dict[int, bytes]]:
    body = raw[4:]
    random = body[2:34]
    pos = 34 + 1 + body[34]
    pos += 3  # suite, compression
    return random, extensions(body[pos + 2 :])


# ---- the observation ------------------------------------------------------- #


@dataclass
class Trace:
    messages: dict[str, bytes] = field(default_factory=dict)
    secrets: dict[str, bytes] = field(default_factory=dict)
    shared_secret: bytes = b""
    client_data: list[bytes] = field(default_factory=list)
    server_data: list[bytes] = field(default_factory=list)
    client_alerts: list[bytes] = field(default_factory=list)
    server_alerts: list[bytes] = field(default_factory=list)
    leaf_alg: str = ""

    def server_flight(self) -> list[bytes]:
        return [self.messages[n] for n in ("EE", "CERT", "CV", "SFIN")]


def _read_side(records: list[bytes], first: bytes, then: bytes | None, end_type: int, trace_data: list[bytes], trace_alerts: list[bytes]) -> list[tuple[int, bytes]]:
    """Decrypt one side's protected records: handshake under ``first`` until ``end_type``, then ``then``."""
    opener, switched = _Opener(first), False
    stream, messages = b"", []
    for rec in records:
        if rec[0] == CCS:
            continue
        if rec[0] == ALERT:  # a plaintext alert
            trace_alerts.append(rec[5:])
            continue
        inner_type, content = opener.open(rec)
        if inner_type == HANDSHAKE:
            expect(not switched, "handshake message after the side's Finished")
            stream += content
            parsed = parse_messages(stream)
            consumed = sum(len(r) for _, r in parsed)
            if parsed and parsed[-1][0] == end_type:
                expect(consumed == len(stream), "data after Finished in its record")
                messages += parsed
                stream = b""
                if then is None:
                    return messages
                opener, switched = _Opener(then), True
            elif parsed:
                messages += parsed
                stream = stream[consumed:]
        elif inner_type == APP_DATA:
            expect(switched, "application data before the side's Finished")
            trace_data.append(content)
        elif inner_type == ALERT:
            trace_alerts.append(content)
        else:
            raise OracleMismatch(f"inner content type {inner_type}")
    return messages


def observe(
    seed: bytes,
    client_wire: bytes,
    server_wire: bytes,
    *,
    kem_backend: str = "liboqs",
    sig_backends: dict[str, str] | None = None,
    keylogs: tuple[list[str], list[str]] | None = None,
) -> Trace:
    """Check a whole seeded handshake from the bytes each side sent (in order)."""
    sig_backends = sig_backends or dict(x509.DEFAULT_BACKENDS)
    t = Trace()
    c_records, s_records = split(client_wire), split(server_wire)

    # ClientHello: plaintext, record version 0x0301 (D22).
    expect(c_records[0][:3] == b"\x16\x03\x01", "first client record isn't a 0x0301 handshake record")
    ch = c_records[0][5:]
    expect(ch[0] == CH, "first client message isn't ClientHello")
    c_random, c_ext = client_hello_fields(ch)
    expect(c_random == seeded(seed, "client", "random", 0, 32), "client random isn't the seeded value")
    c_x = crypto.x25519_from_private_bytes(seeded(seed, "client", "x25519", 0, 32))
    c_kem = crypto.kem_generate(MLKEM, kem_backend, seed=seeded(seed, "client", f"kem/{MLKEM}", 0, 64))
    shares = c_ext[0x0033][2:]
    expect(int.from_bytes(shares[:2], "big") == GROUP, "first client share isn't X25519MLKEM768")
    share = shares[4 : 4 + int.from_bytes(shares[2:4], "big")]
    expect(share == c_kem.public_key + c_x.public_key, "client share isn't ek ‖ x25519 (RFC 10024 §4.1)")

    # ServerHello.
    expect(s_records[0][0] == HANDSHAKE, "first server record isn't plaintext handshake")
    sh = s_records[0][5:]
    expect(sh[0] == SH, "first server message isn't ServerHello")
    s_random, s_ext = server_hello_fields(sh)
    expect(s_random == seeded(seed, "server", "random", 0, 32), "server random isn't the seeded value")
    entry = s_ext[0x0033]
    expect(int.from_bytes(entry[:2], "big") == GROUP, "server group isn't X25519MLKEM768")
    s_share = entry[4:]
    s_x = crypto.x25519_from_private_bytes(seeded(seed, "server", "x25519", 0, 32))
    ct, k_ss = crypto.kem_encapsulate(MLKEM, c_kem.public_key, "liboqs", seed=seeded(seed, "server", f"encap/{MLKEM}", 0, 32))
    expect(s_share == ct + s_x.public_key, "server share isn't ct ‖ x25519 (RFC 10024 §4.2)")
    expect(c_kem.decapsulate(ct) == k_ss, "ML-KEM secrets disagree")
    x_ss = c_x.exchange(s_x.public_key)
    t.shared_secret = k_ss + x_ss  # RFC 10024 §4.3: ML-KEM first

    # Key schedule (RFC 8446 §7.1).
    es = crypto.hkdf_extract(b"", ZEROS)
    hs = crypto.hkdf_extract(derive(es, b"derived", b""), t.shared_secret)
    t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"] = c_hs = derive(hs, b"c hs traffic", ch + sh)
    t.secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"] = s_hs = derive(hs, b"s hs traffic", ch + sh)
    ms = crypto.hkdf_extract(derive(hs, b"derived", b""), ZEROS)

    # The server's encrypted flight. The application keys need the transcript
    # through server Finished, so decrypt the handshake part first.
    s_msgs = _read_side(s_records[1:], s_hs, None, FIN, [], [])
    types = [m[0] for m in s_msgs]
    expect(types[:4] == [EE, CERT, CV, FIN], f"server flight order {types}")
    ee, cert, cv, sfin = (m[1] for m in s_msgs[:4])
    t.messages.update(CH=ch, SH=sh, EE=ee, CERT=cert, CV=cv, SFIN=sfin)

    # CertificateVerify, with the leaf's key.
    body = cert[4:]
    pos = 1 + body[0] + 3
    leaf_der = body[pos + 3 : pos + 3 + int.from_bytes(body[pos : pos + 3], "big")]
    spki_oid, leaf_key = x509.parse_spki(x509.parse(leaf_der).spki_raw)
    scheme = int.from_bytes(cv[4:6], "big")
    t.leaf_alg = alg = SCHEMES[scheme]
    expect(x509.BY_NAME[alg].spki_oid == spki_oid, "CertificateVerify scheme doesn't fit the leaf key")
    signature = cv[8 : 8 + int.from_bytes(cv[6:8], "big")]
    content = b"\x20" * 64 + CV_CONTEXT + b"\x00" + h(ch + sh + ee + cert)
    try:
        crypto.sig_verify(alg, leaf_key, content, signature, sig_backends[alg])
    except crypto.InvalidSignature:
        raise OracleMismatch("CertificateVerify doesn't verify over CH..Certificate with the server context") from None

    # Finished values (RFC 8446 §4.4.4).
    expect(sfin[4:] == crypto.hmac_sha256(expand_label(s_hs, b"finished", b"", 32), h(ch + sh + ee + cert + cv)),
           "server Finished isn't HMAC(finished_key(s hs), H(CH..CV))")  # fmt: skip
    upto_sfin = ch + sh + ee + cert + cv + sfin
    t.secrets["CLIENT_TRAFFIC_SECRET_0"] = c_ap = derive(ms, b"c ap traffic", upto_sfin)
    t.secrets["SERVER_TRAFFIC_SECRET_0"] = s_ap = derive(ms, b"s ap traffic", upto_sfin)
    t.secrets["EXPORTER_SECRET"] = derive(ms, b"exp master", upto_sfin)

    # Now both sides' records, with the application keys.
    s_msgs = _read_side(s_records[1:], s_hs, s_ap, FIN, t.server_data, t.server_alerts)
    expect([m[0] for m in s_msgs] == [EE, CERT, CV, FIN], f"server sent handshake messages {[m[0] for m in s_msgs]}")
    c_msgs = _read_side(c_records[1:], c_hs, c_ap, FIN, t.client_data, t.client_alerts)
    expect([m[0] for m in c_msgs] == [FIN], f"client sent handshake messages {[m[0] for m in c_msgs]}")
    cfin = c_msgs[0][1]
    t.messages["CFIN"] = cfin
    expect(cfin[4:] == crypto.hmac_sha256(expand_label(c_hs, b"finished", b"", 32), h(upto_sfin)),
           "client Finished isn't HMAC(finished_key(c hs), H(CH..server Finished))")  # fmt: skip

    if keylogs is not None:
        for lines in keylogs:
            logged = {line.split()[0]: (line.split()[1], line.split()[2]) for line in lines}
            expect(set(logged) == set(t.secrets), f"keylog labels {sorted(logged)}")
            for label, (random_hex, secret_hex) in logged.items():
                expect(random_hex == c_random.hex(), "keylog isn't keyed by the client random")
                expect(bytes.fromhex(secret_hex) == t.secrets[label], f"keylog {label} differs from the oracle")
    return t
