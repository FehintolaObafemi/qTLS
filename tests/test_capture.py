"""Vendored OpenSSL-to-OpenSSL captures: a second independent oracle (docs/PLAN.md Phase 2e).

tests/vectors/openssl/ holds four handshakes between OpenSSL 3.6.3's
s_client and s_server (scripts/capture_openssl.py): configs A and B/ML-DSA-65,
each with OpenSSL's default record framing and with ``-max_send_frag 1024``,
which splits ServerHello across plaintext records and the Certificate across
many protected ones. They check three things, none of which needs OpenSSL
at test time:

* the keylog-mode oracle (tests/handshake_oracle.py) accepts each capture
  and rejects tampered copies;
* qTLS's own codec (qtls.record, qtls.messages, qtls.x509) reads a foreign
  stack's framing: every record opens, every message decodes, the chain verifies;
* sizes (specs.md D16): a qTLS server answering the captured ClientHello
  with the captured chain produces the same message sizes OpenSSL did.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

import handshake_oracle as ho
import openssl_tools as ot
from handshake_oracle import OracleMismatch
from qtls import crypto, x509
from qtls import handshake as hs
from qtls import messages as m
from qtls import record as rl


pytestmark = pytest.mark.usefixtures("require_liboqs")

VECTORS = Path(__file__).parent / "vectors" / "openssl"
CASES = ["A", "A-frag1024", "B65", "B65-frag1024"]
PINNED_META = {  # SHA-256 of meta.json, which pins every other file's SHA-256
    "A": "20277c8eb99937b39a5a919b8016ea0515bd700b4b3f6f4ced3e4c5a030a997f",
    "A-frag1024": "d227c634cbe35e2ebf09204dc0c89d02852914ef1d54ef96aa588fed07f7ab98",
    "B65": "920850a1f58be0f992e51a0e770fb707e03e6864ed893c2f9ae98a7501db5b0d",
    "B65-frag1024": "d00a940b11ddf1576b6df2b6bcfd8692e8bff705bac6614479fa0948f7a4d551",
}


def load(case: str) -> dict:
    d = VECTORS / case
    meta = json.loads((d / "meta.json").read_text())
    client, server = (d / "client.bin").read_bytes(), (d / "server.bin").read_bytes()
    client_random = ho.client_hello_fields(ho.split(client)[0][5:])[0]
    keylog = {k: bytes.fromhex(v) for k, v in ot.keylog(d / "keylog.txt", client_random).items()}
    return {"dir": d, "meta": meta, "client": client, "server": server, "keylog": keylog}


@pytest.mark.parametrize("case", CASES)
def test_vendored_files_are_pinned(case: str) -> None:
    d = VECTORS / case
    assert hashlib.sha256((d / "meta.json").read_bytes()).hexdigest() == PINNED_META[case]
    meta = json.loads((d / "meta.json").read_text())
    assert meta["openssl"].startswith("OpenSSL 3.6.3 ")
    assert (meta["suite"], meta["group"]) == (ot.SUITE, ot.GROUP)
    files = {p.name for p in d.iterdir()} - {"meta.json"}
    assert files == set(meta["sha256"])
    for name, digest in meta["sha256"].items():
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest, name


# --------------------------------------------------------------------------- #
# The keylog-mode oracle
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", CASES)
def test_oracle_accepts_the_capture(case: str) -> None:
    c = load(case)
    t = ho.observe_capture(c["client"], c["server"], c["keylog"])
    assert t.leaf_alg == ("ECDSA-P256-SHA256" if case.startswith("A") else "ML-DSA-65")
    assert len(t.tickets) == 2  # -num_tickets 2, after the server's Finished
    assert t.client_data == [b"hello from openssl s_client\n"]
    assert t.server_data == [b"hello from openssl s_server\n"]
    assert t.client_alerts == t.server_alerts == [b"\x01\x00"]  # close_notify both ways
    if case.endswith("frag1024"):
        assert [r[0] for r in t.server_records[:3]] == [22, 22, 20]  # ServerHello in two plaintext records, then CCS
        assert ho.CCS_RECORD in t.client_records
        assert max(len(r) for r in t.server_records) <= 5 + 1024 + 1 + 16 + 256


def _flip_last(rec: bytes) -> bytes:
    return rec[:-1] + bytes([rec[-1] ^ 1])


def _tampered(case: str):  # noqa: ANN202
    c = load(case)
    cr, sr = ho.split(c["client"]), ho.split(c["server"])
    for side, records in (("client", cr), ("server", sr)):
        for i in range(len(records)):
            edited = list(records)
            edited[i] = _flip_last(edited[i])
            wires = {"client": c["client"], "server": c["server"], side: b"".join(edited)}
            yield f"{side}-flip-{i}", wires["client"], wires["server"], c["keylog"]
    swapped = list(sr)
    i = next(k for k in range(len(sr) - 1) if sr[k][0] == sr[k + 1][0] == 23)
    swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
    yield "server-swap", c["client"], b"".join(swapped), c["keylog"]
    for label in c["keylog"]:
        if label == "EXPORTER_SECRET":
            continue  # no record uses it
        bad = dict(c["keylog"], **{label: _flip_last(c["keylog"][label])})
        yield f"keylog-{label}", c["client"], c["server"], bad


@pytest.mark.parametrize("case", ["A", "B65-frag1024"])
def test_oracle_rejects_every_tampered_copy(case: str) -> None:
    caught = []
    for label, client, server, keylog in _tampered(case):
        with pytest.raises(OracleMismatch):
            ho.observe_capture(client, server, keylog)
        caught.append(label)
    assert len(caught) > 10


# --------------------------------------------------------------------------- #
# qTLS's codec on a foreign stack's framing
# --------------------------------------------------------------------------- #


def read_side(wire: bytes, hs_secret: bytes, ap_secret: bytes) -> tuple[list[m.RawHandshake], list[bytes]]:
    """Every record through qtls.record, every handshake byte through HandshakeReader."""
    records, rest = rl.split_records(wire)
    assert rest == b""
    reader, protection, messages, data = m.HandshakeReader(), None, [], []
    for rec in records:
        result = rl.receive(rec, protection, ccs_allowed=True)
        if result is None:
            continue
        content_type, content = result
        if content_type is rl.ContentType.handshake:
            new = reader.feed(content)
            messages += new
            if any(r.msg_type in (m.HandshakeType.client_hello, m.HandshakeType.server_hello) for r in new):
                protection = rl.RecordProtection.from_secret(hs_secret)  # the hello ends the plaintext
            if any(r.msg_type == m.HandshakeType.finished for r in new):
                protection = rl.RecordProtection.from_secret(ap_secret)
        elif content_type is rl.ContentType.application_data:
            data.append(content)
    assert not reader.pending()
    return messages, data


@pytest.mark.parametrize("case", CASES)
def test_our_codec_reads_both_sides(case: str) -> None:
    c = load(case)
    k = c["keylog"]
    s_msgs, s_data = read_side(c["server"], k["SERVER_HANDSHAKE_TRAFFIC_SECRET"], k["SERVER_TRAFFIC_SECRET_0"])
    c_msgs, c_data = read_side(c["client"], k["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], k["CLIENT_TRAFFIC_SECRET_0"])
    T = m.HandshakeType
    assert [r.msg_type for r in s_msgs] == [T.server_hello, T.encrypted_extensions, T.certificate,
                                            T.certificate_verify, T.finished, T.new_session_ticket, T.new_session_ticket]  # fmt: skip
    assert [r.msg_type for r in c_msgs] == [T.client_hello, T.finished]
    assert s_data == [b"hello from openssl s_server\n"] and c_data == [b"hello from openssl s_client\n"]
    m.ClientHello.decode(c_msgs[0].body)
    m.ServerHello.decode(s_msgs[0].body)
    m.EncryptedExtensions.decode(s_msgs[1].body)
    cert = m.Certificate.decode(s_msgs[2].body)
    cv = m.CertificateVerify.decode(s_msgs[3].body)
    m.Finished.decode(s_msgs[4].body)
    m.Finished.decode(c_msgs[1].body)
    meta = c["meta"]
    leaf = x509.verify_chain(
        [e.cert_data for e in cert.certificate_list], [x509.TrustAnchor.from_certificate((c["dir"] / "root.der").read_bytes())],
        server_name=meta["server_name"], now=dt.datetime.fromisoformat(meta["now"]),
        accepted=frozenset((cv.algorithm,)), expected_kind="sig",
    )  # fmt: skip
    assert cv.algorithm in x509.BY_NAME[leaf.alg].codepoints


# --------------------------------------------------------------------------- #
# Sizes (D16): a qTLS server answering OpenSSL's ClientHello
# --------------------------------------------------------------------------- #


def vendored_key(case: str, alg: str) -> crypto.SigPrivateKey:
    key = serialization.load_pem_private_key((VECTORS / case / "key.pem").read_bytes(), None)
    if alg == "ECDSA-P256-SHA256":
        seed = key.private_numbers().private_value.to_bytes(32, "big")  # type: ignore[union-attr]
    else:
        seed = key.private_bytes_raw()  # type: ignore[union-attr]  # the FIPS 204 seed
    return crypto.sig_generate(alg, "openssl", seed=seed)


def our_answer(case: str) -> tuple[list[m.RawHandshake], list[m.RawHandshake], bytes]:
    """OpenSSL's server messages, ours for the same ClientHello and chain, and our server's wire bytes."""
    c = load(case)
    k = c["keylog"]
    theirs, _ = read_side(c["server"], k["SERVER_HANDSHAKE_TRAFFIC_SECRET"], k["SERVER_TRAFFIC_SECRET_0"])
    cert = m.Certificate.decode(theirs[2].body)
    leaf_alg = ho.SCHEMES[m.CertificateVerify.decode(theirs[3].body).algorithm]
    server = hs.Server(hs.ServerConfig(
        cert_data=tuple(e.cert_data for e in cert.certificate_list), signing_key=vendored_key(case, leaf_alg),
    ))  # fmt: skip
    records = ho.split(c["client"])
    hello = b"".join(records[: next(i for i, r in enumerate(records) if r[0] != 22)])
    assert server.receive(hello) == []
    wire = server.data_to_send()
    secrets = {label: bytes.fromhex(s) for label, s in ot.our_keylog(server.keylog_lines()).items()}
    ours, _ = read_side(wire, secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"], secrets["SERVER_TRAFFIC_SECRET_0"])
    return theirs, ours, wire


RECORD_OVERHEAD = 5 + 1 + 16  # header, inner content type, AES-GCM tag
SNI_ACK = 4  # we acknowledge server_name with an empty extension in EE (RFC 6066 §3); s_server doesn't


def cv_without_signature(raw: m.RawHandshake) -> int:
    return len(raw.raw) - len(m.CertificateVerify.decode(raw.body).signature)


@pytest.mark.parametrize("case", ["A", "B65"])
def test_message_sizes_match_openssl(case: str) -> None:
    """D16: the sizes Phase 5 reports are a real stack's sizes, up to the differences named here."""
    theirs, ours, wire = our_answer(case)
    assert [r.msg_type for r in ours] == [r.msg_type for r in theirs[:5]]
    sh, ee, cert, cv, fin = zip(theirs[:5], ours, strict=True)
    assert len(sh[1].raw) == len(sh[0].raw)  # same echoed session id, same two extensions
    assert len(ee[1].raw) == len(ee[0].raw) + SNI_ACK
    assert cert[1].raw == cert[0].raw  # the same chain, byte for byte, and no entry extensions
    assert cv_without_signature(cv[1]) == cv_without_signature(cv[0]) == 8
    if case == "B65":
        assert len(cv[1].raw) == len(cv[0].raw) == 8 + 3309  # ML-DSA-65 signatures have one length
    assert len(fin[1].raw) == len(fin[0].raw) == 36
    # The wire: we send ServerHello, then the encrypted flight in as few records as fit (D17);
    # OpenSSL puts each message in its own record. (Middlebox compatibility is off on both.)
    assert ho.CCS_RECORD not in load(case)["server"]
    encrypted = sum(len(r.raw) for r in ours[1:])
    assert len(wire) == 5 + len(sh[1].raw) + encrypted + RECORD_OVERHEAD * -(-encrypted // 16384)
    openssl_flight = 5 + len(sh[0].raw) + sum(len(r.raw) + RECORD_OVERHEAD for r in theirs[1:5])
    assert openssl_flight - len(wire) == 3 * RECORD_OVERHEAD - SNI_ACK - (len(cv[1].raw) - len(cv[0].raw))


# --------------------------------------------------------------------------- #
# Semantic tampering: re-sealed under the keylog's keys, so the AEAD passes and
# the oracle's own checks must catch the edit (flipped bytes only test the AEAD).
# --------------------------------------------------------------------------- #


def _records(wire: bytes, hs_secret: bytes, ap_secret: bytes) -> list[tuple[str, rl.ContentType, bytes]]:
    """Each record as ("plain" | "hs" | "ap", inner type, content); a hello ends the plaintext, Finished the hs key."""
    out, key, opener = [], "plain", None
    for rec in rl.split_records(wire)[0]:
        if rec[0] in (rl.ContentType.handshake, rl.ContentType.change_cipher_spec) and key == "plain" or rec[0] == rl.ContentType.change_cipher_spec:
            ctype, content = rl.decode_plaintext(rec)
            out.append(("plain", ctype, rec))  # kept whole: the ClientHello record says 0x0301
            if ctype is rl.ContentType.handshake and content[0] in (1, 2) and len(content) == 4 + int.from_bytes(content[1:4], "big"):
                key, opener = "hs", rl.RecordProtection.from_secret(hs_secret)
            continue
        ctype, content = opener.open(rec)  # type: ignore[union-attr]
        out.append((key, ctype, content))
        if key == "hs" and ctype is rl.ContentType.handshake and content[0] == 20:
            key, opener = "ap", rl.RecordProtection.from_secret(ap_secret)
    return out


def _seal(records: list[tuple[str, rl.ContentType, bytes]], hs_secret: bytes, ap_secret: bytes) -> bytes:
    sealers = {"hs": rl.RecordProtection.from_secret(hs_secret), "ap": rl.RecordProtection.from_secret(ap_secret)}
    return b"".join(content if key == "plain" else sealers[key].seal(ctype, content) for key, ctype, content in records)


def _edit_message(records, msg_type: int, edit):  # noqa: ANN001, ANN202
    i = next(i for i, (key, ctype, content) in enumerate(records)
             if key != "plain" and ctype is rl.ContentType.handshake and content[0] == msg_type)  # fmt: skip
    key, ctype, content = records[i]
    return records[:i] + [(key, ctype, edit(content))] + records[i + 1 :]


def _flip(content: bytes) -> bytes:
    return content[:-1] + bytes([content[-1] ^ 1])


def _truncate(content: bytes) -> bytes:
    return content[: len(content) // 2]


SEMANTIC = {
    "post-handshake-truncated": ("server", 4, _truncate),
    "post-handshake-stub": ("server", 4, lambda c: b"\x04\x00\x00"),
    # side, message type, edit
    "server-finished": ("server", 20, _flip),
    "client-finished": ("client", 20, _flip),
    "certificate-verify-signature": ("server", 15, _flip),
    "post-handshake-key-update": ("server", 4, lambda c: b"\x18\x00\x00\x01\x00"),  # NewSessionTicket -> KeyUpdate
}


@pytest.mark.parametrize("label", SEMANTIC)
def test_oracle_rejects_semantic_tampering(label: str) -> None:
    side, msg_type, edit = SEMANTIC[label]
    c = load("A")
    k = c["keylog"]
    secrets = {"client": (k["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], k["CLIENT_TRAFFIC_SECRET_0"]),
               "server": (k["SERVER_HANDSHAKE_TRAFFIC_SECRET"], k["SERVER_TRAFFIC_SECRET_0"])}  # fmt: skip
    records = _records(c[side], *secrets[side])
    assert _seal(records, *secrets[side]) == c[side]  # the re-sealer is exact, so only the edit differs
    wires = dict(client=c["client"], server=c["server"])
    wires[side] = _seal(_edit_message(records, msg_type, edit), *secrets[side])
    with pytest.raises(OracleMismatch):
        ho.observe_capture(wires["client"], wires["server"], k)


@pytest.mark.parametrize(("ccs", "accepted"), [(ho.CCS_RECORD, True), (b"\x14\x03\x03\x00\x01\x02", False)])
def test_oracle_checks_a_change_cipher_spec_between_protected_records(ccs: bytes, accepted: bool) -> None:
    """RFC 8446 §5: a CCS may arrive anywhere before Finished; only the 0x01 body is valid."""
    c = load("A")
    records = ho.split(c["server"])
    i = next(i for i, r in enumerate(records) if r[0] == 23) + 1  # after the first protected record
    server = b"".join(records[:i]) + ccs + b"".join(records[i:])
    if accepted:
        ho.observe_capture(c["client"], server, c["keylog"])
    else:
        with pytest.raises(OracleMismatch):
            ho.observe_capture(c["client"], server, c["keylog"])


def test_oracle_rejects_records_after_a_closing_alert() -> None:
    c = load("A")
    k = c["keylog"]
    records = _records(c["server"], k["SERVER_HANDSHAKE_TRAFFIC_SECRET"], k["SERVER_TRAFFIC_SECRET_0"])
    assert records[-1][1] is rl.ContentType.alert
    extra = records + [("ap", rl.ContentType.application_data, b"after close_notify")]
    server = _seal(extra, k["SERVER_HANDSHAKE_TRAFFIC_SECRET"], k["SERVER_TRAFFIC_SECRET_0"])
    with pytest.raises(OracleMismatch, match="follows an alert"):
        ho.observe_capture(c["client"], server, k)


def test_oracle_checks_the_server_group_first() -> None:
    """Defence in depth: a capture whose ServerHello names another group fails on the group, before anything else."""
    c = load("A")
    records = ho.split(c["server"])
    sh = bytearray(records[0])
    at = sh.find(b"\x00\x33")  # the key_share extension; its group follows the 2-byte length
    assert at > 0 and sh[at + 4 : at + 6] == b"\x11\xec"
    sh[at + 4 : at + 6] = b"\x00\x1d"
    with pytest.raises(OracleMismatch, match="server group"):
        ho.observe_capture(c["client"], bytes(sh) + b"".join(records[1:]), c["keylog"])
