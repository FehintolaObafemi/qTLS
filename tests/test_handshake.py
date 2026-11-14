"""The sans-I/O handshake, configs A and B (specs.md D16, D17, D22, D25-D27; P5, P7-P9).

Every handshake here is seeded, and tests/handshake_oracle.py checks it
independently: it re-derives every secret from RFC 8446 with raw primitives
and decrypts every record, so a bug both endpoints share can't pass.

Negatives change one thing in an otherwise valid run and assert the alert
*and* the reason. Messages after ServerHello are edited in plaintext and
re-sealed under the oracle's keys, so the check under test is reached rather
than the AEAD tag. Certificates are dated 2001, so reading the wall clock
anywhere would fail verification.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import functools
import random

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from qtls import chains, configs, crypto, hybrid, x509
from qtls import handshake as hs
from qtls import keyschedule as ks
from qtls import messages as m
from qtls import record as rl
from qtls.alerts import Alert, CodecUsageError
from qtls.handshake import (
    ApplicationData,
    Client,
    ConnectionClosed,
    ConnectionFailed,
    HandshakeComplete,
    PeerAlerted,
    SeededRandomness,
    Server,
    ServerAuthenticated,
    State,
)
from qtls.messages import Context, ExtensionType, HandshakeType
from qtls.record import ContentType as CT
from qtls.transport import memory
from handshake_oracle import OracleMismatch, Trace, observe

pytestmark = pytest.mark.usefixtures("require_liboqs")

UTC = dt.timezone.utc
NOT_BEFORE = dt.datetime(2001, 1, 1, tzinfo=UTC)  # far from the wall clock
NOW = NOT_BEFORE + dt.timedelta(days=30)
SEED = b"handshake test seed"
SEEDED_BACKENDS = {**hs.DEFAULT_BACKENDS, "ML-KEM-768": "liboqs", "ML-DSA-44": "liboqs", "ML-DSA-65": "liboqs"}

A = configs.CONFIG_A
B44 = configs.config_b("ML-DSA-44")
B44_FALCON_ISSUER = configs.config_b("ML-DSA-44", "Falcon-512")
B_FALCON = configs.config_b("Falcon-512", "ML-DSA-44", scts=2)
B65 = configs.config_b("ML-DSA-65", scts=2)
MATRIX = [A, B44, B44_FALCON_ISSUER, B_FALCON, B65]


@functools.cache
def endpoints(cfg: configs.SigConfig) -> tuple[hs.ClientConfig, hs.ServerConfig, chains.Chain]:
    return configs.endpoints(cfg, not_before=NOT_BEFORE, now=NOW, backends=SEEDED_BACKENDS)


def make(cfg: configs.SigConfig = A, seed: bytes = SEED, **client_kw: object) -> tuple[Client, Server]:
    c, s, _ = endpoints(cfg)
    client = Client(dataclasses.replace(c, randomness=SeededRandomness(seed), **client_kw))  # type: ignore[arg-type]
    server = Server(dataclasses.replace(s, randomness=SeededRandomness(seed)))
    return client, server


def wires(link: memory.Link) -> tuple[bytes, bytes]:
    return (b"".join(d for who, d in link.wire if who == "client"), b"".join(d for who, d in link.wire if who == "server"))


def oracle(link: memory.Link, seed: bytes = SEED) -> Trace:
    c, s = wires(link)
    return observe(seed, c, s, keylogs=(link.client.keylog_lines(), link.server.keylog_lines()))


@functools.cache
def reference(cfg: configs.SigConfig = A, seed: bytes = SEED) -> Trace:
    """The oracle's view of a clean handshake, for building edited flights."""
    client, server = make(cfg, seed)
    return oracle(memory.handshake(client, server), seed)


def last_failure(events: list[hs.Event]) -> ConnectionFailed:
    assert events and isinstance(events[-1], ConnectionFailed), events
    return events[-1]


def assert_fails(events: list[hs.Event], alert: Alert, reason: str) -> None:
    failure = last_failure(events)
    assert (failure.alert, failure.reason) == (alert, reason), failure


def plain(content: bytes, version: int = rl.LEGACY_VERSION, content_type: CT = CT.handshake) -> bytes:
    return b"".join(rl.encode_plaintext(content_type, p, version) for p in rl.fragment(content))


def sealed(secret: bytes, content: bytes, content_type: CT = CT.handshake, *, sizes: list[int] | None = None,
           padding: int = 0, protection: rl.RecordProtection | None = None) -> bytes:  # fmt: skip
    p = protection or rl.RecordProtection.from_secret(secret)
    if sizes is None:
        pieces = rl.fragment(content) or [b""]
    else:
        pieces, pos = [], 0
        for n in sizes:
            pieces.append(content[pos : pos + n])
            pos += n
        assert pos == len(content)
    return b"".join(p.seal(content_type, piece, padding) for piece in pieces)


def waiting_client(cfg: configs.SigConfig = A, seed: bytes = SEED, **client_kw: object) -> Client:
    """A client that has sent its ClientHello (identical to the reference run's)."""
    client, _ = make(cfg, seed, **client_kw)
    client.start()
    client.data_to_send()
    return client


def s_hs(trace: Trace) -> bytes:
    return trace.secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]


def deliver_flight(messages: list[bytes], cfg: configs.SigConfig = A, **client_kw: object) -> list[hs.Event]:
    """ServerHello, then ``messages`` re-sealed under the reference s hs key."""
    trace = reference(cfg)
    client = waiting_client(cfg, **client_kw)
    return client.receive(plain(trace.messages["SH"]) + sealed(s_hs(trace), b"".join(messages)))


def handshake_message(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def finished_for(trace: Trace, messages: list[bytes]) -> bytes:
    """A correct server Finished over CH, SH and ``messages`` (for edits that must get past Finished)."""
    th = crypto.sha256(trace.messages["CH"] + trace.messages["SH"] + b"".join(messages)).digest()
    return m.encode_handshake(m.Finished(ks.verify_data(ks.finished_key(s_hs(trace)), th)))


# --------------------------------------------------------------------------- #
# Happy paths, checked by the oracle (P5, P7)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cfg", MATRIX, ids=lambda c: c.name)
def test_matrix_handshakes(cfg: configs.SigConfig) -> None:
    client, server = make(cfg)
    link = memory.handshake(client, server)
    client.send(b"from the client")
    client.send(b"")  # zero-length application data is allowed (D22)
    server.send(b"from the server")
    link.pump()
    client.close()
    link.pump()

    trace = oracle(link)
    assert trace.client_data == [b"from the client", b""] and trace.server_data == [b"from the server"]
    assert trace.client_alerts == [b"\x01\x00"] and trace.server_alerts == [b"\x01\x00"]  # one close_notify each
    assert [type(e) for e in link.client_events] == [ServerAuthenticated, HandshakeComplete, ApplicationData, ConnectionClosed]
    assert [type(e) for e in link.server_events] == [HandshakeComplete, ApplicationData, ApplicationData, ConnectionClosed]
    leaf = link.client_events[0].leaf  # type: ignore[attr-defined]
    assert (leaf.kind, leaf.alg) == ("sig", cfg.leaf_alg)
    assert leaf.public_key == endpoints(cfg)[1].signing_key.public_key
    assert client.state is server.state is State.CLOSED
    assert server.server_name == "qtls.test"
    # Flights (D17): the client's first is one record; its second is Finished
    # plus application data; the server's is ServerHello plus ceil(n / 2^14).
    sizes = [len(r) for r in rl.split_records(wires(link)[1])[0]]
    server_flight = server.flights[0].records
    protected = sum(len(trace.messages[k]) for k in ("EE", "CERT", "CV", "SFIN"))
    assert len(server_flight) == 1 + -(-protected // rl.MAX_FRAGMENT)
    assert [len(f.records) for f in client.flights] == [1, 3, 1]
    assert sum(f.size for f in client.flights) == len(wires(link)[0])
    assert sum(f.size for f in server.flights) == sum(sizes)


@pytest.mark.parametrize("cfg", [A, B44], ids=lambda c: c.name)
def test_unseeded_handshakes_with_the_default_backends(cfg: configs.SigConfig) -> None:
    c, s, _ = configs.endpoints(cfg, not_before=NOT_BEFORE, now=NOW)  # OpenSSL ML-KEM, os.urandom
    link = memory.handshake(Client(c), Server(s))
    link.client.send(b"x")
    link.pump()
    assert link.server_events[-1] == ApplicationData(b"x")
    # A seeded client against an unseeded server, too.
    seeded_client = Client(dataclasses.replace(c, randomness=SeededRandomness(b"mixed")))
    link = memory.handshake(seeded_client, Server(s))
    assert isinstance(link.server_events[-1], HandshakeComplete)


def test_events_in_one_receive_keep_their_order() -> None:
    client, server = make()
    client.start()
    server.receive(client.data_to_send())
    flight = server.data_to_send()
    events = client.receive(flight)
    assert [type(e) for e in events] == [ServerAuthenticated, HandshakeComplete]
    server_events = server.receive(client.data_to_send())
    assert [type(e) for e in server_events] == [HandshakeComplete]
    server.send(b"late")
    assert client.receive(server.data_to_send()) == [ApplicationData(b"late")]


# --------------------------------------------------------------------------- #
# The oracle catches bugs both sides share (D16, P5)
# --------------------------------------------------------------------------- #


def _swap_labels(mp: pytest.MonkeyPatch, a: str, b: str) -> None:
    va, vb = getattr(ks, a), getattr(ks, b)
    mp.setattr(ks, a, vb)
    mp.setattr(ks, b, va)


def _swap_hybrid_halves(mp: pytest.MonkeyPatch, both: bool = True) -> None:
    finish, respond = hybrid.ClientKeyExchange.finish, hybrid.server_respond
    fix = (lambda ss: ss[32:] + ss[:32]) if both else (lambda ss: ss[:32] + bytes(32))
    mp.setattr(hybrid.ClientKeyExchange, "finish", lambda self, share: fix(finish(self, share)))
    mp.setattr(hybrid, "server_respond", lambda *a: (lambda r: (r[0], fix(r[1])))(respond(*a)))


def _no_derived_step(mp: pytest.MonkeyPatch) -> None:
    def handshake(self: ks.KeySchedule, shared_secret: bytes) -> bytes:
        self._advance(("early",), "handshake")
        self.handshake_secret = crypto.hkdf_extract(self.early_secret, shared_secret)  # type: ignore[arg-type]
        return self.handshake_secret

    mp.setattr(ks.KeySchedule, "handshake", handshake)


def _wrong_transcript_point(mp: pytest.MonkeyPatch, label: bytes) -> None:
    derive = hs.Connection._derive

    def patched(self: hs.Connection, secret: bytes, lab: bytes, th: bytes, keylog: str | None = None) -> bytes:
        return derive(self, secret, lab, ks.EMPTY_HASH if lab == label else th, keylog)

    mp.setattr(hs.Connection, "_derive", patched)


def _wrong_finished_label(mp: pytest.MonkeyPatch) -> None:
    original = ks.finished_key
    mp.setattr(ks, "finished_key", lambda secret, label=ks.FINISHED: original(secret, b"finishes"))


def _cv_over_empty_transcript(mp: pytest.MonkeyPatch) -> None:
    original = hs.signed_content
    mp.setattr(hs, "signed_content", lambda ctx, th: original(ctx, ks.EMPTY_HASH))


SHARED_BUGS = {
    "hs-labels-swapped": lambda mp: _swap_labels(mp, "C_HS_TRAFFIC", "S_HS_TRAFFIC"),
    "ap-labels-swapped": lambda mp: _swap_labels(mp, "C_AP_TRAFFIC", "S_AP_TRAFFIC"),
    "hybrid-secret-swapped": lambda mp: _swap_hybrid_halves(mp),
    "hybrid-secret-mlkem-only": lambda mp: _swap_hybrid_halves(mp, both=False),
    "no-derived-step": _no_derived_step,
    "c-ap-transcript-point": lambda mp: _wrong_transcript_point(mp, ks.C_AP_TRAFFIC),
    "s-hs-transcript-point": lambda mp: _wrong_transcript_point(mp, ks.S_HS_TRAFFIC),
    "finished-label": _wrong_finished_label,
    "cv-client-context": lambda mp: mp.setattr(hs, "SERVER_CV_CONTEXT", b"TLS 1.3, client CertificateVerify"),
    "cv-transcript": _cv_over_empty_transcript,
}


@pytest.mark.parametrize("bug", SHARED_BUGS)
def test_oracle_catches_bugs_both_sides_share(bug: str, monkeypatch: pytest.MonkeyPatch) -> None:
    client, server = make()
    with monkeypatch.context() as mp:
        SHARED_BUGS[bug](mp)
        link = memory.handshake(client, server)
        client.send(b"data")
        server.send(b"data")
        link.pump()
    assert client.state is server.state is State.CONNECTED  # the bug is invisible to the endpoints
    with pytest.raises(OracleMismatch):
        oracle(link)


# --------------------------------------------------------------------------- #
# RFC 8448 §3: the machine's packing and signed content (D17)
# --------------------------------------------------------------------------- #


def test_rfc8448_records_from_pack() -> None:
    from rfc8448_trace import CERT, CFIN, CV, EE, SFIN, SH, event, h

    def protection(actor: str, step: str) -> rl.RecordProtection:
        v = event(actor, step)
        return rl.RecordProtection(h(v["key expanded"]), h(v["iv expanded"]))

    server_records = [h(e["values"]["complete record"]) for e in _events("server", "send handshake record")]
    assert hs.pack(CT.handshake, SH, None) == [server_records[0]]
    flight = hs.pack(CT.handshake, EE + CERT + CV + SFIN, protection("server", "derive write traffic keys for handshake data"))
    assert flight == [server_records[1]]  # four messages, one record (D17)
    client_record = h(_events("client", "send handshake record")[1]["values"]["complete record"])
    assert hs.pack(CT.handshake, CFIN, protection("server", "derive read traffic keys for handshake data")) == [client_record]


def _events(actor: str, step: str) -> list[dict]:
    from rfc8448_trace import EVENTS

    return [e for e in EVENTS if e["actor"] == actor and e["step"] == step]


def test_rfc8448_certificate_verify_signs_our_signed_content() -> None:
    from cryptography import x509 as cx
    from rfc8448_trace import CERT, CH, CV, EE, SH

    cert = m.Certificate.decode(CERT[4:])
    key = cx.load_der_x509_certificate(cert.certificate_list[0].cert_data).public_key()
    cv = m.CertificateVerify.decode(CV[4:])
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    def verifies(content: bytes) -> bool:
        try:
            key.verify(cv.signature, content, pss, hashes.SHA256())  # type: ignore[union-attr, call-arg]
        except Exception:
            return False
        return True

    th = crypto.sha256(CH + SH + EE + CERT).digest()
    assert verifies(hs.signed_content(hs.SERVER_CV_CONTEXT, th))
    assert not verifies(hs.signed_content(b"TLS 1.3, client CertificateVerify", th))
    assert not verifies(hs.signed_content(hs.SERVER_CV_CONTEXT, crypto.sha256(CH + SH + EE).digest()))


def test_the_machine_uses_the_rfc8448_tested_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"pack": 0, "signed_content": 0}
    pack, content = hs.pack, hs.signed_content

    def counting_pack(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        calls["pack"] += 1
        return pack(*a, **kw)

    def counting_content(*a):  # noqa: ANN002, ANN202
        calls["signed_content"] += 1
        return content(*a)

    monkeypatch.setattr(hs, "pack", counting_pack)
    monkeypatch.setattr(hs, "signed_content", counting_content)
    memory.handshake(*make())
    assert calls == {"pack": 4, "signed_content": 2}  # CH; SH, flight, CFin; CV signed and verified


# --------------------------------------------------------------------------- #
# Determinism, randomness and pins
# --------------------------------------------------------------------------- #

PINNED_CLIENT_HELLO = {  # SHA-256 of the ClientHello record (D16)
    "A": "2980682493feb33a04fd04b9c417800a9aff3a2f27c5b8ac11ec82db2e64b4a3",
    "B/ML-DSA-44/ML-DSA-44/0": "d134ea8e0dccc5df5c2d166692673a529f13af8139e56e5aad01d14c3446cde8",
    "B/ML-DSA-44/Falcon-512/0": "0c28ed174ea3dc1c58997ca7b435437aa8f8e59fe51357566c2791b86e64fe12",
    "B/Falcon-512/ML-DSA-44/2": "dfbe07c08b54f85537473b9a8f6ab286c379909e69b95a8bb3ec72b964ccf3a0",
    "B/ML-DSA-65/ML-DSA-65/2": "74c63a6748eb32e342878f450c019384ffb9147d4ae9d73dac21249f7e6bb2f4",
}
PINNED_WIRE = {  # SHA-256 of client wire ‖ server wire, for the whole handshake
    "A": "8fef073fc3e4bb0244e8a81363b799462ae03a9698aacbe531e987e738a5b4de",
    "B/ML-DSA-44/ML-DSA-44/0": "1b6c1b9f24ab0ae92de180bae060ffc0189b7cdd5b20db70f3a8abf1b6dd3b2e",
    "B/ML-DSA-44/Falcon-512/0": "dc3d42c00b91f7bee867f830f09a4b0353d5bb980e8830c53f6b67829798d643",
    "B/Falcon-512/ML-DSA-44/2": "06b22422408cd9ab74cf92e6fb7a54137f47e06d800f601d3153c6c0cb43e218",
    "B/ML-DSA-65/ML-DSA-65/2": "5e31a463c58cea2df3c1cb2c02078414a33e0572f6a54e0cca495018b5d4692d",
}
PINNED_STREAM = "21d6875a5e336fe6fe3858cc93ba6322c4d7b415e2c82a258d49cc445d93b9cd"  # the seeded stream on its own


def _run_wires(cfg: configs.SigConfig, seed: bytes = SEED) -> tuple[bytes, bytes]:
    link = memory.handshake(*make(cfg, seed))
    return wires(link)


@pytest.mark.parametrize("cfg", MATRIX, ids=lambda c: c.name)
def test_seeded_handshakes_are_pinned(cfg: configs.SigConfig) -> None:
    c_wire, s_wire = _run_wires(cfg)
    assert (c_wire, s_wire) == _run_wires(cfg)
    first = rl.split_records(c_wire)[0][0]
    assert crypto.sha256(first).digest().hex() == PINNED_CLIENT_HELLO[cfg.name]
    assert crypto.sha256(c_wire + s_wire).digest().hex() == PINNED_WIRE[cfg.name]


def test_seeded_stream_is_pinned() -> None:
    parts = [hs.seeded_bytes(b"s", role, label, i, 40) for role in ("client", "server") for label in ("random", "x") for i in (0, 1)]
    assert crypto.sha256(b"".join(parts)).digest().hex() == PINNED_STREAM
    assert len(set(parts)) == len(parts)


def test_every_random_field_depends_on_the_seed() -> None:
    one, two = reference(A, SEED), reference(A, b"another seed")
    for name in ("CH", "SH", "CV"):  # randoms, both shares, and the server's signature randomness
        assert one.messages[name] != two.messages[name], name
    ch1, sh1 = m.ClientHello.decode(one.messages["CH"][4:]), m.ServerHello.decode(one.messages["SH"][4:])
    ch2, sh2 = m.ClientHello.decode(two.messages["CH"][4:]), m.ServerHello.decode(two.messages["SH"][4:])
    assert ch1.random != ch2.random and sh1.random != sh2.random and ch1.random != sh1.random
    for field_ in (ExtensionType.key_share,):
        assert m.find_extension(ch1.extensions, field_) != m.find_extension(ch2.extensions, field_)
        assert m.find_extension(sh1.extensions, field_) != m.find_extension(sh2.extensions, field_)
    assert one.shared_secret != two.shared_secret


@pytest.mark.parametrize("cfg", [A, B_FALCON], ids=lambda c: c.name)
def test_randomness_draws_are_exact(cfg: configs.SigConfig) -> None:
    c, s, _ = endpoints(cfg)
    cr, sr = SeededRandomness(SEED), SeededRandomness(SEED)
    with crypto.count_ops() as ops:
        memory.handshake(Client(dataclasses.replace(c, randomness=cr)), Server(dataclasses.replace(s, randomness=sr)))
    assert cr.streams["client"].calls == {"x25519": 1, "kem/ML-KEM-768": 1, "random": 1}
    assert sr.streams["server"].calls == {"x25519": 1, "encap/ML-KEM-768": 1, "random": 1, f"sign/{cfg.leaf_alg}": 1}
    assert ("openssl", "X25519", "keygen") not in ops and ops[("openssl", "X25519", "import")] == 2


def test_seeded_randomness_gives_each_role_one_stream() -> None:
    rng = SeededRandomness(SEED)
    rng.for_connection("client")
    with pytest.raises(CodecUsageError):
        rng.for_connection("client")
    c, _, _ = endpoints(A)
    Client(dataclasses.replace(c, randomness=SeededRandomness(SEED)))
    shared = SeededRandomness(SEED)
    Client(dataclasses.replace(c, randomness=shared))
    with pytest.raises(CodecUsageError):
        Client(dataclasses.replace(c, randomness=shared))


# --------------------------------------------------------------------------- #
# Delivery: chunking, record layouts, flights
# --------------------------------------------------------------------------- #


def _bytewise(data: bytes):  # noqa: ANN202
    yield from (data[i : i + 1] for i in range(len(data)))


def _random_chunks(seed: int):  # noqa: ANN202
    rnd = random.Random(seed)

    def chunks(data: bytes):  # noqa: ANN202
        pos = 0
        while pos < len(data):
            n = rnd.randint(1, 3000)
            yield data[pos : pos + n]
            pos += n

    return chunks


@pytest.mark.parametrize("chunker", [_bytewise] + [_random_chunks(i) for i in range(20)])
def test_delivery_chunking_never_changes_the_result(chunker) -> None:  # noqa: ANN001
    whole = memory.handshake(*make(B44_FALCON_ISSUER))
    chunked = memory.handshake(*make(B44_FALCON_ISSUER), chunks=chunker)
    for link in (whole, chunked):
        link.client.send(b"ping")
        link.pump()
    assert chunked.wire == whole.wire
    assert chunked.client_events == whole.client_events and chunked.server_events == whole.server_events


def test_flights_dont_depend_on_when_the_transport_drains() -> None:
    early, late = make(), make()
    for client, server, send_before_drain in ((*early, True), (*late, False)):
        client.start()
        server.receive(client.data_to_send())
        client.receive(server.data_to_send())
        if send_before_drain:
            client.send(b"data")
            server.receive(client.data_to_send())
        else:
            server.receive(client.data_to_send())
            client.send(b"data")
            server.receive(client.data_to_send())
    assert [len(f.records) for f in early[0].flights] == [len(f.records) for f in late[0].flights] == [1, 2]
    assert [f.records for f in early[0].flights] == [f.records for f in late[0].flights]


SERVER_LAYOUTS = {
    "one-record-per-message": lambda t: [len(x) for x in t.server_flight()],
    "certificate-split": lambda t: [len(t.messages["EE"]) + 7, len(t.messages["CERT"]) - 7 - 100, 100,
                                    len(t.messages["CV"]) + len(t.messages["SFIN"])],  # fmt: skip
    "byte-records": lambda t: [1] * 40 + [sum(len(x) for x in t.server_flight()) - 40],
}


@pytest.mark.parametrize("layout", SERVER_LAYOUTS)
def test_client_accepts_any_server_record_layout(layout: str) -> None:
    trace = reference(A)
    flight = b"".join(trace.server_flight())
    sh = trace.messages["SH"]
    records = plain(sh[:50]) + plain(sh[50:])  # ServerHello across two records
    records += sealed(s_hs(trace), flight, sizes=SERVER_LAYOUTS[layout](trace), padding=3)
    client = waiting_client()
    events = client.receive(records)
    assert [type(e) for e in events] == [ServerAuthenticated, HandshakeComplete]


def test_server_accepts_a_split_client_hello_and_any_client_layout() -> None:
    trace = reference(A)
    ch = trace.messages["CH"]
    _, server = make()
    server.receive(rl.encode_plaintext(CT.handshake, ch[:100], 0x0301) + rl.encode_plaintext(CT.handshake, ch[100:]))
    assert server.state is State.WAIT_CLIENT_FINISHED
    cfin = trace.messages["CFIN"]
    c_hs = trace.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]
    assert [type(e) for e in server.receive(sealed(c_hs, cfin, sizes=[5, len(cfin) - 5], padding=9))] == [HandshakeComplete]


# --------------------------------------------------------------------------- #
# ClientHello rules (server side; D16)
# --------------------------------------------------------------------------- #


def _client_hello() -> m.ClientHello:
    return m.ClientHello.decode(reference(A).messages["CH"][4:])


def _with(hello: m.ClientHello, drop: tuple[int, ...] = (), **replace: bytes) -> m.ClientHello:
    """Drop extensions, or replace their bodies (``key_share=...``), keeping wire order."""
    bodies = {ExtensionType[k]: v for k, v in replace.items()}
    exts = tuple(m.Extension(e.ext_type, bodies.get(e.ext_type, e.data)) for e in hello.extensions if e.ext_type not in drop)
    return dataclasses.replace(hello, extensions=exts)


def _share(*entries: tuple[int, bytes]) -> bytes:
    return m.encode_key_share([m.KeyShareEntry(g, k) for g, k in entries], Context.client_hello)


def _ch_share() -> bytes:
    return m.decode_key_share(m.find_extension(_client_hello().extensions, ExtensionType.key_share), Context.client_hello)[0].key_exchange  # type: ignore[index, union-attr, arg-type]


X25519 = 0x001D
CH_RULES = {
    "no-supported-versions": (lambda h: _with(h, drop=(ExtensionType.supported_versions,)), Alert.protocol_version, "version"),
    "tls12-only": (lambda h: _with(h, supported_versions=m.encode_supported_versions([0x0303], Context.client_hello)), Alert.protocol_version, "version"),
    "no-aes128": (lambda h: dataclasses.replace(h, cipher_suites=(0x1302,)), Alert.handshake_failure, "cipher-suite"),
    "no-supported-groups": (lambda h: _with(h, drop=(ExtensionType.supported_groups,)), Alert.missing_extension, "groups-and-shares"),
    "no-key-share": (lambda h: _with(h, drop=(ExtensionType.key_share,)), Alert.missing_extension, "groups-and-shares"),
    "group-not-offered": (lambda h: _with(h, supported_groups=m.encode_supported_groups([X25519]), key_share=_share((X25519, bytes(range(32))))), Alert.handshake_failure, "group"),
    "no-hybrid-share": (lambda h: _with(h, supported_groups=m.encode_supported_groups([hybrid.GROUP, X25519]), key_share=_share((X25519, bytes(range(32))))), Alert.handshake_failure, "no-share"),
    "duplicate-share": (lambda h: _with(h, key_share=_share((hybrid.GROUP, _ch_share()), (hybrid.GROUP, _ch_share()))), Alert.illegal_parameter, "duplicate-share"),
    "share-not-in-groups": (lambda h: _with(h, key_share=_share((X25519, bytes(32)), (hybrid.GROUP, _ch_share()))), Alert.illegal_parameter, "share-not-offered"),
    "no-signature-algorithms": (lambda h: _with(h, drop=(ExtensionType.signature_algorithms,)), Alert.missing_extension, "signature-algorithms"),
    "scheme-not-accepted": (lambda h: _with(h, signature_algorithms=m.encode_signature_algorithms([0x0905])), Alert.handshake_failure, "signature-scheme"),
    "share-length": (lambda h: _with(h, key_share=_share((hybrid.GROUP, _ch_share()[:-1]))), Alert.illegal_parameter, "share-length"),
    "x25519-low-order": (lambda h: _with(h, key_share=_share((hybrid.GROUP, _ch_share()[:-32] + bytes(32)))), Alert.illegal_parameter, "x25519"),
    "unreduced-ek": (lambda h: _with(h, key_share=_share((hybrid.GROUP, bytes([0xFF, _ch_share()[1] | 0x0F]) + _ch_share()[2:]))), Alert.illegal_parameter, "mlkem-ek"),
    "bad-sni": (lambda h: _with(h, server_name=b"\x00\x05\x01\x00\x02ab"), Alert.illegal_parameter, "server-name"),
}  # fmt: skip


@pytest.mark.parametrize("rule", CH_RULES)
def test_client_hello_rules(rule: str) -> None:
    edit, alert, reason = CH_RULES[rule]
    _, server = make()
    events = server.receive(plain(m.encode_handshake(edit(_client_hello())), 0x0301))
    assert_fails(events, alert, reason)
    assert rl.decode_plaintext(server.data_to_send()) == (CT.alert, bytes([2, alert]))  # plaintext: no keys yet
    assert server.receive(b"anything") == []  # input after failure is ignored


def test_client_hello_rule_baseline_is_accepted() -> None:
    _, server = make()
    assert server.receive(plain(m.encode_handshake(_with(_client_hello())), 0x0301)) == []
    assert server.state is State.WAIT_CLIENT_FINISHED


@pytest.mark.parametrize("variant", ["unknown-extensions", "other-shares-first", "no-sni"])
def test_client_hello_tolerances(variant: str) -> None:
    hello = _client_hello()
    variants = {
        "unknown-extensions": dataclasses.replace(hello, extensions=hello.extensions + (m.Extension(0x4A4A, b""), m.Extension(45, b"\x01\x01"))),
        "other-shares-first": _with(hello, supported_groups=m.encode_supported_groups([X25519, hybrid.GROUP]), key_share=_share((X25519, bytes(range(32))), (hybrid.GROUP, _ch_share()))),
        "no-sni": _with(hello, drop=(ExtensionType.server_name,)),
    }  # fmt: skip
    _, server = make()
    assert server.receive(plain(m.encode_handshake(variants[variant]), 0x0301)) == []
    assert server.state is State.WAIT_CLIENT_FINISHED
    assert server.server_name == (None if variant == "no-sni" else "qtls.test")
    # EncryptedExtensions acknowledges server_name only when the client sent it (RFC 6066 §3).
    # The oracle can't follow an edited ClientHello, so decrypt with the server's logged key.
    records = rl.split_records(server.data_to_send())[0]
    _, flight = _open(server.keylog["SERVER_HANDSHAKE_TRAFFIC_SECRET"], records[1])
    ee = m.EncryptedExtensions.decode(flight[4 : 4 + int.from_bytes(flight[1:4], "big")])
    assert [e.ext_type for e in ee.extensions] == ([] if variant == "no-sni" else [ExtensionType.server_name])


def test_compatibility_mode_client_hello_is_echoed_and_its_ccs_dropped() -> None:
    hello = dataclasses.replace(_client_hello(), legacy_session_id=bytes(range(32)))
    _, server = make()
    ccs = rl.encode_plaintext(CT.change_cipher_spec, b"\x01")
    assert server.receive(plain(m.encode_handshake(hello), 0x0301) + ccs) == []
    sh = m.ServerHello.decode(rl.decode_plaintext(rl.split_records(server.data_to_send())[0][0])[1][4:])
    assert sh.legacy_session_id_echo == bytes(range(32))
    assert b"\x14\x03\x03" not in b"".join(r[:3] for r in server.flights[0].records)  # qTLS never sends CCS (D16)


# --------------------------------------------------------------------------- #
# ServerHello rules (client side; D16, D27)
# --------------------------------------------------------------------------- #


def _server_hello() -> m.ServerHello:
    return m.ServerHello.decode(reference(A).messages["SH"][4:])


def _sh_with(hello: m.ServerHello, drop: tuple[int, ...] = (), add: tuple[m.Extension, ...] = (), **replace: bytes) -> m.ServerHello:
    bodies = {ExtensionType[k]: v for k, v in replace.items()}
    exts = tuple(m.Extension(e.ext_type, bodies.get(e.ext_type, e.data)) for e in hello.extensions if e.ext_type not in drop)
    return dataclasses.replace(hello, extensions=exts + add)


def _sh_share(transform) -> bytes:  # noqa: ANN001
    entry = m.decode_key_share(m.find_extension(_server_hello().extensions, ExtensionType.key_share), Context.server_hello)  # type: ignore[arg-type]
    assert isinstance(entry, m.KeyShareEntry)
    group, data = transform(entry.group, entry.key_exchange)
    return m.encode_key_share(m.KeyShareEntry(group, data), Context.server_hello)


def _random(tail: bytes) -> bytes:
    return bytes(24) + tail


SH_RULES = {
    "downgrade-tls12": (lambda h: dataclasses.replace(h, random=_random(b"DOWNGRD\x01")), Alert.illegal_parameter, "downgrade"),
    "downgrade-tls11": (lambda h: dataclasses.replace(h, random=_random(b"DOWNGRD\x00")), Alert.illegal_parameter, "downgrade"),
    "hello-retry-request": (lambda h: dataclasses.replace(h, random=m.HRR_RANDOM), Alert.unexpected_message, "hrr"),
    "session-id-echo": (lambda h: dataclasses.replace(h, legacy_session_id_echo=b"\x01" * 32), Alert.illegal_parameter, "session-id"),
    "cipher-suite": (lambda h: dataclasses.replace(h, cipher_suite=0x1302), Alert.illegal_parameter, "cipher-suite"),
    "no-supported-versions": (lambda h: _sh_with(h, drop=(ExtensionType.supported_versions,)), Alert.protocol_version, "version"),
    "selected-tls12": (lambda h: _sh_with(h, supported_versions=b"\x03\x03"), Alert.illegal_parameter, "version-value"),
    "offered-but-not-allowed": (lambda h: _sh_with(h, add=(m.Extension(ExtensionType.signature_algorithms, b"\x00\x02\x04\x03"),)), Alert.illegal_parameter, "extension-not-allowed"),
    "never-offered": (lambda h: _sh_with(h, add=(m.Extension(0xFF99, b""),)), Alert.unsupported_extension, "extension-not-offered"),
    "group": (lambda h: _sh_with(h, key_share=_sh_share(lambda g, d: (X25519, d))), Alert.illegal_parameter, "group"),
    "share-length": (lambda h: _sh_with(h, key_share=_sh_share(lambda g, d: (g, d[:-1]))), Alert.illegal_parameter, "share-length"),
    "x25519-low-order": (lambda h: _sh_with(h, key_share=_sh_share(lambda g, d: (g, d[:-32] + bytes(32)))), Alert.illegal_parameter, "x25519"),
}  # fmt: skip


@pytest.mark.parametrize("rule", SH_RULES)
def test_server_hello_rules(rule: str) -> None:
    edit, alert, reason = SH_RULES[rule]
    client = waiting_client()
    assert_fails(client.receive(plain(m.encode_handshake(edit(_server_hello())))), alert, reason)
    assert rl.decode_plaintext(client.data_to_send()) == (CT.alert, bytes([2, alert]))


def test_server_hello_without_key_share_is_missing_extension() -> None:
    hello = _sh_with(_server_hello(), drop=(ExtensionType.key_share,))
    raw = m.encode_handshake(dataclasses.replace(hello, extensions=hello.extensions))
    # supported_versions alone is 6 bytes, the ServerHello extension-block minimum.
    assert_fails(waiting_client().receive(plain(raw)), Alert.missing_extension, "no-key-share")


def _tls12_server_hello(random: bytes, extensions: bytes | None) -> bytes:
    body = b"\x03\x03" + random + b"\x00" + b"\xc0\x2f" + b"\x00"
    if extensions is not None:
        body += len(extensions).to_bytes(2, "big") + extensions
    return handshake_message(HandshakeType.server_hello, body)


@pytest.mark.parametrize(
    ("random_", "exts", "alert", "reason"),
    [
        (_random(b"DOWNGRD\x01"), None, Alert.illegal_parameter, "downgrade"),
        (_random(b"DOWNGRD\x00"), b"\xff\x01\x00\x01\x00", Alert.illegal_parameter, "downgrade"),
        (bytes(range(32)), None, Alert.decode_error, "decode"),
        (bytes(range(32)), b"\xff\x01\x00\x01\x00", Alert.decode_error, "decode"),
        (bytes(range(32)), b"\xff\x01\x00\x01\x00\x00\x0b\x00\x02\x01\x00", Alert.protocol_version, "version"),
    ],
    ids=["sentinel-no-extensions", "sentinel-reneg", "no-extensions", "reneg-only", "reneg-and-point-formats"],
)
def test_genuine_tls12_server_hello(random_: bytes, exts: bytes | None, alert: Alert, reason: str) -> None:
    """D27: the sentinel is checked before the TLS 1.3 decode; then the 1.3 shape decides."""
    assert_fails(waiting_client().receive(plain(_tls12_server_hello(random_, exts))), alert, reason)


def test_server_hello_tolerances() -> None:
    hello = _server_hello()
    reordered = dataclasses.replace(hello, extensions=hello.extensions[::-1])
    trace = reference(A)
    client = waiting_client()
    client.receive(plain(m.encode_handshake(reordered)))
    assert client.state is State.WAIT_EE  # the extension order is free; the transcript then differs:
    assert_fails(client.receive(sealed(s_hs(trace), b"".join(trace.server_flight()))), Alert.bad_record_mac, "bad-mac")


def test_server_hello_must_end_its_record() -> None:
    trace = reference(A)
    assert_fails(waiting_client().receive(plain(trace.messages["SH"] + trace.messages["EE"])), Alert.unexpected_message, "record-end")


def test_tampered_key_share_fails_at_the_first_encrypted_record_on_both_sides() -> None:
    """Implicit rejection: the client derives other keys, so neither side can read the other (D10)."""
    client, server = make()
    client.start()
    server.receive(client.data_to_send())
    sh_record, flight = rl.split_records(server.data_to_send())[0][0], server.flights[0].records[1:]
    tampered = bytearray(sh_record)
    tampered[200] ^= 1  # inside the ML-KEM ciphertext
    events = client.receive(bytes(tampered) + b"".join(flight))
    assert_fails(events, Alert.bad_record_mac, "bad-mac")
    assert_fails(server.receive(client.data_to_send()), Alert.bad_record_mac, "bad-mac")


# --------------------------------------------------------------------------- #
# The encrypted server flight (P7, P9)
# --------------------------------------------------------------------------- #


def _ee(*exts: m.Extension) -> bytes:
    return m.encode_handshake(m.EncryptedExtensions(exts))


def _flight(**replace: bytes) -> list[bytes]:
    t = reference(A)
    return [replace.get(k, t.messages[k]) for k in ("EE", "CERT", "CV", "SFIN")]


def _cert(context: bytes = b"", entries: tuple[m.CertificateEntry, ...] | None = None) -> bytes:
    if entries is None:
        entries = tuple(m.CertificateEntry(c) for c in endpoints(A)[2].cert_data)
    return m.encode_handshake(m.Certificate(context, entries))


def _cv(scheme: int = 0x0403, *, context: bytes = hs.SERVER_CV_CONTEXT, key: crypto.SigPrivateKey | None = None,
        transcript: bytes | None = None) -> bytes:  # fmt: skip
    t = reference(A)
    key = key or endpoints(A)[1].signing_key
    th = transcript if transcript is not None else crypto.sha256(t.messages["CH"] + t.messages["SH"] + t.messages["EE"] + t.messages["CERT"]).digest()
    return m.encode_handshake(m.CertificateVerify(scheme, key.sign(hs.signed_content(context, th), seed=b"")))


FLIGHT_RULES = {
    "ee-server-name-not-empty": (lambda: _flight(EE=_ee(m.Extension(0, b"\x00"))), Alert.decode_error, "decode"),
    "ee-key-share": (lambda: _flight(EE=_ee(m.Extension(ExtensionType.key_share, b""))), Alert.illegal_parameter, "extension-not-allowed"),
    "ee-supported-versions": (lambda: _flight(EE=_ee(m.Extension(ExtensionType.supported_versions, b"\x03\x04"))), Alert.illegal_parameter, "extension-not-allowed"),
    "ee-unknown": (lambda: _flight(EE=_ee(m.Extension(28, b"\x40\x01"))), Alert.unsupported_extension, "extension-not-offered"),
    "certificate-context": (lambda: _flight(CERT=_cert(b"\x01")), Alert.illegal_parameter, "certificate-context"),
    "certificate-empty": (lambda: _flight(CERT=_cert(entries=())), Alert.decode_error, "empty-certificate"),
    "certificate-entry-extension": (lambda: _flight(CERT=_cert(entries=(m.CertificateEntry(endpoints(A)[2].cert_data[0], (m.Extension(5, b""),)), m.CertificateEntry(endpoints(A)[2].cert_data[1])))), Alert.unsupported_extension, "extension-not-offered"),
    "certificate-tampered": (lambda: _flight(CERT=_cert(entries=(m.CertificateEntry(endpoints(A)[2].cert_data[0][:-1] + b"\x00"), m.CertificateEntry(endpoints(A)[2].cert_data[1])))), Alert.bad_certificate, "signature"),
    "cv-scheme-not-offered": (lambda: _flight(CV=_cv(0x0905)), Alert.illegal_parameter, "cv-scheme-not-offered"),
    "cv-other-key": (lambda: _flight(CV=_cv(key=chains.signing_key("ECDSA-P256-SHA256", b"other", "leaf"))), Alert.decrypt_error, "cv-signature"),
    "cv-client-context": (lambda: _flight(CV=_cv(context=b"TLS 1.3, client CertificateVerify")), Alert.decrypt_error, "cv-signature"),
    "cv-other-transcript": (lambda: _flight(CV=_cv(transcript=bytes(32))), Alert.decrypt_error, "cv-signature"),
    "finished-flipped": (lambda: _flight(SFIN=reference(A).messages["SFIN"][:-1] + bytes([reference(A).messages["SFIN"][-1] ^ 1])), Alert.decrypt_error, "server-finished"),
    # Accepted EE; the unchanged CertificateVerify then covers a different transcript:
    "ee-supported-groups-accepted": (lambda: _flight(EE=_ee(m.Extension(ExtensionType.supported_groups, m.encode_supported_groups([hybrid.GROUP])))), Alert.decrypt_error, "cv-signature"),
    "finished-not-last-in-record": (lambda: _flight() + [handshake_message(HandshakeType.new_session_ticket, bytes(13))], Alert.unexpected_message, "record-end"),
}  # fmt: skip


@pytest.mark.parametrize("rule", FLIGHT_RULES)
def test_encrypted_flight_rules(rule: str) -> None:
    flight, alert, reason = FLIGHT_RULES[rule]
    assert_fails(deliver_flight(flight()), alert, reason)


def test_cv_scheme_must_fit_the_leaf() -> None:
    # The client offers ML-DSA-44 too, so 0x0904 is offered but isn't the ECDSA leaf's scheme.
    offers = {"signature_algorithms": (0x0403, 0x0904)}
    link = memory.handshake(*make(**offers))
    t = oracle(link)
    cv = m.CertificateVerify.decode(t.messages["CV"][4:])
    flight = [t.messages["EE"], t.messages["CERT"], m.encode_handshake(dataclasses.replace(cv, algorithm=0x0904)), t.messages["SFIN"]]
    client = waiting_client(**offers)
    events = client.receive(plain(t.messages["SH"]) + sealed(s_hs(t), b"".join(flight)))
    assert_fails(events, Alert.illegal_parameter, "cv-scheme-mismatch")


def test_a_correct_flight_with_an_edited_ee_completes() -> None:
    """The positive control for the edit-and-reseal harness: re-signed and re-finished, it's accepted."""
    t = reference(A)
    ee = _ee(m.Extension(ExtensionType.supported_groups, m.encode_supported_groups([hybrid.GROUP])))
    cert = t.messages["CERT"]
    th = crypto.sha256(t.messages["CH"] + t.messages["SH"] + ee + cert).digest()
    cv = _cv(transcript=th)
    events = deliver_flight([ee, cert, cv, finished_for(t, [ee, cert, cv])])
    assert [type(e) for e in events] == [ServerAuthenticated, HandshakeComplete]


@pytest.mark.parametrize(
    ("client_kw", "alert", "reason"),
    [
        ({"anchors": (x509.TrustAnchor(x509.name("another root"), endpoints(A)[2].anchor.spki_raw),)}, Alert.unknown_ca, "unknown-anchor"),
        ({"anchors": (chains.build_chain(leaf_alg="ECDSA-P256-SHA256", issuer_alg="ECDSA-P256-SHA256", not_before=NOT_BEFORE, fixture_seed=b"other").anchor,)}, Alert.bad_certificate, "signature"),
        ({"now": NOT_BEFORE + dt.timedelta(days=91)}, Alert.certificate_expired, "validity"),
        ({"now": NOT_BEFORE - dt.timedelta(seconds=1)}, Alert.certificate_expired, "validity"),
        ({"server_name": "other.test"}, Alert.bad_certificate, "name"),
    ],
    ids=["untrusted-root", "same-name-other-key", "expired", "not-yet-valid", "wrong-name"],
)
def test_client_rejects_the_chain(client_kw: dict, alert: Alert, reason: str) -> None:
    client, server = make(**client_kw)
    link = memory.handshake(client, server)
    assert_fails(link.client_events, alert, reason)
    assert link.server_events == [PeerAlerted(2, alert)]
    # The alert went under c hs traffic (the server's plaintext-alert window would also have taken plaintext).
    alert_record = link.wire[-1][1]
    assert alert_record[0] == CT.application_data
    assert _open(link.client.keylog["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], alert_record) == (CT.alert, bytes([2, alert]))


def test_wall_clock_time_would_fail_the_fixtures() -> None:
    client, server = make(now=dt.datetime.now(UTC))
    assert_fails(memory.handshake(client, server).client_events, Alert.certificate_expired, "validity")


@pytest.mark.parametrize(
    "order",
    [("EE", "CV", "CERT", "SFIN"), ("CERT", "EE", "CV", "SFIN"), ("EE", "EE", "CERT", "CV", "SFIN"),
     ("EE", "CERT", "SFIN"), ("CERT", "CV", "SFIN"), ("EE", "CERT", "CV", "CV", "SFIN"), ("SFIN",)],
    ids=["cv-before-cert", "cert-before-ee", "duplicate-ee", "missing-cv", "missing-ee", "duplicate-cv", "only-finished"],
)  # fmt: skip
def test_server_flight_order(order: tuple[str, ...]) -> None:
    t = reference(A)
    assert_fails(deliver_flight([t.messages[k] for k in order]), Alert.unexpected_message, "unexpected-message")


def test_kem_leaf_is_refused_under_signature_authentication() -> None:
    kem_chain = chains.build_chain(leaf_alg="ML-KEM-768", issuer_alg="ECDSA-P256-SHA256", not_before=NOT_BEFORE)
    events = deliver_flight(_flight(CERT=_cert(entries=tuple(m.CertificateEntry(c) for c in kem_chain.cert_data))),
                            anchors=(kem_chain.anchor,))  # fmt: skip
    assert_fails(events, Alert.unsupported_certificate, "leaf-kind")


# --------------------------------------------------------------------------- #
# Negotiation across configurations (P8, D25)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("client_cfg", [A, B44, B65], ids=lambda c: c.name)
@pytest.mark.parametrize("server_cfg", [A, B44, B65], ids=lambda c: c.name)
def test_cross_config_matrix(client_cfg: configs.SigConfig, server_cfg: configs.SigConfig) -> None:
    client_config = endpoints(client_cfg)[0]
    client, server = make(server_cfg, anchors=client_config.anchors, signature_algorithms=client_config.signature_algorithms,
                          signature_algorithms_cert=client_config.signature_algorithms_cert)  # fmt: skip
    link = memory.handshake(client, server)
    if client_cfg == server_cfg:
        assert isinstance(link.client_events[-1], HandshakeComplete)
    else:
        assert_fails(link.server_events, Alert.handshake_failure, "signature-scheme")
        assert link.client_events == [PeerAlerted(2, Alert.handshake_failure)]


@pytest.mark.parametrize(
    ("sig_algs", "sig_algs_cert", "ok"),
    [
        ((0x0904,), (0xFE50,), True),  # issuer scheme only in signature_algorithms_cert
        ((0x0904, 0xFE50), None, True),  # no _cert list: signature_algorithms is the fallback
        ((0x0904, 0xFE50), (0x0904,), False),  # the _cert list decides even if signature_algorithms has it
        ((0x0904,), None, False),
    ],
    ids=["cert-list", "fallback", "cert-list-wins", "neither"],
)
def test_signature_algorithms_cert_fallback(sig_algs: tuple[int, ...], sig_algs_cert: tuple[int, ...] | None, ok: bool) -> None:
    """RFC 8446 §4.2.3. The server sends its chain anyway; the client decides (D25)."""
    client, server = make(B44_FALCON_ISSUER, signature_algorithms=sig_algs, signature_algorithms_cert=sig_algs_cert)
    link = memory.handshake(client, server)
    if ok:
        assert isinstance(link.client_events[-1], HandshakeComplete)
    else:
        assert_fails(link.client_events, Alert.unsupported_certificate, "algorithm")


# --------------------------------------------------------------------------- #
# State × message matrix (P9)
# --------------------------------------------------------------------------- #


def _client_in(state: State) -> tuple[Client, Trace]:
    t = reference(A)
    client = waiting_client()
    upto = {State.WAIT_SH: 0, State.WAIT_EE: 1, State.WAIT_CERT: 2, State.WAIT_CV: 3, State.WAIT_FINISHED: 4}
    if state is not State.WAIT_SH:
        names = ["EE", "CERT", "CV", "SFIN"][: upto[state] - 1]
        protection = rl.RecordProtection.from_secret(s_hs(t))
        client.receive(plain(t.messages["SH"]) + (sealed(b"", b"".join(t.messages[n] for n in names), protection=protection) if names else b""))
        client._test_protection = protection  # type: ignore[attr-defined]
    assert client.state is state
    return client, t


SAMPLE_BODIES = {int(t): bytes(4) for t in HandshakeType}


CLIENT_ACCEPTS = {State.WAIT_SH: HandshakeType.server_hello, State.WAIT_EE: HandshakeType.encrypted_extensions,
                  State.WAIT_CERT: HandshakeType.certificate, State.WAIT_CV: HandshakeType.certificate_verify,
                  State.WAIT_FINISHED: HandshakeType.finished}  # fmt: skip


@pytest.mark.parametrize(
    ("state", "msg_type"),
    [(s, t) for s in CLIENT_ACCEPTS for t in HandshakeType if t != CLIENT_ACCEPTS[s]],  # accepting rows: every handshake
    ids=lambda v: v.name,
)
def test_client_state_message_matrix(state: State, msg_type: HandshakeType) -> None:
    client, _ = _client_in(state)
    message = handshake_message(msg_type, SAMPLE_BODIES[msg_type])
    if state is State.WAIT_SH:
        events = client.receive(plain(message))
    else:
        events = client.receive(sealed(b"", message, protection=client._test_protection))  # type: ignore[attr-defined]
    assert_fails(events, Alert.unexpected_message, "unexpected-message")


@pytest.mark.parametrize("msg_type", list(HandshakeType), ids=lambda t: t.name)
def test_server_state_message_matrix(msg_type: HandshakeType) -> None:
    t = reference(A)
    message = handshake_message(msg_type, SAMPLE_BODIES[msg_type])
    if msg_type != HandshakeType.client_hello:
        _, server = make()
        assert_fails(server.receive(plain(message, 0x0301)), Alert.unexpected_message, "unexpected-message")
    if msg_type != HandshakeType.finished:  # WAIT_CLIENT_FINISHED
        _, server = make()
        server.receive(plain(t.messages["CH"], 0x0301))
        events = server.receive(sealed(t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], message))
        assert_fails(events, Alert.unexpected_message, "unexpected-message")
    # CONNECTED: no handshake message is accepted from the client (D26).
    client, server = make()
    memory.handshake(client, server)
    events = server.receive(sealed(t.secrets["CLIENT_TRAFFIC_SECRET_0"], message))
    assert_fails(events, Alert.unexpected_message, "unexpected-message")


def test_unknown_handshake_type_is_unexpected_message() -> None:
    client = waiting_client()
    assert_fails(client.receive(plain(handshake_message(99, b""))), Alert.unexpected_message, "unknown-type")


# --------------------------------------------------------------------------- #
# Post-handshake messages and closure (D26)
# --------------------------------------------------------------------------- #


def _connected() -> tuple[Client, Server, Trace]:
    client, server = make()
    memory.handshake(client, server)
    return client, server, reference(A)


def test_new_session_ticket_is_dropped_after_the_handshake() -> None:
    client, _, t = _connected()
    s_ap = rl.RecordProtection.from_secret(t.secrets["SERVER_TRAFFIC_SECRET_0"])
    ticket = handshake_message(HandshakeType.new_session_ticket, bytes(40))
    events = client.receive(sealed(b"", ticket, sizes=[10, len(ticket) - 10], protection=s_ap)
                            + sealed(b"", b"after", CT.application_data, protection=s_ap))  # fmt: skip
    assert events == [ApplicationData(b"after")]


def test_other_post_handshake_messages_are_unexpected() -> None:
    client, _, t = _connected()
    s_ap = rl.RecordProtection.from_secret(t.secrets["SERVER_TRAFFIC_SECRET_0"])
    events = client.receive(sealed(b"", handshake_message(HandshakeType.key_update, b"\x00"), protection=s_ap))
    assert_fails(events, Alert.unexpected_message, "unexpected-message")


def test_new_session_ticket_before_the_handshake_ends_is_unexpected() -> None:
    t = reference(A)
    events = deliver_flight([t.messages["EE"], handshake_message(HandshakeType.new_session_ticket, bytes(40))])
    assert_fails(events, Alert.unexpected_message, "unexpected-message")


def test_half_close_still_delivers_the_peers_data() -> None:
    client, server = make()
    memory.handshake(client, server)
    client.close()
    server.send(b"in flight")  # sent before the server sees our close_notify
    assert client.receive(server.data_to_send()) == [ApplicationData(b"in flight")]
    with pytest.raises(CodecUsageError):
        client.send(b"after close")
    assert server.receive(client.data_to_send()) == [ConnectionClosed()]  # the server answers with its own
    assert client.receive(server.data_to_send()) == [ConnectionClosed()]
    assert client.state is server.state is State.CLOSED
    assert client.data_to_send() == b""  # ours was already sent


@pytest.mark.parametrize(
    ("level", "description"),
    [(2, Alert.handshake_failure), (1, Alert.handshake_failure), (1, Alert.user_canceled), (2, 255)],
    ids=["fatal", "warning-level-error", "user-canceled", "unknown-description"],
)
def test_peer_alerts_end_the_connection_and_are_never_answered(level: int, description: int) -> None:
    client, server, t = _connected()
    s_ap = rl.RecordProtection.from_secret(t.secrets["SERVER_TRAFFIC_SECRET_0"])
    events = client.receive(sealed(b"", bytes([level, description]), CT.alert, protection=s_ap))
    assert events == [PeerAlerted(level, description)]
    assert client.state is State.FAILED and client.data_to_send() == b""
    assert client.receive(sealed(b"", b"late", CT.application_data, protection=s_ap)) == []


def test_close_notify_during_the_handshake() -> None:
    client = waiting_client()
    assert client.receive(plain(b"\x01\x00", content_type=CT.alert)) == [ConnectionClosed()]
    assert rl.decode_plaintext(client.data_to_send()) == (CT.alert, b"\x01\x00")
    assert client.state is State.CLOSED


def test_eof_without_close_notify_is_truncation() -> None:
    client, _, _ = _connected()
    assert client.receive_eof() == [ConnectionFailed(None, None, "truncated")]
    assert client.state is State.FAILED and client.receive_eof() == []


def test_closing_mid_handshake_abandons_it() -> None:
    client = waiting_client()
    client.close()
    assert client.state is State.CLOSED
    assert rl.decode_plaintext(client.data_to_send()) == (CT.alert, b"\x01\x00")
    with pytest.raises(CodecUsageError):
        client.close()


# --------------------------------------------------------------------------- #
# Record rules in the handshake (D22)
# --------------------------------------------------------------------------- #

CCS = rl.encode_plaintext(CT.change_cipher_spec, b"\x01")


def test_change_cipher_spec_window() -> None:
    _, server = make()
    assert_fails(server.receive(CCS), Alert.unexpected_message, "ccs-outside-window")  # before ClientHello
    t = reference(A)
    client = waiting_client()
    assert client.receive(CCS) == []  # dropped in the window
    events = client.receive(plain(t.messages["SH"]) + CCS + sealed(s_hs(t), b"".join(t.server_flight())))
    assert [type(e) for e in events] == [ServerAuthenticated, HandshakeComplete]
    assert_fails(client.receive(CCS), Alert.unexpected_message, "ccs-outside-window")  # after the peer's Finished


def test_ccs_inside_a_handshake_message_is_interleaving() -> None:
    t = reference(B65)
    client = waiting_client(B65)
    protection = rl.RecordProtection.from_secret(s_hs(t))
    flight = b"".join(t.server_flight())
    first = sealed(b"", flight[: rl.MAX_FRAGMENT], protection=protection)
    assert client.receive(plain(t.messages["SH"]) + first) == []
    assert_fails(client.receive(CCS), Alert.unexpected_message, "interleaved")


def test_application_data_inside_a_handshake_message_is_interleaving() -> None:
    t = reference(B65)
    client = waiting_client(B65)
    protection = rl.RecordProtection.from_secret(s_hs(t))
    first = sealed(b"", b"".join(t.server_flight())[: rl.MAX_FRAGMENT], protection=protection)
    client.receive(plain(t.messages["SH"]) + first)
    assert_fails(client.receive(sealed(b"", b"x", CT.application_data, protection=protection)), Alert.unexpected_message, "interleaved")


def test_an_alert_inside_a_handshake_message_is_honoured() -> None:
    t = reference(B65)
    client = waiting_client(B65)
    protection = rl.RecordProtection.from_secret(s_hs(t))
    first = sealed(b"", b"".join(t.server_flight())[: rl.MAX_FRAGMENT], protection=protection)
    client.receive(plain(t.messages["SH"]) + first)
    assert client.receive(sealed(b"", b"\x02\x28", CT.alert, protection=protection)) == [PeerAlerted(2, 40)]


def test_application_data_before_the_handshake_finishes() -> None:
    t = reference(A)
    client = waiting_client()
    client.receive(plain(t.messages["SH"]))
    assert_fails(client.receive(sealed(s_hs(t), b"early", CT.application_data)), Alert.unexpected_message, "early-data")


def test_plaintext_alert_window_on_the_server() -> None:
    t = reference(A)
    _, server = make()
    server.receive(plain(t.messages["CH"], 0x0301))
    assert server.receive(plain(b"\x02\x28", content_type=CT.alert)) == [PeerAlerted(2, 40)]
    _, server = make()
    server.receive(plain(t.messages["CH"], 0x0301))
    c_hs = rl.RecordProtection.from_secret(t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"])
    assert server.receive(sealed(b"", t.messages["CFIN"], protection=c_hs)) == [HandshakeComplete()]
    assert_fails(server.receive(plain(b"\x02\x28", content_type=CT.alert)), Alert.unexpected_message, "unprotected-after-keys")


def test_replayed_and_tampered_records_mid_handshake() -> None:
    t = reference(B65)
    flight = sealed(s_hs(t), b"".join(t.server_flight()))
    records = rl.split_records(flight)[0]
    client = waiting_client(B65)
    assert_fails(client.receive(plain(t.messages["SH"]) + records[0] + records[0]), Alert.bad_record_mac, "bad-mac")
    tampered = bytearray(records[1])
    tampered[-1] ^= 1
    client = waiting_client(B65)
    assert_fails(client.receive(plain(t.messages["SH"]) + records[0] + bytes(tampered)), Alert.bad_record_mac, "bad-mac")


# --------------------------------------------------------------------------- #
# Alerts go under the key the peer can read (D17)
# --------------------------------------------------------------------------- #


def _open(secret: bytes, data: bytes, skip: int = 0) -> tuple[CT, bytes]:
    p = rl.RecordProtection.from_secret(secret)
    p.seq = skip
    return p.open(data)


def test_alert_keys_per_state() -> None:
    t = reference(A)
    # Client, WAIT_SH: plaintext (tested in test_server_hello_rules). WAIT_EE..WAIT_FINISHED: c hs.
    client = waiting_client()
    client.receive(plain(t.messages["SH"]) + sealed(s_hs(t), _ee(m.Extension(0xFF99, b""))))
    assert _open(t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], client.data_to_send()) == (CT.alert, bytes([2, Alert.unsupported_extension]))
    # Client, CONNECTED: c ap, after its Finished-flight application data.
    client, _, _ = _connected()
    client.send(b"one")
    client.data_to_send()
    s_ap = rl.RecordProtection.from_secret(t.secrets["SERVER_TRAFFIC_SECRET_0"])
    client.receive(sealed(b"", handshake_message(HandshakeType.key_update, b"\x00"), protection=s_ap))
    assert _open(t.secrets["CLIENT_TRAFFIC_SECRET_0"], client.data_to_send(), skip=1) == (CT.alert, bytes([2, Alert.unexpected_message]))
    # Server, WAIT_CLIENT_FINISHED: s ap (the client has it once it sent Finished).
    _, server = make()
    server.receive(plain(t.messages["CH"], 0x0301))
    server.data_to_send()
    flipped = t.messages["CFIN"][:-1] + bytes([t.messages["CFIN"][-1] ^ 1])
    assert_fails(server.receive(sealed(t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], flipped)), Alert.decrypt_error, "client-finished")
    assert _open(t.secrets["SERVER_TRAFFIC_SECRET_0"], server.data_to_send()) == (CT.alert, bytes([2, Alert.decrypt_error]))


def test_a_bad_client_finished_reaches_the_client_as_its_alert() -> None:
    client, server = make()
    client.start()
    server.receive(client.data_to_send())
    client.receive(server.data_to_send())
    record_ = bytearray(client.data_to_send())
    record_[-1] ^= 1
    assert_fails(server.receive(bytes(record_)), Alert.bad_record_mac, "bad-mac")
    assert client.receive(server.data_to_send()) == [PeerAlerted(2, Alert.bad_record_mac)]


# --------------------------------------------------------------------------- #
# The error contract and configuration checks
# --------------------------------------------------------------------------- #


def test_a_local_bug_is_reraised_after_queueing_internal_error(monkeypatch: pytest.MonkeyPatch) -> None:
    t = reference(A)
    client = waiting_client()

    def broken(body: bytes) -> m.EncryptedExtensions:
        raise ValueError("bug")

    monkeypatch.setattr(m.EncryptedExtensions, "decode", staticmethod(broken))
    with pytest.raises(ValueError, match="bug"):
        client.receive(plain(t.messages["SH"]) + sealed(s_hs(t), b"".join(t.server_flight())))
    assert client.state is State.FAILED
    assert _open(t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], client.data_to_send()) == (CT.alert, bytes([2, Alert.internal_error]))
    assert client.receive(b"more") == []


def test_send_and_lifecycle_misuse() -> None:
    client, server = make()
    with pytest.raises(CodecUsageError):
        client.send(b"too early")
    client.start()
    with pytest.raises(CodecUsageError):
        client.start()
    assert_fails(client.receive(plain(handshake_message(99, b""))), Alert.unexpected_message, "unknown-type")
    with pytest.raises(CodecUsageError, match="can't send"):
        client.send(b"after failure")
    with pytest.raises(CodecUsageError, match="can't close"):
        client.close()
    assert server.state is State.WAIT_CH


def test_configuration_is_checked_up_front() -> None:
    c, s, _ = endpoints(B44)
    openssl_leaf = chains.signing_key("ML-DSA-44", b"qtls fixture v1", "leaf", backend="openssl")
    openssl_map = {**SEEDED_BACKENDS, "ML-DSA-44": "openssl"}
    seeded = SeededRandomness(SEED)

    def server(**kw: object) -> Server:
        return Server(dataclasses.replace(s, **kw))  # type: ignore[arg-type]

    with pytest.raises(CodecUsageError, match="seeded ML-KEM encapsulation needs the liboqs backend"):
        server(randomness=SeededRandomness(SEED), backends={**SEEDED_BACKENDS, "ML-KEM-768": "openssl"})
    with pytest.raises(CodecUsageError, match="seeded ML-DSA-44 signing needs the liboqs backend"):
        server(randomness=seeded, signing_key=openssl_leaf, backends=openssl_map)
    with pytest.raises(CodecUsageError, match="signing key is on liboqs, but backends says openssl"):
        server(backends=openssl_map)  # the key and the map must agree, so CPU is attributed honestly
    with pytest.raises(CodecUsageError, match="backends has no entry for ML-KEM-768"):
        server(backends={"ML-DSA-44": "liboqs"})
    with pytest.raises(CodecUsageError, match="doesn't match the leaf"):
        server(signing_key=crypto.sig_generate("ML-DSA-44", "openssl", seed=b"\x01" * 32), backends=openssl_map)
    with pytest.raises(CodecUsageError, match="needs a certificate chain"):
        server(cert_data=())
    assert server(signing_key=openssl_leaf, backends=openssl_map).state is State.WAIT_CH  # unseeded OpenSSL signing is fine

    def client(**kw: object) -> Client:
        return Client(dataclasses.replace(c, **kw))  # type: ignore[arg-type]

    with pytest.raises(CodecUsageError, match="backends has no entry for ML-DSA-44"):
        client(backends={"ML-KEM-768": "liboqs"})
    with pytest.raises(CodecUsageError, match="backends has no entry for ML-KEM-768"):
        client(backends={"ML-DSA-44": "liboqs"})
    with pytest.raises(CodecUsageError, match="backends has no entry for Falcon-512"):
        client(signature_algorithms_cert=(0xFE50,), backends={"ML-KEM-768": "liboqs", "ML-DSA-44": "liboqs"})
    with pytest.raises(CodecUsageError, match="isn't one qTLS implements"):
        client(signature_algorithms=(0x0904, 0xFE41))  # an AuthKEM codepoint isn't a signature scheme
    with pytest.raises(CodecUsageError, match="unknown backend"):
        client(backends={**SEEDED_BACKENDS, "ML-KEM-768": "bogus"})
    with pytest.raises(CodecUsageError, match="isn't one qTLS implements"):
        client(signature_algorithms=(0x0904, 0x0807))
    with pytest.raises(CodecUsageError, match="at least one signature algorithm"):
        client(signature_algorithms=())
    with pytest.raises(CodecUsageError, match="trust anchor"):
        client(anchors=())


def test_the_server_signs_on_the_configured_backend() -> None:
    for backend in ("openssl", "liboqs"):
        c, s, _ = configs.endpoints(B44, not_before=NOT_BEFORE, now=NOW, backends={**hs.DEFAULT_BACKENDS, "ML-DSA-44": backend})
        with crypto.count_ops() as ops:
            memory.handshake(Client(c), Server(s))
        assert ops[(backend, "ML-DSA-44", "sign")] == 1, backend
        assert ops[(backend, "ML-DSA-44", "verify")] == 3, backend  # two chain links and CertificateVerify


def test_configs_follow_the_levels_table() -> None:
    for leaf, issuer in [("ML-DSA-44", "ML-DSA-65"), ("ML-DSA-65", "Falcon-512"), ("Falcon-512", "ECDSA-P256-SHA256")]:
        with pytest.raises(ValueError, match="isn't a configuration"):
            configs.config_b(leaf, issuer)
    with pytest.raises(ValueError, match="ECDSA is config A"):
        configs.config_b("ECDSA-P256-SHA256")
    for scts in (1, 3):
        with pytest.raises(ValueError, match="SCT count"):
            configs.config_b("ML-DSA-44", scts=scts)
    assert configs.config_a(2).scts == 2 and configs.config_b("Falcon-512", "ML-DSA-44", 2).issuer_alg == "ML-DSA-44"


# --------------------------------------------------------------------------- #
# Fuzzing (P9)
# --------------------------------------------------------------------------- #


def _positions(length: int, header: range, seed: int, n: int) -> list[int]:
    rnd = random.Random(seed)
    return sorted(set(header) | {rnd.randrange(length) for _ in range(n)})


def test_fuzz_server_hello_record() -> None:
    """Completes iff the flipped byte is the record's legacy_version (ignored, not hashed)."""
    t = reference(A)
    sh_record = plain(t.messages["SH"])
    flight = sealed(s_hs(t), b"".join(t.server_flight()))
    for pos in _positions(len(sh_record), range(0, 50), seed=1, n=60):
        tampered = bytearray(sh_record)
        tampered[pos] ^= 0x01
        events = waiting_client().receive(bytes(tampered) + flight)
        completed = any(isinstance(e, HandshakeComplete) for e in events)
        assert completed == (pos in (1, 2)), pos
        if not completed and pos not in (3, 4):  # a changed record length can leave the client waiting
            last_failure(events)


def test_fuzz_encrypted_flight_plaintext() -> None:
    """Every edit inside the encrypted flight, re-sealed so it gets past AEAD, makes the client fail."""
    t = reference(A)
    flight = b"".join(t.server_flight())
    header_positions, length_positions = [], set()
    pos = 0
    for message in t.server_flight():
        header_positions += list(range(pos, pos + 4))
        length_positions |= set(range(pos + 1, pos + 4))
        pos += len(message)
    for pos in _positions(len(flight), range(0), seed=2, n=150) + header_positions:
        tampered = bytearray(flight)
        tampered[pos] ^= 0x01 << (pos % 8)
        events = waiting_client().receive(plain(t.messages["SH"]) + sealed(s_hs(t), bytes(tampered)))
        assert not any(isinstance(e, HandshakeComplete) for e in events), pos
        if events:
            last_failure(events)
        else:  # only a changed message length can leave the client waiting for more bytes
            assert pos in length_positions, pos


def test_fuzz_raw_bytes_of_each_flight() -> None:
    """Random flips on the wire never raise; encrypted flips are always bad_record_mac."""
    client_wire, server_wire = _run_wires(A)
    rnd = random.Random(3)
    for _ in range(60):
        pos = rnd.randrange(len(server_wire))
        tampered = bytearray(server_wire)
        tampered[pos] ^= 1 << rnd.randrange(8)
        events = waiting_client().receive(bytes(tampered))
        completed = any(isinstance(e, HandshakeComplete) for e in events)
        assert completed == (pos in (1, 2)), pos
        sh_len = len(plain(reference(A).messages["SH"]))
        if pos >= sh_len and events:
            assert last_failure(events).alert in (Alert.bad_record_mac, Alert.record_overflow, Alert.unexpected_message), pos
    for _ in range(40):
        pos = rnd.randrange(len(client_wire))
        tampered = bytearray(client_wire)
        tampered[pos] ^= 1 << rnd.randrange(8)
        _, server = make()
        events = server.receive(bytes(tampered))
        assert not any(isinstance(e, HandshakeComplete) for e in events) or pos in (1, 2), pos


# --------------------------------------------------------------------------- #
# Review follow-ups: alert keys, closure, lifecycle and record-end rules
# --------------------------------------------------------------------------- #


def test_every_live_state_has_an_alert_key() -> None:
    client_states = {State.START, State.WAIT_SH, State.WAIT_EE, State.WAIT_CERT, State.WAIT_CV, State.WAIT_FINISHED, State.CONNECTED}
    assert set(Client._ALERT_KEYS) == client_states
    assert set(Server._ALERT_KEYS) == {State.WAIT_CH, State.WAIT_CLIENT_FINISHED, State.CONNECTED}


def test_a_missing_alert_key_row_is_a_local_bug(monkeypatch: pytest.MonkeyPatch) -> None:
    keys = {k: v for k, v in Client._ALERT_KEYS.items() if k is not State.WAIT_CV}
    monkeypatch.setattr(Client, "_ALERT_KEYS", keys)
    t = reference(A)
    client = waiting_client()
    with pytest.raises(CodecUsageError, match="no alert key for state WAIT_CV"):
        client.receive(plain(t.messages["SH"]) + sealed(s_hs(t), b"".join(_flight(CV=_cv(0x0905)))))
    assert client.state is State.FAILED and client.receive(b"more") == []


@pytest.mark.parametrize(
    ("flight", "state", "alert"),
    [
        (lambda: _flight(CERT=_cert(b"\x01")), State.WAIT_CERT, Alert.illegal_parameter),
        (lambda: _flight(CV=_cv(0x0905)), State.WAIT_CV, Alert.illegal_parameter),
        (lambda: _flight(SFIN=reference(A).messages["SFIN"][:-1] + b"\x00"), State.WAIT_FINISHED, Alert.decrypt_error),
    ],
    ids=["wait-certificate", "wait-certificate-verify", "wait-finished"],
)
def test_client_alerts_under_c_hs_in_every_handshake_state(flight, state: State, alert: Alert) -> None:  # noqa: ANN001
    t = reference(A)
    client = waiting_client()
    events = client.receive(plain(t.messages["SH"]) + sealed(s_hs(t), b"".join(flight())))
    assert last_failure(events).alert is alert
    out = client.data_to_send()
    assert out[0] == CT.application_data
    assert _open(t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], out) == (CT.alert, bytes([2, alert])), state


@pytest.mark.parametrize("alert", [b"\x01\x00", b"\x02\x28"], ids=["close-notify", "fatal"])
def test_nothing_after_a_peer_alert_in_the_same_delivery_is_processed(alert: bytes) -> None:
    client, _, t = _connected()
    s_ap = rl.RecordProtection.from_secret(t.secrets["SERVER_TRAFFIC_SECRET_0"])
    data = sealed(b"", alert, CT.alert, protection=s_ap) + sealed(b"", b"after", CT.application_data, protection=s_ap)
    events = client.receive(data)
    assert events == ([ConnectionClosed()] if alert[1] == 0 else [PeerAlerted(2, 40)])


@pytest.mark.parametrize("bad", ["tampered-record", "key-update"])
def test_after_our_close_notify_a_failure_sends_and_reports_no_alert(bad: str) -> None:
    client, _, t = _connected()
    client.close()
    client.data_to_send()
    s_ap = rl.RecordProtection.from_secret(t.secrets["SERVER_TRAFFIC_SECRET_0"])
    if bad == "tampered-record":
        data = b"\x17\x03\x03\x00\x20" + bytes(32)
    else:
        data = sealed(b"", handshake_message(HandshakeType.key_update, b"\x00"), protection=s_ap)
    failure = last_failure(client.receive(data))
    assert failure.alert is None and client.data_to_send() == b""


def test_start_runs_once_and_changes_nothing_the_second_time() -> None:
    client, _ = make()
    client.start()
    first = client.data_to_send()
    transcript = client._transcript.hash()
    with pytest.raises(CodecUsageError, match="runs once"):
        client.start()
    assert client.data_to_send() == b"" and client.state is State.WAIT_SH and client._transcript.hash() == transcript
    assert first


def test_close_twice_and_send_after_failure() -> None:
    client, _, t = _connected()
    client.close()
    with pytest.raises(CodecUsageError):
        client.close()
    assert len(rl.split_records(client.data_to_send())[0]) == 1  # one close_notify
    other, _, _ = _connected()
    s_ap = rl.RecordProtection.from_secret(t.secrets["SERVER_TRAFFIC_SECRET_0"])
    other.receive(sealed(b"", b"\x02\x28", CT.alert, protection=s_ap))
    assert other.state is State.FAILED
    with pytest.raises(CodecUsageError):
        other.send(b"x")


def test_server_may_send_before_the_clients_finished() -> None:
    """0.5-RTT data (RFC 8446 §2): sending is gated on keys, not on CONNECTED."""
    client, server = make()
    with pytest.raises(CodecUsageError):
        client.send(b"no keys yet")
    client.start()
    server.receive(client.data_to_send())
    assert server.state is State.WAIT_CLIENT_FINISHED
    server.send(b"half rtt")
    events = client.receive(server.data_to_send())
    assert events == [ServerAuthenticated(client.leaf), HandshakeComplete(), ApplicationData(b"half rtt")]  # type: ignore[arg-type]
    assert server.flights[0].labels[-1] == ("application_data", "ap")


def test_flight_labels() -> None:
    client, server = make()
    link = memory.handshake(client, server)
    client.send(b"data")
    link.pump()
    assert [f.labels for f in client.flights] == [
        [("handshake", "plaintext")],
        [("handshake", "hs"), ("application_data", "ap")],
    ]
    assert server.flights[0].labels == [("handshake", "plaintext"), ("handshake", "hs")]
    assert all(len(f.labels) == len(f.records) for f in client.flights + server.flights)


def test_client_hello_and_client_finished_must_end_their_records() -> None:
    t = reference(A)
    _, server = make()
    assert_fails(server.receive(plain(t.messages["CH"] * 2, 0x0301)), Alert.unexpected_message, "record-end")
    _, server = make()  # a partial message after it would span the key change
    assert_fails(server.receive(plain(t.messages["CH"] + t.messages["CH"][:10], 0x0301)), Alert.unexpected_message, "key-change-span")
    _, server = make()
    server.receive(plain(t.messages["CH"], 0x0301))
    extra = handshake_message(HandshakeType.finished, bytes(32))
    events = server.receive(sealed(t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], t.messages["CFIN"] + extra))
    assert_fails(events, Alert.unexpected_message, "record-end")


def test_server_ccs_window_closes_at_the_clients_finished() -> None:
    t = reference(A)
    _, server = make()
    server.receive(plain(t.messages["CH"], 0x0301))
    assert server.receive(CCS) == []  # inside the window
    server.receive(sealed(t.secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], t.messages["CFIN"]))
    assert_fails(server.receive(CCS), Alert.unexpected_message, "ccs-outside-window")


def test_more_encrypted_extension_rules() -> None:
    assert_fails(deliver_flight(_flight(EE=_ee(m.Extension(ExtensionType.supported_groups, b"\x00\x01\x00")))), Alert.decode_error, "decode")
    entries = tuple(m.CertificateEntry(c, (m.Extension(18, b""),) if i == 1 else ()) for i, c in enumerate(endpoints(A)[2].cert_data))
    assert_fails(deliver_flight(_flight(CERT=_cert(entries=entries))), Alert.unsupported_extension, "extension-not-offered")


def test_the_hybrid_share_is_found_wherever_it_is() -> None:
    hello = _with(_client_hello(), supported_groups=m.encode_supported_groups([hybrid.GROUP, X25519]),
                  key_share=_share((hybrid.GROUP, _ch_share()), (X25519, bytes(range(32)))))  # fmt: skip
    _, server = make()
    assert server.receive(plain(m.encode_handshake(hello), 0x0301)) == []
    assert server.state is State.WAIT_CLIENT_FINISHED


def test_pre_shared_key_must_be_the_last_extension() -> None:
    hello = _client_hello()
    psk = m.Extension(41, b"\x00\x00")
    _, server = make()
    events = server.receive(plain(m.encode_handshake(dataclasses.replace(hello, extensions=(psk,) + hello.extensions)), 0x0301))
    assert_fails(events, Alert.illegal_parameter, "psk-not-last")
    _, server = make()  # checked before anything else, the version included
    no_tls13 = _with(hello, supported_versions=m.encode_supported_versions([0x0303], Context.client_hello))
    events = server.receive(plain(m.encode_handshake(dataclasses.replace(no_tls13, extensions=(psk,) + no_tls13.extensions)), 0x0301))
    assert_fails(events, Alert.illegal_parameter, "psk-not-last")
    _, server = make()  # last, it's ignored: qTLS has no resumption
    assert server.receive(plain(m.encode_handshake(dataclasses.replace(hello, extensions=hello.extensions + (psk,))), 0x0301)) == []


def test_missing_signature_algorithms_comes_before_group_selection() -> None:
    """RFC 8446 §9.2: without pre_shared_key, a missing signature_algorithms is missing_extension."""
    hello = _with(_client_hello(), drop=(ExtensionType.signature_algorithms,),
                  supported_groups=m.encode_supported_groups([X25519]), key_share=_share((X25519, bytes(range(32)))))  # fmt: skip
    _, server = make()
    assert_fails(server.receive(plain(m.encode_handshake(hello), 0x0301)), Alert.missing_extension, "signature-algorithms")


def test_a_backend_decapsulation_failure_is_a_local_bug(monkeypatch: pytest.MonkeyPatch) -> None:
    t = reference(A)
    client = waiting_client()

    def broken(self: crypto.KEMPrivateKey, ct: bytes) -> bytes:
        raise RuntimeError("backend failure")

    monkeypatch.setattr(crypto.KEMPrivateKey, "decapsulate", broken)
    with pytest.raises(RuntimeError, match="backend failure"):
        client.receive(plain(t.messages["SH"]))
    assert client.state is State.FAILED
    assert rl.decode_plaintext(client.data_to_send()) == (CT.alert, bytes([2, Alert.internal_error]))


def test_eof_mid_handshake_and_after_our_close() -> None:
    client = waiting_client()
    assert client.receive_eof() == [ConnectionFailed(None, None, "truncated")]
    client, _, _ = _connected()
    client.close()
    assert client.receive_eof() == [ConnectionFailed(None, None, "truncated")]  # the peer never answered
