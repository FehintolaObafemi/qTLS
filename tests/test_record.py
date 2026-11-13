"""Record layer (RFC 8446 §5, specs.md D22): RFC 8448 records, boundaries, tampering."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qtls import record as rl
from qtls.alerts import Alert, AlertError, CodecUsageError
from qtls.record import ContentType as CT
from rfc8448_trace import event, h

HS, APP, ALERT = CT.handshake, CT.application_data, CT.alert


def keys(actor: str, step: str) -> tuple[bytes, bytes]:
    v = event(actor, step)
    return h(v["key expanded"]), h(v["iv expanded"])


SERVER_HS = keys("server", "derive write traffic keys for handshake data")
CLIENT_HS = keys("server", "derive read traffic keys for handshake data")
SERVER_AP = keys("server", "derive write traffic keys for application data")
CLIENT_AP = keys("client", "derive write traffic keys for application data")


def rec(actor: str, step: str, nth: int = 0) -> tuple[bytes, bytes]:
    v = event(actor, step, nth)
    return h(v["payload"]), h(v["complete record"])


# --------------------------------------------------------------------------- #
# RFC 8448 records
# --------------------------------------------------------------------------- #


def test_plaintext_hello_records() -> None:
    ch_payload, ch_record = rec("client", "send handshake record", 0)
    sh_payload, sh_record = rec("server", "send handshake record", 0)
    # The first ClientHello may carry legacy version 0x0301 (RFC 8446 §5.1); RFC 8448 does.
    assert rl.encode_plaintext(HS, ch_payload, rl.INITIAL_CLIENT_HELLO_VERSION) == ch_record
    assert rl.encode_plaintext(HS, sh_payload) == sh_record
    assert rl.decode_plaintext(ch_record) == (HS, ch_payload)
    assert rl.decode_plaintext(sh_record) == (HS, sh_payload)
    odd_version = sh_record[:1] + b"\x7f\x7f" + sh_record[3:]
    assert rl.decode_plaintext(odd_version) == (HS, sh_payload)  # version ignored on receipt


DIRECTIONS = {
    "server handshake": (SERVER_HS, [(HS, rec("server", "send handshake record", 1))]),
    "client handshake": (CLIENT_HS, [(HS, rec("client", "send handshake record", 1))]),
    "server application": (SERVER_AP, [
        (HS, rec("server", "send handshake record", 2)),  # NewSessionTicket
        (APP, rec("server", "send application_data record")),
        (ALERT, rec("server", "send alert record")),
    ]),
    "client application": (CLIENT_AP, [
        (APP, rec("client", "send application_data record")),
        (ALERT, rec("client", "send alert record")),
    ]),
}  # fmt: skip


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_rfc8448_records_in_sequence(direction: str) -> None:
    (key, iv), records = DIRECTIONS[direction]
    sender, receiver = rl.RecordProtection(key, iv), rl.RecordProtection(key, iv)
    for content_type, (payload, record) in records:
        assert sender.seal(content_type, payload) == record
        assert receiver.open(record) == (content_type, payload)
    assert sender.seq == receiver.seq == len(records)


def test_from_secret_uses_the_rfc_key_derivation() -> None:
    from qtls import keyschedule as ks

    secret = h(event("server", 'derive secret "tls13 s hs traffic"')["expanded"])
    payload, record = rec("server", "send handshake record", 1)
    assert rl.RecordProtection.from_secret(secret).seal(HS, payload) == record
    assert ks.traffic_keys(secret) == SERVER_HS


# --------------------------------------------------------------------------- #
# Nonces and sequence numbers
# --------------------------------------------------------------------------- #


def _inline_nonce(iv: bytes, seq: int) -> bytes:
    """RFC 8446 §5.3, written out: left-pad seq to 12 bytes and XOR with the IV."""
    return bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big"), strict=True))


@pytest.mark.parametrize("seq", [1 << 8, 1 << 32, (1 << 64) - 1])
def test_high_sequence_numbers(seq: int) -> None:
    key, iv = SERVER_AP
    prot = rl.RecordProtection(key, iv)
    prot.seq = seq
    record = prot.seal(APP, b"data")
    header = b"\x17\x03\x03" + (5 + 16).to_bytes(2, "big")  # written out, not taken from qtls
    assert record[:5] == header
    assert record[5:] == AESGCM(key).encrypt(_inline_nonce(iv, seq), b"data\x17", header)
    reader = rl.RecordProtection(key, iv)
    reader.seq = seq
    assert reader.open(record) == (APP, b"data")


def test_last_sequence_number_is_usable_then_exhausted() -> None:
    key, iv = SERVER_AP
    sender, receiver = rl.RecordProtection(key, iv), rl.RecordProtection(key, iv)
    sender.seq = receiver.seq = (1 << 64) - 1
    record = sender.seal(APP, b"x")
    receiver.open(record)
    with pytest.raises(CodecUsageError, match="exhausted"):
        sender.seal(APP, b"x")
    with pytest.raises(CodecUsageError, match="exhausted"):
        receiver.open(record)


# --------------------------------------------------------------------------- #
# Tampering, replay, reordering
# --------------------------------------------------------------------------- #


def _alert(call) -> Alert:  # noqa: ANN001
    with pytest.raises(AlertError) as exc:
        call()
    return exc.value.alert


def _flip(b: bytes, i: int) -> bytes:
    out = bytearray(b)
    out[i] ^= 1
    return bytes(out)


def test_tampering_each_region() -> None:
    key, iv = SERVER_HS
    payload, record = rec("server", "send handshake record", 1)
    cases = {
        "version (in the AAD)": (_flip(record, 1), Alert.bad_record_mac),
        "body": (_flip(record, 10), Alert.bad_record_mac),
        "tag": (_flip(record, -1), Alert.bad_record_mac),
    }
    for label, (bad, alert) in cases.items():
        assert _alert(lambda bad=bad: rl.RecordProtection(key, iv).open(bad)) is alert, label
    for outer in (CT.handshake, CT.alert, CT.change_cipher_spec):
        bad = bytes([outer]) + record[1:]
        assert _alert(lambda bad=bad: rl.RecordProtection(key, iv).open(bad)) is Alert.unexpected_message
    other_key = rl.RecordProtection(*CLIENT_HS)
    assert _alert(lambda: other_key.open(record)) is Alert.bad_record_mac


def test_failed_record_leaves_the_sequence_number_alone() -> None:
    key, iv = SERVER_HS
    payload, record = rec("server", "send handshake record", 1)
    receiver = rl.RecordProtection(key, iv)
    assert _alert(lambda: receiver.open(_flip(record, 10))) is Alert.bad_record_mac
    assert receiver.seq == 0
    assert receiver.open(record) == (HS, payload)


def test_replay_and_reorder_are_rejected() -> None:
    key, iv = SERVER_AP
    (_, (_, r0)), (_, (_, r1)), (_, (_, r2)) = DIRECTIONS["server application"][1]
    receiver = rl.RecordProtection(key, iv)
    receiver.open(r0)
    assert _alert(lambda: receiver.open(r0)) is Alert.bad_record_mac  # replay
    assert _alert(lambda: receiver.open(r2)) is Alert.bad_record_mac  # #2 before #1
    receiver.open(r1)
    receiver.open(r2)


# --------------------------------------------------------------------------- #
# Lengths and inner plaintext
# --------------------------------------------------------------------------- #


def _raw_record(key: bytes, iv: bytes, inner: bytes, seq: int = 0) -> bytes:
    """A record built with raw AEAD, to reach states seal() refuses to produce."""
    length = len(inner) + 16
    header = bytes([23, 3, 3]) + length.to_bytes(2, "big")
    return header + AESGCM(key).encrypt(_inline_nonce(iv, seq), inner, header)


@pytest.mark.parametrize("n", [0, 15, 16, 17, rl.MAX_CIPHERTEXT])
def test_garbage_ciphertexts_are_bad_record_mac(n: int) -> None:
    record = bytes([23, 3, 3]) + n.to_bytes(2, "big") + bytes(n)
    assert _alert(lambda: rl.RecordProtection(*SERVER_AP).open(record)) is Alert.bad_record_mac


def test_oversized_ciphertext_is_record_overflow_before_decrypting() -> None:
    n = rl.MAX_CIPHERTEXT + 1
    record = bytes([23, 3, 3]) + n.to_bytes(2, "big") + bytes(n)
    assert _alert(lambda: rl.RecordProtection(*SERVER_AP).open(record)) is Alert.record_overflow
    with pytest.raises(AlertError) as exc:
        rl.split_records(record[:5])  # the header alone is enough to refuse it
    assert exc.value.alert is Alert.record_overflow


def test_inner_plaintext_boundaries() -> None:
    key, iv = SERVER_AP
    ok = _raw_record(key, iv, bytes(1 << 14) + b"\x17")  # 2^14 + 1
    assert rl.RecordProtection(key, iv).open(ok) == (APP, bytes(1 << 14))
    too_big = _raw_record(key, iv, bytes(1 << 14) + b"\x17\x00")  # 2^14 + 2
    assert _alert(lambda: rl.RecordProtection(key, iv).open(too_big)) is Alert.record_overflow


@pytest.mark.parametrize(
    ("inner", "result"),
    [
        (bytes(10), Alert.unexpected_message),  # no content type at all
        (b"x\x14", Alert.unexpected_message),  # change_cipher_spec
        (b"x\x18", Alert.unexpected_message),  # unknown type 24
        (b"x\xff", Alert.unexpected_message),
        (b"\x16", Alert.unexpected_message),  # zero-length handshake
        (b"\x15", Alert.unexpected_message),  # zero-length alert
        (b"\x17", (APP, b"")),  # zero-length application data is fine
        (b"a\x00\x00\x17" + bytes(5), (APP, b"a\x00\x00")),  # padding stripped, content zeros kept
    ],
    ids=["all-zero", "ccs", "type-24", "type-255", "empty-handshake", "empty-alert", "empty-app", "padding"],
)
def test_inner_plaintext_rules(inner: bytes, result: object) -> None:
    key, iv = SERVER_AP
    record = _raw_record(key, iv, inner)
    if isinstance(result, Alert):
        assert _alert(lambda: rl.RecordProtection(key, iv).open(record)) is result
    else:
        assert rl.RecordProtection(key, iv).open(record) == result


def test_seal_bounds_and_padding() -> None:
    key, iv = SERVER_AP
    prot = rl.RecordProtection(key, iv)
    record = prot.seal(APP, b"a", padding=5)
    assert rl.RecordProtection(key, iv).open(record) == (APP, b"a")
    prot.seal(APP, bytes((1 << 14) - 10), padding=10)  # exactly 2^14 + 1 inner
    prot.seal(APP, b"", padding=1 << 14)
    for bad in (
        lambda: prot.seal(APP, bytes((1 << 14) - 10), padding=11),  # 2^14 + 2
        lambda: prot.seal(APP, b"a", padding=-1),
        lambda: prot.seal(HS, b""),
        lambda: prot.seal(ALERT, b""),
    ):
        with pytest.raises(CodecUsageError):
            bad()


def test_key_and_iv_lengths() -> None:
    with pytest.raises(ValueError):
        rl.RecordProtection(bytes(15), bytes(12))
    with pytest.raises(CodecUsageError):
        rl.RecordProtection(bytes(16), bytes(11))


# --------------------------------------------------------------------------- #
# Plaintext records and framing
# --------------------------------------------------------------------------- #


def test_plaintext_record_rules() -> None:
    def plain(t: int, payload: bytes) -> bytes:
        return bytes([t, 3, 3]) + len(payload).to_bytes(2, "big") + payload

    assert rl.decode_plaintext(plain(20, b"\x01")) == (CT.change_cipher_spec, b"\x01")
    cases = {
        "ccs 0x02": plain(20, b"\x02"),
        "ccs empty": plain(20, b""),
        "app data before keys": plain(23, b"x"),
        "unknown type": plain(99, b"x"),
        "empty handshake": plain(22, b""),
        "empty alert": plain(21, b""),
    }
    for label, record in cases.items():
        assert _alert(lambda r=record: rl.decode_plaintext(r)) is Alert.unexpected_message, label
    assert rl.decode_plaintext(plain(22, bytes(1 << 14)))[1] == bytes(1 << 14)
    assert _alert(lambda: rl.decode_plaintext(plain(22, bytes((1 << 14) + 1)))) is Alert.record_overflow
    with pytest.raises(CodecUsageError):
        rl.encode_plaintext(HS, bytes((1 << 14) + 1))
    with pytest.raises(CodecUsageError):
        rl.encode_plaintext(HS, b"")


def test_split_records_byte_by_byte() -> None:
    stream = b"".join(r for _, r in [rec("server", "send handshake record", i) for i in range(3)])
    whole, rest = rl.split_records(stream)
    assert rest == b"" and len(whole) == 3
    buffer, collected = b"", []
    for i in range(len(stream)):
        records, buffer = rl.split_records(buffer + stream[i : i + 1])
        collected += records
    assert collected == whole and buffer == b""
    assert rl.split_records(stream[:3]) == ([], stream[:3])


def test_fragment() -> None:
    assert rl.fragment(bytes(1 << 14)) == [bytes(1 << 14)]
    assert [len(x) for x in rl.fragment(bytes((1 << 14) + 1))] == [1 << 14, 1]
    assert rl.fragment(b"") == []


# --------------------------------------------------------------------------- #
# Added after the Phase 2b review
# --------------------------------------------------------------------------- #


def test_split_records_accepts_the_largest_legal_record() -> None:
    n = rl.MAX_CIPHERTEXT
    record = bytes([23, 3, 3]) + n.to_bytes(2, "big") + bytes(n)
    assert rl.split_records(record) == ([record], b"")


def test_misframed_records_are_usage_errors() -> None:
    _, record = rec("server", "send handshake record", 1)
    _, sh_record = rec("server", "send handshake record", 0)
    for bad in (record + b"\x00", record[:-1], b"\x17\x03"):
        with pytest.raises(CodecUsageError):
            rl.RecordProtection(*SERVER_HS).open(bad)
    with pytest.raises(CodecUsageError):
        rl.decode_plaintext(sh_record + b"\x00")


def test_seal_refuses_content_types_never_sent_protected() -> None:
    prot = rl.RecordProtection(*SERVER_AP)
    for bad in (CT.change_cipher_spec, 0, 24):
        with pytest.raises(CodecUsageError):
            prot.seal(bad, b"\x01")  # type: ignore[arg-type]


def test_receive_routes_by_state() -> None:
    _, sh_record = rec("server", "send handshake record", 0)
    payload, protected = rec("server", "send handshake record", 1)
    ccs = b"\x14\x03\x03\x00\x01\x01"
    # Before keys: plaintext only; a valid CCS is dropped while allowed.
    assert rl.receive(sh_record, None, ccs_allowed=True) == (HS, h(event("server", "send handshake record", 0)["payload"]))
    assert rl.receive(ccs, None, ccs_allowed=True) is None
    # After keys: protected records open; a CCS is still dropped until the peer's Finished.
    assert rl.receive(protected, rl.RecordProtection(*SERVER_HS), ccs_allowed=True) == (HS, payload)
    assert rl.receive(ccs, rl.RecordProtection(*SERVER_HS), ccs_allowed=True) is None
    for bad, prot, allowed in (
        (sh_record, rl.RecordProtection(*SERVER_HS), True),  # plaintext handshake after the key change
        (b"\x15\x03\x03\x00\x02\x02\x32", rl.RecordProtection(*SERVER_HS), True),  # plaintext alert after keys
        (ccs, rl.RecordProtection(*SERVER_AP), False),  # CCS after the peer's Finished
        (b"\x14\x03\x03\x00\x01\x02", None, True),  # CCS with the wrong body
        (protected, None, True),  # protected record before any keys
    ):
        assert _alert(lambda b=bad, p=prot, a=allowed: rl.receive(b, p, ccs_allowed=a)) is Alert.unexpected_message


def test_plaintext_alert_window_after_server_hello() -> None:
    """A client rejecting ServerHello has no keys, so its alert is unprotected."""
    alert = rl.encode_plaintext(ALERT, b"\x02\x2f")  # fatal illegal_parameter
    server_reads = rl.RecordProtection(*CLIENT_HS)
    assert rl.receive(alert, server_reads, ccs_allowed=True, plain_alerts_allowed=True) == (ALERT, b"\x02\x2f")
    assert _alert(lambda: rl.receive(alert, server_reads, ccs_allowed=True)) is Alert.unexpected_message
    handshake = rl.encode_plaintext(HS, b"\x14\x00\x00\x00")
    assert _alert(
        lambda: rl.receive(handshake, server_reads, ccs_allowed=True, plain_alerts_allowed=True)
    ) is Alert.unexpected_message  # the window admits alerts only


def test_receive_before_keys() -> None:
    alert = rl.encode_plaintext(ALERT, b"\x02\x28")  # a server's fatal reply to a ClientHello
    assert rl.receive(alert, None, ccs_allowed=False) == (ALERT, b"\x02\x28")
    ccs = b"\x14\x03\x03\x00\x01\x01"
    assert _alert(lambda: rl.receive(ccs, None, ccs_allowed=False)) is Alert.unexpected_message
    with pytest.raises(CodecUsageError):
        rl.receive(b"", None, ccs_allowed=True)


def test_record_layer_only_raises_alert_errors() -> None:
    """Fuzz framing, routing and decryption with mutations of the RFC 8448 records."""
    import random

    rng = random.Random(8446)
    seeds = [rec("server", "send handshake record", i)[1] for i in range(3)]
    seeds += [rec("client", "send application_data record")[1], b"\x14\x03\x03\x00\x01\x01"]
    for _ in range(2000):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 3)):
            i = rng.randrange(len(data))
            if rng.randrange(2):
                data[i] ^= 1 << rng.randrange(8)
            else:
                data[i:i] = rng.randbytes(rng.randint(1, 3))
        try:
            records, _ = rl.split_records(bytes(data))
        except AlertError:
            continue
        for record in records:
            for protection in (None, rl.RecordProtection(*SERVER_HS)):
                try:
                    rl.receive(record, protection, ccs_allowed=rng.random() < 0.5)
                except AlertError:
                    pass
