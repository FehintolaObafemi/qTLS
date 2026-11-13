"""Key schedule against RFC 8448 §3: inputs from qtls, expected values from the RFC.

Inputs never come from the vector's own ``hash`` or ``info`` fields: the
transcript is built by qtls from the RFC's messages, and labels are the
module's constants. The vector's ``hash``/``info`` fields are checked
separately, so a wrong transcript range or label encoding fails twice.
"""

from __future__ import annotations

import pytest

from qtls import crypto
from qtls import keyschedule as ks
from qtls.alerts import Alert, AlertError, CodecUsageError
from rfc8448_trace import CERT, CFIN, CH, CV, EE, SFIN, SH, event, h

IKM = h(event("server", 'extract secret "handshake"')["IKM"])


def transcript(*msgs: bytes) -> bytes:
    t = ks.Transcript()
    for msg in msgs:
        t.add(msg)
    return t.hash()


TH_SH = transcript(CH, SH)  # CH..SH
TH_CV = transcript(CH, SH, EE, CERT, CV)  # CH..CertificateVerify
TH_SFIN = transcript(CH, SH, EE, CERT, CV, SFIN)  # CH..server Finished
TH_CFIN = transcript(CH, SH, EE, CERT, CV, SFIN, CFIN)  # CH..client Finished


def expected(step: str, actor: str = "server", field: str = "expanded") -> bytes:
    return h(event(actor, step)[field])


# --------------------------------------------------------------------------- #
# HkdfLabel encoding
# --------------------------------------------------------------------------- #

LABEL_EVENTS = {
    ks.DERIVED: ('derive secret for handshake "tls13 derived"', "server"),
    ks.C_HS_TRAFFIC: ('derive secret "tls13 c hs traffic"', "server"),
    ks.S_HS_TRAFFIC: ('derive secret "tls13 s hs traffic"', "server"),
    ks.C_AP_TRAFFIC: ('derive secret "tls13 c ap traffic"', "server"),
    ks.S_AP_TRAFFIC: ('derive secret "tls13 s ap traffic"', "server"),
    ks.EXP_MASTER: ('derive secret "tls13 exp master"', "server"),
    ks.RES_MASTER: ('derive secret "tls13 res master"', "client"),
    ks.FINISHED: ('calculate finished "tls13 finished"', "server"),
}


@pytest.mark.parametrize("label", LABEL_EVENTS, ids=lambda b: b.decode())
def test_hkdf_label_matches_rfc_info_bytes(label: bytes) -> None:
    step, actor = LABEL_EVENTS[label]
    v = event(actor, step)
    assert ks.hkdf_label(label, h(v["hash"]), 32) == h(v["info"])


def test_key_and_iv_labels_match_rfc_info_bytes() -> None:
    v = event("server", "derive write traffic keys for handshake data")
    assert ks.hkdf_label(ks.KEY, b"", 16) == h(v["key info"])
    assert ks.hkdf_label(ks.IV, b"", 12) == h(v["iv info"])


def test_authkem_finished_label_encoding() -> None:
    """specs.md D18: the prefix appears once, never twice."""
    assert ks.hkdf_label(ks.SERVER_FINISHED, b"", 32) == b"\x00\x20\x15tls13 server finished\x00"
    assert ks.hkdf_label(ks.CLIENT_FINISHED, b"", 32) == b"\x00\x20\x15tls13 client finished\x00"


def test_hkdf_label_bounds() -> None:
    ks.hkdf_label(b"x" * 249, b"", 32)
    ks.hkdf_label(b"x", bytes(255), 32)
    for bad in (
        lambda: ks.hkdf_label(b"x" * 250, b"", 32),
        lambda: ks.hkdf_label(b"", b"", 32),
        lambda: ks.hkdf_label(b"x", bytes(256), 32),
        lambda: ks.hkdf_label(b"x", b"", 0),
        lambda: ks.derive_secret(bytes(32), b"x", bytes(31)),
    ):
        with pytest.raises(CodecUsageError):
            bad()


# --------------------------------------------------------------------------- #
# Transcript
# --------------------------------------------------------------------------- #


def test_transcript_ranges_match_the_rfc() -> None:
    assert ks.Transcript().hash() == ks.EMPTY_HASH == crypto.sha256().digest()
    assert TH_SH == h(event("server", 'derive secret "tls13 c hs traffic"')["hash"])
    assert TH_SFIN == h(event("server", 'derive secret "tls13 c ap traffic"')["hash"])
    assert TH_CFIN == h(event("client", 'derive secret "tls13 res master"')["hash"])


def test_transcript_hash_is_a_snapshot() -> None:
    t = ks.Transcript()
    t.add(CH)
    t.hash()
    t.hash()
    t.add(SH)
    assert t.hash() == TH_SH


# --------------------------------------------------------------------------- #
# The full RFC 8448 secret chain
# --------------------------------------------------------------------------- #


def test_rfc8448_secret_chain() -> None:
    schedule = ks.KeySchedule()
    assert schedule.early() == expected('extract secret "early"', field="secret")
    hs = schedule.handshake(IKM)
    assert hs == expected('extract secret "handshake"', field="secret")
    c_hs = ks.derive_secret(hs, ks.C_HS_TRAFFIC, TH_SH)
    s_hs = ks.derive_secret(hs, ks.S_HS_TRAFFIC, TH_SH)
    assert c_hs == expected('derive secret "tls13 c hs traffic"')
    assert s_hs == expected('derive secret "tls13 s hs traffic"')

    ms = schedule.main()
    assert ms == expected('extract secret "master"', field="secret")
    assert ks.derive_secret(ms, ks.C_AP_TRAFFIC, TH_SFIN) == expected('derive secret "tls13 c ap traffic"')
    assert ks.derive_secret(ms, ks.S_AP_TRAFFIC, TH_SFIN) == expected('derive secret "tls13 s ap traffic"')
    assert ks.derive_secret(ms, ks.EXP_MASTER, TH_SFIN) == expected('derive secret "tls13 exp master"')
    assert ks.derive_secret(ms, ks.RES_MASTER, TH_CFIN) == expected('derive secret "tls13 res master"', "client")


def test_rfc8448_finished() -> None:
    hs = ks.KeySchedule()
    hs.early()
    secret = hs.handshake(IKM)
    s_key = ks.finished_key(ks.derive_secret(secret, ks.S_HS_TRAFFIC, TH_SH))
    c_key = ks.finished_key(ks.derive_secret(secret, ks.C_HS_TRAFFIC, TH_SH))
    assert s_key == expected('calculate finished "tls13 finished"')
    assert c_key == expected('calculate finished "tls13 finished"', "client")
    assert ks.verify_data(s_key, TH_CV) == expected('calculate finished "tls13 finished"', field="finished")
    assert ks.verify_data(c_key, TH_SFIN) == expected(
        'calculate finished "tls13 finished"', "client", field="finished"
    )
    ks.verify_finished(s_key, TH_CV, SFIN[4:])
    for bad in (bytes(32), SFIN[4:-1] + bytes([SFIN[-1] ^ 1])):
        with pytest.raises(AlertError) as exc:
            ks.verify_finished(s_key, TH_CV, bad)
        assert exc.value.alert is Alert.decrypt_error


@pytest.mark.parametrize(
    ("actor", "step", "secret_label", "transcript_hash"),
    [
        ("server", "derive write traffic keys for handshake data", ks.S_HS_TRAFFIC, "sh"),
        ("server", "derive read traffic keys for handshake data", ks.C_HS_TRAFFIC, "sh"),
        ("server", "derive write traffic keys for application data", ks.S_AP_TRAFFIC, "sfin"),
        ("client", "derive write traffic keys for application data", ks.C_AP_TRAFFIC, "sfin"),
    ],
    ids=["server-hs", "client-hs", "server-ap", "client-ap"],
)
def test_rfc8448_traffic_keys(actor: str, step: str, secret_label: bytes, transcript_hash: str) -> None:
    schedule = ks.KeySchedule()
    schedule.early()
    hs = schedule.handshake(IKM)
    base = hs if transcript_hash == "sh" else schedule.main()
    th = TH_SH if transcript_hash == "sh" else TH_SFIN
    key, iv = ks.traffic_keys(ks.derive_secret(base, secret_label, th))
    v = event(actor, step)
    assert (key, iv) == (h(v["key expanded"]), h(v["iv expanded"]))


# --------------------------------------------------------------------------- #
# Stages
# --------------------------------------------------------------------------- #


def test_stages_must_run_once_in_order() -> None:
    misuse = [
        lambda s: s.handshake(IKM),  # before early
        lambda s: s.main(),
        lambda s: s.authenticated(bytes(32)),
        lambda s: (s.early(), s.early()),
        lambda s: (s.early(), s.main()),  # main before handshake
        lambda s: (s.early(), s.handshake(IKM), s.main(), s.authenticated(bytes(32))),
        lambda s: (s.early(), s.handshake(IKM), s.main(), s.main()),
        lambda s: (s.early(), s.handshake(IKM), s.handshake(IKM)),
        lambda s: (s.early(), s.handshake(IKM), s.authenticated(bytes(32)), s.authenticated(bytes(32))),
        lambda s: (s.early(), s.authenticated(bytes(32))),
    ]
    for call in misuse:
        with pytest.raises(CodecUsageError, match="key schedule"):
            call(ks.KeySchedule())


def _inline_expand_label(secret: bytes, label: bytes, context: bytes) -> bytes:
    """HKDF-Expand-Label written out from RFC 8446 §7.1, independently of qtls.keyschedule."""
    full = b"tls13 " + label
    info = (32).to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return crypto.hkdf_expand(secret, info, 32)


def test_early_secret_takes_injected_ikm() -> None:
    """The pre-distributed AuthKEM slot (specs.md D12): ES = Extract(0, SSs)."""
    ss = bytes(range(32))
    assert ks.KeySchedule().early(ss) == crypto.hkdf_extract(bytes(32), ss)
    assert ks.KeySchedule().early(ss) != ks.KeySchedule().early()


def test_authenticated_stage_follows_specs_d4() -> None:
    """AHS = Extract(Derive-Secret(HS, "derived", ""), SSs); MS = Extract(Derive-Secret(AHS, "derived", ""), 0)."""
    ss_s = bytes(range(32, 64))
    schedule = ks.KeySchedule()
    schedule.early()
    hs = schedule.handshake(IKM)
    ahs = schedule.authenticated(ss_s)
    ms = schedule.main()

    empty = crypto.sha256().digest()
    expected_ahs = crypto.hkdf_extract(_inline_expand_label(hs, b"derived", empty), ss_s)
    expected_ms = crypto.hkdf_extract(_inline_expand_label(expected_ahs, b"derived", empty), bytes(32))
    assert (ahs, ms) == (expected_ahs, expected_ms)

    plain = ks.KeySchedule()
    plain.early()
    plain.handshake(IKM)
    assert plain.main() != ms  # the AHS stage really feeds the Main Secret

    zero = ks.KeySchedule()
    zero.early()
    zero.handshake(IKM)
    assert zero.authenticated(bytes(32)) != ahs  # SSs really feeds AHS


def test_finished_key_uses_its_label() -> None:
    """The AuthKEM labels (D18) really reach the derivation."""
    secret = bytes(range(32))
    for label in (ks.SERVER_FINISHED, ks.CLIENT_FINISHED):
        info = b"\x00\x20" + bytes([6 + len(label)]) + b"tls13 " + label + b"\x00"
        assert ks.finished_key(secret, label) == crypto.hkdf_expand(secret, info, 32)
        assert ks.finished_key(secret, label) != ks.finished_key(secret)


def test_hkdf_label_length_must_fit_uint16() -> None:
    with pytest.raises(CodecUsageError):
        ks.hkdf_label(b"x", b"", 1 << 16)
