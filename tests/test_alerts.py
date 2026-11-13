"""The single exception → alert table (specs.md D10) and the alert codes."""

from __future__ import annotations

import pytest

from qtls import crypto
from qtls.alerts import Alert, AlertError, CodecUsageError, alert_for


@pytest.mark.parametrize(
    ("exc", "alert"),
    [
        (AlertError(Alert.record_overflow, "x"), Alert.record_overflow),
        (crypto.AeadFailure("x"), Alert.bad_record_mac),
        (crypto.InvalidSignature(), Alert.decrypt_error),
        (crypto.InvalidPublicKey("x"), Alert.illegal_parameter),
        (CodecUsageError("x"), Alert.internal_error),
        (ValueError("x"), Alert.internal_error),  # peer lengths are checked before crypto
        (RuntimeError("x"), Alert.internal_error),
        (crypto.RandomnessError("x"), Alert.internal_error),
    ],
    ids=lambda v: type(v).__name__ if isinstance(v, BaseException) else v.name,
)
def test_alert_for(exc: BaseException, alert: Alert) -> None:
    assert alert_for(exc) is alert


def test_alert_codes_used_by_qtls() -> None:
    """RFC 8446 §6 values for every alert the protocol layer raises."""
    assert {a.name: int(a) for a in Alert if a.name in USED} == USED


USED = {
    "close_notify": 0,
    "unexpected_message": 10,
    "bad_record_mac": 20,
    "record_overflow": 22,
    "handshake_failure": 40,
    "unsupported_certificate": 43,
    "illegal_parameter": 47,
    "decode_error": 50,
    "decrypt_error": 51,
    "internal_error": 80,
}


def test_a_peer_alert_is_never_answered() -> None:
    from qtls.alerts import PeerAlert

    for level, description in ((1, 0), (2, 50), (2, 254)):
        assert alert_for(PeerAlert(level, description)) is None
