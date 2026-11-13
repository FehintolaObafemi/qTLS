"""TLS alerts (RFC 8446 §6) and the exception protocol code raises to send one.

Protocol code (codec, record layer, handshake) raises :class:`AlertError` with
the alert the peer should receive. :func:`alert_for` is the single fallback
table (specs.md D10) for exceptions that reach the top of a connection.

Context matters for crypto failures: a signature that fails in
CertificateVerify is ``decrypt_error``, but one that fails in a certificate
chain is ``bad_certificate``. Code that verifies chains (Phase 2c) or AuthKEM
certificate keys (Phase 4) therefore catches crypto exceptions itself and
raises :class:`AlertError`; the table only covers what's left.
"""

from __future__ import annotations

from enum import IntEnum


class Alert(IntEnum):
    """AlertDescription values from RFC 8446 §6."""

    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    record_overflow = 22
    handshake_failure = 40
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    missing_extension = 109
    unsupported_extension = 110
    unrecognized_name = 112
    bad_certificate_status_response = 113
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120


class AlertError(Exception):
    """A protocol failure that must be reported to the peer as ``alert``."""

    def __init__(self, alert: Alert, message: str) -> None:
        super().__init__(f"{alert.name}: {message}")
        self.alert = alert


class CodecUsageError(Exception):
    """A local programming error (e.g. encoding a value outside its bounds).

    Never caused by peer input, so it maps to ``internal_error``. Kept apart
    from ``ValueError``, which qtls.crypto also uses for framing errors.
    """


class PeerAlert(Exception):
    """The peer sent an alert (``close_notify`` included). Never answered with one."""

    def __init__(self, level: int, description: int) -> None:
        name = Alert(description).name if description in Alert._value2member_map_ else str(description)
        super().__init__(f"peer sent {name} (level {level})")
        self.level = level
        self.description = description


def alert_for(exc: BaseException) -> Alert | None:
    """The single exception → alert table (specs.md D10).

    Returns ``None`` when no *error* alert may be sent: the peer's own alert
    (RFC 8446 §6.2). After a peer's close_notify the local side still sends
    its own close_notify before closing (RFC 8446 §6.1). Protocol code checks peer-controlled lengths itself and
    raises :class:`AlertError`, so anything not listed here is a local failure.
    """
    # Imported here so the codec can use this module without pulling in crypto.
    from qtls.crypto import AeadFailure, InvalidPublicKey, InvalidSignature

    if isinstance(exc, PeerAlert):
        return None
    if isinstance(exc, AlertError):
        return exc.alert
    if isinstance(exc, AeadFailure):
        return Alert.bad_record_mac
    if isinstance(exc, InvalidSignature):
        return Alert.decrypt_error
    if isinstance(exc, InvalidPublicKey):
        return Alert.illegal_parameter
    return Alert.internal_error
