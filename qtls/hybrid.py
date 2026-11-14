"""The X25519MLKEM768 key-exchange group (RFC 10024), the only group qTLS offers.

This module is the only place that knows the share and secret layouts:

    client share   ML-KEM-768 ek (1184) ‖ X25519 public key (32)   = 1216 bytes
    server share   ML-KEM-768 ct (1088) ‖ X25519 public key (32)   = 1120 bytes
    shared secret  ML-KEM ss (32) ‖ X25519 ss (32)                 =   64 bytes

ML-KEM comes first in all three (RFC 10024 §4.1-4.3). Bad key-share content is
``illegal_parameter`` (RFC 10024 §4.2, §4.3; specs.md D10). The randomness
(key pairs, encapsulation) is passed in, so handshakes can be deterministic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from qtls import crypto
from qtls.alerts import Alert, AlertError
from qtls.levels import KEY_EXCHANGE_GROUP

GROUP = KEY_EXCHANGE_GROUP
MLKEM = "ML-KEM-768"
_EK_LEN = crypto.KEMS[MLKEM].public_key_len
_CT_LEN = crypto.KEMS[MLKEM].ciphertext_len
X25519_LEN = 32
CLIENT_SHARE_LEN = _EK_LEN + X25519_LEN
SERVER_SHARE_LEN = _CT_LEN + X25519_LEN
SECRET_LEN = 64

Encapsulate = Callable[[bytes], tuple[bytes, bytes]]  # ek -> (ciphertext, shared secret)


def _illegal(message: str, reason: str) -> AlertError:
    return AlertError(Alert.illegal_parameter, message, reason)


def _x25519(key: crypto.X25519PrivateKey, peer: bytes) -> bytes:
    try:
        return key.exchange(peer)
    except crypto.InvalidPublicKey:
        raise _illegal("X25519 key share is a low-order point", "x25519") from None


@dataclass(frozen=True)
class ClientKeyExchange:
    """The client's ephemeral keys, from ClientHello until ServerHello."""

    mlkem: crypto.KEMPrivateKey
    x25519: crypto.X25519PrivateKey

    def __post_init__(self) -> None:
        if self.mlkem.alg != MLKEM:
            raise ValueError(f"X25519MLKEM768 needs an {MLKEM} key, not {self.mlkem.alg}")

    @property
    def share(self) -> bytes:
        return self.mlkem.public_key + self.x25519.public_key

    def finish(self, server_share: bytes) -> bytes:
        """The 64-byte shared secret from the server's key share."""
        if len(server_share) != SERVER_SHARE_LEN:
            raise _illegal(f"server key share is {len(server_share)} bytes, expected {SERVER_SHARE_LEN}", "share-length")
        ct, peer = server_share[:_CT_LEN], server_share[_CT_LEN:]
        x_ss = _x25519(self.x25519, peer)
        # Implicit rejection: a valid-length ciphertext never fails to decapsulate.
        # If the backend raises anyway, that's a local failure, never the peer's (D10).
        return self.mlkem.decapsulate(ct) + x_ss


def server_respond(
    client_share: bytes, x25519: crypto.X25519PrivateKey, encapsulate: Encapsulate
) -> tuple[bytes, bytes]:
    """Return ``(server_share, shared_secret)`` for a client's key share."""
    if len(client_share) != CLIENT_SHARE_LEN:
        raise _illegal(f"client key share is {len(client_share)} bytes, expected {CLIENT_SHARE_LEN}", "share-length")
    ek, peer = client_share[:_EK_LEN], client_share[_EK_LEN:]
    try:
        ct, k_ss = encapsulate(ek)
    except crypto.InvalidPublicKey:
        raise _illegal("ML-KEM-768 encapsulation key fails the FIPS 203 check", "mlkem-ek") from None
    x_ss = _x25519(x25519, peer)
    return ct + x25519.public_key, k_ss + x_ss
