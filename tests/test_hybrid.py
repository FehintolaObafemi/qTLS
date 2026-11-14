"""X25519MLKEM768 (RFC 10024, specs.md D10, P5).

Expected values are computed here from the raw primitives, never from
qtls.hybrid, so a layout bug shared by both sides can't pass. The handshake
oracle (tests/handshake_oracle.py) checks the same layout on the wire.
"""

from __future__ import annotations

import pytest

from qtls import crypto, hybrid
from qtls.alerts import Alert, AlertError

pytestmark = pytest.mark.usefixtures("require_liboqs")

LOW_ORDER = bytes(32)  # u = 0: the shared secret is all zeros


def keys(n: int = 0) -> hybrid.ClientKeyExchange:
    kem = crypto.kem_generate("ML-KEM-768", "liboqs", seed=bytes([n]) * 64)
    return hybrid.ClientKeyExchange(kem, crypto.x25519_from_private_bytes(bytes([n + 1]) * 32))


def encapsulator(seed: bytes = b"\x07" * 32):  # noqa: ANN201
    return lambda ek: crypto.kem_encapsulate("ML-KEM-768", ek, "liboqs", seed=seed)


def fails(alert: Alert, reason: str, call) -> None:  # noqa: ANN001
    with pytest.raises(AlertError) as exc:
        call()
    assert (exc.value.alert, exc.value.reason) == (alert, reason), exc.value


def unreduced(ek: bytes) -> bytes:
    """First 12-bit coefficient set to 4095 >= q: fails the FIPS 203 modulus check."""
    return bytes([0xFF, ek[1] | 0x0F]) + ek[2:]


def test_share_and_secret_layout() -> None:
    client = keys()
    assert client.share == client.mlkem.public_key + client.x25519.public_key
    assert len(client.share) == hybrid.CLIENT_SHARE_LEN == 1216
    server_x = crypto.x25519_from_private_bytes(b"\x09" * 32)
    share, secret = hybrid.server_respond(client.share, server_x, encapsulator())
    ct, k_ss = crypto.kem_encapsulate("ML-KEM-768", client.mlkem.public_key, "liboqs", seed=b"\x07" * 32)
    x_ss = server_x.exchange(client.x25519.public_key)
    assert share == ct + server_x.public_key and len(share) == hybrid.SERVER_SHARE_LEN == 1120
    assert secret == k_ss + x_ss and len(secret) == hybrid.SECRET_LEN == 64  # ML-KEM first
    assert client.finish(share) == secret


def test_each_half_contributes() -> None:
    client = keys()
    base_share, base = hybrid.server_respond(client.share, crypto.x25519_from_private_bytes(b"\x09" * 32), encapsulator())
    _, other_x = hybrid.server_respond(client.share, crypto.x25519_from_private_bytes(b"\x0a" * 32), encapsulator())
    _, other_kem = hybrid.server_respond(client.share, crypto.x25519_from_private_bytes(b"\x09" * 32), encapsulator(b"\x08" * 32))
    assert other_x[:32] == base[:32] and other_x[32:] != base[32:]
    assert other_kem[:32] != base[:32] and other_kem[32:] == base[32:]


@pytest.mark.parametrize("n", [1215, 1217, 0])
def test_client_share_length_is_illegal_parameter(n: int) -> None:
    share = (keys().share * 2)[:n]
    fails(Alert.illegal_parameter, "share-length",
          lambda: hybrid.server_respond(share, crypto.x25519_from_private_bytes(b"\x09" * 32), encapsulator()))  # fmt: skip


@pytest.mark.parametrize("n", [1119, 1121])
def test_server_share_length_is_illegal_parameter(n: int) -> None:
    fails(Alert.illegal_parameter, "share-length", lambda: keys().finish(bytes(n)))


@pytest.mark.parametrize("backend", ["openssl", "liboqs"])
def test_unreduced_encapsulation_key_is_illegal_parameter(backend: str) -> None:
    client = keys()
    bad = unreduced(client.mlkem.public_key) + client.x25519.public_key

    def encapsulate(ek: bytes) -> tuple[bytes, bytes]:
        return crypto.kem_encapsulate("ML-KEM-768", ek, backend)

    fails(Alert.illegal_parameter, "mlkem-ek",
          lambda: hybrid.server_respond(bad, crypto.x25519_from_private_bytes(b"\x09" * 32), encapsulate))  # fmt: skip


def test_low_order_x25519_is_illegal_parameter_both_ways() -> None:
    client = keys()
    share = client.mlkem.public_key + LOW_ORDER
    fails(Alert.illegal_parameter, "x25519",
          lambda: hybrid.server_respond(share, crypto.x25519_from_private_bytes(b"\x09" * 32), encapsulator()))  # fmt: skip
    server_share, _ = hybrid.server_respond(client.share, crypto.x25519_from_private_bytes(b"\x09" * 32), encapsulator())
    fails(Alert.illegal_parameter, "x25519", lambda: client.finish(server_share[:-32] + LOW_ORDER))


def test_decapsulation_failure_is_a_local_error() -> None:
    """Implicit rejection means a valid-length ciphertext never fails; if the backend does, it isn't the peer's fault."""
    client = keys()
    server_share, _ = hybrid.server_respond(client.share, crypto.x25519_from_private_bytes(b"\x09" * 32), encapsulator())

    class Broken:
        alg = "ML-KEM-768"
        public_key = client.mlkem.public_key

        def decapsulate(self, ct: bytes) -> bytes:
            raise RuntimeError("backend failure")

    broken = hybrid.ClientKeyExchange(Broken(), client.x25519)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="backend failure"):
        broken.finish(server_share)


def test_client_key_must_be_mlkem768() -> None:
    with pytest.raises(ValueError):
        hybrid.ClientKeyExchange(crypto.kem_generate("ML-KEM-512", "liboqs"), crypto.x25519_generate())
