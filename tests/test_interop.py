"""Interop with OpenSSL over TCP: the independent stack that closes P5 (specs.md D16, D29).

Both directions, configs A and B with ML-DSA (Falcon-512 has a private
codepoint and never meets another stack). Each run checks that the handshake
completes on both sides, data larger than one record crosses both ways,
close_notify crosses both ways, and **every keylog secret OpenSSL derived
equals ours** for that connection: five labels, filtered by client_random.
Mutants of the hybrid layout must turn these tests red.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import re
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

import openssl_tools as ot
from qtls import configs, hybrid
from qtls import handshake as hs
from qtls.alerts import Alert
from qtls.handshake import HandshakeComplete
from qtls.transport import tcp

pytestmark = [pytest.mark.openssl, pytest.mark.usefixtures("require_liboqs")]

UTC = dt.timezone.utc
NOT_BEFORE = dt.datetime(2026, 1, 1, tzinfo=UTC)
NOW = NOT_BEFORE + dt.timedelta(days=30)
TIMEOUT = 20.0

A = configs.CONFIG_A
CONFIGS = [A, configs.config_a(2), configs.config_b("ML-DSA-44"), configs.config_b("ML-DSA-65", scts=2)]
PEER_SIGNATURE = {"ECDSA-P256-SHA256": "ecdsa_secp256r1_sha256", "ML-DSA-44": "mldsa44", "ML-DSA-65": "mldsa65"}
BACKENDS = {
    # The interop peer and the openssl backend share a code lineage, so run liboqs too.
    "openssl": dict(hs.DEFAULT_BACKENDS),
    "liboqs": {**hs.DEFAULT_BACKENDS, "ML-KEM-768": "liboqs", "ML-DSA-44": "liboqs", "ML-DSA-65": "liboqs"},
}


def payload(tag: bytes, n: int = 20_000) -> bytes:
    """More than one 2^14-byte record, one line (s_server and s_client relay stdin line by line)."""
    body = (tag * n)[:n]
    return body + b"\n"


@dataclasses.dataclass
class Setup:
    client: hs.ClientConfig
    server: hs.ServerConfig
    pki: ot.Pki
    keylog: Path


def setup(cfg: configs.SigConfig, backends: dict, tmp_path: Path) -> Setup:
    client, server, chain = configs.endpoints(cfg, not_before=NOT_BEFORE, now=NOW, backends=backends)
    return Setup(client, server, ot.write_pki(tmp_path, chain, server.signing_key), tmp_path / "openssl.keylog")


def recv_exactly(session: tcp.Session, n: int) -> bytes:
    got = b""
    while len(got) < n:
        data = session.recv(timeout=TIMEOUT)
        assert data, f"peer closed after {len(got)} of {n} bytes"
        got += data
    return got


def assert_keylogs_match(session: tcp.Session, keylog_file: Path) -> None:
    ours = ot.our_keylog(session.conn.keylog_lines())
    theirs = ot.keylog(keylog_file, session.conn._client_random)
    assert sorted(ours) == sorted(ot.KEYLOG_LABELS), ours.keys()
    assert sorted(theirs) == sorted(ot.KEYLOG_LABELS), theirs.keys()
    assert ours == theirs


@pytest.fixture
def nst_drops(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[int]]:
    """Counts NewSessionTickets the client receives and drops (D26)."""
    dropped: list[int] = []
    original = hs.Client._drop_post_handshake

    def spy(self: hs.Client, raw) -> bool:  # noqa: ANN001
        result = original(self, raw)
        if result:
            dropped.append(raw.msg_type)
        return result

    monkeypatch.setattr(hs.Client, "_drop_post_handshake", spy)
    yield dropped


# --------------------------------------------------------------------------- #
# qTLS client -> openssl s_server
# --------------------------------------------------------------------------- #


def run_client(binary: str, s: Setup, *server_args: str) -> tuple[tcp.Session, str]:
    """Handshake, data both ways (the first with our Finished), close; returns the session and s_server's output."""
    server, port = ot.s_server(binary, s.pki, s.keylog, "-groups", ot.GROUP, *server_args)
    with server:
        ours, theirs = payload(b"qtls client "), payload(b"openssl server ")

        def first_data(session: tcp.Session, events: list[hs.Event]) -> None:
            if any(isinstance(e, HandshakeComplete) for e in events):
                session.queue(ours)

        with tcp.connect(("127.0.0.1", port), s.client, timeout=TIMEOUT, on_receive=first_data) as session:
            server.wait_for(re.escape(ours[-64:]))
            server.write(theirs)
            assert recv_exactly(session, len(theirs)) == theirs
            session.close(timeout=TIMEOUT)
        return session, server.finish()


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("cfg", CONFIGS, ids=lambda c: c.name)
def test_qtls_client_with_openssl_server(require_openssl: str, tmp_path: Path, cfg: configs.SigConfig, backend: str,
                                        nst_drops: list[int]) -> None:  # fmt: skip
    s = setup(cfg, BACKENDS[backend], tmp_path)
    session, _ = run_client(require_openssl, s, "-num_tickets", "2")
    assert_keylogs_match(session, s.keylog)
    assert nst_drops == [4, 4]  # both tickets arrived after Finished and were dropped
    assert session.conn.state is hs.State.CLOSED


# --------------------------------------------------------------------------- #
# openssl s_client -> qTLS server
# --------------------------------------------------------------------------- #


def listener() -> socket.socket:
    return socket.create_server(("127.0.0.1", 0))


def run_server(binary: str, s: Setup, *client_args: str) -> tuple[tcp.Session, str]:
    with listener() as sock:
        client = ot.s_client(binary, sock.getsockname()[1], s.pki, NOW, s.keylog, *client_args)
        with client:
            ours, theirs = payload(b"qtls server "), payload(b"openssl client ")
            with tcp.accept(sock, s.server, timeout=TIMEOUT) as session:
                client.write(theirs)
                assert recv_exactly(session, len(theirs)) == theirs
                session.send(ours, timeout=TIMEOUT)
                client.wait_for(re.escape(ours[-64:]))
                session.close(timeout=TIMEOUT)
            return session, client.finish()


def openssl_saw(output: str, signature: str) -> None:
    assert "Verify return code: 0 (ok)" in output, output
    assert "Negotiated TLS1.3 group: X25519MLKEM768" in output, output
    assert f"Peer signature type: {signature}" in output, output


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("cfg", CONFIGS, ids=lambda c: c.name)
def test_openssl_client_with_qtls_server(require_openssl: str, tmp_path: Path, cfg: configs.SigConfig, backend: str) -> None:
    s = setup(cfg, BACKENDS[backend], tmp_path)
    session, output = run_server(require_openssl, s, "-groups", ot.GROUP)
    openssl_saw(output, PEER_SIGNATURE[cfg.leaf_alg])
    assert_keylogs_match(session, s.keylog)
    assert session.conn.state is hs.State.CLOSED


def test_default_openssl_client_gets_the_hybrid_group(require_openssl: str, tmp_path: Path) -> None:
    """OpenSSL's default ClientHello offers X25519MLKEM768 and X25519 shares; we pick the hybrid."""
    s = setup(A, BACKENDS["openssl"], tmp_path)
    session, output = run_server(require_openssl, s)
    openssl_saw(output, "ecdsa_secp256r1_sha256")
    assert_keylogs_match(session, s.keylog)


# --------------------------------------------------------------------------- #
# Failing negotiations
# --------------------------------------------------------------------------- #


def test_openssl_server_without_the_hybrid_group_refuses_our_client(require_openssl: str, tmp_path: Path) -> None:
    s = setup(A, BACKENDS["openssl"], tmp_path)
    server, port = ot.s_server(require_openssl, s.pki, s.keylog, "-groups", "X25519")
    with server, pytest.raises(tcp.TLSFailed) as exc:
        tcp.connect(("127.0.0.1", port), s.client, timeout=TIMEOUT)
    assert exc.value.event == hs.PeerAlerted(2, Alert.handshake_failure)


def _server_fails(binary: str, s: Setup, *client_args: str) -> tuple[hs.ConnectionFailed, str]:
    with listener() as sock:
        client = ot.s_client(binary, sock.getsockname()[1], s.pki, NOW, s.keylog, *client_args)
        with client:
            with pytest.raises(tcp.TLSFailed) as exc:
                tcp.accept(sock, s.server, timeout=TIMEOUT)
            return exc.value.event, client.finish()  # type: ignore[return-value]


def test_openssl_client_without_the_hybrid_group_gets_handshake_failure(require_openssl: str, tmp_path: Path) -> None:
    """No HelloRetryRequest (D16): the only answer is the alert."""
    event, output = _server_fails(require_openssl, setup(A, BACKENDS["openssl"], tmp_path), "-groups", "X25519")
    assert event.alert is Alert.handshake_failure, event
    assert "handshake failure" in output, output


def test_openssl_client_without_our_signature_schemes_gets_handshake_failure(require_openssl: str, tmp_path: Path) -> None:
    event, output = _server_fails(require_openssl, setup(A, BACKENDS["openssl"], tmp_path), "-groups", ot.GROUP,
                                  "-sigalgs", "rsa_pss_rsae_sha256")  # fmt: skip
    assert (event.alert, event.reason) == (Alert.handshake_failure, "signature-scheme"), event
    assert "handshake failure" in output, output


def test_our_client_rejects_an_untrusted_openssl_server(require_openssl: str, tmp_path: Path) -> None:
    s = setup(A, BACKENDS["openssl"], tmp_path)
    other = configs.endpoints(A, not_before=NOT_BEFORE, now=NOW, fixture_seed=b"another pki")[0]
    server, port = ot.s_server(require_openssl, s.pki, s.keylog, "-groups", ot.GROUP)
    with server:
        with pytest.raises(tcp.TLSFailed) as exc:
            tcp.connect(("127.0.0.1", port), dataclasses.replace(s.client, anchors=other.anchors), timeout=TIMEOUT)
        assert exc.value.event.alert in (Alert.unknown_ca, Alert.bad_certificate), exc.value.event
        server.wait_for(rb"alert (unknown ca|bad certificate)")


def test_openssl_key_update_is_refused(require_openssl: str, tmp_path: Path) -> None:
    """KeyUpdate isn't implemented in Phase 2 (D26): it ends the connection with unexpected_message."""
    s = setup(A, BACKENDS["openssl"], tmp_path)
    with listener() as sock:
        client = ot.s_client(require_openssl, sock.getsockname()[1], s.pki, NOW, s.keylog, "-groups", ot.GROUP)
        with client, tcp.accept(sock, s.server, timeout=TIMEOUT) as session:
            client.write(b"k\n")
            with pytest.raises(tcp.TLSFailed) as exc:
                session.recv(timeout=TIMEOUT)
            assert exc.value.event.alert is Alert.unexpected_message, exc.value.event


# --------------------------------------------------------------------------- #
# Mutants: a wrong hybrid layout in qTLS must turn the interop red (P5)
# --------------------------------------------------------------------------- #


def _swap_secret_client(mp: pytest.MonkeyPatch) -> None:
    finish = hybrid.ClientKeyExchange.finish
    mp.setattr(hybrid.ClientKeyExchange, "finish", lambda self, share: (ss := finish(self, share))[32:] + ss[:32])


def _swap_secret_server(mp: pytest.MonkeyPatch) -> None:
    respond = hybrid.server_respond
    mp.setattr(hybrid, "server_respond", lambda *a: (lambda r: (r[0], r[1][32:] + r[1][:32]))(respond(*a)))


def _swap_share_client(mp: pytest.MonkeyPatch) -> None:
    mp.setattr(hybrid.ClientKeyExchange, "share", property(lambda self: self.x25519.public_key + self.mlkem.public_key))


def _swap_share_server(mp: pytest.MonkeyPatch) -> None:
    respond = hybrid.server_respond
    mp.setattr(hybrid, "server_respond", lambda *a: (lambda r: (r[0][-32:] + r[0][:-32], r[1]))(respond(*a)))


def _drop_x25519_client(mp: pytest.MonkeyPatch) -> None:
    finish = hybrid.ClientKeyExchange.finish
    mp.setattr(hybrid.ClientKeyExchange, "finish", lambda self, share: finish(self, share)[:32])


def _drop_x25519_server(mp: pytest.MonkeyPatch) -> None:
    respond = hybrid.server_respond
    mp.setattr(hybrid, "server_respond", lambda *a: (lambda r: (r[0], r[1][:32]))(respond(*a)))


MUTANTS = {
    "client-secret-order": ("client", _swap_secret_client),
    "server-secret-order": ("server", _swap_secret_server),
    "client-share-order": ("client", _swap_share_client),
    "server-share-order": ("server", _swap_share_server),
    "client-drops-x25519": ("client", _drop_x25519_client),
    "server-drops-x25519": ("server", _drop_x25519_server),
}


@pytest.mark.parametrize("mutant", MUTANTS)
def test_hybrid_layout_mutants_fail_interop(require_openssl: str, tmp_path: Path, mutant: str, monkeypatch: pytest.MonkeyPatch) -> None:
    side, apply = MUTANTS[mutant]
    s = setup(A, BACKENDS["openssl"], tmp_path)
    apply(monkeypatch)
    with pytest.raises(tcp.TLSFailed) as exc:
        if side == "client":
            run_client(require_openssl, s)
        else:
            run_server(require_openssl, s, "-groups", ot.GROUP)
    # Wrong keys fail the first protected record; a mangled ek fails OpenSSL's FIPS 203 check.
    event = exc.value.event
    alert = event.alert if isinstance(event, hs.ConnectionFailed) else event.description
    assert alert in (Alert.bad_record_mac, Alert.illegal_parameter), event


def test_keylog_comparison_notices_a_mislabelled_secret(require_openssl: str, tmp_path: Path) -> None:
    s = setup(A, BACKENDS["openssl"], tmp_path)
    session, _ = run_client(require_openssl, s)
    lines = s.keylog.read_text().replace("CLIENT_TRAFFIC_SECRET_0", "@@").replace("SERVER_TRAFFIC_SECRET_0", "CLIENT_TRAFFIC_SECRET_0").replace("@@", "SERVER_TRAFFIC_SECRET_0")
    s.keylog.write_text(lines)
    with pytest.raises(AssertionError):
        assert_keylogs_match(session, s.keylog)
