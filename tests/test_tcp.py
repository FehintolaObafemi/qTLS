"""The TCP transport (specs.md D29): one write per flight, full duplex, one deadline, failures.

The per-flight oracle is the connection's own ``flights`` (protocol-defined,
qtls.handshake), compared with every byte the transport hands the kernel
through a strict socket wrapper. The transport's ``writes`` log is never the
oracle for itself.
"""

from __future__ import annotations

import datetime as dt
import os
import socket
import struct
import threading
import time
from collections.abc import Callable

import pytest

from qtls import configs
from qtls import handshake as hs
from qtls import messages as m
from qtls import record as rl
from qtls.alerts import Alert, CodecUsageError
from qtls.handshake import HandshakeComplete, SeededRandomness
from qtls.transport import tcp
from handshake_oracle import observe

pytestmark = pytest.mark.usefixtures("require_liboqs")

UTC = dt.timezone.utc
NOT_BEFORE = dt.datetime(2001, 1, 1, tzinfo=UTC)
NOW = NOT_BEFORE + dt.timedelta(days=30)
SEED = b"tcp test seed"
SEEDED_BACKENDS = {**hs.DEFAULT_BACKENDS, "ML-KEM-768": "liboqs", "ML-DSA-44": "liboqs", "ML-DSA-65": "liboqs"}
A = configs.CONFIG_A
MATRIX = [A, configs.config_b("ML-DSA-44"), configs.config_b("Falcon-512", "ML-DSA-44", scts=2), configs.config_b("ML-DSA-65", scts=2)]
T = 10.0


def endpoints(cfg: configs.SigConfig = A) -> tuple[hs.ClientConfig, hs.ServerConfig]:
    c, s, _ = configs.endpoints(cfg, not_before=NOT_BEFORE, now=NOW, backends=SEEDED_BACKENDS,
                                client_randomness=SeededRandomness(SEED), server_randomness=SeededRandomness(SEED))  # fmt: skip
    return c, s


class StrictSocket:
    """A socket the transport may only use through the calls it documents; every send is recorded."""

    ALLOWED = {"setblocking", "setsockopt", "getsockopt", "fileno", "close", "shutdown"}

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self.sends: list[bytes] = []  # what each send() call was handed
        self.taken: list[int] = []  # what the kernel took
        self.recv_calls = 0

    def send(self, data: bytes | bytearray) -> int:
        self.sends.append(bytes(data))
        n = self._sock.send(data)
        self.taken.append(n)
        return n

    def recv(self, n: int) -> bytes:
        self.recv_calls += 1
        return self._sock.recv(n)

    def __getattr__(self, name: str):  # noqa: ANN204
        if name not in self.ALLOWED:
            raise AssertionError(f"transport used socket.{name}")
        return getattr(self._sock, name)


_sessions: list[tcp.Session] = []


@pytest.fixture(autouse=True)
def _close_sessions():  # noqa: ANN202
    yield
    while _sessions:
        _sessions.pop().__exit__(None, None, None)


def run_pair(
    cfg: configs.SigConfig = A,
    client_hook: tcp.OnReceive | None = None,
    server_hook: tcp.OnReceive | None = None,
    after: Callable[[tcp.Session, str], None] | None = None,
) -> tuple[tcp.Session, tcp.Session, StrictSocket, StrictSocket]:
    """A handshake over a loopback TCP connection, each side on its own thread, through StrictSockets."""
    client_cfg, server_cfg = endpoints(cfg)
    listener = socket.create_server(("127.0.0.1", 0))
    out: dict[str, object] = {}

    def serve() -> None:
        try:
            raw, _ = listener.accept()
            strict = StrictSocket(raw)
            session = tcp.Session(hs.Server(server_cfg), strict)  # type: ignore[arg-type]
            _sessions.append(session)
            out["server"], out["server_sock"] = session, strict
            session.handshake(timeout=T, on_receive=server_hook)
            if after:
                after(session, "server")
        except BaseException as exc:  # noqa: BLE001
            out["server_error"] = exc

    thread = threading.Thread(target=serve)
    thread.start()
    raw = socket.create_connection(listener.getsockname(), timeout=T)
    strict = StrictSocket(raw)
    client = hs.Client(client_cfg)
    session = tcp.Session(client, strict)  # type: ignore[arg-type]
    _sessions.append(session)
    client.start()
    try:
        session.handshake(timeout=T, on_receive=client_hook)
        if after:
            after(session, "client")
    finally:
        thread.join(T * 2)
        listener.close()
    if "server_error" in out:
        raise out["server_error"]  # type: ignore[misc]
    return session, out["server"], strict, out["server_sock"]  # type: ignore[return-value]


def flight_bytes(conn: hs.Connection) -> list[bytes]:
    return [b"".join(f.records) for f in conn.flights]


# --------------------------------------------------------------------------- #
# Handshakes, one write per flight
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cfg", MATRIX, ids=lambda c: c.name)
def test_handshake_over_tcp_writes_each_flight_once(cfg: configs.SigConfig) -> None:
    client, server, csock, ssock = run_pair(cfg)
    for session, strict in ((client, csock), (server, ssock)):
        assert strict.sends == flight_bytes(session.conn), session.conn.role
        assert_no_flight_split(strict.sends, session.conn)
        assert strict.taken == [len(d) for d in strict.sends]  # the kernel took each flight whole
    c_wire, s_wire = b"".join(csock.sends), b"".join(ssock.sends)
    observe(SEED, c_wire, s_wire, keylogs=(client.conn.keylog_lines(), server.conn.keylog_lines()))
    assert len(ssock.sends) == 1 and len(csock.sends) == 2  # server: SH..Finished; client: CH, then Finished


def test_a_per_record_transport_fails_the_flight_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """The check above can fail: a transport that writes record by record."""

    def per_record(self: tcp.Session) -> None:
        data = self.conn.data_to_send()
        records, _ = rl.split_records(data)
        for rec in records:
            self._out += rec
            self._send_now()

    monkeypatch.setattr(tcp.Session, "_queue", per_record)
    client, server, csock, ssock = run_pair(configs.config_b("ML-DSA-44"))
    assert ssock.sends != flight_bytes(server.conn)
    with pytest.raises(AssertionError, match="split"):
        assert_no_flight_split(ssock.sends, server.conn)


def assert_no_flight_split(sends: list[bytes], conn: hs.Connection) -> None:
    """Every flight lies inside one write (a write may carry several flights queued in one reaction)."""
    assert b"".join(sends) == b"".join(flight_bytes(conn))
    ends, pos = set(), 0
    for data in sends:
        pos += len(data)
        ends.add(pos)
    pos = 0
    for flight in flight_bytes(conn):
        start, pos = pos, pos + len(flight)
        assert not any(start < end < pos for end in ends), "a flight was split across writes"


def test_finished_and_first_data_share_a_write() -> None:
    """The on_receive hook runs before the reply is written (arch review: Phase 4/5 metrics)."""

    def client_hook(session: tcp.Session, events: list[hs.Event]) -> None:
        if any(isinstance(e, HandshakeComplete) for e in events):
            session.queue(b"first client data")

    client, server, csock, _ = run_pair(client_hook=client_hook)
    assert csock.sends == flight_bytes(client.conn) and len(csock.sends) == 2
    assert client.conn.flights[1].labels == [("handshake", "hs"), ("application_data", "ap")]
    assert server.recv(timeout=T) == b"first client data"


def test_half_rtt_data_joins_the_server_flight() -> None:
    def server_hook(session: tcp.Session, events: list[hs.Event]) -> None:
        if session.conn.state is hs.State.WAIT_CLIENT_FINISHED and not session.sends:
            session.queue(b"half-rtt data")

    def client_hook(session: tcp.Session, events: list[hs.Event]) -> None:
        if any(isinstance(e, HandshakeComplete) for e in events):
            session.queue(b"first client data")

    client, server, csock, ssock = run_pair(client_hook=client_hook, server_hook=server_hook)
    assert ssock.sends == flight_bytes(server.conn) and len(ssock.sends) == 1
    assert server.conn.flights[0].labels[-1] == ("application_data", "ap")
    # The 0.5-RTT record may arrive with the server's Finished, so the client's
    # Finished and its data are two protocol flights in one reaction, and one write.
    assert_no_flight_split(csock.sends, client.conn)
    assert len(csock.sends) == 2
    assert client.recv(timeout=T) == b"half-rtt data"
    assert server.recv(timeout=T) == b"first client data"


def test_nodelay_is_set_on_both_sockets() -> None:
    client, server, csock, ssock = run_pair()
    for strict in (csock, ssock):
        assert strict.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0


def test_events_and_writes_are_timestamped_in_order() -> None:
    client, _, _, _ = run_pair()
    stamps = [t for t, _ in client.events]
    assert stamps == sorted(stamps) and [type(e) for _, e in client.events] == [hs.ServerAuthenticated, HandshakeComplete]
    assert client.sends[0].t_ns < stamps[0] < client.sends[-1].t_ns


# --------------------------------------------------------------------------- #
# Data, closing, full duplex
# --------------------------------------------------------------------------- #


def test_large_data_both_ways_at_once_does_not_deadlock() -> None:
    n = 4 * 1024 * 1024

    def exchange(session: tcp.Session, role: str) -> None:
        session.queue(role.encode()[:1] * n)  # both sides queue 4 MiB before reading anything
        got = b""
        while len(got) < n:
            got += session.recv(timeout=T)
        assert got == (b"s" if role == "client" else b"c") * n

    run_pair(after=exchange)


def test_clean_close_both_ways_and_eof_ends_the_loop() -> None:
    def close(session: tcp.Session, role: str) -> None:
        if role == "client":
            session.send(b"bye", timeout=T)
            session.close(timeout=T)
        else:
            assert session.recv(timeout=T) == b"bye"
            assert session.recv(timeout=T) == b""  # the peer's close_notify
            session.close(timeout=T)

    client, server, csock, ssock = run_pair(after=close)
    assert client.conn.state is server.conn.state is hs.State.CLOSED
    assert csock.fileno() == -1 and ssock.fileno() == -1
    assert csock.recv_calls < 10 and ssock.recv_calls < 10  # no spinning on recv() == b""


# --------------------------------------------------------------------------- #
# Failures
# --------------------------------------------------------------------------- #


def raw_peer(behaviour: Callable[[socket.socket], None]) -> tuple[socket.socket, threading.Thread]:
    """A listener whose one connection is handled by ``behaviour`` on a thread."""
    listener = socket.create_server(("127.0.0.1", 0))

    def run() -> None:
        conn, _ = listener.accept()
        try:
            behaviour(conn)
        finally:
            conn.close()
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return listener, thread


def test_silent_peer_times_out_at_the_deadline() -> None:
    stop = threading.Event()
    listener, thread = raw_peer(lambda conn: stop.wait(5))
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        tcp.connect(listener.getsockname(), endpoints()[0], timeout=0.5)
    assert 0.5 <= time.monotonic() - start < 1.5
    stop.set()
    thread.join()


def test_trickling_peer_cannot_extend_the_deadline() -> None:
    """A per-recv timeout would never fire here: one byte arrives every quarter deadline."""
    stop = threading.Event()

    def trickle(conn: socket.socket) -> None:
        conn.recv(65536)
        sh = plain_server_hello()
        for b in sh:
            if stop.wait(0.15):
                return
            conn.sendall(bytes([b]))

    listener, thread = raw_peer(trickle)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        tcp.connect(listener.getsockname(), endpoints()[0], timeout=0.6)
    assert time.monotonic() - start < 1.5
    stop.set()
    thread.join()


def plain_server_hello() -> bytes:
    """A real ServerHello record from a seeded memory handshake (any bytes will do for trickling)."""
    from qtls.transport import memory

    c, s = endpoints()
    link = memory.handshake(hs.Client(c), hs.Server(s))
    return next(d for who, d in link.wire if who == "server")


@pytest.mark.parametrize("cut", ["before-server-hello", "inside-a-record", "after-server-hello-record"])
def test_peer_closing_mid_handshake_is_truncation(cut: str) -> None:
    flight = plain_server_hello()
    sh_len = 5 + int.from_bytes(flight[3:5], "big")
    keep = {"before-server-hello": 0, "inside-a-record": 20, "after-server-hello-record": sh_len}[cut]

    def cut_off(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.sendall(flight[:keep])
        conn.shutdown(socket.SHUT_WR)
        conn.recv(65536)  # wait for the client to go

    listener, thread = raw_peer(cut_off)
    with pytest.raises(tcp.TLSFailed) as exc:
        tcp.connect(listener.getsockname(), endpoints()[0], timeout=T)
    assert exc.value.event == hs.ConnectionFailed(None, None, "truncated")
    thread.join(T)


def test_server_sees_truncation_when_the_client_goes_after_its_hello() -> None:
    client_cfg, server_cfg = endpoints()
    listener = socket.create_server(("127.0.0.1", 0))
    client = hs.Client(client_cfg)
    client.start()
    raw = socket.create_connection(listener.getsockname())
    raw.sendall(client.data_to_send())
    raw.shutdown(socket.SHUT_WR)
    with pytest.raises(tcp.TLSFailed) as exc:
        tcp.accept(listener, server_cfg, timeout=T)
    assert exc.value.event == hs.ConnectionFailed(None, None, "truncated")
    raw.close()
    listener.close()


def test_reset_is_an_oserror_and_the_session_is_dead() -> None:
    def reset_after_handshake(session: tcp.Session, role: str) -> None:
        if role == "server":
            session.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            session.sock.close()  # RST
        else:
            with pytest.raises(OSError):
                for _ in range(50):
                    session.send(b"x" * 65536, timeout=T)
                    session.recv(timeout=0.05)
            with pytest.raises(CodecUsageError):  # using a closed session is misuse
                session.send(b"more")

    try:
        run_pair(after=reset_after_handshake)
    except TimeoutError:  # pragma: no cover - the client's recv(0.05) can expire before the RST lands
        pytest.fail("RST not seen")


def test_our_alert_is_flushed_before_the_failure_is_raised() -> None:
    got = bytearray()

    def bad_server_hello(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.sendall(rl.encode_plaintext(rl.ContentType.handshake, b"\x02\x00\x00\x01\x00"))
        while chunk := conn.recv(65536):
            got.extend(chunk)

    listener, thread = raw_peer(bad_server_hello)
    with pytest.raises(tcp.TLSFailed) as exc:
        tcp.connect(listener.getsockname(), endpoints()[0], timeout=T)
    thread.join(T)
    assert exc.value.event.alert is Alert.decode_error
    assert bytes(got) == rl.encode_plaintext(rl.ContentType.alert, bytes([2, Alert.decode_error]))


def test_a_local_bug_flushes_internal_error_and_is_reraised(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(body: bytes) -> m.EncryptedExtensions:
        raise ValueError("bug")

    monkeypatch.setattr(m.EncryptedExtensions, "decode", staticmethod(broken))
    got: list[bytes] = []

    client_cfg, server_cfg = endpoints()
    listener = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        sock, _ = listener.accept()
        server = hs.Server(server_cfg)
        server.receive(sock.recv(65536))
        sock.sendall(server.data_to_send())
        while chunk := sock.recv(65536):
            got.append(chunk)
        sock.close()

    thread = threading.Thread(target=serve)
    thread.start()
    with pytest.raises(ValueError, match="bug"):
        tcp.connect(listener.getsockname(), client_cfg, timeout=T)
    thread.join(T)
    listener.close()
    record = b"".join(got)
    assert record[:3] == bytes([rl.ContentType.application_data, 3, 3]) and len(record) == 5 + 2 + 1 + 16  # an encrypted alert


def test_no_descriptors_leak() -> None:
    before = len(os.listdir("/dev/fd"))
    for _ in range(5):
        for session in run_pair()[:2]:
            session.__exit__(None, None, None)
        with pytest.raises(TimeoutError):
            stop = threading.Event()
            listener, thread = raw_peer(lambda conn: stop.wait(5))
            try:
                tcp.connect(listener.getsockname(), endpoints()[0], timeout=0.1)
            finally:
                stop.set()
                thread.join()
    assert len(os.listdir("/dev/fd")) <= before


def test_a_session_context_closes_the_socket_on_error() -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        sock = socket.create_connection(listener.getsockname())
        peer, _ = listener.accept()
        with pytest.raises(RuntimeError), tcp.Session(hs.Client(endpoints()[0]), sock) as session:
            raise RuntimeError
        assert session.sock.fileno() == -1
        peer.close()


class OneByteSocket(StrictSocket):
    """A kernel that takes one byte per send(), so output is always pending after the first write."""

    def send(self, data: bytes | bytearray) -> int:
        return super().send(bytes(data[:1]))


def test_a_partially_written_alert_is_flushed_before_the_failure_is_raised() -> None:
    got = bytearray()

    def bad_server_hello(conn: socket.socket) -> None:
        conn.recv(1)
        conn.sendall(rl.encode_plaintext(rl.ContentType.handshake, b"\x02\x00\x00\x01\x00"))
        while chunk := conn.recv(65536):
            got.extend(chunk)

    listener, thread = raw_peer(bad_server_hello)
    client = hs.Client(endpoints()[0])
    session = tcp.Session(client, OneByteSocket(socket.create_connection(listener.getsockname())))  # type: ignore[arg-type]
    _sessions.append(session)
    client.start()
    with pytest.raises(tcp.TLSFailed) as exc:
        session.handshake(timeout=T)
    thread.join(T)
    assert exc.value.event.alert is Alert.decode_error
    assert bytes(got).endswith(rl.encode_plaintext(rl.ContentType.alert, bytes([2, Alert.decode_error])))


# --------------------------------------------------------------------------- #
# Failures are TLSFailed whatever the timing; misuse is CodecUsageError
# (full-review findings: arch, eng, test)
# --------------------------------------------------------------------------- #


def raw(session: tcp.Session) -> socket.socket:
    """The real socket under a StrictSocket, for a test peer that writes by hand."""
    sock = session.sock._sock if isinstance(session.sock, StrictSocket) else session.sock
    sock.setblocking(True)
    return sock


def _server_raw(session: tcp.Session, data: bytes) -> None:
    raw(session).sendall(data)


def test_data_and_a_fatal_alert_together_then_every_call_raises_the_alert() -> None:
    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            session.conn.send(b"hello")
            session.conn._send_alert(Alert.internal_error)  # data and a fatal alert in one write
            _server_raw(session, session.conn.data_to_send())
            time.sleep(0.3)
        else:
            assert session.recv(timeout=T) == b"hello"
            assert session._failure is not None  # arrived with the data, not raised yet
            with pytest.raises(tcp.TLSFailed) as exc:
                session.close(timeout=T)
            assert exc.value.event == hs.PeerAlerted(2, Alert.internal_error)
            assert session.sock.fileno() == -1
            with pytest.raises(tcp.TLSFailed):
                session.send(b"x")
            with pytest.raises(tcp.TLSFailed):
                session.recv(timeout=T)
            session.close()  # already reported and closed: a no-op

    run_pair(after=after)


@pytest.mark.parametrize("call", ["send", "recv", "queue"])
def test_a_pending_peer_alert_is_raised_by_the_next_call(call: str) -> None:
    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            session.conn.send(b"hello")
            session.conn._send_alert(Alert.internal_error)
            _server_raw(session, session.conn.data_to_send())
            time.sleep(0.3)
        else:
            assert session.recv(timeout=T) == b"hello"
            with pytest.raises(tcp.TLSFailed):
                {"send": lambda: session.send(b"x"), "recv": lambda: session.recv(timeout=T), "queue": lambda: session.queue(b"x")}[call]()
            assert session.sock.fileno() == -1

    run_pair(after=after)


def test_a_peer_alert_while_our_output_is_stuck_is_tlsfailed_at_once() -> None:
    """Our 64 MiB can never be written (the peer stops reading); the peer's alert must still win."""

    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            time.sleep(0.3)  # let the client's buffers fill
            session.conn._send_alert(Alert.bad_record_mac)
            _server_raw(session, session.conn.data_to_send())
            time.sleep(1.0)
        else:
            start = time.monotonic()
            with pytest.raises(tcp.TLSFailed) as exc:
                session.send(b"x" * (64 << 20), timeout=T)
            assert exc.value.event == hs.PeerAlerted(2, Alert.bad_record_mac)
            assert time.monotonic() - start < T / 2

    run_pair(after=after)


def test_our_failure_while_data_is_queued_sends_the_alert_after_it_in_order() -> None:
    """Queued records are already encrypted under consecutive sequence numbers, so they all go out, then
    the alert, and the peer's own connection must decrypt every one of them (full re-review Block)."""
    n = 8 << 20
    peer_events: list[hs.Event] = []

    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            time.sleep(0.3)  # the client's buffers fill
            sock = raw(session)
            sock.sendall(rl.encode_plaintext(rl.ContentType.application_data, b"\x00" * 40)[:5] + bytes(40))
            sock.settimeout(T)
            while chunk := sock.recv(1 << 20):
                peer_events.extend(session.conn.receive(chunk))
        else:
            with pytest.raises(tcp.TLSFailed) as exc:
                session.send(b"x" * n, timeout=T)
            assert (exc.value.event.alert, exc.value.event.reason) == (Alert.bad_record_mac, "bad-mac")

    run_pair(after=after)
    assert peer_events[-1] == hs.PeerAlerted(2, Alert.bad_record_mac)
    assert sum(len(e.data) for e in peer_events if isinstance(e, hs.ApplicationData)) == n


class BrokenPipeAfterHello(StrictSocket):
    def send(self, data: bytes | bytearray) -> int:
        if self.sends:
            raise BrokenPipeError(32, "Broken pipe")
        return super().send(data)


def test_a_socket_error_after_our_failure_is_tlsfailed_chained_to_it() -> None:
    def bad_server_hello(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.sendall(rl.encode_plaintext(rl.ContentType.handshake, b"\x02\x00\x00\x01\x00"))
        conn.recv(65536)

    listener, thread = raw_peer(bad_server_hello)
    client = hs.Client(endpoints()[0])
    session = tcp.Session(client, BrokenPipeAfterHello(socket.create_connection(listener.getsockname())))  # type: ignore[arg-type]
    _sessions.append(session)
    client.start()
    with pytest.raises(tcp.TLSFailed) as exc:
        session.handshake(timeout=T)
    assert exc.value.event.alert is Alert.decode_error
    assert isinstance(exc.value.__cause__, BrokenPipeError)
    assert session.sock.fileno() == -1
    thread.join(T)


@pytest.mark.parametrize("side", ["client", "server"])
def test_an_exception_in_the_hook_abandons_the_reaction(side: str) -> None:
    """The peer never sees a flight from a connection the application has given up (it sees EOF)."""

    def boom(session: tcp.Session, events: list[hs.Event]) -> None:
        if side == "client" and any(isinstance(e, HandshakeComplete) for e in events):
            raise RuntimeError("app")
        if side == "server":
            raise RuntimeError("app")

    client_cfg, server_cfg = endpoints()
    listener = socket.create_server(("127.0.0.1", 0))
    seen: dict[str, BaseException] = {}

    def serve() -> None:
        try:
            tcp.accept(listener, server_cfg, timeout=T, on_receive=boom if side == "server" else None)
        except BaseException as exc:  # noqa: BLE001
            seen["server"] = exc

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        tcp.connect(listener.getsockname(), client_cfg, timeout=T, on_receive=boom if side == "client" else None)
    except BaseException as exc:  # noqa: BLE001
        seen["client"] = exc
    thread.join(T)
    listener.close()
    other = "server" if side == "client" else "client"
    assert isinstance(seen[side], RuntimeError)
    assert isinstance(seen[other], tcp.TLSFailed) and seen[other].event == hs.ConnectionFailed(None, None, "truncated")


def test_only_queue_may_be_called_from_the_hook() -> None:
    def hook(session: tcp.Session, events: list[hs.Event]) -> None:
        if any(isinstance(e, HandshakeComplete) for e in events):
            session.send(b"re-entered")

    with pytest.raises(CodecUsageError, match="only queue"):
        run_pair(client_hook=hook)


# --------------------------------------------------------------------------- #
# Timing records, partial writes, deadlines, closing
# --------------------------------------------------------------------------- #


def test_every_send_call_and_every_arrival_is_recorded() -> None:
    got = bytearray()

    def bad_server_hello(conn: socket.socket) -> None:
        got.extend(conn.recv(1))
        conn.sendall(rl.encode_plaintext(rl.ContentType.handshake, b"\x02\x00\x00\x01\x00"))
        while chunk := conn.recv(65536):
            got.extend(chunk)

    listener, thread = raw_peer(bad_server_hello)
    client = hs.Client(endpoints()[0])
    strict = OneByteSocket(socket.create_connection(listener.getsockname()))
    session = tcp.Session(client, strict)  # type: ignore[arg-type]
    _sessions.append(session)
    client.start()
    with pytest.raises(tcp.TLSFailed):
        session.handshake(timeout=T)
    thread.join(T)
    assert [s.sent for s in session.sends] == strict.taken  # one record per send() call, none missed
    assert all(s.offered >= s.sent for s in session.sends)
    assert sum(s.sent for s in session.sends) == len(got)  # every byte on the wire is accounted for
    assert [s.t_ns for s in session.sends] == sorted(s.t_ns for s in session.sends)
    assert session.arrivals and session.arrivals[0].nbytes == 10
    assert session.arrivals[0].t_ns <= session.events[0][0]  # arrival before the processed event


def test_arrivals_are_logged_per_segment_before_processing() -> None:
    flight = plain_server_hello()

    def two_segments(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.sendall(flight[:100])
        time.sleep(0.2)
        conn.sendall(flight[100:])
        conn.recv(65536)

    listener, thread = raw_peer(two_segments)
    client = hs.Client(endpoints()[0])
    session = tcp.Session(client, socket.create_connection(listener.getsockname()))
    _sessions.append(session)
    client.start()
    session.handshake(timeout=T)  # the seeded flight is genuine, just split in two segments
    first, second = session.arrivals[:2]
    assert (first.nbytes, second.nbytes) == (100, len(flight) - 100)
    assert second.t_ns - first.t_ns >= 150_000_000


def test_local_bug_alert_is_flushed_whole_through_partial_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(body: bytes) -> m.EncryptedExtensions:
        raise ValueError("bug")

    monkeypatch.setattr(m.EncryptedExtensions, "decode", staticmethod(broken))
    client_cfg, server_cfg = endpoints()
    got = bytearray()

    servers: list[hs.Server] = []

    def serve(conn: socket.socket) -> None:
        server = hs.Server(server_cfg)
        servers.append(server)
        hello = b""
        while len(hello) < 5 or len(hello) < 5 + int.from_bytes(hello[3:5], "big"):
            hello += conn.recv(65536)
        server.receive(hello)
        conn.sendall(server.data_to_send())
        while chunk := conn.recv(65536):
            got.extend(chunk)

    listener, thread = raw_peer(serve)
    client = hs.Client(client_cfg)
    session = tcp.Session(client, OneByteSocket(socket.create_connection(listener.getsockname())))  # type: ignore[arg-type]
    _sessions.append(session)
    client.start()
    with pytest.raises(ValueError, match="bug"):
        session.handshake(timeout=T)
    thread.join(T)
    assert servers[0].receive(bytes(got)) == [hs.PeerAlerted(2, Alert.internal_error)]  # whole, and decryptable


def test_accept_times_out_without_a_client_and_leaves_the_listener_alone() -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(123.0)
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            tcp.accept(listener, endpoints()[1], timeout=0.3)
        assert time.monotonic() - start < 1.0
        assert listener.gettimeout() == 123.0


def test_accept_is_one_deadline_for_accept_and_handshake() -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        silent = socket.socket()

        def late_connect() -> None:
            time.sleep(0.4)
            silent.connect(listener.getsockname())

        thread = threading.Thread(target=late_connect)
        thread.start()
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            tcp.accept(listener, endpoints()[1], timeout=0.6)
        assert time.monotonic() - start < 0.9  # not 0.4 + a fresh 0.6
        thread.join()
        silent.close()


def test_close_notify_then_silence_mid_handshake_is_an_error() -> None:
    def close_notify_and_hold(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.sendall(rl.encode_plaintext(rl.ContentType.alert, bytes([1, Alert.close_notify])))
        conn.recv(65536)  # hold the socket open until the client goes

    listener, thread = raw_peer(close_notify_and_hold)
    with pytest.raises(ConnectionError, match="during the handshake"):
        tcp.connect(listener.getsockname(), endpoints()[0], timeout=T)
    thread.join(T)


def test_recv_returns_at_close_notify_while_the_peer_holds_the_socket_open() -> None:
    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            session.conn.close()
            _server_raw(session, session.conn.data_to_send())
            time.sleep(1.0)  # no FIN yet
        else:
            start = time.monotonic()
            assert session.recv(timeout=T) == b""
            assert time.monotonic() - start < 0.8

    run_pair(after=after)


def test_close_is_idempotent_and_closed_sessions_refuse_use() -> None:
    def after(session: tcp.Session, role: str) -> None:
        session.close(timeout=T)
        session.close(timeout=T)
        with pytest.raises(CodecUsageError, match="closed"):
            session.send(b"x")
        with pytest.raises(CodecUsageError, match="closed"):
            session.recv()

    run_pair(after=after)


def test_peer_eof_with_our_output_pending_is_an_error_never_a_silent_return() -> None:
    """EOF without close_notify is truncation (D26), even while we are still writing; the peer gets whole records."""
    n = 8 << 20
    received = bytearray()

    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            session.sock.setblocking(True)
            session.sock.shutdown(socket.SHUT_WR)  # EOF to the client; we keep reading
            sock = raw(session)
            sock.settimeout(T)
            while chunk := sock.recv(1 << 20):
                received.extend(chunk)
        else:
            time.sleep(0.1)
            with pytest.raises(tcp.TLSFailed) as exc:
                session.send(b"y" * n, timeout=T)
            assert exc.value.event == hs.ConnectionFailed(None, None, "truncated")

    run_pair(after=after)
    _, rest = rl.split_records(bytes(received))
    assert rest == b""


def test_a_peer_alert_then_close_while_we_write_is_the_alert_not_a_reset() -> None:
    """Reads come first: the alert in our receive buffer wins over the reset our next write would hit."""

    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            time.sleep(0.3)  # the client's buffers fill
            session.conn._send_alert(Alert.bad_record_mac)
            sock = raw(session)
            sock.sendall(session.conn.data_to_send())
            sock.close()  # unread data in our buffer: the kernel answers further writes with RST
        else:
            with pytest.raises(tcp.TLSFailed) as exc:
                session.send(b"x" * (64 << 20), timeout=T)
            assert exc.value.event == hs.PeerAlerted(2, Alert.bad_record_mac)

    run_pair(after=after)


def test_recv_raises_a_peer_alert_that_arrives_alone() -> None:
    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            time.sleep(0.2)
            session.conn._send_alert(Alert.internal_error)
            _server_raw(session, session.conn.data_to_send())
            time.sleep(0.5)
        else:
            with pytest.raises(tcp.TLSFailed) as exc:
                session.recv(timeout=T)
            assert exc.value.event == hs.PeerAlerted(2, Alert.internal_error)

    run_pair(after=after)


def test_connect_is_one_deadline_for_connecting_and_the_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = threading.Event()
    listener, thread = raw_peer(lambda conn: stop.wait(5))
    real = socket.create_connection

    def slow(address, timeout=None):  # noqa: ANN001, ANN202
        time.sleep(0.4)
        return real(address, timeout=timeout)

    monkeypatch.setattr(socket, "create_connection", slow)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        tcp.connect(listener.getsockname(), endpoints()[0], timeout=0.6)
    assert time.monotonic() - start < 0.9  # not 0.4 + a fresh 0.6
    stop.set()
    thread.join()


@pytest.mark.parametrize("previous", [123.0, 0.0, None], ids=["timeout", "non-blocking", "blocking"])
def test_a_successful_accept_leaves_the_listener_as_it_was(previous: float | None) -> None:
    client_cfg, server_cfg = endpoints()
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(previous)
        thread = threading.Thread(target=lambda: _sessions.append(tcp.connect(listener.getsockname(), client_cfg, timeout=T)))
        thread.start()
        _sessions.append(tcp.accept(listener, server_cfg, timeout=T))
        thread.join(T)
        assert listener.gettimeout() == previous


# --------------------------------------------------------------------------- #
# Test re-review: behaviours mutants showed were unpinned
# --------------------------------------------------------------------------- #


def test_the_hook_is_not_called_for_a_receive_that_ends_the_connection() -> None:
    seen: list[list[hs.Event]] = []

    def bad_server_hello(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.sendall(rl.encode_plaintext(rl.ContentType.handshake, b"\x02\x00\x00\x01\x00"))
        conn.recv(65536)

    listener, thread = raw_peer(bad_server_hello)
    with pytest.raises(tcp.TLSFailed):
        tcp.connect(listener.getsockname(), endpoints()[0], timeout=T, on_receive=lambda s, ev: seen.append(list(ev)))
    thread.join(T)
    assert seen == []


def test_nothing_is_written_after_the_peer_alert_arrives() -> None:
    """With the socket writable, the alert still stops our writes in the same wait (D26: never answered)."""
    box: dict[str, tcp.Session] = {}

    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            time.sleep(0.2)
            session.conn._send_alert(Alert.bad_record_mac)
            raw(session).sendall(session.conn.data_to_send())
            time.sleep(1.0)
        else:
            session.sock.__class__ = OneByteSocket  # from now on the kernel takes one byte per send
            with pytest.raises(tcp.TLSFailed):
                session.send(b"x" * 2_000_000, timeout=T)
            box["client"] = session

    run_pair(after=after)
    client = box["client"]
    t_alert = max(a.t_ns for a in client.arrivals if a.nbytes)
    assert all(s.t_ns < t_alert for s in client.sends)


def test_close_notify_then_true_silence_mid_handshake_is_prompt() -> None:
    """The peer neither reads our reply nor closes: close_notify alone must end the handshake."""
    stop = threading.Event()

    def close_notify_then_nothing(conn: socket.socket) -> None:
        conn.recv(65536)
        conn.sendall(rl.encode_plaintext(rl.ContentType.alert, bytes([1, Alert.close_notify])))
        stop.wait(5)

    listener, thread = raw_peer(close_notify_then_nothing)
    start = time.monotonic()
    with pytest.raises(ConnectionError, match="during the handshake"):
        tcp.connect(listener.getsockname(), endpoints()[0], timeout=3)
    assert time.monotonic() - start < 1
    stop.set()
    thread.join(T)


class WouldBlockEveryOtherSend(StrictSocket):
    """A kernel that is full on every other send(): the attempt is recorded with nothing taken."""

    def send(self, data: bytes | bytearray) -> int:
        if len(self.sends) % 2:
            self.sends.append(bytes(data))
            self.taken.append(0)
            raise BlockingIOError
        return super().send(bytes(data[:500]))


def test_a_send_the_kernel_refuses_is_recorded_with_nothing_sent() -> None:
    got = bytearray()

    def bad_server_hello(conn: socket.socket) -> None:
        got.extend(conn.recv(1))
        conn.sendall(rl.encode_plaintext(rl.ContentType.handshake, b"\x02\x00\x00\x01\x00"))
        while chunk := conn.recv(65536):
            got.extend(chunk)

    listener, thread = raw_peer(bad_server_hello)
    client = hs.Client(endpoints()[0])
    strict = WouldBlockEveryOtherSend(socket.create_connection(listener.getsockname()))
    session = tcp.Session(client, strict)  # type: ignore[arg-type]
    _sessions.append(session)
    client.start()
    with pytest.raises(tcp.TLSFailed):
        session.handshake(timeout=T)
    thread.join(T)
    assert [s.sent for s in session.sends] == strict.taken and 0 in strict.taken
    assert sum(s.sent for s in session.sends) == len(got)


def test_a_hook_exception_with_output_pending_writes_nothing_more() -> None:
    box: dict[str, object] = {}

    def after(session: tcp.Session, role: str) -> None:
        if role == "server":
            time.sleep(0.2)
            session.send(b"poke", timeout=T)  # makes the client's hook run while its output is stuck
            sock = raw(session)
            sock.settimeout(T)
            try:
                while sock.recv(1 << 20):
                    pass
            except OSError:
                pass
        else:
            session.sock.__class__ = OneByteSocket
            session.queue(b"x" * 200_000)

            def boom(s: tcp.Session, events: list[hs.Event]) -> None:
                box["t_hook"] = time.perf_counter_ns()
                raise RuntimeError("app")

            with pytest.raises(RuntimeError, match="app"):
                session.drive(lambda: False, timeout=T, on_receive=boom)
            box["client"] = session

    run_pair(after=after)
    client = box["client"]
    assert isinstance(client, tcp.Session)
    assert client.sends and all(s.t_ns < box["t_hook"] for s in client.sends)  # type: ignore[operator]
