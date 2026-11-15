"""A TCP transport for sans-I/O connections (specs.md D29).

The contract is the in-memory transport's: write what ``data_to_send``
returns, feed what arrives to ``receive``, and call ``receive_eof`` when the
peer goes away. What TCP adds:

* ``TCP_NODELAY`` on every socket, so a flight isn't held back by Nagle.
* **One write per reaction.** Everything a connection queues in reaction to
  one ``receive`` is handed to the kernel in a single ``send`` call; a flight
  is never split across calls unless the kernel takes only part of it (a
  full socket buffer), and then the rest follows as soon as it can. The
  application's ``on_receive`` hook runs *before* that write and may call
  :meth:`Session.queue`, so data it sends in reaction joins the write: the
  client's Finished and its first application data go out together, and so
  do the server's first flight and its 0.5-RTT data.
* **Full duplex.** The socket is non-blocking and driven by a selector that
  reads before it writes, so both peers can send large data at once and a
  peer's alert is seen even when our write fails.
* **One deadline per call**, on the monotonic clock. It bounds the whole call
  (``connect`` and ``accept`` included), not each ``recv``, so a peer that
  trickles bytes can't hold it open.
* **Timing records** for Phase 5: every ``send`` call (``sends``), every
  ``recv`` before it is processed (``arrivals``), and every event after it is
  processed (``events``), all on ``time.perf_counter_ns``.

Failures, whatever the timing:

* A TLS failure raises :class:`TLSFailed`. For our own failure the alert is
  written first, after any output already queued (it is encrypted under
  consecutive sequence numbers, so none of it can be skipped); a peer's alert
  is never answered, so our pending output is dropped at once. A socket error
  after a TLS failure is chained to it.
* A deadline raises ``TimeoutError``; any other socket error is ``OSError``.
* A local bug inside the connection flushes its ``internal_error`` alert the
  same way and is re-raised unchanged. An exception from the ``on_receive``
  hook is the application's: nothing more is written (the peer sees EOF, never
  a completed flight from an abandoned connection), and it is re-raised.

Any failure closes the socket. A failure that arrives with data is raised by
the next call. Using a session after ``close()`` is a :class:`CodecUsageError`,
and so is calling anything but ``queue`` from inside the hook.
"""

from __future__ import annotations

import selectors
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from qtls.alerts import CodecUsageError
from qtls.handshake import (
    ApplicationData,
    Client,
    ClientConfig,
    Connection,
    ConnectionClosed,
    ConnectionFailed,
    Event,
    HandshakeComplete,
    PeerAlerted,
    Server,
    ServerConfig,
)

RECV_SIZE = 65536
DEFAULT_TIMEOUT = 10.0

OnReceive = Callable[["Session", list[Event]], None]


class TLSFailed(ConnectionError):
    """The TLS connection failed; ``event`` is the ConnectionFailed or PeerAlerted that ended it."""

    def __init__(self, event: ConnectionFailed | PeerAlerted) -> None:
        super().__init__(str(event))
        self.event = event


@dataclass(frozen=True)
class Send:
    t_ns: int
    offered: int  # bytes handed to one send() call
    sent: int  # how many the kernel took (0: it would have blocked)


@dataclass(frozen=True)
class Arrival:
    t_ns: int  # taken right after recv(), before the bytes are processed
    nbytes: int  # 0: the peer closed its side


@dataclass
class Session:
    """One TLS connection over one TCP socket."""

    conn: Connection
    sock: socket.socket
    sends: list[Send] = field(default_factory=list)
    arrivals: list[Arrival] = field(default_factory=list)
    events: list[tuple[int, Event]] = field(default_factory=list)  # (perf_counter_ns after processing, event)
    eof: bool = False  # the peer closed its side
    _out: bytearray = field(default_factory=bytearray)
    _app: bytearray = field(default_factory=bytearray)
    _dead: bool = False
    _failure: ConnectionFailed | PeerAlerted | None = None
    _reported: bool = False
    _in_hook: bool = False
    _closed_by_peer: bool = False
    _complete: bool = False

    def __post_init__(self) -> None:
        self.sock.setblocking(False)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._selector = selectors.DefaultSelector()

    # ----- the loop -------------------------------------------------------- #

    def drive(self, until: Callable[[], bool], *, timeout: float, on_receive: OnReceive | None = None) -> None:
        """Move bytes until ``until()`` holds and all output is written.

        Returns with ``until()`` false only if the peer closed its side and
        nothing is left to write; callers decide what that means.
        """
        self._usable()
        self._run(until, time.monotonic() + timeout, timeout, on_receive)

    def _run(self, until: Callable[[], bool], deadline: float, timeout: float, on_receive: OnReceive | None) -> None:
        try:
            while True:
                self._queue()
                if isinstance(self._failure, PeerAlerted):
                    self._out.clear()  # never answered (D26)
                if self._failure is not None and not self._out:  # our own alert is written first
                    self._reported = True
                    raise TLSFailed(self._failure)
                if until() and not self._out:
                    return
                if self.eof and not self._out:
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"no progress within {timeout} s")
                self._wait(remaining, on_receive)
        except TLSFailed:
            self._kill()
            raise
        except OSError as exc:
            self._kill()
            if self._failure is not None:
                self._reported = True
                raise TLSFailed(self._failure) from exc
            raise
        except BaseException:
            self._flush_best_effort(deadline)  # a local bug's internal_error (an abandoned hook left nothing)
            self._kill()
            raise

    def _queue(self) -> None:
        # Everything queued is already encrypted under consecutive sequence
        # numbers (RFC 8446 §5.3), so it is written in order, never dropped:
        # dropping a record would make every later one, our alert included,
        # undecryptable for the peer.
        data = self.conn.data_to_send()
        if data:
            self._out += data
            self._send_now()

    def _send_now(self) -> None:
        offered = len(self._out)
        try:
            n = self.sock.send(self._out)
        except BlockingIOError:
            n = 0
        self.sends.append(Send(time.perf_counter_ns(), offered, n))
        del self._out[:n]

    def _wait(self, remaining: float, on_receive: OnReceive | None) -> None:
        mask = 0 if self.eof else selectors.EVENT_READ
        if self._out:
            mask |= selectors.EVENT_WRITE
        self._selector.register(self.sock, mask)
        try:
            ready = self._selector.select(remaining)
        finally:
            self._selector.unregister(self.sock)
        flags = 0
        for _, f in ready:
            flags |= f
        if flags & selectors.EVENT_READ:  # first, so a peer's alert is seen even if our write fails
            self._read(on_receive)
        if flags & selectors.EVENT_WRITE and self._out and (self._failure is None or isinstance(self._failure, ConnectionFailed)):
            self._send_now()

    def _read(self, on_receive: OnReceive | None) -> None:
        try:
            data = self.sock.recv(RECV_SIZE)
        except BlockingIOError:
            return
        self.arrivals.append(Arrival(time.perf_counter_ns(), len(data)))
        if data:
            events = self.conn.receive(data)
        else:
            self.eof = True
            events = self.conn.receive_eof()
        t = time.perf_counter_ns()
        for event in events:
            self.events.append((t, event))
            if isinstance(event, ApplicationData):
                self._app += event.data
            elif isinstance(event, HandshakeComplete):
                self._complete = True
            elif isinstance(event, ConnectionClosed):
                self._closed_by_peer = True
            elif isinstance(event, (ConnectionFailed, PeerAlerted)):
                self._failure = event
        if on_receive is not None and self._failure is None:
            self._in_hook = True
            try:
                on_receive(self, events)
            except BaseException:
                self.conn.data_to_send()  # the reaction is abandoned: nothing more is written
                self._out.clear()
                raise
            finally:
                self._in_hook = False

    def _flush_best_effort(self, deadline: float) -> None:
        try:
            data = self.conn.data_to_send()
            if data:
                self._out += data
            while self._out and time.monotonic() < deadline:
                self._selector.register(self.sock, selectors.EVENT_WRITE)
                try:
                    self._selector.select(deadline - time.monotonic())
                finally:
                    self._selector.unregister(self.sock)
                self._send_now()
        except OSError:
            pass

    def _kill(self) -> None:
        if not self._dead:
            self._dead = True
            self._selector.close()
            self.sock.close()

    # ----- the application's view ------------------------------------------ #

    def _usable(self) -> None:
        if self._in_hook:
            raise CodecUsageError("only queue() may be called from on_receive")
        if self._failure is not None and not self._reported:  # arrived with data, not raised yet
            self._reported = True
            self._kill()
            raise TLSFailed(self._failure)
        if self._dead:
            if self._failure is not None:
                raise TLSFailed(self._failure)
            raise CodecUsageError("the session is closed")

    def handshake(self, *, timeout: float = DEFAULT_TIMEOUT, on_receive: OnReceive | None = None) -> None:
        self._usable()
        self._handshake(time.monotonic() + timeout, timeout, on_receive)

    def _handshake(self, deadline: float, timeout: float, on_receive: OnReceive | None) -> None:
        self._run(lambda: self._complete or self._closed_by_peer, deadline, timeout, on_receive)
        if not self._complete:  # close_notify or EOF during the handshake: abandoned, not connected
            self._kill()
            raise ConnectionError("the peer closed the connection during the handshake")

    def queue(self, data: bytes) -> None:
        """Queue application data without writing it: from ``on_receive``, it joins the reply's write."""
        if not self._in_hook:
            self._usable()
        self.conn.send(data)

    def send(self, data: bytes, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._usable()
        self.conn.send(data)
        self.drive(lambda: True, timeout=timeout)

    def recv(self, *, timeout: float = DEFAULT_TIMEOUT) -> bytes:
        """Application data received so far (waiting for some); ``b""`` once the peer has sent close_notify."""
        self._usable()
        try:
            self.drive(lambda: bool(self._app) or self._closed_by_peer, timeout=timeout)
        except TLSFailed:
            if not self._app:
                raise
            self._reported = False  # data arrived before the failure: deliver it; the next call raises
        data = bytes(self._app)
        self._app.clear()
        return data

    def close(self, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        """close_notify, then wait for the peer's close_notify, then close the socket.

        A no-op on a session that is already closed or failed. Raises a failure
        that arrived but wasn't raised yet, and ``TimeoutError`` if the peer
        never answers (the socket is closed either way).
        """
        if self._in_hook:
            raise CodecUsageError("only queue() may be called from on_receive")
        if self._failure is not None and not self._reported:
            self._usable()  # raises it
        if self._dead:
            return
        if not self._closed_by_peer:
            self.conn.close()
        self.drive(lambda: self._closed_by_peer, timeout=timeout)
        self._kill()

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self._kill()


def connect(
    address: tuple[str, int], config: ClientConfig, *, timeout: float = DEFAULT_TIMEOUT,
    on_receive: OnReceive | None = None,
) -> Session:  # fmt: skip
    """Connect and run the handshake within ``timeout`` in all.

    ``on_receive`` sees each receive's events before the reply is written,
    except a receive that ends the connection (``TLSFailed`` is raised instead).
    """
    deadline = time.monotonic() + timeout
    client = Client(config)
    client.start()  # before the socket exists, so a failure here can't leak it
    sock = socket.create_connection(address, timeout=max(deadline - time.monotonic(), 0.001))
    session = Session(client, sock)
    session._handshake(deadline, timeout, on_receive)
    return session


def accept(
    listener: socket.socket, config: ServerConfig, *, timeout: float = DEFAULT_TIMEOUT,
    on_receive: OnReceive | None = None,
) -> Session:  # fmt: skip
    """Accept one connection and run the handshake within ``timeout`` in all (see :func:`connect`).

    The listener's own timeout and blocking mode are left as they were.
    """
    deadline = time.monotonic() + timeout
    server = Server(config)
    with selectors.DefaultSelector() as selector:
        selector.register(listener, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise TimeoutError(f"no connection within {timeout} s")
    previous = listener.gettimeout()  # None, 0.0 or a timeout: settimeout restores all three exactly
    listener.setblocking(False)  # if the pending connection vanished, fail now rather than block past the deadline
    try:
        sock, _ = listener.accept()
    except BlockingIOError:
        raise TimeoutError("the pending connection went away before accept") from None
    finally:
        listener.settimeout(previous)
    session = Session(server, sock)
    session._handshake(deadline, timeout, on_receive)
    return session
