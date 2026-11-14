"""An in-memory transport for tests: pumps bytes between a client and a server.

It has the contract TCP (Phase 2e) will have: write what ``data_to_send``
returns, feed what arrives to ``receive``, and call ``receive_eof`` when the
peer goes away. ``chunks`` re-splits every delivery, to show the result never
depends on how the bytes arrive.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from qtls.handshake import Client, Connection, Event, Server

Chunker = Callable[[bytes], Iterator[bytes]]


def whole(data: bytes) -> Iterator[bytes]:
    yield data


@dataclass
class Link:
    client: Client
    server: Server
    chunks: Chunker = whole
    client_events: list[Event] = field(default_factory=list)
    server_events: list[Event] = field(default_factory=list)
    wire: list[tuple[str, bytes]] = field(default_factory=list)  # (sender, bytes), in delivery order

    def _deliver(self, sender: Connection, receiver: Connection, sink: list[Event]) -> bool:
        data = sender.data_to_send()
        if not data:
            return False
        self.wire.append((sender.role, data))
        for piece in self.chunks(data):
            sink += receiver.receive(piece)
        return True

    def pump(self, max_rounds: int = 16) -> None:
        """Move bytes both ways until neither side has anything to send."""
        for _ in range(max_rounds):
            moved = self._deliver(self.client, self.server, self.server_events)
            moved |= self._deliver(self.server, self.client, self.client_events)
            if not moved:
                return
        raise RuntimeError("connections still talking after max_rounds")  # pragma: no cover


def handshake(client: Client, server: Server, chunks: Chunker = whole) -> Link:
    link = Link(client, server, chunks)
    client.start()
    link.pump()
    return link
