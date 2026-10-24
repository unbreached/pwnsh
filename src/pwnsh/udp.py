"""UDP pseudo-session demultiplexing.

UDP is connectionless, so there's no accept() and no per-peer socket. This
listener binds one UDP socket and routes each datagram to a virtual session
keyed by its source ``(src_ip, src_port)``. Each distinct source shows up as a
session in the shared registry, exactly like a TCP shell, so the same UI drives
both.

A virtual session never closes on its own (UDP has no FIN); it stays live until
the operator kills it.
"""
from __future__ import annotations

import asyncio
import logging

from .config import MAX_CONCURRENT_SESSIONS
from .session import SessionRegistry

log = logging.getLogger(__name__)


class _UDPWriter:
    """Duck-typed StreamWriter so a UDP virtual session flows through the normal
    ``Session.send()`` path. ``write`` sends a datagram back to the peer; there's
    no stream to flush, so ``drain`` is a no-op."""

    def __init__(self, transport: asyncio.DatagramTransport, addr: tuple[str, int]) -> None:
        self._transport = transport
        self._addr = addr
        self._closed = False

    def write(self, data: bytes) -> None:
        if not self._closed:
            self._transport.sendto(data, self._addr)

    async def drain(self) -> None:
        return

    def close(self) -> None:
        self._closed = True

    def is_closing(self) -> bool:
        return self._closed

    async def wait_closed(self) -> None:
        return

    def get_extra_info(self, name: str, default=None):
        if name == "peername":
            return self._addr
        return default


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_datagram) -> None:
        self._on_datagram = on_datagram
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self._on_datagram(data, (str(addr[0]), int(addr[1])))

    def error_received(self, exc: Exception) -> None:
        log.debug("udp error: %s", exc)


class UDPListener:
    """Binds one UDP socket and demuxes datagrams into virtual sessions."""

    def __init__(
        self,
        registry: SessionRegistry,
        host: str = "0.0.0.0",
        port: int = 9090,
        max_sessions: int = MAX_CONCURRENT_SESSIONS,
    ) -> None:
        self.registry = registry
        self.host = host
        self.port = port
        self.max_sessions = max_sessions
        self._transport: asyncio.DatagramTransport | None = None
        self._by_addr: dict[tuple[str, int], int] = {}  # source addr -> session id

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._on_datagram),
            local_addr=(self.host, self.port),
        )

    async def stop(self) -> None:
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None

    def _on_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        sid = self._by_addr.get(addr)
        s = self.registry.get(sid) if sid is not None else None
        if s is None or s.status != "alive":
            live = sum(1 for x in self.registry.all() if x.status == "alive")
            if live >= self.max_sessions:
                log.warning("udp: refusing new source %s:%d - at max_sessions", *addr)
                return
            writer = _UDPWriter(self._transport, addr)  # type: ignore[arg-type]
            try:
                s = self.registry.add(None, writer, addr)  # type: ignore[arg-type]
            except Exception:
                log.exception("udp: failed to register session for %s:%d", *addr)
                return
            self._by_addr[addr] = s.id
        self.registry.emit_data(s, data)
