from __future__ import annotations

import asyncio
import socket

from pwnsh.session import SessionRegistry
from pwnsh.udp import UDPListener


def test_udp_demux_by_source(free_port):
    async def go():
        reg = SessionRegistry()
        lst = UDPListener(reg, host="127.0.0.1", port=free_port)
        await lst.start()
        try:
            a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            a.sendto(b"hello\n", ("127.0.0.1", free_port))
            a.sendto(b"again\n", ("127.0.0.1", free_port))
            await asyncio.sleep(0.2)
            b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            b.sendto(b"other\n", ("127.0.0.1", free_port))
            await asyncio.sleep(0.2)
            sessions = reg.all()
            a.close()
            b.close()
            return sessions
        finally:
            await lst.stop()

    sessions = asyncio.run(go())
    # same source reuses one session; a different source makes a second
    assert len(sessions) == 2
    blobs = [b"".join(s.scrollback) for s in sessions]
    assert any(b"hello" in x and b"again" in x for x in blobs)
    assert any(b"other" in x for x in blobs)


def test_udp_evicts_by_addr_when_session_removed(free_port):
    """Regression: _by_addr must not keep a mapping for a removed session, or it
    grows without bound as sessions are killed/pruned over a long run."""

    async def go():
        reg = SessionRegistry()
        lst = UDPListener(reg, host="127.0.0.1", port=free_port)
        await lst.start()
        try:
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c.sendto(b"hi\n", ("127.0.0.1", free_port))
            await asyncio.sleep(0.2)
            c.close()
            assert len(lst._by_addr) == 1
            sid = reg.all()[0].id
            reg.remove(sid)
            return dict(lst._by_addr)
        finally:
            await lst.stop()

    assert asyncio.run(go()) == {}


def test_udp_session_send_replies_to_peer(free_port):
    async def go():
        reg = SessionRegistry()
        lst = UDPListener(reg, host="127.0.0.1", port=free_port)
        await lst.start()
        try:
            cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cli.bind(("127.0.0.1", 0))
            cli.settimeout(1.0)
            cli.sendto(b"ping\n", ("127.0.0.1", free_port))
            await asyncio.sleep(0.2)
            s = reg.all()[0]
            assert s.is_live
            await s.send(b"pong\n")
            data, _ = cli.recvfrom(65535)
            cli.close()
            return data
        finally:
            await lst.stop()

    assert asyncio.run(go()) == b"pong\n"
