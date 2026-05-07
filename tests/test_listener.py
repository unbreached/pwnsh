from __future__ import annotations

import asyncio

from multishell.listener import TCPListener
from multishell.session import SessionRegistry


def test_listener_accepts_connection_and_records_bytes(free_port):
    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", free_port)
            w.write(b"hello multishell\n")
            await w.drain()
            await asyncio.sleep(0.1)
            w.close()
            await w.wait_closed()
            await asyncio.sleep(0.1)
        finally:
            await listener.stop()
        return reg

    reg = asyncio.run(go())
    sessions = reg.all()
    assert len(sessions) == 1
    s = sessions[0]
    assert s.bytes_rx >= len(b"hello multishell\n")
    assert s.status == "closed"


def test_listener_enforces_max_sessions(free_port):
    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port, max_sessions=2)
        await listener.start()
        try:
            conns = []
            for _ in range(3):
                r, w = await asyncio.open_connection("127.0.0.1", free_port)
                conns.append((r, w))
                await asyncio.sleep(0.05)
            live = sum(1 for s in reg.all() if s.status == "alive")
            for _, w in conns:
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
            return live
        finally:
            await listener.stop()

    live = asyncio.run(go())
    assert live == 2


def test_listener_stop_twice_is_safe(free_port):
    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        await listener.stop()
        await listener.stop()

    asyncio.run(go())
