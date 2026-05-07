from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import re

from multishell.listener import TCPListener
from multishell.session import SessionRegistry
from multishell.transfer import get_file, put_file


def test_put_roundtrip_succeeds_with_sha256_match(tmp_path, free_port):
    payload = b"A" * 2048 + b"\nB" * 1024
    local = tmp_path / "upload.bin"
    local.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", free_port)

            async def scripted():
                buf = b""
                try:
                    while True:
                        data = await r.read(8192)
                        if not data:
                            return
                        buf += data
                        text = buf.decode(errors="replace")
                        m_eot = re.search(r"MSX_EOT_[0-9a-f]+", text)
                        m_done = re.search(r"@@MSX_PUT_DONE_[0-9a-f]+@@", text)
                        if m_eot and m_done and b"<H>" not in buf:
                            reply = (m_eot.group(0) + "\n" + digest + "  /tmp/out.bin\n"
                                     + m_done.group(0) + "\n")
                            w.write(reply.encode())
                            await w.drain()
                            buf += b"<H>"
                except (asyncio.CancelledError, ConnectionResetError, OSError):
                    pass

            t = asyncio.create_task(scripted())
            await asyncio.sleep(0.1)
            s = reg.all()[0]
            res = await put_file(s, local, remote="/tmp/out.bin", timeout=5.0)
            t.cancel()
            with contextlib.suppress(BaseException):
                await t
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return res
        finally:
            await listener.stop()

    res = asyncio.run(go())
    assert res.ok, res.message
    assert res.sha256 == digest


def test_get_roundtrip_lands_in_loot_with_matching_bytes(loot_dir, free_port):
    payload = b"pretend /etc/passwd line\n" * 20
    digest = hashlib.sha256(payload).hexdigest()

    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", free_port)

            async def scripted():
                buf = b""
                try:
                    while True:
                        data = await r.read(8192)
                        if not data:
                            return
                        buf += data
                        text = buf.decode(errors="replace")
                        m_b = re.search(r"@@MSX_GET_BEGIN_[0-9a-f]+@@", text)
                        m_e = re.search(r"@@MSX_GET_END_[0-9a-f]+@@", text)
                        if m_b and m_e and b"<H>" not in buf:
                            b64 = base64.b64encode(payload).decode()
                            reply = m_b.group(0) + "\n" + b64 + "\n" + m_e.group(0) + "\n"
                            w.write(reply.encode())
                            await w.drain()
                            buf += b"<H>"
                except (asyncio.CancelledError, ConnectionResetError, OSError):
                    pass

            t = asyncio.create_task(scripted())
            await asyncio.sleep(0.1)
            s = reg.all()[0]
            res = await get_file(s, "/etc/passwd", timeout=5.0)
            t.cancel()
            with contextlib.suppress(BaseException):
                await t
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return res, s.id
        finally:
            await listener.stop()

    res, sid = asyncio.run(go())
    assert res.ok, res.message
    assert res.path is not None
    assert res.path.read_bytes() == payload
    assert res.sha256 == digest
    assert res.path.parent.name == f"session-{sid:04d}"


def test_put_fails_cleanly_on_missing_file(tmp_path, free_port):
    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", free_port)
            await asyncio.sleep(0.1)
            s = reg.all()[0]
            res = await put_file(s, tmp_path / "nope.bin", timeout=2.0)
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return res
        finally:
            await listener.stop()

    res = asyncio.run(go())
    assert not res.ok
    assert "no such file" in res.message


def test_get_timeout_when_target_silent(free_port):
    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", free_port)
            await asyncio.sleep(0.1)
            s = reg.all()[0]
            res = await get_file(s, "/etc/anything", timeout=0.3)
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return res
        finally:
            await listener.stop()

    res = asyncio.run(go())
    assert not res.ok and "timed out" in res.message
