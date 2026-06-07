"""Raw-interact mode — direct keystroke ↔ socket passthrough.

Used while the Textual app is suspended (`App.suspend()`):

  1. Put the local terminal in `cfmakeraw` so every keystroke is delivered
     to us byte-by-byte (no line buffering, no echo, no signal generation).
  2. asyncio bridge:
       stdin (fd 0) → session.writer    via `loop.add_reader`
       session.record_rx → stdout (fd 1) via a data-hook
  3. Watch for an `escape` byte (default 0x07, i.e. Ctrl+G) on stdin to
     break out and return to the dashboard.

The session keeps recording everything to its log/cast files because we
hook into `record_rx` rather than replacing it.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import termios
import tty

from .session import Session

DEFAULT_ESCAPE = b"\x07"  # Ctrl+G — works on every keyboard layout


async def run_raw_bridge(
    session: Session,
    escape: bytes = DEFAULT_ESCAPE,
    banner: bool = True,
) -> str:
    """Pump bytes between stdin and the session's socket until `escape` arrives.

    Returns a short status string for the caller to surface in the TUI.
    """
    if session.writer is None:
        return "session is archived (read-only) — can't enter raw mode"

    # Use raw fd 0 / fd 1 directly — pytest, pipe-based wrappers, and other
    # contexts that replace sys.stdin/stdout with non-fd objects can break
    # `sys.stdin.fileno()`. The actual OS file descriptors are stable.
    fd_in, fd_out = 0, 1
    try:
        if not os.isatty(fd_in):
            return "stdin is not a tty — raw mode skipped"
    except OSError:
        return "stdin is not a tty — raw mode skipped"

    old_attr = termios.tcgetattr(fd_in)
    loop = asyncio.get_running_loop()
    done = asyncio.Event()
    state = {"reason": "exit", "send_failed": False}

    # Push subsequent socket bytes to stdout while we're in raw mode.
    def on_data(_s: Session, data: bytes) -> None:
        try:
            os.write(fd_out, data)
        except OSError:
            pass

    # Direct write to the writer's transport — bypass send()'s lock so the
    # add_reader callback (sync) doesn't have to schedule a coroutine per
    # keystroke. Single-producer, so no interleaving risk.
    def emit(payload: bytes) -> bool:
        if session.writer is None:
            return False
        try:
            session.writer.write(payload)
            session.bytes_tx += len(payload)
            session._cast_event("i", payload)
            return True
        except Exception:
            return False

    def on_stdin() -> None:
        try:
            data = os.read(fd_in, 4096)
        except OSError:
            done.set()
            return
        if not data:
            state["reason"] = "stdin closed"
            done.set()
            return
        if escape in data:
            pre, _, _post = data.partition(escape)
            if pre:
                emit(pre)
            done.set()
            return
        if not emit(data):
            state["reason"] = "send failed"
            state["send_failed"] = True
            done.set()

    session.add_data_hook(on_data)
    try:
        if banner:
            label = session.label
            tag = f"\r\n\x1b[36m[pwnsh raw mode — {label} — Ctrl+G to return]\x1b[0m\r\n"
            with contextlib.suppress(OSError):
                os.write(fd_out, tag.encode())

        # Replay the tail of scrollback so the user sees recent context once
        # the screen has been cleared by Textual's suspend.
        with contextlib.suppress(Exception):
            tail = list(session.scrollback)[-4:]
            for chunk in tail:
                with contextlib.suppress(OSError):
                    os.write(fd_out, chunk)

        tty.setraw(fd_in)
        loop.add_reader(fd_in, on_stdin)
        try:
            await done.wait()
        finally:
            with contextlib.suppress(Exception):
                loop.remove_reader(fd_in)
    finally:
        with contextlib.suppress(Exception):
            termios.tcsetattr(fd_in, termios.TCSADRAIN, old_attr)
        session.remove_data_hook(on_data)
        with contextlib.suppress(OSError):
            os.write(fd_out, b"\r\n")

    if state["send_failed"]:
        return "send failed — session may have closed"
    return f"left raw mode ({state['reason']})"
