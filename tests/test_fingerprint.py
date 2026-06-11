from __future__ import annotations

import asyncio
import contextlib
import re

from pwnsh.fingerprint import (
    Fingerprinter,
    PtyUpgrader,
    _guess_os,
    pty_upgrade_payload,
)
from pwnsh.listener import TCPListener
from pwnsh.session import SessionRegistry


def test_guess_os_maps_uname_strings():
    assert _guess_os("Linux 6.5 x86_64") == "Linux"
    assert _guess_os("Darwin 24.6.0 arm64") == "macOS"
    assert _guess_os("FreeBSD 14.0") == "FreeBSD"
    assert _guess_os("CYGWIN_NT-10.0") == "Windows (cygwin)"
    assert _guess_os("wut") == ""


def test_pty_payload_is_os_branched_and_has_interactive_flag():
    payload, marker = pty_upgrade_payload(rows=40, cols=120)
    assert marker in payload
    assert "Darwin" in payload
    assert "FreeBSD" in payload
    assert "-i" in payload
    assert "python3" in payload
    assert "stty rows 40 cols 120" in payload


def test_pty_payload_resolves_shell_and_verifies_spawn():
    """Regression: the upgrade used to hard-code /bin/bash (via an un-exported
    var), so it blew up on bash-less hosts and could falsely report success. The
    payload must resolve an existing shell and ship a relay that VERIFIES the
    spawn, emitting the fail marker on failure instead of a half-broken shell."""
    import base64
    import re

    payload, _ready = pty_upgrade_payload(rows=40, cols=120)
    fail = re.search(r"@@PW_PTY_FAIL_[0-9a-f]+@@", payload).group(0)

    # No hard-coded bash path — the shell is resolved on-target with fallback.
    assert "/bin/bash" not in payload
    assert "command -v bash" in payload
    assert "command -v sh" in payload

    # The embedded relay decodes to valid Python that forks a pty, verifies the
    # child survived exec (waitpid), and emits the fail marker itself.
    b64 = re.search(r'b64decode\(\\"([A-Za-z0-9+/=]+)\\"\)', payload).group(1)
    code = base64.b64decode(b64).decode()
    compile(code, "<relay>", "exec")
    assert "pty.fork" in code
    assert "waitpid" in code
    assert fail in code


def test_fingerprinter_parses_sentinel_reply(free_port):
    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", free_port)

            async def fake_shell():
                buf = b""
                try:
                    while True:
                        data = await r.read(4096)
                        if not data:
                            return
                        buf += data
                        if b"@@PWFPBEGIN@@" in buf and b"<SENT>" not in buf:
                            w.write(
                                b"@@PWFPBEGIN@@\n"
                                b"Linux 6.5 x86_64\n"
                                b"uid=1000(alice) gid=1000(alice) groups=1000\n"
                                b"victim01\n"
                                b"/bin/bash\n"
                                b"/home/alice\n"
                                b"@@PWFPEND@@\n"
                            )
                            await w.drain()
                            buf += b"<SENT>"
                except (asyncio.CancelledError, ConnectionResetError, OSError):
                    pass

            t = asyncio.create_task(fake_shell())
            await asyncio.sleep(0.1)
            s = reg.all()[0]
            ok = await Fingerprinter(s).run(timeout=3.0)
            t.cancel()
            with contextlib.suppress(BaseException):
                await t
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return ok, s.fingerprint
        finally:
            await listener.stop()

    ok, fp = asyncio.run(go())
    assert ok
    assert fp.os == "Linux"
    assert fp.user == "alice"
    assert fp.hostname == "victim01"
    assert fp.shell == "/bin/bash"
    assert fp.cwd == "/home/alice"


def _drive_pty_sync(emit: str, free_port: int) -> tuple[bool, str]:
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
                        m = re.search(r"@@PW_PTY_READY_[0-9a-f]+@@", text)
                        if m and b"<H>" not in buf:
                            if emit == "ready":
                                w.write((m.group(0) + "\n").encode())
                            elif emit == "fail":
                                w.write(b"@@PW_PTY_FAIL_deadbeef@@\n")
                            await w.drain()
                            buf += b"<H>"
                except (asyncio.CancelledError, ConnectionResetError, OSError):
                    pass

            t = asyncio.create_task(scripted())
            await asyncio.sleep(0.1)
            s = reg.all()[0]
            ok, msg = await PtyUpgrader(s, rows=40, cols=120).run(timeout=3.0)
            t.cancel()
            with contextlib.suppress(BaseException):
                await t
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return ok, msg
        finally:
            await listener.stop()

    return asyncio.run(go())


def test_pty_upgrader_success(free_port):
    ok, msg = _drive_pty_sync("ready", free_port)
    assert ok, msg


def test_pty_upgrader_failure(free_port):
    ok, msg = _drive_pty_sync("fail", free_port)
    assert not ok and "no python or script" in msg


def test_pty_upgrader_silent_target_times_out(free_port):
    async def go():
        reg = SessionRegistry()
        listener = TCPListener(reg, host="127.0.0.1", port=free_port)
        await listener.start()
        try:
            r, w = await asyncio.open_connection("127.0.0.1", free_port)
            await asyncio.sleep(0.1)
            s = reg.all()[0]
            ok, msg = await PtyUpgrader(s, rows=40, cols=120).run(timeout=0.4)
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            return ok, msg
        finally:
            await listener.stop()

    ok, msg = asyncio.run(go())
    assert not ok and "no response" in msg
