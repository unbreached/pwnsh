"""Path completion for the ``/put`` and ``/get`` command bar.

Two very different jobs share one small vocabulary of "given the fragment being
typed and the entry names in its directory, what completes it?":

* ``/put <local>`` completes against the **local** filesystem — the box pwnsh
  runs on. Synchronous, always available (:func:`complete_local`).
* ``/get <remote>`` (and ``/put``'s optional second, remote argument) completes
  against the **target's** filesystem. There is no local view of that, so it is
  best-effort: :class:`RemoteLister` runs one short ``ls`` over the live session
  and reads the entry names back. It only works on a cooperative shell, adds a
  round-trip of latency, and the ``ls`` it runs is briefly visible in the
  session's output. The caller caches per directory so this happens at most once
  per directory visited rather than once per keystroke.

The pure matching logic (:func:`pick`) lives here too so it can be unit-tested
without a socket, and so local and remote completion behave identically.
"""
from __future__ import annotations

import asyncio
import os
import re
import secrets
from pathlib import Path

from ._scan import StreamScanner
from .session import Session

# A path fragment we are willing to interpolate into a shell command sent to the
# target must contain nothing that could break out of the command or trigger an
# unintended glob: no quotes, whitespace, or shell metacharacters. A fragment
# that fails this simply gets no remote completion (the operator can still type
# it by hand). Note this is defence in depth, not a trust boundary — the
# operator already has code execution on the target by definition.
_SAFE_FRAGMENT = re.compile(r"^[A-Za-z0-9_./~+-]*$")


def _split_token(token: str) -> tuple[str, str, str]:
    """Split a path fragment into (dir-with-trailing-sep, sep, leaf).

    ``"~/tools/lin"`` -> ``("~/tools", "/", "lin")``; ``"lin"`` -> ``("", "", "lin")``.
    The directory part keeps the operator's original spelling (e.g. ``~``) so it
    is echoed back unchanged in the completion.
    """
    dirpart, sep, leaf = token.rpartition("/")
    return dirpart, sep, leaf


def pick(token: str, names: list[str]) -> str | None:
    """Complete ``token`` against the candidate entry ``names`` in its directory.

    ``names`` may carry a trailing ``/`` on directories (as ``ls -p`` emits);
    the marker is preserved so a completed directory reads as one and the
    operator can keep completing into it. A single match completes fully; several
    matches complete to their longest common prefix so typing can continue.
    Returns ``None`` when nothing extends what is already typed.
    """
    dirpart, sep, leaf = _split_token(token)
    matches = [n for n in names if n.startswith(leaf)]
    if not matches:
        return None
    completed = matches[0] if len(matches) == 1 else os.path.commonprefix(matches)
    if completed == leaf:
        return None
    return dirpart + sep + completed


def complete_local(token: str) -> str | None:
    """Complete a local filesystem path fragment (``/put``'s local argument)."""
    if not token:
        return None
    dirpart, sep, _leaf = _split_token(token)
    listing_dir = os.path.expanduser(dirpart) if sep else "."
    try:
        entries = os.listdir(listing_dir or "/")
    except OSError:
        return None
    names = sorted(e + ("/" if _is_local_dir(listing_dir, e) else "") for e in entries)
    return pick(token, names)


def _is_local_dir(parent: str, name: str) -> bool:
    try:
        return Path(parent or "/", name).is_dir()
    except OSError:
        return False


class RemoteLister:
    """List one directory on the target over the live session, best-effort.

    Mirrors :class:`pwnsh.fingerprint.Fingerprinter`: attach a temporary data
    hook, send a sentinel-wrapped ``ls``, collect the bytes between the
    sentinels, detach. Uses plain ``ls`` (not a bash builtin) so it works on
    ``sh``/``dash``/busybox catches, and tolerates a PTY that echoes the command
    back — see :meth:`list_dir`.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    async def list_dir(self, remote_dir: str, timeout: float = 1.5) -> list[str] | None:
        """Return the entry names of ``remote_dir`` (dirs marked with ``/``), or
        ``None`` if the fragment is unsafe, the probe times out, or the shell
        could not run it. An existing but empty directory returns ``[]``."""
        if not _SAFE_FRAGMENT.match(remote_dir):
            return None
        target = remote_dir or "."
        token = secrets.token_hex(4)
        # The sentinels are written as two adjacent quoted strings —  "@@""<t>B@@"
        # — so the marker only becomes contiguous in the shell's *output*, never
        # in the command line a PTY echoes back. Searching for the contiguous
        # form therefore locks onto the real output, not the echo.
        begin = f"@@{token}B@@".encode()
        end = f"@@{token}E@@".encode()
        cmd = (
            f'echo "@@""{token}B@@"; '
            f"ls -1pA -- {target} 2>/dev/null; "
            f'echo "@@""{token}E@@"\n'
        )

        scan = StreamScanner()
        done = asyncio.Event()
        captured: dict[str, str] = {}

        def _on_data(_s: Session, data: bytes) -> None:
            scan.feed(data)
            i = scan.find(begin)
            if i < 0:
                return
            start = i + len(begin)
            stop = scan.find(end, start)
            if stop < 0:
                return
            captured["block"] = scan.text(start, stop)
            done.set()

        self.session.add_data_hook(_on_data)
        try:
            await self.session.send(cmd.encode())
            try:
                await asyncio.wait_for(done.wait(), timeout=timeout)
            except (asyncio.TimeoutError, TimeoutError):
                return None
        except Exception:
            return None
        finally:
            self.session.remove_data_hook(_on_data)

        names = [ln.strip() for ln in captured.get("block", "").splitlines()]
        return [n for n in names if n and n not in ("./", "../")]


def parse_completion_target(value: str) -> tuple[str, str, str] | None:
    """Classify what, if anything, to complete in the command-bar ``value``.

    Returns ``(head, token, scope)`` where ``head`` is the untouched text before
    the fragment (so the caller returns ``head + completion`` to the widget),
    ``token`` is the fragment being typed, and ``scope`` is ``"local"`` or
    ``"remote"``. Returns ``None`` when the value is not a completable ``/put`` /
    ``/get`` argument (including the empty fragment right after the command).

    ``/get`` always completes remotely. ``/put`` completes its first argument
    locally and its optional second argument (the remote destination) remotely.
    """
    if value[:5].lower() not in ("/put ", "/get "):
        return None
    cmd = value[1:4].lower()
    last_space = value.rfind(" ")
    token = value[last_space + 1 :]
    if not token:
        return None
    head = value[: last_space + 1]
    # Words before the fragment, minus the command word, give the argument index.
    arg_index = len(value[:last_space].split()) - 1
    if cmd == "get":
        scope = "remote"
    else:
        scope = "local" if arg_index == 0 else "remote"
    return head, token, scope
