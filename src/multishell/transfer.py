from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import shlex
from dataclasses import dataclass
from pathlib import Path

from .config import LOOT_DIR
from .session import Session


def _sentinel(tag: str) -> str:
    return f"@@MSX_{tag}_{secrets.token_hex(4)}@@"


@dataclass
class TransferResult:
    ok: bool
    path: Path | None = None
    sha256: str = ""
    message: str = ""


class Collector:
    """Collects incoming bytes until two sentinels are seen, returns the span between."""

    def __init__(self, session: Session, begin: str, end: str) -> None:
        self.session = session
        self.begin = begin
        self.end = end
        self._buf = bytearray()
        self._done = asyncio.Event()
        self._payload = ""

    def _on_data(self, s: Session, data: bytes) -> None:
        self._buf.extend(data)
        text = self._buf.decode("utf-8", errors="replace")
        if self.begin in text and self.end in text:
            start = text.index(self.begin) + len(self.begin)
            stop = text.index(self.end, start)
            self._payload = text[start:stop]
            self._done.set()

    async def wait(self, timeout: float) -> str | None:
        self.session.add_data_hook(self._on_data)
        try:
            try:
                await asyncio.wait_for(self._done.wait(), timeout=timeout)
                return self._payload
            except asyncio.TimeoutError:
                return None
        finally:
            self.session.remove_data_hook(self._on_data)


async def put_file(
    session: Session,
    local: Path,
    remote: str | None = None,
    timeout: float = 30.0,
) -> TransferResult:
    local = local.expanduser().resolve()
    if not local.is_file():
        return TransferResult(False, message=f"no such file: {local}")
    payload = local.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    b64 = base64.b64encode(payload).decode()

    remote_path = remote or local.name
    q_remote = shlex.quote(remote_path)
    done = _sentinel("PUT_DONE")

    eot = "MSX_EOT_" + secrets.token_hex(4)
    cmd = (
        f"(base64 -d > {q_remote} 2>/dev/null || "
        f"openssl base64 -d -A > {q_remote} 2>/dev/null) <<'{eot}'\n"
        f"{b64}\n"
        f"{eot}\n"
        f"(command -v sha256sum >/dev/null && sha256sum {q_remote}) "
        f"|| (command -v shasum >/dev/null && shasum -a 256 {q_remote}) "
        f"|| (command -v openssl >/dev/null && openssl dgst -sha256 {q_remote}); "
        f"echo {done}\n"
    )
    collector = Collector(session, begin=eot, end=done)
    await session.send(cmd.encode())
    tail = await collector.wait(timeout)
    if tail is None:
        return TransferResult(False, message="timed out waiting for upload confirmation")
    remote_digest = _extract_sha256(tail)
    if remote_digest and remote_digest != digest:
        return TransferResult(
            False,
            sha256=digest,
            message=f"sha256 mismatch: local={digest[:12]} remote={remote_digest[:12]}",
        )
    return TransferResult(
        True,
        path=Path(remote_path),
        sha256=digest,
        message=f"uploaded {len(payload)} B → {remote_path}"
        + (f" (sha256 ok)" if remote_digest else " (no sha256 tool on target)"),
    )


async def get_file(
    session: Session,
    remote: str,
    timeout: float = 60.0,
) -> TransferResult:
    begin = _sentinel("GET_BEGIN")
    end = _sentinel("GET_END")
    q_remote = shlex.quote(remote)
    cmd = (
        f"echo {begin}; "
        f"(base64 -w0 {q_remote} 2>/dev/null "
        f"|| base64 {q_remote} 2>/dev/null "
        f"|| openssl base64 -A -in {q_remote} 2>/dev/null); "
        f"echo; echo {end}\n"
    )
    collector = Collector(session, begin=begin, end=end)
    await session.send(cmd.encode())
    body = await collector.wait(timeout)
    if body is None:
        return TransferResult(False, message="timed out waiting for download data")
    b64_blob = "".join(body.split())
    if not b64_blob:
        return TransferResult(False, message=f"remote file empty or unreadable: {remote}")
    try:
        payload = base64.b64decode(b64_blob, validate=False)
    except Exception as e:
        return TransferResult(False, message=f"base64 decode failed: {e}")
    digest = hashlib.sha256(payload).hexdigest()
    loot_dir = LOOT_DIR / f"session-{session.id:04d}"
    loot_dir.mkdir(parents=True, exist_ok=True)
    dest = loot_dir / Path(remote).name
    dest.write_bytes(payload)
    return TransferResult(
        True,
        path=dest,
        sha256=digest,
        message=f"downloaded {len(payload)} B → {dest}",
    )


def _extract_sha256(text: str) -> str:
    for token in text.split():
        token = token.strip()
        if len(token) == 64 and all(c in "0123456789abcdef" for c in token.lower()):
            return token.lower()
    return ""
