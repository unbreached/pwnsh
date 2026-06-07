from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from .config import MAX_ARCHIVE_LOG_BYTES, SCROLLBACK_CHUNKS, SESSIONS_DIR

log = logging.getLogger(__name__)


@dataclass
class Fingerprint:
    os: str = ""
    kernel: str = ""
    user: str = ""
    hostname: str = ""
    shell: str = ""
    cwd: str = ""

    def summary(self) -> str:
        parts = []
        if self.user and self.hostname:
            parts.append(f"{self.user}@{self.hostname}")
        elif self.user:
            parts.append(self.user)
        if self.os:
            parts.append(self.os)
        return "  ".join(parts)

    def is_empty(self) -> bool:
        return not any([self.os, self.kernel, self.user, self.hostname, self.shell, self.cwd])


@dataclass
class Session:
    id: int
    reader: asyncio.StreamReader | None
    writer: asyncio.StreamWriter | None
    remote: tuple[str, int]
    connected_at: float = field(default_factory=time.time)
    status: str = "alive"  # alive | closed | archived
    tag: str = ""
    note: str = ""
    fingerprint: Fingerprint = field(default_factory=Fingerprint)
    scrollback: deque = field(default_factory=lambda: deque(maxlen=SCROLLBACK_CHUNKS))
    log_path: Path | None = None
    cast_path: Path | None = None
    meta_path: Path | None = None
    bytes_rx: int = 0
    bytes_tx: int = 0
    _log_fh: IO[bytes] | None = None
    _cast_fh: IO[str] | None = None
    _data_hooks: list[Callable[[Session, bytes], None]] = field(default_factory=list)
    _send_lock: asyncio.Lock | None = None

    @property
    def ts_slug(self) -> str:
        return time.strftime("%Y%m%d-%H%M%S", time.localtime(self.connected_at))

    @property
    def label(self) -> str:
        return self.tag or f"{self.remote[0]}:{self.remote[1]}"

    @property
    def is_live(self) -> bool:
        return self.status == "alive" and self.writer is not None

    def open_log(self) -> None:
        try:
            SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            log.warning("session %d: cannot create sessions dir: %s", self.id, e)
            return
        base = f"{self.ts_slug}-{self.id:04d}-{self.remote[0]}"
        self.log_path = SESSIONS_DIR / f"{base}.log"
        self.cast_path = SESSIONS_DIR / f"{base}.cast"
        self.meta_path = SESSIONS_DIR / f"{base}.meta.json"
        try:
            self._log_fh = open(self.log_path, "ab")
            # Tight perms from birth — logs may contain creds/loot.
            os.chmod(self.log_path, 0o600)
        except OSError as e:
            log.warning("session %d: cannot open log file: %s", self.id, e)
            self._log_fh = None
        try:
            self._cast_fh = open(self.cast_path, "w", encoding="utf-8")
            os.chmod(self.cast_path, 0o600)
            header = {
                "version": 2,
                "width": 120,
                "height": 32,
                "timestamp": int(self.connected_at),
                "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
                "title": f"pwnsh #{self.id} {self.remote[0]}:{self.remote[1]}",
            }
            self._cast_fh.write(json.dumps(header) + "\n")
            self._cast_fh.flush()
        except OSError as e:
            log.warning("session %d: cannot open cast file: %s", self.id, e)
            self._cast_fh = None
        self.save_meta()

    def _cast_event(self, kind: str, data: bytes) -> None:
        if self._cast_fh is None:
            return
        offset = max(0.0, time.time() - self.connected_at)
        text = data.decode("utf-8", errors="replace")
        try:
            self._cast_fh.write(json.dumps([round(offset, 4), kind, text]) + "\n")
            self._cast_fh.flush()
        except Exception:
            pass

    def record_rx(self, data: bytes) -> None:
        self.scrollback.append(data)
        self.bytes_rx += len(data)
        if self._log_fh:
            try:
                self._log_fh.write(data)
                self._log_fh.flush()
            except Exception:
                pass
        self._cast_event("o", data)
        for hook in list(self._data_hooks):
            try:
                hook(self, data)
            except Exception:
                pass

    def add_data_hook(self, hook: Callable[[Session, bytes], None]) -> None:
        self._data_hooks.append(hook)

    def remove_data_hook(self, hook: Callable[[Session, bytes], None]) -> None:
        try:
            self._data_hooks.remove(hook)
        except ValueError:
            pass

    def close_log(self) -> None:
        if self._log_fh:
            try:
                self._log_fh.close()
            finally:
                self._log_fh = None
        if self._cast_fh:
            try:
                self._cast_fh.close()
            finally:
                self._cast_fh = None

    def delete_archive(self) -> None:
        """Close any open file handles and unlink the on-disk artifacts.

        Idempotent — missing files are ignored. Used when the user removes
        a session so it doesn't reappear on the next startup via load_history.
        """
        self.close_log()
        for path in (self.log_path, self.cast_path, self.meta_path):
            if path is None:
                continue
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                log.warning("session %d: cannot remove %s: %s", self.id, path, e)

    async def send(self, data: bytes) -> None:
        if self.writer is None:
            raise RuntimeError("session is archived (read-only)")
        if self._send_lock is None:
            self._send_lock = asyncio.Lock()
        async with self._send_lock:
            self.writer.write(data)
            await self.writer.drain()
            self.bytes_tx += len(data)
            self._cast_event("i", data)

    def save_meta(self) -> None:
        if self.meta_path is None:
            return
        payload: dict[str, Any] = {
            "id": self.id,
            "remote": list(self.remote),
            "connected_at": self.connected_at,
            "tag": self.tag,
            "note": self.note,
            "fingerprint": self.fingerprint.__dict__,
        }
        try:
            self.meta_path.write_text(json.dumps(payload, indent=2))
        except Exception:
            pass

    @classmethod
    def from_archive(cls, meta_path: Path) -> Session | None:
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            return None
        try:
            remote = tuple(meta["remote"])
            s = cls(
                id=int(meta["id"]),
                reader=None,
                writer=None,
                remote=(str(remote[0]), int(remote[1])),
                connected_at=float(meta.get("connected_at", time.time())),
                status="archived",
                tag=str(meta.get("tag", "")),
                note=str(meta.get("note", "")),
                fingerprint=Fingerprint(**meta.get("fingerprint", {})),
            )
        except Exception:
            return None
        base = meta_path.name.removesuffix(".meta.json")
        s.meta_path = meta_path
        log_path = meta_path.parent / f"{base}.log"
        cast_path = meta_path.parent / f"{base}.cast"
        if log_path.exists():
            s.log_path = log_path
            try:
                size = log_path.stat().st_size
                with open(log_path, "rb") as fh:
                    if size > MAX_ARCHIVE_LOG_BYTES:
                        fh.seek(size - MAX_ARCHIVE_LOG_BYTES)
                        banner = f"[... truncated, showing last {MAX_ARCHIVE_LOG_BYTES} bytes ...]\n".encode()
                        data = banner + fh.read()
                    else:
                        data = fh.read()
                if data:
                    s.scrollback.append(data)
                    s.bytes_rx = size
            except OSError:
                pass
        if cast_path.exists():
            s.cast_path = cast_path
        return s


OnAdd = Callable[[Session], None]
OnData = Callable[[Session, bytes], None]
OnClose = Callable[[Session], None]
OnRemove = Callable[[Session], None]


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[int, Session] = {}
        self._next_id = 1
        self._on_add: list[OnAdd] = []
        self._on_data: list[OnData] = []
        self._on_close: list[OnClose] = []
        self._on_remove: list[OnRemove] = []

    def add(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote: tuple[str, int],
    ) -> Session:
        sid = self._next_id
        self._next_id += 1
        s = Session(id=sid, reader=reader, writer=writer, remote=remote)
        s.open_log()
        self._sessions[sid] = s
        for cb in self._on_add:
            cb(s)
        return s

    def get(self, sid: int) -> Session | None:
        return self._sessions.get(sid)

    def all(self) -> list[Session]:
        return list(self._sessions.values())

    def live(self) -> list[Session]:
        return [s for s in self._sessions.values() if s.status == "alive"]

    def dead(self) -> list[Session]:
        return [s for s in self._sessions.values() if s.status != "alive"]

    def on_add(self, cb: OnAdd) -> None:
        self._on_add.append(cb)

    def on_data(self, cb: OnData) -> None:
        self._on_data.append(cb)

    def on_close(self, cb: OnClose) -> None:
        self._on_close.append(cb)

    def on_remove(self, cb: OnRemove) -> None:
        self._on_remove.append(cb)

    def emit_data(self, session: Session, data: bytes) -> None:
        session.record_rx(data)
        for cb in self._on_data:
            cb(session, data)

    def emit_close(self, session: Session) -> None:
        if session.status != "alive":
            return
        session.status = "closed"
        session.close_log()
        for cb in self._on_close:
            cb(session)

    def remove(self, sid: int) -> bool:
        s = self._sessions.pop(sid, None)
        if s is None:
            return False
        if s.status == "alive" and s.writer is not None:
            try:
                s.writer.close()
            except Exception:
                pass
            s.status = "closed"
        s.delete_archive()
        for cb in self._on_remove:
            cb(s)
        return True

    def close_all(self) -> None:
        """Flush every session's logs + cast and close sockets. Safe on shutdown."""
        for s in list(self._sessions.values()):
            if s.writer is not None and s.status == "alive":
                try:
                    s.writer.close()
                except Exception:
                    pass
            s.close_log()

    def load_history(self, limit: int = 50) -> int:
        if not SESSIONS_DIR.exists():
            return 0
        metas = sorted(
            SESSIONS_DIR.glob("*.meta.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:limit]
        loaded = 0
        max_id = 0
        for m in metas:
            s = Session.from_archive(m)
            if s is None:
                continue
            if s.id in self._sessions:
                continue
            self._sessions[s.id] = s
            max_id = max(max_id, s.id)
            for cb in self._on_add:
                cb(s)
            loaded += 1
        self._next_id = max(self._next_id, max_id + 1)
        return loaded
