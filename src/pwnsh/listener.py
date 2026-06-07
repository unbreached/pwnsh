from __future__ import annotations

import asyncio
import logging

from .config import MAX_CONCURRENT_SESSIONS, READ_CHUNK
from .session import SessionRegistry

log = logging.getLogger(__name__)


class TCPListener:
    def __init__(
        self,
        registry: SessionRegistry,
        host: str = "0.0.0.0",
        port: int = 9090,
        max_sessions: int = MAX_CONCURRENT_SESSIONS,
    ) -> None:
        self.registry = registry
        self.host = host
        self.port = port
        self.max_sessions = max_sessions
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        remote = (str(peer[0]), int(peer[1]))

        # DoS guard: if a scanner is hammering us, hang up fast.
        live_count = sum(1 for s in self.registry.all() if s.status == "alive")
        if live_count >= self.max_sessions:
            log.warning(
                "refusing connection from %s:%d — at max_sessions=%d",
                *remote, self.max_sessions,
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        try:
            session = self.registry.add(reader, writer, remote)
        except Exception:
            log.exception("failed to register session from %s:%d", *remote)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        try:
            while not reader.at_eof():
                data = await reader.read(READ_CHUNK)
                if not data:
                    break
                self.registry.emit_data(session, data)
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            self.registry.emit_close(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
