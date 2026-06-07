"""Incremental sentinel scanning over a growing byte stream.

The collectors in :mod:`pwnsh.transfer` and :mod:`pwnsh.fingerprint` all share
one job: buffer bytes arriving from the target and notice when a delimiter
marker shows up. The obvious implementation — decode the whole buffer to ``str``
and run ``marker in text`` on every chunk — is doubly wasteful:

* it re-materialises the entire accumulated payload as a fresh ``str`` on every
  4 KB read, which is O(n²) over a transfer, and
* decoding a partial UTF-8 sequence at a chunk boundary churns replacement
  characters needlessly.

Markers are always ASCII, so we keep the raw bytes and search them with
``bytearray.find`` (memchr-fast in C), decoding only the slice we actually want,
once. ``find(..., streaming=True)`` remembers how far it scanned per marker so a
marker that hasn't arrived yet is never re-scanned from the start — turning the
``/get`` of a multi-megabyte file from seconds back into milliseconds.
"""
from __future__ import annotations


class StreamScanner:
    def __init__(self) -> None:
        self.buf = bytearray()
        self._resume: dict[bytes, int] = {}

    def feed(self, data: bytes) -> None:
        self.buf.extend(data)

    def find(self, marker: bytes, start: int = 0, *, streaming: bool = False) -> int:
        """Index of ``marker`` at or after ``start`` in the buffer, or ``-1``.

        With ``streaming=True`` the search resumes from where the previous
        unsuccessful look for the same marker left off, so polling the same
        marker across many feeds stays O(total) rather than O(total) per feed.
        A one-marker-length overlap is preserved so a marker split across two
        feeds is still caught.
        """
        if not streaming:
            return self.buf.find(marker, start)
        begin = max(start, self._resume.get(marker, 0))
        idx = self.buf.find(marker, begin)
        if idx == -1:
            self._resume[marker] = max(begin, len(self.buf) - len(marker) + 1)
        return idx

    def text(self, start: int, end: int) -> str:
        """Decode just the ``[start:end]`` slice (UTF-8, lossy)."""
        return self.buf[start:end].decode("utf-8", errors="replace")
