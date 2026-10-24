"""Content-addressed loot vault with sha256 dedup across hosts.

Every file pulled with ``/get`` is stored once, keyed by its sha256. Pulling the
same file from ten hosts stores one object and records ten references, so the
vault never keeps duplicate bytes. Per-session loot dirs still exist for
convenience: each is a hardlink (or copy, cross-filesystem) into the vault, so
they cost nothing extra.

Layout under ``~/.pwnsh/vault/``:
  objects/<sha256>   the file bytes, stored once
  index.json         { sha256: {size, first_seen, refs: [{host, session, remote, name, at}]} }
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .config import DATA_DIR

VAULT_DIR = DATA_DIR / "vault"


@dataclass
class VaultResult:
    sha256: str
    size: int
    deduped: bool  # True if the bytes were already in the vault
    path: Path     # the object path in the vault
    refs: int      # how many references now point at this object


class LootVault:
    """A tiny content-addressed store. Single-process (the TUI), so no locking
    beyond atomic replace on the index and objects."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or VAULT_DIR
        self.objects = self.root / "objects"
        self.index_path = self.root / "index.json"

    # -- index ---------------------------------------------------------
    def _load_index(self) -> dict:
        try:
            data = json.loads(self.index_path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_index(self, index: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        tmp = self.index_path.with_name("index.json.tmp")
        tmp.write_text(json.dumps(index, indent=2, sort_keys=True))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.index_path)

    # -- store ---------------------------------------------------------
    def store(
        self,
        data: bytes,
        *,
        host: str = "",
        session_id: int | None = None,
        remote_path: str = "",
        name: str = "",
    ) -> VaultResult:
        """Store ``data`` (deduped by sha256) and record a reference."""
        sha = hashlib.sha256(data).hexdigest()
        self.objects.mkdir(parents=True, exist_ok=True)
        for d in (self.root, self.objects):
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

        obj = self.objects / sha
        deduped = obj.exists()
        if not deduped:
            tmp = obj.with_name(sha + ".tmp")
            tmp.write_bytes(data)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            tmp.replace(obj)

        index = self._load_index()
        entry = index.get(sha) or {
            "size": len(data),
            "first_seen": time.time(),
            "refs": [],
        }
        ref = {
            "host": host,
            "session": session_id,
            "remote": remote_path,
            "name": name or (remote_path.rsplit("/", 1)[-1] if remote_path else ""),
            "at": time.time(),
        }
        # Collapse identical references (same host + session + remote path) so a
        # re-pull doesn't grow the list without bound.
        if not any(
            r.get("host") == ref["host"]
            and r.get("session") == ref["session"]
            and r.get("remote") == ref["remote"]
            for r in entry["refs"]
        ):
            entry["refs"].append(ref)
        index[sha] = entry
        self._save_index(index)
        return VaultResult(sha, len(data), deduped, obj, len(entry["refs"]))

    def link_into(self, dest: Path, sha: str) -> Path | None:
        """Materialise the object at ``dest`` (hardlink, else copy). Returns the
        destination path, or None if the object is missing / unwritable."""
        obj = self.objects / sha
        if not obj.exists():
            return None
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            os.link(obj, dest)
        except OSError:
            try:
                dest.write_bytes(obj.read_bytes())
            except OSError:
                return None
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        return dest

    # -- reporting -----------------------------------------------------
    def stats(self) -> dict:
        """Summary for a ``/loot`` view: object count, total references, and the
        bytes saved by dedup (logical minus physical)."""
        index = self._load_index()
        objects = len(index)
        references = sum(len(e.get("refs", [])) for e in index.values())
        stored_bytes = sum(int(e.get("size", 0)) for e in index.values())
        logical_bytes = sum(
            int(e.get("size", 0)) * max(1, len(e.get("refs", []))) for e in index.values()
        )
        return {
            "objects": objects,
            "references": references,
            "stored_bytes": stored_bytes,
            "logical_bytes": logical_bytes,
            "saved_bytes": logical_bytes - stored_bytes,
        }
