from __future__ import annotations

import asyncio
import json
import os
import stat

import pytest

from pwnsh.session import Fingerprint, Session, SessionRegistry


class _FakeWriter:
    """Minimal asyncio.StreamWriter stand-in for unit tests."""

    def __init__(self):
        self.buf = bytearray()

    def write(self, data: bytes) -> None:
        self.buf.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, key, default=None):
        return default


class _FakeReader:
    """Placeholder; tests that need a real reader use the listener."""
    pass


def _make_pair():
    return _FakeReader(), _FakeWriter()


def test_session_label_falls_back_to_peer_without_tag():
    r, w = _make_pair()
    s = Session(id=1, reader=r, writer=w, remote=("10.0.0.1", 4444))
    assert s.label == "10.0.0.1:4444"
    s.tag = "web-prod-01"
    assert s.label == "web-prod-01"


def test_session_open_log_writes_header_and_tight_perms(sessions_dir):
    r, w = _make_pair()
    s = Session(id=7, reader=r, writer=w, remote=("1.2.3.4", 5555))
    s.open_log()
    assert s.log_path is not None and s.log_path.exists()
    assert s.cast_path is not None and s.cast_path.exists()
    assert s.meta_path is not None and s.meta_path.exists()
    assert stat.S_IMODE(os.stat(s.log_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(s.cast_path).st_mode) == 0o600
    header = json.loads(s.cast_path.read_text().splitlines()[0])
    assert header["version"] == 2
    assert header["title"].startswith("pwnsh #7")
    s.close_log()


def test_session_send_records_tx_and_cast(sessions_dir):
    async def go():
        r, w = _make_pair()
        s = Session(id=9, reader=r, writer=w, remote=("127.0.0.1", 1))
        s.open_log()
        await s.send(b"echo hi\n")
        await s.send(b"id\n")
        s.close_log()
        return s, w

    s, w = asyncio.run(go())
    assert s.bytes_tx == len(b"echo hi\n") + len(b"id\n")
    assert w.buf == b"echo hi\nid\n"
    lines = s.cast_path.read_text().splitlines()
    assert len(lines) == 3
    ev1 = json.loads(lines[1])
    assert ev1[1] == "i"


def test_archived_session_cannot_send():
    async def go():
        s = Session(id=1, reader=None, writer=None, remote=("1.1.1.1", 2), status="archived")
        with pytest.raises(RuntimeError):
            await s.send(b"nope")

    asyncio.run(go())


def test_from_archive_roundtrips_metadata(sessions_dir):
    r, w = _make_pair()
    s = Session(id=42, reader=r, writer=w, remote=("10.0.0.42", 31337))
    s.open_log()
    s.tag = "db-prod"
    s.note = "found creds in /opt/app/.env"
    s.fingerprint = Fingerprint(
        os="Linux", kernel="Linux 6.5 x86_64",
        user="root", hostname="victim01", shell="/bin/bash", cwd="/root",
    )
    s.save_meta()
    s.record_rx(b"banner line\n")
    s.close_log()

    loaded = Session.from_archive(s.meta_path)
    assert loaded is not None
    assert loaded.id == 42
    assert loaded.status == "archived"
    assert loaded.tag == "db-prod"
    assert loaded.note.startswith("found creds")
    assert loaded.fingerprint.user == "root"
    assert loaded.fingerprint.os == "Linux"
    assert any(b"banner line" in chunk for chunk in loaded.scrollback)


def test_registry_add_emits_callbacks_in_order(sessions_dir):
    reg = SessionRegistry()
    events = []
    reg.on_add(lambda s: events.append(("add", s.id)))
    reg.on_data(lambda s, d: events.append(("data", s.id, bytes(d))))
    reg.on_close(lambda s: events.append(("close", s.id)))
    reg.on_remove(lambda s: events.append(("remove", s.id)))

    r, w = _make_pair()
    s = reg.add(r, w, ("1.1.1.1", 2))
    reg.emit_data(s, b"hello")
    reg.emit_close(s)
    assert reg.remove(s.id) is True
    assert events == [
        ("add", s.id),
        ("data", s.id, b"hello"),
        ("close", s.id),
        ("remove", s.id),
    ]
    assert reg.get(s.id) is None


def test_registry_load_history_bumps_next_id(sessions_dir):
    for i in (7, 13):
        r, w = _make_pair()
        s = Session(id=i, reader=r, writer=w, remote=("10.0.0.1", i))
        s.open_log()
        s.save_meta()
        s.close_log()

    fresh = SessionRegistry()
    loaded = fresh.load_history(limit=50)
    assert loaded == 2
    r, w = _make_pair()
    new = fresh.add(r, w, ("1.1.1.1", 9999))
    assert new.id == 14
    new.close_log()


def test_registry_close_all_is_idempotent(sessions_dir):
    reg = SessionRegistry()
    r, w = _make_pair()
    s = reg.add(r, w, ("1.1.1.1", 1))
    reg.close_all()
    reg.close_all()
    assert s._log_fh is None and s._cast_fh is None


def test_registry_remove_deletes_archive_and_does_not_reload(sessions_dir):
    """Regression: removing a session must delete its on-disk artifacts so
    `load_history()` on the next startup doesn't resurrect it."""
    reg = SessionRegistry()
    r, w = _make_pair()
    s = reg.add(r, w, ("1.2.3.4", 4444))
    log_path, cast_path, meta_path = s.log_path, s.cast_path, s.meta_path
    assert log_path.exists() and cast_path.exists() and meta_path.exists()

    assert reg.remove(s.id) is True
    assert not log_path.exists()
    assert not cast_path.exists()
    assert not meta_path.exists()

    fresh = SessionRegistry()
    assert fresh.load_history(limit=50) == 0
    assert fresh.all() == []
