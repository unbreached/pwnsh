from __future__ import annotations

from pwnsh.vault import LootVault


def test_dedup_same_bytes_one_object_two_refs(tmp_path):
    v = LootVault(root=tmp_path / "vault")
    data = b"the same secret bytes"
    r1 = v.store(data, host="hostA", session_id=1, remote_path="/etc/x")
    r2 = v.store(data, host="hostB", session_id=2, remote_path="/etc/y")
    assert not r1.deduped
    assert r2.deduped
    assert r1.sha256 == r2.sha256
    objs = [o for o in (tmp_path / "vault" / "objects").glob("*") if not o.name.endswith(".tmp")]
    assert len(objs) == 1
    assert r2.refs == 2


def test_distinct_bytes_distinct_objects(tmp_path):
    v = LootVault(root=tmp_path / "vault")
    a = v.store(b"aaa", host="h", session_id=1, remote_path="/a")
    b = v.store(b"bbb", host="h", session_id=1, remote_path="/b")
    assert a.sha256 != b.sha256
    assert not a.deduped and not b.deduped


def test_link_into_materialises_content(tmp_path):
    v = LootVault(root=tmp_path / "vault")
    data = b"loot"
    r = v.store(data, host="h", session_id=1, remote_path="/f")
    dest = tmp_path / "loot" / "session-0001" / "f"
    out = v.link_into(dest, r.sha256)
    assert out == dest
    assert dest.read_bytes() == data


def test_stats_reports_dedup_savings(tmp_path):
    v = LootVault(root=tmp_path / "vault")
    data = b"x" * 100
    v.store(data, host="a", session_id=1, remote_path="/x")
    v.store(data, host="b", session_id=2, remote_path="/x")
    st = v.stats()
    assert st["objects"] == 1
    assert st["references"] == 2
    assert st["stored_bytes"] == 100
    assert st["logical_bytes"] == 200
    assert st["saved_bytes"] == 100


def test_identical_reference_collapses_and_persists(tmp_path):
    root = tmp_path / "vault"
    LootVault(root=root).store(b"z", host="a", session_id=1, remote_path="/z")
    r = LootVault(root=root).store(b"z", host="a", session_id=1, remote_path="/z")
    assert r.deduped
    assert r.refs == 1
