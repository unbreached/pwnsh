"""Tests for /put and /get path completion (pwnsh.complete)."""
from __future__ import annotations

import asyncio
import re

import pytest

from pwnsh.complete import (
    RemoteLister,
    complete_local,
    parse_completion_target,
    pick,
)


def test_parse_classifies_put_and_get():
    assert parse_completion_target("/put ~/too") == ("/put ", "~/too", "local")
    # /put's second argument is the remote destination
    assert parse_completion_target("/put a.txt /tm") == ("/put a.txt ", "/tm", "remote")
    assert parse_completion_target("/get /etc/pa") == ("/get ", "/etc/pa", "remote")
    assert parse_completion_target("/PUT ~/x") == ("/PUT ", "~/x", "local")


@pytest.mark.parametrize(
    "value", ["/get ", "/put ", "/put", "ls -la", "", "/getx a", "/putter a"]
)
def test_parse_returns_none_for_non_targets(value):
    assert parse_completion_target(value) is None


def test_pick_single_multiple_and_no_progress():
    names = ["passwd", "passwd-", "pam.d/"]
    # 'pa' is a prefix of every match, so nothing extends it yet
    assert pick("/etc/pa", names) is None
    # single match completes fully; the trailing '/' marks it as a directory
    assert pick("/etc/pam", names) == "/etc/pam.d/"
    # two matches complete only to their common prefix
    assert pick("/etc/passw", names) == "/etc/passwd"
    assert pick("/etc/zzz", names) is None


def test_complete_local(tmp_path):
    (tmp_path / "linpeas.sh").touch()
    (tmp_path / "loot").mkdir()
    assert complete_local(f"{tmp_path}/linp") == f"{tmp_path}/linpeas.sh"
    assert complete_local(f"{tmp_path}/lo") == f"{tmp_path}/loot/"  # dir keeps '/'
    assert complete_local(f"{tmp_path}/zzz") is None
    assert complete_local("") is None


class _FakeSession:
    """Minimal stand-in for a live Session: feeds canned ``ls`` output back
    through the data hook when a command is sent."""

    id = 1
    is_live = True

    def __init__(self, echo: bool, names: list[str]) -> None:
        self._hooks: list = []
        self._echo = echo
        self._names = names

    def add_data_hook(self, h) -> None:
        self._hooks.append(h)

    def remove_data_hook(self, h) -> None:
        self._hooks.remove(h)

    async def send(self, data: bytes) -> None:
        if self._echo:  # a PTY echoes the raw command line back first
            for h in list(self._hooks):
                h(self, data)
        token = re.search(r'@@""([0-9a-f]+)B@@', data.decode()).group(1)
        body = "".join(n + "\n" for n in self._names)
        out = f"@@{token}B@@\n{body}@@{token}E@@\n".encode()
        for h in list(self._hooks):
            h(self, out)


def _list(session, d="/etc", **kw):
    return asyncio.run(RemoteLister(session).list_dir(d, **kw))


def test_remote_lister_reads_names():
    s = _FakeSession(False, ["passwd", "pam.d/", ".hidden"])
    assert _list(s) == ["passwd", "pam.d/", ".hidden"]


def test_remote_lister_ignores_pty_command_echo():
    # The split sentinel must lock onto the real output, not the echoed command
    # line — otherwise a PTY-upgraded session would parse garbage.
    s = _FakeSession(True, ["passwd", "pam.d/"])
    assert _list(s) == ["passwd", "pam.d/"]


def test_remote_lister_empty_dir_is_not_failure():
    # An existing but empty directory returns [], distinct from a failed probe.
    assert _list(_FakeSession(False, [])) == []


def test_remote_lister_rejects_unsafe_fragment():
    s = _FakeSession(False, ["x"])
    assert asyncio.run(RemoteLister(s).list_dir("/tmp/$(id)")) is None


def test_remote_lister_times_out_on_silent_shell():
    class _Silent(_FakeSession):
        async def send(self, data: bytes) -> None:  # never feeds output back
            pass

    assert asyncio.run(RemoteLister(_Silent(False, [])).list_dir("/etc", timeout=0.2)) is None
