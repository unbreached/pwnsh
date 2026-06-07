from __future__ import annotations

import pytest

from pwnsh.payloads import KINDS, generate


@pytest.mark.parametrize("kind", KINDS)
def test_every_kind_renders_with_host_port(kind: str) -> None:
    out = generate(kind, "10.10.14.5", 4444)
    assert out is not None and out, f"{kind} produced empty payload"
    assert "10.10.14.5" in out
    assert "4444" in out


def test_unknown_kind_returns_none() -> None:
    assert generate("javascript", "1.2.3.4", 9090) is None


def test_unbound_host_falls_back_to_localhost() -> None:
    out = generate("bash", "0.0.0.0", 9090)
    assert out is not None
    assert "127.0.0.1" in out
    assert "0.0.0.0" not in out
