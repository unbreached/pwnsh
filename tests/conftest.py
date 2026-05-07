"""Shared pytest fixtures.

Tests run against a per-suite tmp dir so the user's real ~/.multishell/ is
never touched. We rewire HOME *before* any multishell module is imported,
so `pathlib.Path.home()` (and everything derived from it in config.py) sees
the tmp path. Then we patch the names that other modules captured at import
time (`session.py` does `from .config import SESSIONS_DIR`, which binds the
value at module load).
"""
from __future__ import annotations

import os
import socket
import tempfile
from pathlib import Path

# 1) Rewire HOME so config.py's module-level `Path.home() / ".multishell"` lands
#    in tmp.  This MUST run before `import multishell.*`.
_tmp_home = Path(tempfile.mkdtemp(prefix="multishell-test-"))
os.environ["HOME"] = str(_tmp_home)

import pytest  # noqa: E402

from multishell import config as _config  # noqa: E402
from multishell import session as _session  # noqa: E402
from multishell import transfer as _transfer  # noqa: E402

# 2) Other modules captured these dir paths at import. Re-bind their names too.
_session.SESSIONS_DIR = _config.SESSIONS_DIR
_transfer.LOOT_DIR = _config.LOOT_DIR


@pytest.fixture(autouse=True)
def _ensure_dirs_each_test():
    """Wipe + recreate the test data dirs before every test so tests don't see
    each other's meta.json / log files."""
    import shutil
    if _config.DATA_DIR.exists():
        shutil.rmtree(_config.DATA_DIR, ignore_errors=True)
    _config.ensure_dirs()
    yield


@pytest.fixture
def sessions_dir() -> Path:
    return _config.SESSIONS_DIR


@pytest.fixture
def loot_dir() -> Path:
    return _config.LOOT_DIR


@pytest.fixture
def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
