from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path.home() / ".pwnsh"
SESSIONS_DIR = DATA_DIR / "sessions"
LOOT_DIR = DATA_DIR / "loot"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9090
SCROLLBACK_CHUNKS = 10_000
READ_CHUNK = 4096

# When replaying an archived session's .log back into memory, refuse to slurp
# more than this many bytes per file. Prevents OOM when a session previously
# logged a huge binary exfil.
MAX_ARCHIVE_LOG_BYTES = 10 * 1024 * 1024  # 10 MB

# Soft cap on concurrent live sessions. Generous — this is just a DoS guard
# against a noisy scanner hammering the listener.
MAX_CONCURRENT_SESSIONS = 512


def ensure_dirs() -> None:
    """Create the runtime data dirs with tight permissions.

    Logs can contain credentials, tokens, and loot — so chmod 700.
    """
    for d in (DATA_DIR, SESSIONS_DIR, LOOT_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
