from __future__ import annotations

import argparse
import socket
import sys

from . import __version__
from .config import DEFAULT_HOST, DEFAULT_PORT
from .tui.app import MultiShellApp


def _check_bind_or_die(host: str, port: int) -> None:
    """Pre-flight bind check so a port-in-use scenario fails with a friendly
    message instead of a Textual traceback. There is a small TOCTOU window
    between this check and the real listener — acceptable, since this only
    exists to give a clean error in the common case (previous run still
    holding the port, port collides with another service)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
    except OSError as e:
        print(
            f"error: cannot bind {host}:{port} — {e.strerror or e}",
            file=sys.stderr,
        )
        print(
            f"hint:  another process is holding the port. Try -p <other> "
            f"(e.g. -p 4444) or -b 127.0.0.1 for local-only.",
            file=sys.stderr,
        )
        sys.exit(2)
    finally:
        s.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="multishell",
        description="Multi-session reverse-shell handler with a console dashboard",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP listen port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "-b",
        "--bind",
        default=DEFAULT_HOST,
        help=(
            f"interface to bind on (default: {DEFAULT_HOST} — all interfaces). "
            "Use 127.0.0.1 for a local-only listener."
        ),
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="don't load archived sessions from ~/.multishell/sessions/ on startup",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"multishell {__version__}",
    )
    args = parser.parse_args()

    if not (1 <= args.port <= 65535):
        print(f"error: port must be 1..65535 (got {args.port})", file=sys.stderr)
        sys.exit(2)

    _check_bind_or_die(args.bind, args.port)

    app = MultiShellApp(
        port=args.port,
        host=args.bind,
        load_history=not args.no_history,
    )
    app.run()


if __name__ == "__main__":
    main()
