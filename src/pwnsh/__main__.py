from __future__ import annotations

import argparse
import socket
import sys

from . import __version__
from .config import DEFAULT_HOST, DEFAULT_PORT
from .tui.app import PwnshApp


def _die(msg: str, hint: str | None = None) -> None:
    print(f"error: {msg}", file=sys.stderr)
    if hint:
        print(f"hint:  {hint}", file=sys.stderr)
    sys.exit(2)


def _probe_bind(host: str, port: int, socktype: int) -> None:
    """Try to bind ``host:port`` for one socket type, dying with a friendly
    message on failure. Resolves the address family from the bind string so
    IPv6 binds (``-b ::1``, ``-b ::``) and hostnames work, not just IPv4
    literals."""
    proto_label = "TCP" if socktype == socket.SOCK_STREAM else "UDP"
    try:
        infos = socket.getaddrinfo(host, port, type=socktype)
    except socket.gaierror as e:
        _die(
            f"cannot resolve bind address {host!r} — {e.strerror or e}",
            "pass an IP literal or a resolvable hostname to -b "
            "(e.g. 0.0.0.0, 127.0.0.1, ::1).",
        )
        return
    family, st, proto, _canon, sockaddr = infos[0]
    s = socket.socket(family, st, proto)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(sockaddr)
    except OSError as e:
        _die(
            f"cannot bind {proto_label} {host}:{port} — {e.strerror or e}",
            "another process is holding the port. Try -p <other> "
            "(e.g. -p 4444) or -b 127.0.0.1 for local-only.",
        )
    finally:
        s.close()


def _check_bind_or_die(host: str, port: int, udp: bool = False) -> None:
    """Pre-flight bind check so a port-in-use (or bad-address) scenario fails
    with a friendly message instead of a Textual traceback. There is a small
    TOCTOU window between this check and the real listener — acceptable, since
    this only exists to give a clean error in the common case (previous run
    still holding the port, port collides with another service).

    With ``--udp`` the UDP socket binds the same port separately, so probe it
    too — otherwise a UDP-only clash slips past the TCP check and crashes the
    listener at start.
    """
    _probe_bind(host, port, socket.SOCK_STREAM)
    if udp:
        _probe_bind(host, port, socket.SOCK_DGRAM)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pwnsh",
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
        help="don't load archived sessions from ~/.pwnsh/sessions/ on startup",
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="also demux UDP on the same host:port - each datagram source "
        "(src_ip, src_port) becomes a virtual session",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"pwnsh {__version__}",
    )
    args = parser.parse_args()

    if not (1 <= args.port <= 65535):
        print(f"error: port must be 1..65535 (got {args.port})", file=sys.stderr)
        sys.exit(2)

    _check_bind_or_die(args.bind, args.port, udp=args.udp)

    app = PwnshApp(
        port=args.port,
        host=args.bind,
        load_history=not args.no_history,
        udp=args.udp,
    )
    # mouse=False: pwnsh is a keyboard-driven tool. Leaving the mouse alone means
    # the terminal keeps its own click-drag selection and copy (so you can select
    # the payload / output the normal way), and pwnsh emits less terminal-control
    # state — one fewer thing to leave the terminal wedged on a rough exit.
    app.run(mouse=False)


if __name__ == "__main__":
    main()
