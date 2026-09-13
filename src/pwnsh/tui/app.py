from __future__ import annotations

import asyncio
import codecs
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

from rich.style import Style
from rich.text import Span, Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Click
from textual.reactive import reactive
from textual.suggester import Suggester
from textual.theme import Theme
from textual.widgets import DataTable, Input, RichLog, Static

from .. import __version__
from ..config import DATA_DIR, DEFAULT_HOST, DEFAULT_PORT, ensure_dirs
from ..fingerprint import (
    Fingerprinter,
    PtyUpgrader,
    callback_pty_payload,
    validate_target,
)
from ..listener import TCPListener
from ..payloads import KINDS as PAYLOAD_KINDS
from ..payloads import generate as generate_payload
from ..raw_interact import run_raw_bridge
from ..session import Session, SessionRegistry
from ..complete import (
    RemoteLister,
    complete_local,
    parse_completion_target,
    pick,
)
from ..transfer import get_file, put_file
from .modals import ConfirmModal, PromptModal, SearchHit, SearchModal
from .palette import PwnshCommands


def _is_dumb_terminal() -> bool:
    """True if the host terminal can't render the custom theme reliably.

    Triggered by TERM=dumb / unset / unknown, or NO_COLOR being set.
    Used so an SSH session into a stripped-down box still launches usable
    instead of crashing on theme registration.
    """
    term = os.environ.get("TERM", "").lower()
    if term in ("", "dumb", "unknown"):
        return True
    if os.environ.get("NO_COLOR"):
        return True
    return False


def _detect_multiplexer() -> str | None:
    """Return 'tmux', 'screen', or None - used to surface a key-collision tip."""
    if os.environ.get("TMUX") or os.environ.get("TERM", "").startswith("tmux"):
        return "tmux"
    if os.environ.get("STY") or os.environ.get("TERM", "").startswith("screen"):
        return "screen"
    return None


# -- graphite console palette -----------------------------------------
# A cool, near-neutral instrument rather than a themed "look": deep graphite
# ground, soft off-white text, and ONE calm cyan for all chrome (titles, keys,
# focus, the prompt, the mark). Status hues stay out of the chrome so state
# reads at a glance and nothing competes with it - green=live, red=dead/danger,
# dim=archived. This is what I'd ship for a tool an operator stares at for hours.
C_ACCENT = "#54c7de"  # chrome accent - cool cyan (titles, keys, prompt, mark)
C_HI     = "#eaf0f6"  # brightest text - wordmark, active values
C_TEXT   = "#c3ccd8"  # body text - cool off-white
C_DIM    = "#697585"  # muted - labels, separators
C_LIVE   = "#5fd88a"  # live sessions - signal green
C_ERR    = "#e5624a"  # dead / danger / errors - red
C_BG     = "#0c0f14"  # deep cool graphite ground

# ASCII wordmark for the waiting screen. Deliberately plain ASCII only - no
# box-drawing or block glyphs - so it renders identically in every terminal,
# multiplexer, and console font (bare TTYs included), with no wide/ambiguous
# characters to misalign the layout. ~36 cols, fits an 80-col terminal.
_BANNER_ART = [
    r" ___  __      __  _  _   ___   _  _ ",
    r"| _ \ \ \ /\ / / | \| | / __| | || |",
    r"|  _/  \ V  V /  | .` | \__ \ | __ |",
    r"|_|     \_/\_/   |_|\_| |___/ |_||_|",
]


# Curated key hints - replaces Textual's Footer, which surfaced the focused
# Input's own edit bindings (e.g. "^k delete-to-end") and looked cluttered.
def _key(k: str, label: str) -> str:
    return f"[bold {C_ACCENT}]{k}[/] [{C_DIM}]{label}[/]"


_KEYBAR = f"  [{C_DIM}]|[/]  ".join(
    _key(k, label)
    for k, label in (
        ("^q", "quit"), ("^n/^p", "cycle"), ("^f", "search"), ("^u", "pty"),
        ("^g", "raw"), ("^x", "kill"), ("f2", "rename"), ("^k", "palette"),
    )
)


CONSOLE_THEME = Theme(
    name="console",
    primary=C_ACCENT,
    secondary=C_TEXT,
    accent=C_HI,
    success=C_LIVE,
    warning="#e0a852",
    error=C_ERR,
    foreground=C_TEXT,
    background=C_BG,
    surface=C_BG,
    panel="#12171f",
    boost="#1a212b",
    dark=True,
)


_NO_BLINK = Style(blink=False, blink2=False)


def _ansi_to_text(text: str) -> Text:
    """Render terminal output as Rich Text with blink neutralized.

    Remote MOTDs, colored prompts, and tools like `ls --color` frequently
    emit SGR 5/6 (blink). Rich preserves it and Textual renders it as actual
    blinking - obnoxious in the dashboard - so strip it from every span.
    """
    t = Text.from_ansi(text)
    if t.spans:
        t.spans = [
            Span(
                s.start,
                s.end,
                (s.style if isinstance(s.style, Style) else Style.parse(s.style)) + _NO_BLINK,
            )
            for s in t.spans
        ]
    return t


class _ScrollbackLog(RichLog):
    """The output pane. It never takes keyboard focus itself - clicking
    anywhere in it hands focus straight to the command input, so the whole
    right-hand pane behaves like one terminal you click into and type at.
    The mouse wheel still scrolls it regardless of focus.
    """

    can_focus = False

    def on_click(self, event: Click) -> None:
        try:
            self.app.query_one("#cmd", Input).focus()
        except Exception:
            pass


class _PathSuggester(Suggester):
    """Ghost-text path completion for the command bar (accept with Right arrow).

    Fires only on ``/put`` and ``/get`` arguments; every other input returns no
    suggestion, so ordinary commands typed to the shell are untouched.

    * ``/put <local>`` completes against the local filesystem (synchronous).
    * ``/get <remote>`` and ``/put``'s second argument complete against the
      target, best-effort: the first keystroke into a directory runs one ``ls``
      over the session (visible briefly in the pane) and the result is cached
      per (session, directory), so further keystrokes filter locally with no
      extra round-trips. Remote completion is silently unavailable when no live
      session is selected, during raw-interact, or on a shell that can't run the
      probe.
    """

    def __init__(self, app: PwnshApp) -> None:
        super().__init__(use_cache=True, case_sensitive=True)
        self._app = app
        # (session id, directory-fragment) -> entry names. Bounded in practice by
        # the number of distinct directories tab-completed within a session.
        self._dir_cache: dict[tuple[int, str], list[str]] = {}

    async def get_suggestion(self, value: str) -> str | None:
        parsed = parse_completion_target(value)
        if parsed is None:
            return None
        head, token, scope = parsed
        if scope == "local":
            completed = complete_local(token)
        else:
            completed = await self._complete_remote(token)
        return head + completed if completed else None

    async def _complete_remote(self, token: str) -> str | None:
        s = self._app.current_session()
        if s is None or not s.is_live or self._app._raw_active:
            return None
        dirpart, _sep, _leaf = token.rpartition("/")
        key = (s.id, dirpart)
        names = self._dir_cache.get(key)
        if names is None:
            names = await RemoteLister(s).list_dir(dirpart)
            if names is None:
                return None  # probe failed/timed out - don't cache the failure
            self._dir_cache[key] = names
        return pick(token, names)


class PwnshApp(App):
    CSS_PATH = "styles.tcss"
    TITLE = "pwnsh"
    SUB_TITLE = "multi-session reverse-shell handler"

    COMMANDS = App.COMMANDS | {PwnshCommands}
    COMMAND_PALETTE_BINDING = "ctrl+k"

    # priority=True so these always fire even though the command Input is the
    # default-focused widget - otherwise Textual's Input would swallow ctrl+u
    # (delete-to-start) and ctrl+k (delete-to-end) before we ever saw them.
    BINDINGS = [
        Binding("ctrl+n", "next_session", "Next", show=True, priority=True),
        Binding("ctrl+p", "prev_session", "Prev", show=True, priority=True),
        Binding("ctrl+f", "search", "Search", show=True, priority=True),
        Binding("f2", "set_tag", "Rename", show=True, priority=True),
        Binding("ctrl+t", "set_tag", "Rename", show=False, priority=True),
        Binding("ctrl+o", "edit_note", "Note", show=True, priority=True),
        Binding("ctrl+u", "pty_upgrade", "PTY", show=True, priority=True),
        Binding("ctrl+g", "raw_interact", "Raw", show=True, priority=True),
        Binding("ctrl+x", "kill_session", "Kill", show=True, priority=True),
        Binding("ctrl+y", "copy_output", "Copy", show=True, priority=True),
        Binding("ctrl+k", "command_palette", "Palette", show=True, priority=True),
        Binding("ctrl+q", "request_quit", "Quit", show=True, priority=True),
        # NB: Esc is deliberately NOT bound to quit at the app level - it is far
        # too easy to hit by reflex and silently drop every live session. Esc
        # still dismisses modals (each modal binds it locally).
    ]

    selected_id: reactive[int | None] = reactive(None)

    def __init__(
        self,
        port: int = DEFAULT_PORT,
        host: str = DEFAULT_HOST,
        load_history: bool = True,
    ) -> None:
        super().__init__()
        self.port = port
        self.host = host
        self.registry = SessionRegistry()
        self.listener = TCPListener(self.registry, host=host, port=port)
        self._load_history = load_history
        self._status_msg = ""  # most recent notification, mirrored to the status bar
        self._raw_active = False  # True while suspended for raw-interact mode
        # Incremental UTF-8 decoder for the pane currently on screen. Keeping
        # decoder state across socket reads means a multibyte char split across
        # two 4 KiB chunks renders correctly instead of as replacement glyphs.
        # Reset whenever the displayed session changes (see _repaint_scrollback).
        self._live_decoder: codecs.IncrementalDecoder | None = None

    def compose(self) -> ComposeResult:
        # Persistent PWNSH wordmark, top-left. Plain ASCII, left-aligned.
        yield Static("\n".join(_BANNER_ART), id="logo", markup=False)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):  # border-title set in on_mount
                yield DataTable(id="sessions", cursor_type="row", zebra_stripes=False)
            with Vertical(id="main"):  # border-title tracks the live session
                yield _ScrollbackLog(id="scrollback", wrap=True, highlight=False, markup=False)
                with Horizontal(id="prompt-row"):
                    yield Static(">", id="prompt-prefix", markup=True)
                    yield Input(
                        placeholder="type a command - enter sends - /help",
                        id="cmd",
                        suggester=_PathSuggester(self),
                    )
        # Framed status panel: TARGET (fingerprint) over LISTENER (listener/debug).
        with Vertical(id="status"):
            yield Static("", id="status-target", markup=True)
            yield Static("", id="status-listener", markup=True)
        yield Static(_KEYBAR, id="keybar", markup=True)

    async def on_mount(self) -> None:
        ensure_dirs()
        if not _is_dumb_terminal():
            try:
                self.register_theme(CONSOLE_THEME)
                self.theme = "console"
            except Exception:
                pass
        # Static panel frame titles.
        self.query_one("#sidebar").border_title = "SESSIONS"
        self.query_one("#status").border_title = "TARGET"
        self.query_one("#status-listener").border_title = "LISTENER"

        table = self.query_one("#sessions", DataTable)
        table.add_column("ID", key="id", width=4)
        table.add_column("Host", key="peer")
        table.add_column("OS", key="os", width=10)
        table.add_column("St", key="status", width=5)
        table.add_column("Up", key="uptime", width=6)

        # Steady (non-blinking) command cursor - the blink is distracting in a
        # terminal that's already streaming live output.
        self.query_one("#cmd", Input).cursor_blink = False

        self.registry.on_add(self._on_session_add)
        self.registry.on_data(self._on_session_data)
        self.registry.on_close(self._on_session_close)
        self.registry.on_remove(self._on_session_remove)

        if self._load_history:
            n = self.registry.load_history()
            if n:
                self.notify(f"loaded {n} archived session{'s' if n != 1 else ''}")

        await self.listener.start()
        self.set_interval(1.0, self._refresh_table)
        self._update_prompt()
        self._refresh_status()
        # Banner is the default scrollback content until a session is selected.
        if self.selected_id is None:
            self._show_banner()
        # Keep focus on the prompt by default so the operator can just type.
        self.query_one("#cmd", Input).focus()

    async def on_unmount(self) -> None:
        """Graceful shutdown - flush logs, close sockets."""
        try:
            await self.listener.stop()
        except Exception:
            pass
        self.registry.close_all()

    def notify(self, message: str, *args, **kwargs) -> None:
        """Route messages to the plain-ASCII LISTENER status line instead of a
        pop-up toast. Textual toasts are bordered boxes (a graphic); the status
        line keeps everything to plain text, and the latest message stays
        visible instead of fading. ``*args``/``**kwargs`` (e.g. ``severity``)
        are accepted for call compatibility and ignored."""
        self._status_msg = message
        try:
            self._refresh_status()
        except Exception:
            pass

    # -- session helpers -------------------------------------------
    def current_session(self) -> Session | None:
        if self.selected_id is None:
            return None
        return self.registry.get(self.selected_id)

    def select_session(self, sid: int) -> None:
        if self.registry.get(sid) is None:
            return
        self.selected_id = sid
        table = self.query_one("#sessions", DataTable)
        try:
            row_index = table.get_row_index(str(sid))
            table.move_cursor(row=row_index)
        except Exception:
            pass

    # -- registry callbacks ----------------------------------------
    def _on_session_add(self, s: Session) -> None:
        table = self.query_one("#sessions", DataTable)
        try:
            table.add_row(
                str(s.id),
                s.label,
                s.fingerprint.os or "",
                _status_cell(s.status),
                "0s" if s.status == "alive" else "-",
                key=str(s.id),
            )
        except Exception:
            pass
        if s.status == "alive":
            cur = self.current_session()
            if cur is None or cur.status != "alive":
                self.select_session(s.id)
            try:
                self.bell()  # ring the terminal so a landed shell is noticed
            except Exception:
                pass
            self.notify(f"[!] new shell - session #{s.id} from {s.remote[0]}:{s.remote[1]}")
            self._run_fingerprint(s, auto=True)

    def _on_session_data(self, s: Session, data: bytes) -> None:
        # During raw-interact the app is suspended - touching widgets here can
        # raise and (before the reader loop was hardened) kill the session.
        # Output still reaches the terminal via the raw bridge's own hook, and
        # we repaint from scrollback on return. So skip the TUI update entirely.
        if self._raw_active:
            return
        if self.selected_id == s.id:
            self._append_scrollback(data)

    def _on_session_close(self, s: Session) -> None:
        if self.selected_id == s.id:
            self._refresh_status()
            self._update_prompt()

    def _on_session_remove(self, s: Session) -> None:
        table = self.query_one("#sessions", DataTable)
        try:
            table.remove_row(str(s.id))
        except Exception:
            pass
        if self.selected_id == s.id:
            remaining = sorted(x.id for x in self.registry.all())
            self.selected_id = remaining[0] if remaining else None
            if self.selected_id is None:
                rich_log = self.query_one("#scrollback", RichLog)
                rich_log.clear()
                self._refresh_status()
                self._update_prompt()

    # -- rendering -------------------------------------------------
    def _show_banner(self) -> None:
        """Waiting-room screen, written into the scrollback when no session is
        selected. The PWNSH wordmark lives permanently in the top-left #logo
        band, so here we lead straight with the listening state, then the one
        thing a new user needs - a copy-paste payload to catch a shell -
        followed by file-transfer, key, and multiplexer hints."""
        rich_log = self.query_one("#scrollback", RichLog)
        rich_log.clear()
        archived = sum(1 for s in self.registry.all() if s.status != "alive")
        live = sum(1 for s in self.registry.all() if s.status == "alive")
        muxer = _detect_multiplexer()

        def row(label: str, value: str) -> Text:
            return Text.from_markup(f"[{C_DIM}]{label:<12}[/] {value}")

        # Listening state - the headline of the empty screen.
        if live:
            state = (
                f"[bold {C_LIVE}]*[/] [bold {C_ACCENT}]{live} LIVE[/]"
                f"   [{C_DIM}]select a session on the left[/]"
            )
        else:
            state = (
                f"[bold {C_LIVE}]*[/] [bold {C_ACCENT}]LISTENING[/]"
                f"   [{C_DIM}]waiting for a shell to connect...[/]"
            )

        example = generate_payload("bash", self.host, self.port) or ""
        lines = [
            Text(""),
            Text.from_markup(
                f"[bold {C_ACCENT}]pwnsh[/]  [{C_DIM}]-[/]  "
                f"[{C_TEXT}]multi-session reverse-shell handler[/]"
                f"   [{C_DIM}]v{__version__} - David Jacoby[/]"
            ),
            Text(""),
            row(f"{self.host}:{self.port}", state),
            row("data", f"[{C_TEXT}]{DATA_DIR}[/]"),
            row("sessions", f"[{C_TEXT}]{live} live[/]  [{C_DIM}]-[/]  [{C_TEXT}]{archived} archived[/]"),
            Text(""),
            Text.from_markup(
                f"[{C_DIM}]catch a shell - run this on the target "
                f"([/][bold {C_ACCENT}]^Y[/][{C_DIM}] copies it to your clipboard):[/]"
            ),
            Text.from_markup(f"  [bold {C_HI}]{example}[/]"),
            Text.from_markup(f"  [{C_DIM}]/payload nc|python|powershell|perl|ruby for other variants (also copied)[/]"),
            Text(""),
            row("files", f"[{C_TEXT}]/put <local> \\[remote][/]   [{C_DIM}]send a file to the target[/]"),
            row("", f"[{C_TEXT}]/get <remote>[/]           [{C_DIM}]pull a file into loot/[/]"),
            Text(""),
            row("keys", f"[{C_ACCENT}]^N/^P[/] [{C_DIM}]switch[/]   [{C_ACCENT}]^F[/] [{C_DIM}]search[/]   "
                        f"[{C_ACCENT}]^U[/] [{C_DIM}]pty[/]   [{C_ACCENT}]^G[/] [{C_DIM}]raw[/]"),
            row("", f"[{C_ACCENT}]^X[/] [{C_DIM}]kill[/]      [{C_ACCENT}]^K[/] [{C_DIM}]palette[/]  "
                    f"[{C_ACCENT}]^Q[/] [{C_DIM}]quit[/]   [{C_DIM}]/help for everything[/]"),
        ]
        for line in lines:
            rich_log.write(line)

        if muxer:
            rich_log.write(Text(""))
            rich_log.write(row(
                "tip",
                f"[{C_TEXT}]inside {muxer} - pwnsh keys don't collide with the "
                f"{muxer} prefix. raw mode (^G) needs a real tty.[/]",
            ))

    def _append_scrollback(self, data: bytes) -> None:
        rich_log = self.query_one("#scrollback", RichLog)
        if self._live_decoder is None:
            self._live_decoder = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            text = self._live_decoder.decode(data)
            if text:
                rich_log.write(_ansi_to_text(text))
        except Exception:
            rich_log.write(repr(data))

    def _repaint_scrollback(self, s: Session) -> None:
        """Clear the pane and replay a session's full scrollback into it.

        Decodes the whole buffer through a single incremental decoder so chunk
        boundaries never split a multibyte character, then keeps that decoder as
        the live one so subsequent streamed bytes continue from the same state.
        """
        rich_log = self.query_one("#scrollback", RichLog)
        rich_log.clear()
        dec = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            text = dec.decode(b"".join(s.scrollback))
            if text:
                rich_log.write(_ansi_to_text(text))
        except Exception:
            for chunk in s.scrollback:
                rich_log.write(repr(chunk))
        self._live_decoder = dec

    def _refresh_status(self) -> None:
        """Update the framed status panel - the main pane's title, the TARGET
        (fingerprint) line, and the LISTENER (listener / debug) line."""
        try:
            main = self.query_one("#main")
            target = self.query_one("#status-target", Static)
            lst = self.query_one("#status-listener", Static)
        except Exception:
            return  # called before the panel is mounted
        s = self.current_session()
        main.border_title = _render_frame_title(s)
        target.update(
            _render_target(s) if s is not None else "[dim]no session selected[/]"
        )
        live = len(self.registry.live())
        archived = sum(1 for x in self.registry.all() if x.status != "alive")
        msg = self._status_msg or "ready"
        lst.update(
            f"[bold {C_LIVE}]*[/] [{C_ACCENT}]{self.host}:{self.port}[/]"
            f"   [{C_TEXT}]{live} live[/] [{C_DIM}]-[/] [{C_TEXT}]{archived} archived[/]"
            f"   [{C_DIM}]- {msg}[/]"
        )

    def _update_prompt(self) -> None:
        prefix = self.query_one("#prompt-prefix", Static)
        cmd = self.query_one("#cmd", Input)
        s = self.current_session()
        if s is None:
            prefix.update("[dim]>[/]")
            cmd.placeholder = f"no session - listening on :{self.port}"
        elif s.status == "alive":
            prefix.update(f"[bold {C_ACCENT}]>[/]")
            cmd.placeholder = "type a command - enter sends - /help"
        else:
            prefix.update("[dim]>[/]")
            cmd.placeholder = f"[{s.status}] - read-only - /tag /note /kill"

    def _refresh_table(self) -> None:
        table = self.query_one("#sessions", DataTable)
        now = time.time()
        for s in self.registry.all():
            key = str(s.id)
            try:
                table.update_cell(key, "peer", s.label)
                table.update_cell(key, "os", s.fingerprint.os or "")
                table.update_cell(key, "status", _status_cell(s.status))
                table.update_cell(
                    key, "uptime",
                    _fmt_uptime(now - s.connected_at) if s.status == "alive" else "-",
                )
            except Exception:
                continue
        self._refresh_status()

    def watch_selected_id(self, old: int | None, new: int | None) -> None:
        s = self.registry.get(new) if new is not None else None
        if s is None:
            self.query_one("#scrollback", RichLog).clear()
            self._show_banner()
        else:
            self._repaint_scrollback(s)
        self._refresh_status()
        self._update_prompt()

    # -- events ----------------------------------------------------
    @on(DataTable.RowHighlighted)
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        try:
            self.selected_id = int(event.row_key.value)
        except (TypeError, ValueError):
            pass

    @on(Input.Submitted, "#cmd")
    async def _cmd_submitted(self, event: Input.Submitted) -> None:
        raw = event.value
        event.input.value = ""
        if raw.startswith("/"):
            await self._run_slash(raw)
            return
        s = self.current_session()
        if s is None:
            return
        if not s.is_live:
            self.notify("session is not live - can't send", severity="warning")
            return
        try:
            await s.send((raw + "\n").encode())
        except Exception as e:
            self.notify(f"send failed: {e}", severity="error")
            self.registry.emit_close(s)

    async def _run_slash(self, raw: str) -> None:
        try:
            parts = shlex.split(raw[1:])
        except ValueError as e:
            self.notify(f"parse error: {e}", severity="error")
            return
        if not parts:
            return
        cmd, *args = parts
        cmd = cmd.lower()
        if cmd == "help":
            self._show_help()
        elif cmd == "put":
            if not args:
                self.notify("usage: /put <local> [remote]", severity="warning")
                return
            self._do_put(Path(args[0]), args[1] if len(args) > 1 else None)
        elif cmd == "get":
            if not args:
                self.notify("usage: /get <remote>", severity="warning")
                return
            self._do_get(args[0])
        elif cmd in ("tag", "rename"):
            self._apply_tag(" ".join(args))
        elif cmd == "note":
            self._apply_note(" ".join(args))
        elif cmd == "pty":
            args_lower = [a.lower() for a in args]
            if "--reconnect" in args_lower or "-r" in args_lower:
                tag = "--reconnect" if "--reconnect" in args_lower else "-r"
                idx = args_lower.index(tag)
                target = args[idx + 1] if idx + 1 < len(args) else ""
                self.action_pty_reconnect(target)
            else:
                self.action_pty_upgrade(shell=args[0] if args else "")
        elif cmd == "raw" or cmd == "interact":
            await self.action_raw_interact()
        elif cmd in ("fingerprint", "fp"):
            self.action_fingerprint()
        elif cmd == "kill":
            self.action_kill_session()
        elif cmd == "prune":
            self.action_prune_dead()
        elif cmd == "sessions":
            self.action_search()
        elif cmd == "payload":
            self._show_payload(args[0] if args else "")
        elif cmd == "copy":
            self.action_copy_output()
        else:
            self.notify(f"unknown slash command: /{cmd}", severity="warning")

    def _show_payload(self, kind: str) -> None:
        """Render a reverse-shell one-liner for the listener's host:port into
        the scrollback as a copy-paste-ready block."""
        kind = kind.lower().strip()
        rich_log = self.query_one("#scrollback", RichLog)
        if not kind:
            self.notify(
                f"usage: /payload <{'|'.join(PAYLOAD_KINDS)}>",
                severity="warning",
            )
            return
        line = generate_payload(kind, self.host, self.port)
        if line is None:
            self.notify(
                f"unknown payload kind {kind!r} - try one of: {', '.join(PAYLOAD_KINDS)}",
                severity="warning",
            )
            return
        rich_log.write(Text(""))
        rich_log.write(Text.from_markup(
            f"[bold {C_ACCENT}]-- payload ({kind}) -> {self.host}:{self.port} --[/]"
        ))
        rich_log.write(Text(line, style=C_HI))
        rich_log.write(Text.from_markup(
            f"[{C_DIM}]copied to clipboard - paste onto the target. /payload for another type.[/]"
        ))
        self._copy_clipboard(line, f"{kind} payload")

    def _show_help(self) -> None:
        rich_log = self.query_one("#scrollback", RichLog)
        rich_log.write(Text("---- pwnsh commands ----", style=f"bold {C_ACCENT}"))
        for line in [
            "  /put <local> [remote]   upload a file (base64 heredoc, sha256 verify)",
            "  /get <remote>           download a file to ~/.pwnsh/loot/",
            "  /tag <name>             rename the current session  (also F2)",
            "  /note <text>            sticky note on the session   (Ctrl+O)",
            "  /pty                    upgrade to a PTY + sync size (Ctrl+U)",
            "  /fp                     re-run fingerprint probe",
            "  /kill                   disconnect + remove current   (Ctrl+X)",
            "  /prune                  remove every non-live session",
            "  /payload <kind>         print + copy a host:port-stamped one-liner (bash, python, nc, ...)",
            "  /copy                   copy this session's output to the clipboard (Ctrl+Y)",
            "  Ctrl+N / Ctrl+P         next / previous session",
            "  Ctrl+F                  search scrollback across all sessions",
            "  Ctrl+K                  command palette",
            "  Ctrl+Q                  quit (confirms if a session is live)",
        ]:
            rich_log.write(Text(line, style=C_TEXT))
        rich_log.write(Text(
            "  copy: mouse is off, so select text and copy the normal way,",
            style=C_DIM,
        ))
        rich_log.write(Text(
            "        or press Ctrl+Y / run /copy to send it to the clipboard.",
            style=C_DIM,
        ))
        rich_log.write(Text(
            "  paths: /put and /get complete filenames as you type - press the",
            style=C_DIM,
        ))
        rich_log.write(Text(
            "         right arrow to accept. /get probes the target (best-effort).",
            style=C_DIM,
        ))

    # -- actions ---------------------------------------------------
    def action_request_quit(self) -> None:
        """Quit, but confirm first if it would disconnect live sessions."""
        live = self.registry.live()
        if not live:
            self.exit()
            return
        n = len(live)

        def handle(confirm: bool | None) -> None:
            if confirm:
                self.exit()

        self.push_screen(
            ConfirmModal(
                f"Quit pwnsh? {n} live session{'s' if n != 1 else ''} "
                "will be disconnected.",
                confirm_label="Quit",
            ),
            handle,
        )

    def action_next_session(self) -> None:
        self._cycle(1)

    def action_prev_session(self) -> None:
        self._cycle(-1)

    def _cycle(self, delta: int) -> None:
        ids = sorted(s.id for s in self.registry.all())
        if not ids:
            return
        if self.selected_id is None or self.selected_id not in ids:
            self.select_session(ids[0])
            return
        idx = (ids.index(self.selected_id) + delta) % len(ids)
        self.select_session(ids[idx])

    def action_search(self) -> None:
        def handle(hit: SearchHit | None) -> None:
            if hit is None:
                return
            self.select_session(hit.session_id)
            self.notify(f"-> #{hit.session_id}")

        self.push_screen(SearchModal(self.registry), handle)

    def action_copy_output(self) -> None:
        """Copy something useful to the clipboard.

        The dashboard captures the mouse (so a click can focus the prompt),
        which disables the terminal's native drag-to-select - so provide a
        one-key copy instead. With a session selected it copies that session's
        scrollback; on the waiting screen it copies the ready-to-paste bash
        reverse-shell one-liner shown in the banner, which is the thing an
        operator most wants to grab there.
        """
        s = self.current_session()
        if s is None:
            payload = generate_payload("bash", self.host, self.port) or ""
            self._copy_clipboard(payload, "bash payload")
            return
        text = b"".join(s.scrollback).decode("utf-8", errors="replace")
        self._copy_clipboard(text, f"#{s.id} output")

    def _copy_clipboard(self, text: str, what: str) -> None:
        """Copy text to the clipboard by two independent routes, because either
        one alone fails silently in common setups:

        * OSC 52 (Textual's ``copy_to_clipboard``) reaches the operator's
          clipboard *through the terminal*, so it works over SSH - but only if
          the terminal supports and allows it (Apple Terminal never does; tmux
          needs ``set -g set-clipboard on``).
        * A local clipboard tool (``pbcopy``/``wl-copy``/``xclip``/``xsel``)
          works on the box pwnsh runs on regardless of the terminal, but not
          across SSH.

        Trying both means "copy" just works whether you're local or remote.
        """
        if not text:
            self.notify(f"nothing to copy ({what})", severity="warning")
            return
        methods: list[str] = []
        try:
            self.copy_to_clipboard(text)  # OSC 52 - SSH-friendly, may no-op
            methods.append("osc52")
        except Exception:
            pass
        tool = self._system_clipboard_copy(text)
        if tool:
            methods.append(tool)
        if methods:
            self.notify(
                f"copied {what} -> clipboard ({len(text)} chars - {', '.join(methods)})"
            )
        else:
            self.notify(
                "no clipboard reachable - install pbcopy/xclip/xsel/wl-copy, or "
                "hold Shift and drag (Option+drag on macOS) to select manually",
                severity="warning",
            )

    @staticmethod
    def _system_clipboard_copy(text: str) -> str | None:
        """Pipe text to a local OS clipboard tool. Returns the tool name on
        success, else None. Never raises."""
        if sys.platform == "darwin":
            candidates = [["pbcopy"]]
        elif sys.platform.startswith(("linux", "freebsd", "openbsd", "netbsd")):
            candidates = []
            if os.environ.get("WAYLAND_DISPLAY"):
                candidates.append(["wl-copy"])
            candidates.append(["xclip", "-selection", "clipboard"])
            candidates.append(["xsel", "--clipboard", "--input"])
            candidates.append(["wl-copy"])  # last resort even without the env var
        elif sys.platform == "win32":
            candidates = [["clip"]]
        else:
            candidates = []
        data = text.encode("utf-8", errors="replace")
        for cmd in candidates:
            try:
                subprocess.run(
                    cmd, input=data, timeout=3, check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                return cmd[0]
            except (FileNotFoundError, OSError, subprocess.SubprocessError):
                continue
        return None

    def action_set_tag(self) -> None:
        s = self.current_session()
        if s is None:
            return

        def handle(value: str | None) -> None:
            if value is None:
                return
            self._apply_tag(value.strip())

        self.push_screen(PromptModal("Rename session:", initial=s.tag), handle)

    def action_edit_note(self) -> None:
        s = self.current_session()
        if s is None:
            return

        def handle(value: str | None) -> None:
            if value is None:
                return
            self._apply_note(value)

        self.push_screen(PromptModal("Session note:", initial=s.note), handle)

    def action_kill_session(self) -> None:
        s = self.current_session()
        if s is None:
            return
        sid = s.id
        label = s.label
        was_alive = s.status == "alive"
        verb = "Disconnect and remove" if was_alive else "Remove"
        msg = (
            f"{verb} #{sid} {label}?\n"
            "This also deletes its recorded .cast / .log evidence from disk."
        )

        def handle(confirm: bool | None) -> None:
            if confirm:
                self._do_kill(sid, label, was_alive)

        self.push_screen(ConfirmModal(msg, confirm_label="Remove"), handle)

    def _do_kill(self, sid: int, label: str, was_alive: bool) -> None:
        self.registry.remove(sid)
        self.notify(
            f"{'disconnected + ' if was_alive else ''}removed #{sid} {label}",
            severity="warning",
        )

    def action_prune_dead(self) -> None:
        victims = [s.id for s in self.registry.all() if s.status != "alive"]
        if not victims:
            self.notify("no non-live sessions to prune")
            return
        n = len(victims)

        def handle(confirm: bool | None) -> None:
            if not confirm:
                return
            for sid in victims:
                self.registry.remove(sid)
            self.notify(f"pruned {n} non-live session{'s' if n != 1 else ''}")

        self.push_screen(
            ConfirmModal(
                f"Prune {n} non-live session{'s' if n != 1 else ''}?\n"
                "This deletes their recorded .cast / .log evidence from disk.",
                confirm_label="Prune",
            ),
            handle,
        )

    def _apply_tag(self, tag: str) -> None:
        s = self.current_session()
        if s is None:
            return
        s.tag = tag
        s.save_meta()
        self._refresh_status()
        self._update_prompt()
        self.notify(f"renamed -> {tag or '(cleared)'}")

    def _apply_note(self, note: str) -> None:
        s = self.current_session()
        if s is None:
            return
        s.note = note
        s.save_meta()
        self._refresh_status()

    def action_fingerprint(self) -> None:
        s = self.current_session()
        if s is None or not s.is_live:
            self.notify("need a live session to fingerprint", severity="warning")
            return
        self._run_fingerprint(s, auto=False)

    @work(exclusive=False)
    async def _run_fingerprint(self, s: Session, auto: bool) -> None:
        if auto:
            await asyncio.sleep(0.8)
        if not s.is_live:
            return
        ok = await Fingerprinter(s).run()
        if ok:
            self.notify(f"#{s.id} fingerprinted: {s.fingerprint.summary() or 'parsed'}")
            self._refresh_status()
        elif not auto:
            self.notify(f"#{s.id} fingerprint: no response", severity="warning")

    async def action_raw_interact(self) -> None:
        """Suspend Textual, drop the local tty into raw mode, and pipe stdin<->socket
        directly until Ctrl+G is pressed. Inside, full interactive use of vim,
        htop, tab completion, history, Ctrl+C, etc."""
        s = self.current_session()
        if s is None or not s.is_live:
            self.notify("need a live session for raw-interact", severity="warning")
            return
        sid = s.id
        self._raw_active = True
        try:
            with self.suspend():
                msg = await run_raw_bridge(s)
        except Exception as e:
            self.notify(f"raw-interact error: {e}", severity="error")
            return
        finally:
            self._raw_active = False
        # We suppressed live scrollback updates while suspended - repaint the
        # pane from the session's scrollback so the TUI catches up on the
        # bytes that flowed during raw mode.
        self._repaint_scrollback(s)
        self._refresh_table()
        self._refresh_status()
        self.notify(f"#{sid} {msg}")

    @work(exclusive=False)
    async def action_pty_reconnect(self, target: str = "") -> None:
        """Send a callback-PTY payload that opens a fresh socket back to us
        with a real PTY around bash. The new connection lands as a brand-new
        session - the current dumb session stays alive."""
        s = self.current_session()
        if s is None or not s.is_live:
            self.notify("need a live session to issue reconnect", severity="warning")
            return
        host = ""
        port = self.port
        if target:
            if ":" in target:
                host, _, p = target.rpartition(":")
                try:
                    port = int(p)
                except ValueError:
                    self.notify(f"bad port in {target!r}", severity="error")
                    return
            else:
                host = target
        if not host:
            host = self.host if self.host not in ("0.0.0.0", "::", "") else "127.0.0.1"
        err = validate_target(host, port)
        if err:
            self.notify(f"reconnect target rejected: {err}", severity="error")
            return
        payload = callback_pty_payload(host, port)
        try:
            await s.send(payload.encode())
        except Exception as e:
            self.notify(f"#{s.id} reconnect-PTY send failed: {e}", severity="error")
            return
        self.notify(
            f"#{s.id} reconnect-PTY dispatched -> {host}:{port} - watch sidebar for new session"
        )

    @work(exclusive=False)
    async def action_pty_upgrade(self, shell: str = "") -> None:
        s = self.current_session()
        if s is None or not s.is_live:
            self.notify("need a live session for PTY upgrade", severity="warning")
            return
        size = self.size
        rows = max(24, size.height)
        cols = max(80, size.width)
        self.notify(f"#{s.id} upgrading PTY ({rows}x{cols})...")
        ok, msg = await PtyUpgrader(s, rows=rows, cols=cols, shell=shell).run()
        self.notify(
            f"#{s.id} {msg}",
            severity="information" if ok else "error",
        )

    def action_put_prompt(self) -> None:
        def handle(value: str | None) -> None:
            if not value:
                return
            try:
                parts = shlex.split(value)
            except ValueError as e:
                self.notify(f"parse error: {e}", severity="error")
                return
            if not parts:
                return
            self._do_put(Path(parts[0]), parts[1] if len(parts) > 1 else None)

        self.push_screen(PromptModal("Upload - local [remote]:"), handle)

    def action_get_prompt(self) -> None:
        def handle(value: str | None) -> None:
            if not value:
                return
            self._do_get(value.strip())

        self.push_screen(PromptModal("Download - remote path:"), handle)

    @work(exclusive=False)
    async def _do_put(self, local: Path, remote: str | None) -> None:
        s = self.current_session()
        if s is None or not s.is_live:
            self.notify("need a live session", severity="warning")
            return
        self.notify(f"#{s.id} uploading {local}...")
        result = await put_file(s, local, remote)
        self.notify(
            f"#{s.id} {result.message}",
            severity="information" if result.ok else "error",
        )

    @work(exclusive=False)
    async def _do_get(self, remote: str) -> None:
        s = self.current_session()
        if s is None or not s.is_live:
            self.notify("need a live session", severity="warning")
            return
        self.notify(f"#{s.id} downloading {remote}...")
        result = await get_file(s, remote)
        self.notify(
            f"#{s.id} {result.message}",
            severity="information" if result.ok else "error",
        )


# -- helpers ----------------------------------------------------------
def _status_cell(status: str) -> Text:
    glyph, color = {
        "alive": ("*", C_LIVE),
        "closed": ("x", C_ERR),
        "archived": ("-", C_DIM),
    }.get(status, (status, C_TEXT))
    return Text(glyph, style=color)


def _fmt_uptime(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}"
    hours, rem = divmod(seconds, 3600)
    if hours < 24:
        return f"{hours}h{rem // 60:02d}"
    days, rem = divmod(hours, 24)
    return f"{days}d{rem:02d}h"


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n/1024:.1f}K"
    if n < 1024 * 1024 * 1024:
        return f"{n/(1024*1024):.1f}M"
    return f"{n/(1024*1024*1024):.1f}G"


def _render_frame_title(s: Session | None) -> str:
    """Plain-text title for the main terminal frame: #id - label - status."""
    if s is None:
        return " no session "
    word = {"alive": "* LIVE", "closed": "x CLOSED", "archived": "- ARCHIVED"}.get(
        s.status, s.status
    )
    return f" #{s.id} - {s.label} - {word} "


def _render_target(s: Session) -> str:
    """TARGET line: fingerprint (user@host - OS - shell - cwd) + byte counters
    + note marker. Markup, dot-separated, clipped to one row."""
    fp = s.fingerprint
    if fp.is_empty():
        body = "[dim]no fingerprint yet - /fp to probe - ctrl+u for PTY[/]"
    else:
        bits = []
        who = f"{fp.user}@{fp.hostname}" if fp.user and fp.hostname else (fp.user or fp.hostname)
        if who:
            bits.append(f"[bold {C_ACCENT}]{who}[/]")
        if fp.os:
            bits.append(f"[{C_TEXT}]{fp.os}[/]")
        if fp.shell:
            bits.append(f"[{C_DIM}]{fp.shell}[/]")
        if fp.cwd:
            bits.append(f"[{C_DIM}]{fp.cwd}[/]")
        body = f"  [{C_DIM}]-[/]  ".join(bits)
    counters = (
        f"[{C_DIM}]rx[/] [{C_TEXT}]{_fmt_bytes(s.bytes_rx)}[/] "
        f"[{C_DIM}]tx[/] [{C_TEXT}]{_fmt_bytes(s.bytes_tx)}[/]"
    )
    line = f"{body}   {counters}"
    if s.note:
        line += f"   [{C_ACCENT}]~ {s.note}[/]"
    return line
