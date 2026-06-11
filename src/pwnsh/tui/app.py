from __future__ import annotations

import asyncio
import os
import shlex
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
    """Return 'tmux', 'screen', or None — used to surface a key-collision tip."""
    if os.environ.get("TMUX") or os.environ.get("TERM", "").startswith("tmux"):
        return "tmux"
    if os.environ.get("STY") or os.environ.get("TERM", "").startswith("screen"):
        return "screen"
    return None


# Compact (~36 col) ASCII header — fits inside the main pane on 80-col SSH
# terminals after the 38-col sidebar. Rendered into the scrollback via the
# operator banner. Pure ASCII so it renders on dumb terminals too.
_BANNER_ART = [
    r" ___  __      __  _  _   ___   _  _ ",
    r"| _ \ \ \ /\ / / | \| | / __| | || |",
    r"|  _/  \ V  V /  | .` | \__ \ | __ |",
    r"|_|     \_/\_/   |_|\_| |___/ |_||_|",
]


# Curated key hints — replaces Textual's Footer, which surfaced the focused
# Input's own edit bindings (e.g. "^k delete-to-end") and looked cluttered.
def _key(k: str, label: str) -> str:
    return f"[bold #00d4ff]{k}[/] [#c5d4e0]{label}[/]"


_KEYBAR = "  ".join(
    _key(k, label)
    for k, label in (
        ("^q", "quit"), ("^n/^p", "cycle"), ("^f", "search"), ("^u", "pty"),
        ("^g", "raw"), ("^x", "kill"), ("f2", "rename"), ("^k", "palette"),
    )
)


HACKER_THEME = Theme(
    name="hacker",
    primary="#00d4ff",
    secondary="#5af78e",
    accent="#ff3864",
    success="#5af78e",
    warning="#ffb454",
    error="#ff3864",
    foreground="#c5d4e0",
    background="#0a0e12",
    surface="#0a0e12",
    panel="#101820",
    boost="#182028",
    dark=True,
)


_NO_BLINK = Style(blink=False, blink2=False)


def _ansi_to_text(text: str) -> Text:
    """Render terminal output as Rich Text with blink neutralized.

    Remote MOTDs, colored prompts, and tools like `ls --color` frequently
    emit SGR 5/6 (blink). Rich preserves it and Textual renders it as actual
    blinking — obnoxious in the dashboard — so strip it from every span.
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
    """The output pane. It never takes keyboard focus itself — clicking
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


class PwnshApp(App):
    CSS_PATH = "styles.tcss"
    TITLE = "pwnsh"
    SUB_TITLE = "multi-session reverse-shell handler"

    COMMANDS = App.COMMANDS | {PwnshCommands}
    COMMAND_PALETTE_BINDING = "ctrl+k"

    # priority=True so these always fire even though the command Input is the
    # default-focused widget — otherwise Textual's Input would swallow ctrl+u
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
        Binding("ctrl+k", "command_palette", "Palette", show=True, priority=True),
        Binding("ctrl+q", "request_quit", "Quit", show=True, priority=True),
        # NB: Esc is deliberately NOT bound to quit at the app level — it is far
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

    def compose(self) -> ComposeResult:
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):  # border-title set in on_mount
                yield DataTable(id="sessions", cursor_type="row", zebra_stripes=False)
            with Vertical(id="main"):  # border-title tracks the live session
                yield _ScrollbackLog(id="scrollback", wrap=True, highlight=False, markup=False)
                with Horizontal(id="prompt-row"):
                    yield Static("❯", id="prompt-prefix", markup=True)
                    yield Input(placeholder="type a command · enter sends · /help", id="cmd")
        # Framed status panel: TARGET (fingerprint) over LISTENER (listener/debug).
        with Vertical(id="status"):
            yield Static("", id="status-target", markup=True)
            yield Static("", id="status-listener", markup=True)
        yield Static(_KEYBAR, id="keybar", markup=True)

    async def on_mount(self) -> None:
        ensure_dirs()
        if not _is_dumb_terminal():
            try:
                self.register_theme(HACKER_THEME)
                self.theme = "hacker"
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

        # Steady (non-blinking) command cursor — the blink is distracting in a
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
        """Graceful shutdown — flush logs, close sockets."""
        try:
            await self.listener.stop()
        except Exception:
            pass
        self.registry.close_all()

    def notify(self, message: str, *args, **kwargs) -> None:
        """Also mirror the toast into the persistent bottom debug line, so a
        notification that has already faded is still recoverable at a glance."""
        self._status_msg = message
        try:
            self._refresh_status()
        except Exception:
            pass
        return super().notify(message, *args, **kwargs)

    # ── session helpers ───────────────────────────────────────────
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

    # ── registry callbacks ────────────────────────────────────────
    def _on_session_add(self, s: Session) -> None:
        table = self.query_one("#sessions", DataTable)
        try:
            table.add_row(
                str(s.id),
                s.label,
                s.fingerprint.os or "",
                _status_cell(s.status),
                "0s" if s.status == "alive" else "—",
                key=str(s.id),
            )
        except Exception:
            pass
        if s.status == "alive":
            cur = self.current_session()
            if cur is None or cur.status != "alive":
                self.select_session(s.id)
            self.notify(f"⚡ session #{s.id} from {s.remote[0]}:{s.remote[1]}")
            self._run_fingerprint(s, auto=True)

    def _on_session_data(self, s: Session, data: bytes) -> None:
        # During raw-interact the app is suspended — touching widgets here can
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

    # ── rendering ─────────────────────────────────────────────────
    def _show_banner(self) -> None:
        """Operator info block, written into the scrollback when no session
        is selected. Shows the project header, listener, data dir, archive
        count, key cheatsheet, and a tmux/screen tip when relevant."""
        rich_log = self.query_one("#scrollback", RichLog)
        rich_log.clear()
        archived = sum(1 for s in self.registry.all() if s.status != "alive")
        live = sum(1 for s in self.registry.all() if s.status == "alive")
        muxer = _detect_multiplexer()

        for art_line in _BANNER_ART:
            rich_log.write(Text.from_markup(f"[bold #00d4ff]{art_line}[/]"))

        for line in [
            Text(""),
            Text.from_markup(
                f"[bold #5af78e][ PWNSH ][/]  [dim]//[/]  "
                f"[#c5d4e0]David Jacoby[/] [dim]—[/] [#c5d4e0]Syndis · 2026[/]  "
                f"[dim]· v{__version__}[/]"
            ),
            Text(""),
            Text.from_markup(f"[#5af78e]listener[/]   [#c5d4e0]{self.host}:{self.port}[/]"),
            Text.from_markup(f"[#5af78e]data    [/]   [#c5d4e0]{DATA_DIR}[/]"),
            Text.from_markup(
                f"[#5af78e]sessions[/]   [#c5d4e0]{live} live  ·  {archived} archived[/]"
            ),
            Text(""),
            Text.from_markup(
                "[#5af78e]keys    [/]   [#c5d4e0]ctrl+n/p next/prev   ctrl+f search   "
                "ctrl+u pty   ctrl+g raw[/]"
            ),
            Text.from_markup(
                "[#5af78e]        [/]   [#c5d4e0]ctrl+x kill          ctrl+k palette  "
                "ctrl+q quit[/]"
            ),
            Text.from_markup(
                "[#5af78e]slash   [/]   [#c5d4e0]/put /get /tag /note /pty /fp /kill /prune /payload /help[/]"
            ),
        ]:
            rich_log.write(line)

        if muxer:
            rich_log.write(Text(""))
            rich_log.write(Text.from_markup(
                f"[#ffb454]tip     [/]   [#c5d4e0]inside {muxer} — pwnsh keys do not collide "
                f"with the {muxer} prefix.[/]"
            ))
            rich_log.write(Text.from_markup(
                "[#ffb454]        [/]   [#c5d4e0]raw-interact (ctrl+g) needs a real tty; "
                "exit it with ctrl+g if it locks up.[/]"
            ))

    def _append_scrollback(self, data: bytes) -> None:
        rich_log = self.query_one("#scrollback", RichLog)
        try:
            rich_log.write(_ansi_to_text(data.decode("utf-8", errors="replace")))
        except Exception:
            rich_log.write(repr(data))

    def _repaint_scrollback(self, s: Session) -> None:
        """Clear the pane and replay a session's full scrollback into it."""
        rich_log = self.query_one("#scrollback", RichLog)
        rich_log.clear()
        for chunk in s.scrollback:
            try:
                rich_log.write(_ansi_to_text(chunk.decode("utf-8", errors="replace")))
            except Exception:
                rich_log.write(repr(chunk))

    def _refresh_status(self) -> None:
        """Update the framed status panel — the main pane's title, the TARGET
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
            f"[bold #5af78e]●[/] [#5af78e]{self.host}:{self.port}[/]"
            f"   [#c5d4e0]{live} live · {archived} archived[/]"
            f"   [dim]· {msg}[/]"
        )

    def _update_prompt(self) -> None:
        prefix = self.query_one("#prompt-prefix", Static)
        cmd = self.query_one("#cmd", Input)
        s = self.current_session()
        if s is None:
            prefix.update("[dim]❯[/]")
            cmd.placeholder = f"no session — listening on :{self.port}"
        elif s.status == "alive":
            prefix.update("[bold #00d4ff]❯[/]")
            cmd.placeholder = "type a command · enter sends · /help"
        else:
            prefix.update("[dim]❯[/]")
            cmd.placeholder = f"[{s.status}] — read-only · /tag /note /kill"

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
                    _fmt_uptime(now - s.connected_at) if s.status == "alive" else "—",
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

    # ── events ────────────────────────────────────────────────────
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
            self.notify("session is not live — can't send", severity="warning")
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
                f"unknown payload kind {kind!r} — try one of: {', '.join(PAYLOAD_KINDS)}",
                severity="warning",
            )
            return
        rich_log.write(Text(""))
        rich_log.write(Text.from_markup(
            f"[bold #00d4ff]── payload ({kind}) → {self.host}:{self.port} ──[/]"
        ))
        rich_log.write(Text(line, style="#5af78e"))
        rich_log.write(Text.from_markup(
            "[dim]select with mouse to copy. /payload again for another type.[/]"
        ))
        self.notify(f"payload ({kind}) printed — host:port baked in")

    def _show_help(self) -> None:
        rich_log = self.query_one("#scrollback", RichLog)
        rich_log.write(Text("──── pwnsh commands ────", style="bold #00d4ff"))
        for line in [
            "  /put <local> [remote]   upload a file (base64 heredoc, sha256 verify)",
            "  /get <remote>           download a file to ~/.pwnsh/loot/",
            "  /tag <name>             rename the current session  (also F2)",
            "  /note <text>            sticky note on the session   (Ctrl+O)",
            "  /pty                    upgrade to a PTY + sync size (Ctrl+U)",
            "  /fp                     re-run fingerprint probe",
            "  /kill                   disconnect + remove current   (Ctrl+X)",
            "  /prune                  remove every non-live session",
            "  /payload <kind>         print a host:port-stamped one-liner (bash, python, nc, …)",
            "  Ctrl+N / Ctrl+P         next / previous session",
            "  Ctrl+F                  search scrollback across all sessions",
            "  Ctrl+K                  command palette",
            "  Ctrl+Q                  quit (confirms if a session is live)",
        ]:
            rich_log.write(Text(line, style="#c5d4e0"))

    # ── actions ───────────────────────────────────────────────────
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
            self.notify(f"→ #{hit.session_id}")

        self.push_screen(SearchModal(self.registry), handle)

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
        self.notify(f"renamed → {tag or '(cleared)'}")

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
        """Suspend Textual, drop the local tty into raw mode, and pipe stdin↔socket
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
        # We suppressed live scrollback updates while suspended — repaint the
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
        session — the current dumb session stays alive."""
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
            f"#{s.id} reconnect-PTY dispatched → {host}:{port} — watch sidebar for new session"
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
        self.notify(f"#{s.id} upgrading PTY ({rows}×{cols})…")
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

        self.push_screen(PromptModal("Upload — local [remote]:"), handle)

    def action_get_prompt(self) -> None:
        def handle(value: str | None) -> None:
            if not value:
                return
            self._do_get(value.strip())

        self.push_screen(PromptModal("Download — remote path:"), handle)

    @work(exclusive=False)
    async def _do_put(self, local: Path, remote: str | None) -> None:
        s = self.current_session()
        if s is None or not s.is_live:
            self.notify("need a live session", severity="warning")
            return
        self.notify(f"#{s.id} uploading {local}…")
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
        self.notify(f"#{s.id} downloading {remote}…")
        result = await get_file(s, remote)
        self.notify(
            f"#{s.id} {result.message}",
            severity="information" if result.ok else "error",
        )


# ── helpers ──────────────────────────────────────────────────────────
def _status_cell(status: str) -> str:
    return {"alive": "●", "closed": "✗", "archived": "·"}.get(status, status)


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
    """Plain-text title for the main terminal frame: #id · label · status."""
    if s is None:
        return " no session "
    word = {"alive": "● LIVE", "closed": "✗ CLOSED", "archived": "· ARCHIVED"}.get(
        s.status, s.status
    )
    return f" #{s.id} · {s.label} · {word} "


def _render_target(s: Session) -> str:
    """TARGET line: fingerprint (user@host · OS · shell · cwd) + byte counters
    + note marker. Markup, dot-separated, clipped to one row."""
    fp = s.fingerprint
    if fp.is_empty():
        body = "[dim]no fingerprint yet — /fp to probe · ctrl+u for PTY[/]"
    else:
        bits = []
        who = f"{fp.user}@{fp.hostname}" if fp.user and fp.hostname else (fp.user or fp.hostname)
        if who:
            bits.append(f"[#5af78e]{who}[/]")
        if fp.os:
            bits.append(f"[#c5d4e0]{fp.os}[/]")
        if fp.shell:
            bits.append(f"[dim]{fp.shell}[/]")
        if fp.cwd:
            bits.append(f"[dim]{fp.cwd}[/]")
        body = "  [dim]·[/]  ".join(bits)
    counters = (
        f"[dim]rx[/] [#c5d4e0]{_fmt_bytes(s.bytes_rx)}[/] "
        f"[dim]tx[/] [#c5d4e0]{_fmt_bytes(s.bytes_tx)}[/]"
    )
    line = f"{body}   {counters}"
    if s.note:
        line += f"   [#ffb454]✎ {s.note}[/]"
    return line
