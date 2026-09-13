from __future__ import annotations

import re
from dataclasses import dataclass

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, ListItem, ListView, Static

from ..session import SessionRegistry


class ConfirmModal(ModalScreen[bool]):
    """Yes/No confirmation for destructive actions (quit with live sessions,
    kill, prune). Key-driven and plain ASCII - no button widgets: ``y``
    confirms, ``n`` / ``Esc`` cancel (the safe default)."""

    BINDINGS = [
        Binding("escape", "dismiss(False)", "Cancel", show=False),
        Binding("n", "dismiss(False)", "No", show=False),
        Binding("y", "confirm", "Yes", show=False),
    ]

    DEFAULT_CSS = """
    ConfirmModal { align: center middle; }
    ConfirmModal > Vertical {
        width: 64;
        height: auto;
        padding: 1 2;
        background: $panel;
        border: ascii $accent;
    }
    ConfirmModal #msg { padding-bottom: 1; }
    ConfirmModal #hint { color: $primary; text-style: bold; }
    """

    def __init__(self, message: str, confirm_label: str = "Confirm") -> None:
        super().__init__()
        self._message = message
        self._confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self._message, id="msg", markup=False)
            yield Static(
                f"[ y ] {self._confirm_label}    [ n ] cancel",
                id="hint", markup=False,
            )

    def action_confirm(self) -> None:
        self.dismiss(True)


class PromptModal(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel", show=False)]

    DEFAULT_CSS = """
    PromptModal { align: center middle; }
    PromptModal > Vertical {
        width: 70;
        height: auto;
        padding: 1 2;
        background: $panel;
        border: ascii $primary;
    }
    PromptModal #prompt-label { padding-bottom: 1; }
    PromptModal #hint { color: $primary; padding-top: 1; }
    PromptModal Input { border: ascii $primary; }
    """

    def __init__(self, prompt: str, initial: str = "") -> None:
        super().__init__()
        self._prompt = prompt
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self._prompt, id="prompt-label", markup=False)
            yield Input(value=self._initial, id="prompt-input")
            yield Static("[ enter ] ok    [ esc ] cancel", id="hint", markup=False)

    def on_mount(self) -> None:
        self.query_one("#prompt-input", Input).focus()

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)


@dataclass
class SearchHit:
    session_id: int
    label: str
    line: str


class SearchModal(ModalScreen[SearchHit | None]):
    BINDINGS = [
        Binding("escape", "dismiss(None)", "Close", show=True),
        Binding("enter", "pick", "Jump", show=True),
    ]

    DEFAULT_CSS = """
    SearchModal { align: center middle; }
    SearchModal > Vertical {
        width: 80%;
        height: 80%;
        padding: 1 2;
        background: $panel;
        border: ascii $primary;
    }
    SearchModal #search-label { padding-bottom: 1; }
    SearchModal Input { border: ascii $primary; }
    SearchModal ListView { height: 1fr; background: $panel; }
    SearchModal #status { padding-top: 1; color: $text-muted; }
    """

    def __init__(self, registry: SessionRegistry) -> None:
        super().__init__()
        self._registry = registry
        self._hits: list[SearchHit] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("Search all sessions (regex):", id="search-label", markup=False)
            yield Input(placeholder="pattern...", id="search-input")
            yield ListView(id="search-results")
            yield Static("", id="status", markup=False)

    def on_mount(self) -> None:
        self.query_one("#search-input", Input).focus()

    @on(Input.Changed, "#search-input")
    def _on_change(self, event: Input.Changed) -> None:
        self._run_search(event.value)

    @on(Input.Submitted, "#search-input")
    def _on_submit(self) -> None:
        lv = self.query_one("#search-results", ListView)
        if lv.children:
            lv.focus()

    def _run_search(self, pattern: str) -> None:
        lv = self.query_one("#search-results", ListView)
        status = self.query_one("#status", Static)
        lv.clear()
        self._hits = []
        if not pattern:
            status.update("")
            return
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            status.update(f"bad regex: {e}")
            return
        total = 0
        for s in self._registry.all():
            blob = b"".join(s.scrollback).decode("utf-8", errors="replace")
            for line in blob.splitlines():
                if rx.search(line):
                    self._hits.append(SearchHit(s.id, s.label, line))
                    total += 1
                    if total >= 500:
                        break
            if total >= 500:
                break
        for hit in self._hits:
            lv.append(ListItem(Label(f"#{hit.session_id}  {hit.label}  |  {hit.line[:160]}")))
        status.update(f"{total} hit(s)" + (" (capped at 500)" if total >= 500 else ""))

    def action_pick(self) -> None:
        lv = self.query_one("#search-results", ListView)
        idx = lv.index
        if idx is None or idx >= len(self._hits):
            return
        self.dismiss(self._hits[idx])
