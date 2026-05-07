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


class PromptModal(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel", show=False)]

    DEFAULT_CSS = """
    PromptModal { align: center middle; }
    PromptModal > Vertical {
        width: 70;
        height: auto;
        padding: 1 2;
        background: $panel;
        border: tall $primary;
    }
    PromptModal Label { padding-bottom: 1; }
    """

    def __init__(self, prompt: str, initial: str = "") -> None:
        super().__init__()
        self._prompt = prompt
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._prompt)
            yield Input(value=self._initial, id="prompt-input")

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
        border: tall $primary;
    }
    SearchModal Label { padding-bottom: 1; }
    SearchModal ListView { height: 1fr; }
    SearchModal #status { padding-top: 1; color: $text-muted; }
    """

    def __init__(self, registry: SessionRegistry) -> None:
        super().__init__()
        self._registry = registry
        self._hits: list[SearchHit] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Search all sessions (regex):")
            yield Input(placeholder="pattern…", id="search-input")
            yield ListView(id="search-results")
            yield Static("", id="status")

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
            lv.append(ListItem(Label(f"#{hit.session_id}  {hit.label}  │  {hit.line[:160]}")))
        status.update(f"{total} hit(s)" + (" (capped at 500)" if total >= 500 else ""))

    def action_pick(self) -> None:
        lv = self.query_one("#search-results", ListView)
        idx = lv.index
        if idx is None or idx >= len(self._hits):
            return
        self.dismiss(self._hits[idx])
