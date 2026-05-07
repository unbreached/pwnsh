from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from textual.command import DiscoveryHit, Hit, Hits, Provider

if TYPE_CHECKING:
    from .app import MultiShellApp


class MultiShellCommands(Provider):
    """Surfaces multishell actions + session switches in the command palette."""

    @property
    def ms_app(self) -> "MultiShellApp":
        return self.app  # type: ignore[return-value]

    async def discover(self) -> Hits:
        for hit in self._static_actions():
            yield hit
        async for hit in self._session_actions():
            yield hit

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for hit in self._static_actions():
            score = matcher.match(hit.text)
            if score > 0:
                yield Hit(score, matcher.highlight(hit.text), hit.command, help=hit.help)
        async for hit in self._session_actions():
            score = matcher.match(hit.text)
            if score > 0:
                yield Hit(score, matcher.highlight(hit.text), hit.command, help=hit.help)

    def _static_actions(self) -> list[DiscoveryHit]:
        app = self.ms_app
        return [
            DiscoveryHit("Rename session", app.action_set_tag, help="Tag / rename (F2)"),
            DiscoveryHit("Edit session note", app.action_edit_note, help="Sticky note (Ctrl+O)"),
            DiscoveryHit("Search scrollback", app.action_search, help="Regex across every session (Ctrl+F)"),
            DiscoveryHit("Fingerprint target", app.action_fingerprint, help="Probe OS / user / shell"),
            DiscoveryHit("Upgrade to PTY", app.action_pty_upgrade, help="In-place pty.spawn wrapper (Ctrl+U)"),
            DiscoveryHit("Reconnect with fresh PTY", app.action_pty_reconnect, help="Callback shell with a clean PTY — new session"),
            DiscoveryHit("Raw interact (Ctrl+G)", app.action_raw_interact, help="Suspend TUI, raw stdin↔socket — vim/htop/tab/Ctrl-C work"),
            DiscoveryHit("Upload file (/put)", app.action_put_prompt, help="Send a local file to the target"),
            DiscoveryHit("Download file (/get)", app.action_get_prompt, help="Pull a remote file into loot"),
            DiscoveryHit("Close and remove session", app.action_kill_session, help="Disconnect + drop from list (Ctrl+X)"),
            DiscoveryHit("Prune dead sessions", app.action_prune_dead, help="Remove every non-live session"),
            DiscoveryHit("Quit", app.action_quit, help="Exit multishell"),
        ]

    async def _session_actions(self):
        app = self.ms_app
        for s in app.registry.all():
            fp = s.fingerprint.summary()
            marker = {"alive": "●", "closed": "✗", "archived": "·"}.get(s.status, "")
            label = f"Switch to #{s.id} {marker} {s.label}"
            if fp:
                label += f"  [{fp}]"
            yield DiscoveryHit(label, partial(app.select_session, s.id), help=f"Status: {s.status}")
