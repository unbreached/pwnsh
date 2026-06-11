"""Headless TUI smoke tests via Textual's pilot.

These don't drive a real terminal — ``run_test()`` uses a headless driver — but
they catch the class of regressions a pure-core unit test can't: a broken CSS
rule, a binding that points at a missing action, a compose() that raises, and
the deliberate UX choices around quitting.
"""
from __future__ import annotations

import asyncio

from pwnsh.tui.app import PwnshApp
from pwnsh.tui.modals import ConfirmModal


def _app(free_port: int) -> PwnshApp:
    return PwnshApp(port=free_port, host="127.0.0.1", load_history=False)


def test_app_mounts_with_banner(free_port):
    async def go():
        app = _app(free_port)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.query_one("#scrollback") is not None
            assert app.query_one("#sessions") is not None
            assert app.selected_id is None
        return True

    assert asyncio.run(go())


def test_layout_is_framed_panels_plus_status_and_keybar(free_port):
    """Framed sidebar + terminal, a TARGET/LISTENER status box, and a curated
    key bar — no standalone session-header / session-info / Footer widgets."""

    async def go():
        app = _app(free_port)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            for wid in (
                "#body", "#sidebar", "#main", "#scrollback", "#cmd",
                "#prompt-prefix", "#status", "#status-target", "#status-listener",
                "#keybar",
            ):
                assert app.query(wid), f"missing {wid}"
            # the old stacked panels are gone
            assert not app.query("#session-header")
            assert not app.query("#session-info")
            # framed panels carry ASCII titles
            assert app.query_one("#sidebar").border_title == "SESSIONS"
            assert app.query_one("#status").border_title == "TARGET"
            # listener line shows live/archived counts
            assert "live" in str(app.query_one("#status-listener").render())
        return True

    assert asyncio.run(go())


def test_render_frame_title_and_target():
    from pwnsh.session import Fingerprint, Session
    from pwnsh.tui.app import _render_frame_title, _render_target

    s = Session(id=3, reader=None, writer=None, remote=("10.0.0.5", 4444))
    s.tag = "web-prod-01"
    s.fingerprint = Fingerprint(
        os="Linux", user="alice", hostname="victim01", shell="/bin/bash", cwd="/home/alice"
    )
    s.bytes_rx = 12345
    s.note = "creds in .env"
    title = _render_frame_title(s)
    assert "#3" in title and "web-prod-01" in title and "LIVE" in title
    target = _render_target(s)
    assert "alice@victim01" in target
    assert "Linux" in target and "/bin/bash" in target
    assert "rx" in target and "tx" in target
    assert "creds in .env" in target


def test_ansi_to_text_strips_blink():
    """Remote output (MOTDs, colored prompts, ls --color) often carries SGR 5/6
    blink; we must neutralize it so the dashboard doesn't blink."""
    from rich.style import Style

    from pwnsh.tui.app import _ansi_to_text

    t = _ansi_to_text("\x1b[1;5;31mALERT\x1b[0m ok \x1b[5mblinky\x1b[25m done")
    assert "ALERT" in t.plain and "blinky" in t.plain  # text preserved
    for span in t.spans:
        st = span.style if isinstance(span.style, Style) else Style.parse(span.style)
        assert not st.blink and not st.blink2  # blink removed everywhere


def test_command_cursor_steady_and_output_wraps(free_port):
    """UX guards: the prompt cursor must not blink, and the output pane must
    wrap (no weird horizontal scrolling)."""

    async def go():
        app = _app(free_port)
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import Input, RichLog

            assert app.query_one("#cmd", Input).cursor_blink is False
            assert app.query_one("#scrollback", RichLog).wrap is True
        return True

    assert asyncio.run(go())


def test_render_target_handles_missing_fingerprint():
    from pwnsh.session import Session
    from pwnsh.tui.app import _render_frame_title, _render_target

    s = Session(id=1, reader=None, writer=None, remote=("1.1.1.1", 2))
    assert "no fingerprint" in _render_target(s)
    assert _render_frame_title(None) == " no session "


def test_operator_hotkeys_not_swallowed_by_prompt(free_port):
    """Ctrl+U is delete-to-start inside a Textual Input; our priority binding
    maps it to PTY-upgrade, so typed text must survive the keypress (proving the
    app binding wins over the focused prompt)."""

    async def go():
        app = _app(free_port)
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import Input
            cmd = app.query_one("#cmd", Input)
            assert app.focused is cmd
            await pilot.press("a", "b", "c")
            await pilot.pause()
            assert cmd.value == "abc"
            await pilot.press("ctrl+u")  # PTY-upgrade action, NOT input delete
            await pilot.pause()
            return cmd.value

    assert asyncio.run(go()) == "abc"


def test_prompt_is_focused_by_default(free_port):
    async def go():
        app = _app(free_port)
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import Input
            return app.focused is app.query_one("#cmd", Input)

    assert asyncio.run(go()) is True


def test_clicking_output_focuses_prompt_and_typing_works(free_port):
    """The core of the new UX: click anywhere in the output, then type."""

    async def go():
        app = _app(free_port)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            from textual.widgets import Input
            cmd = app.query_one("#cmd", Input)
            # move focus away, then click the output to bring it back
            app.query_one("#sessions").focus()
            await pilot.pause()
            assert app.focused is not cmd
            await pilot.click("#scrollback")
            await pilot.pause()
            assert app.focused is cmd
            await pilot.press("i", "d")
            await pilot.pause()
            return cmd.value

    assert asyncio.run(go()) == "id"


def test_escape_does_not_quit_the_app(free_port):
    """Regression guard: Esc must not hard-quit and drop live sessions."""

    async def go():
        app = _app(free_port)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            return app.is_running

    assert asyncio.run(go()) is True


def test_ctrl_q_exits_cleanly_without_live_sessions(free_port):
    async def go():
        app = _app(free_port)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("ctrl+q")
            await pilot.pause()
        return True

    assert asyncio.run(go())


def test_confirm_modal_cancel_returns_false(free_port):
    async def go():
        app = _app(free_port)
        results: list[bool | None] = []
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(
                ConfirmModal("delete it?", confirm_label="Delete"),
                results.append,
            )
            await pilot.pause()
            await pilot.press("escape")  # cancel
            await pilot.pause()
            assert app.is_running
        return results

    assert asyncio.run(go()) == [False]
