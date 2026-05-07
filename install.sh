#!/usr/bin/env bash
# multishell installer — creates .venv, installs editable, symlinks the entry point.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

BIN_DIR="${MULTISHELL_BIN_DIR:-$HOME/.local/bin}"
PY="${PYTHON:-python3}"

say()  { printf '\033[36m[multishell]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[multishell]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[multishell]\033[0m %s\n' "$*" >&2; exit 1; }

command -v "$PY" >/dev/null 2>&1 || die "python3 not found in PATH (override with PYTHON=/path/to/python3)"

PY_VER="$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER##*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    die "Python 3.11+ required (found $PY_VER)"
fi

say "creating venv at .venv"
"$PY" -m venv .venv

say "upgrading pip"
.venv/bin/pip install --upgrade pip --quiet

say "installing multishell (editable) + runtime deps"
.venv/bin/pip install -e . --quiet

mkdir -p "$BIN_DIR"
LINK="$BIN_DIR/multishell"

if [ -L "$LINK" ] || [ -f "$LINK" ]; then
    rm -f "$LINK"
fi
ln -s "$HERE/.venv/bin/multishell" "$LINK"
say "symlinked $LINK -> $HERE/.venv/bin/multishell"

case ":$PATH:" in
    *":$BIN_DIR:"*) : ;;
    *) warn "$BIN_DIR is not on your PATH — add this to your shell rc:"
       printf '\n    export PATH="%s:$PATH"\n\n' "$BIN_DIR" ;;
esac

cat <<EOF

$(printf '\033[32m✓ multishell installed\033[0m')

    start it:             multishell
    custom port:          multishell -p 4444
    local-only listener:  multishell -b 127.0.0.1
    skip archive load:    multishell --no-history
    help:                 multishell --help

see REVERSE_SHELLS.md for shell payloads matched to your target.
EOF
