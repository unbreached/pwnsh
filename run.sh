#!/usr/bin/env bash
# pwnsh — self-bootstrapping launcher.
#
# Designed for "clone the repo on a fresh box and run it":
#   git clone <repo> pwnsh && cd pwnsh && ./run.sh
#
# On first run we create .venv and install in editable mode. Subsequent
# runs just exec the entry point. Pass any pwnsh flags as args:
#   ./run.sh -p 4444 --no-history
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PY="${PYTHON:-python3}"

if [ ! -x ".venv/bin/pwnsh" ]; then
    if ! command -v "$PY" >/dev/null 2>&1; then
        printf '\033[31m[pwnsh]\033[0m python3 not found — install Python 3.11+ (or set PYTHON=/path/to/python3)\n' >&2
        exit 1
    fi
    PY_VER="$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    PY_MAJOR="${PY_VER%%.*}"
    PY_MINOR="${PY_VER##*.}"
    if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
        printf '\033[31m[pwnsh]\033[0m Python 3.11+ required (found %s)\n' "$PY_VER" >&2
        exit 1
    fi
    printf '\033[36m[pwnsh]\033[0m first-run bootstrap — creating .venv ...\n'
    "$PY" -m venv .venv
    .venv/bin/pip install --upgrade pip --quiet
    .venv/bin/pip install -e . --quiet
    printf '\033[32m[pwnsh]\033[0m bootstrap done.\n'
fi

exec .venv/bin/pwnsh "$@"
