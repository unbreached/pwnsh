# Contributing to pwnsh

Thanks for your interest. pwnsh is a focused tool — a multi-session
reverse-shell handler with a terminal dashboard, for **authorized** security
work. Contributions that make it more reliable, more usable, or more portable
are very welcome. Contributions that turn it into a C2 framework, add
self-propagation, or help evade defenders on systems you don't own are not.

## Getting set up

```sh
git clone https://github.com/unbreached/pwnsh
cd pwnsh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
```

## Before you open a PR

Everything must stay green and lint-clean:

```sh
ruff check src tests
pytest -q
```

- **Add a test** for any behavior change or fix. The suite is fast and runs
  headless (including the Textual TUI, via the pilot driver).
- **Keep the core Textual-free.** `session`, `listener`, `transfer`,
  `fingerprint`, `udp`, `vault`, `complete`, `payloads`, `_scan` must not import
  `textual`. The TUI layer sits on top of them. This keeps the engine testable
  and reusable.
- **Match the surrounding style.** Comments explain *why*, not *what*;
  `ruff` (line length 100, rules `E/F/W/I/B/UP`) is the formatter of record.
- **Payloads that touch a target shell** should degrade gracefully: resolve
  tools/shells on-target (don't hard-code `/bin/bash`), prefer POSIX `sh`, and
  fail with a clear marker rather than silently half-working.

## Commit / PR hygiene

- One logical change per PR; describe the *why* in the body.
- Note any user-visible change in `CHANGELOG.md` under `[Unreleased]`.
- By submitting, you agree your contribution is licensed under the project's
  [MIT License](LICENSE).

## Reporting bugs / security issues

Functional bugs: open a GitHub issue with `pwnsh -V`, your OS, and repro steps.
Security issues in pwnsh itself: follow [SECURITY.md](SECURITY.md) (report
privately, don't open a public issue).
