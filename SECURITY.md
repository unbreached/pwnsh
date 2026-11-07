# Security Policy

## Intended use

pwnsh is an **offensive-security tool for authorized testing only** —
penetration tests, CTFs, red-team labs, and research against systems you own
or have explicit written permission to test. Using it against systems without
authorization is illegal in most jurisdictions. You are responsible for staying
inside your scope and your contracts. See the project's [Ethics](README.md#ethics)
note.

## Reporting a vulnerability

If you find a security issue **in pwnsh itself** (for example: a payload that
mishandles untrusted target output, a path-traversal in file transfer or the
loot vault, or a flaw that could harm the operator's own machine), please
report it privately rather than opening a public issue:

- Preferred: open a [GitHub security advisory](https://github.com/unbreached/pwnsh/security/advisories/new)
  (**Security → Report a vulnerability**).
- Or email **david@unbreached.se** with `pwnsh security` in the subject.

Please include a description, affected version (`pwnsh -V`), and steps to
reproduce. I aim to acknowledge reports within a few days. Coordinated
disclosure is appreciated — give me a reasonable window to ship a fix before
going public.

## Scope

In scope: anything that lets a **target** compromise the **operator**
(the machine running pwnsh), corrupt recorded evidence, or escape the
documented data directory (`~/.pwnsh/`). Also in scope: plugin-loading or
deserialization issues.

Out of scope: that pwnsh can, by design, interact with and control a remote
shell — that is the whole point of the tool, not a vulnerability.

## Supported versions

Fixes land on the latest released version. Pin a version if you need
reproducibility for an engagement.
