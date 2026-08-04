# ioi-ai — dormant adoption provenance

This tree is **adopted bytes**. It is not served, not rebound, not built, and
carries no parity, executable, or product-membership claim. Nothing in it has
been executed on this machine, and nothing in it runs.

## Upstream

| | |
|---|---|
| URL | `https://github.com/yc-software/qm.git` |
| Pinned sha | `5eb3393315b45b338b860572ab516db9f6eae6da` (`refs/heads/main`) |
| Observation 1 | director, 2026-08-04 |
| Observation 2 | implementer, 2026-08-04, independent `git ls-remote` |
| Agreement | both readings identical — the pin is double-observed |

The double read exists to catch a head moving between observations. It did not
move.

## Fetch discipline

Bytes only. `--no-checkout` clone with `core.hooksPath=/dev/null`, then checkout
at the pin. **No `npm install`, no build, no script from the fetched tree
executed — ever, on this box.** The stack is adopted verbatim (Lit/Vite,
TypeScript); no React port, no rewrite.

## Exclusions, every one listed

`.git` · `.github` · `deploy` · `fly` · `aws` · `.dockerignore` · `.env.example`
· `.claude` · `.codex`

Verified absent after the copy; no leak.

## Pinned verbatim vendoring — the corrected claim

**This tree is byte-identical to upstream at pin `5eb3393315b45b338b860572ab516db9f6eae6da`,
modulo the declared exclusion list.** Proven by `check-adoption-completeness`:
blob-SHA comparison in both directions, **empty deviation list**, 1224 files,
0 discrepancies. MIT `LICENSE` and `Copyright (c) 2026 QM contributors` are
upstream bytes like everything else.

### CORRECTION (bytes quoted)

This document previously claimed: *"YC branding is stripped from **prose** (14
files: `README.md`, `CLAUDE.md`, docs, tests)."* It also carried a paragraph
headed *"A correction worth recording"* asserting that machine identities had
been restored — **that assertion was false when written**: eleven files still
carried rewrites. Codex found two; nine more were found on sweep.

The deeper correction is about the ACT, not the count. **The 14 rewrites were
identity rewriting wearing a rebrand's name.** All were reverted. Applying
*rebrand touches display strings only* strictly yields an **empty rebrand set**,
because every YC string in this tree is an identity a resolver, installer, or
cross-reference depends on: `@yc-software/qm` in npm install commands (including
inside `.md` files), and `yc-software/qm` in a `git origin` check in `AGENTS.md`.
**No display-only branding existed.**

The branding obligation has not vanished — it moved to where it belongs. The
rebind record now carries it: the **served surface** presents IOI branding at
the display and config layer, without touching vendored identity bytes.
Branding is a property of what we serve, never of what we vendor.

### Exclusion list — exhaustive or false

`.git` · `.github` · `deploy` · `fly` · `aws` · `.dockerignore` · `.env.example`
· `.claude` · `.codex`

The earlier list **omitted three `.gitignore` files** that were never adopted —
not because they were stripped, but because **`git add -A` honours a
`.gitignore` inside the tree being added**. The list was true about what was
removed and silent about what git declined to add. All three are now adopted
verbatim, and the completeness bar closes that mechanism and every sibling of it
generically.

A method note, because it produced a wrong number: the first completeness diff
was taken against a working **copy** of upstream — a copy produced by the same
skip mechanism it was meant to detect — and reported 1239 upstream files where
the pin has **1277**. The upstream side is now rebuilt from the pin via
`git ls-tree` on a bare clone. *The verifier must not inherit the subject's
enumeration.*

## What this cut claims

Adoption of bytes. Nothing else. The executable rebind is a separate record
(`m5-qm-reference-shell-executable-rebind`) which gates **M6**, not M5.
