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

## Branding versus attribution — deliberately different acts

YC branding is stripped from **prose** (14 files: `README.md`, `CLAUDE.md`,
docs, tests). MIT `LICENSE` and its `Copyright (c) 2026 QM contributors` are
**retained verbatim** — MIT requires attribution, and stripping branding is not
a licence to strip attribution.

**A correction worth recording.** The first rebranding pass rewrote
`package.json` and `package-lock.json` too, turning the real npm scope
`@yc-software/qm` into `@IOI/qm` and a live release tarball URL into one that
does not exist. That is not rebranding, it is corrupting machine identities that
happen to contain a string. Both files were restored **verbatim** from the
pinned fetch. Branding lives in prose; identities are bytes a resolver depends
on, and the difference is not cosmetic.

Remaining `yc-software` occurrences: 7, all in `package.json` /
`package-lock.json`, all dependency identities or URLs, all intentional.

## What this cut claims

Adoption of bytes. Nothing else. The executable rebind is a separate record
(`m5-qm-reference-shell-executable-rebind`) which gates **M6**, not M5.
