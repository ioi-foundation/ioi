# QM dormant adoption — review packet

Delta-scoped. This cut claims **adoption of bytes** and nothing else.

## Gates, measured from a dedicated detached worktree at `3dda6066f`

| gate | result |
|---|---|
| discovery-exclusions | PASS (0 error, 1 warn) |
| tracked-caller census | PASS (0 error, 4 warn) |
| pre-next-leg gate pin | 4 pass / 0 fail |
| check-estate | PASS |
| internal-architecture headers | PASS |
| M0 | 1603 entries, exit verified |

Each transcript carries its own `IOI_MEASURED_COMMIT`.

## Five disclosures

**1. The adopted tree crashed a gate.** 1221 files of upstream TypeScript took
M0 discovery down with `TypeError: Cannot read properties of null (reading
'kind')`. The tree is never served, built, or executed — and it still changed a
gate's behaviour, because **discovery reads the repository, not the runtime**.
"Inert" described intent; the input surface disagreed.

**2. A commit was discarded.** `83529c984` landed the adoption over a *failing*
regeneration wrapper — the wrapper refused correctly and its own author
overrode it, on the day it was built. Reset to the rebase point on owner ruling;
these are the same bytes, reproducible from the pin.

**3. The discovery rule.** A per-file **named refusal**
(`undeclared-unparseable-tree`) replaces the raw crash; `apps/ioi-ai/` carries a
**declared exclusion** printing its own cost every run; the dormancy it asserts
is **checked** by reachability teeth. Three proofs retained under
`docs/evidence/m5-event-substrate/discovery-proofs/`. Rather than restate the
exclusion here: **it prints in every census run you measure** — read it there.

**4. The wrapper override**, disclosed in full above rather than summarised. The
layered gate (`check:pre-next-leg`) would have caught the defective commit
before certification; the cheap commit-time net was the one overridden.

**5. A latent defect in *our* code, filed not fixed.** Every guard on the effect
walk is undefined-shaped, so a **null** AST child passes all of them.
Systemic — three site-patches missed before the boundary placement worked. Filed
as `m0-effect-walk-null-child-guards-successor` with a 91-frame reproduction.
**The adopted tree did not break M0 — it revealed M0.**

## Adoption constraints, all met

Pin `5eb3393315b45b338b860572ab516db9f6eae6da`, **double-observed** 2026-08-04 by
director and implementer independently. Bytes-only clone, `core.hooksPath=/dev/null`,
**no install, no build, no script from the tree executed**. Exclusions listed and
verified absent: `.git .github deploy fly aws .dockerignore .env.example .claude
.codex`. Branding stripped from prose; **MIT licence and attribution retained
verbatim** — `package.json`/`package-lock.json` were restored byte-exact after a
first pass corrupted the real npm scope `@yc-software/qm` and a live tarball URL,
because rebranding prose is not rebranding identities.

## Two corrections made before landing, not after

The teeth first matched bare **mentions** and fired on eight work-item records;
then, once narrowed, still fired on the null-defect successor whose prose reads
*"…can contain a route — the file that exposed this defect is literally
apps/ioi-ai/src/api/routes/…"*. A record describing reachability does not create
it. Teeth now scan code and build wiring only, re-proven to still fire on a real
import edge.

One detail worth checking rather than believing: the first file the refusal ever
named is `apps/ioi-ai/src/api/routes/admin/sessions.ts` — a **routes** file,
demonstrating the rule ("an unreadable file can contain a route") that forbade
skip-and-continue. It reads as too neat to write. It happened; proof (i) is the
warrant.
