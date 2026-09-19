# @ioi-ai/orchestration — scope of the rules that apply here

This directory is a **root workspace of the ioi monorepo** (`npm run build --workspace=@ioi-ai/orchestration`)
that lives beside the qm application because it is ioi.ai application code (register R-200,
2026-09-19). It is not part of qm's package graph: qm has its own `package.json`, lock and
`node_modules`, its `tsconfig.json` does not include this directory, and qm reaches this package
only by relative path from `plugins/web-ui`.

So the guidance in [`../AGENTS.md`](../AGENTS.md) applies to qm — its `src/`, `plugins/`, `test/`,
`scripts/`, its private-fork discipline and its zero-comment standard — and **not to this
subtree**, which is governed by the monorepo's own conventions:

- Files here carry the program's rationale in comments and docblocks on purpose. The Hypervisor's
  driven verifiers make structural claims over this source (they read it and assert what it does and
  does not name), and the estate's ledger (`docs/architecture/_meta/canon-to-code-delta.md`) and its
  private register cite that prose. Do not strip it to satisfy qm's rule; it is not qm's file.
- Changes land on `master` in dependency-ordered slices behind the monorepo's 21-gate pre-push sweep
  and CI's matrix of daemon-driven verifiers, not through qm's PR-and-review flow.
- qm's private-fork rules do not apply: `origin` here is the ioi monorepo.

If the owner prefers this package outside qm's directory altogether (for example
`apps/ioi-ai-orchestration/`), that is a one-slice move; this file records the reading that applies
until then (register R-203).
