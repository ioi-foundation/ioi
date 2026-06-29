# Agent guide — Hypervisor App

**Before changing ANY UX, read [docs/design-system.md](docs/design-system.md).** It is the
canonical, ground-truth design system (tokens, typography, components, motion, a11y) for
this app, extracted from the running UI. Don't reinvent UI; match it.

Essential facts for UX work:

- **There is one canonical, IOI-owned app.** It is the tracked product-ui bundle
  (`product-ui/`) + an IOI `/api` adapter, served by `scripts/serve-product-ui.mjs`. Run it
  and treat it as source of truth:
  `npm run serve:product-ui --workspace=@ioi/hypervisor-app` → http://localhost:4173
- **The bundle is a committed, source-neutral seed shell** (no upstream brand; the upstream
  identifiers were rebranded to IOI and this is enforced by `npm run check:source-neutral`). The migration target is to
  extract surfaces into source-owned React under `apps/hypervisor/src/surfaces/`; until a
  surface is extracted, product/UX/content changes go in the **committed serve layer** — the
  `/api` adapter (`scripts/ioi-api-adapter.mjs`) and response rewrites. Pattern + per-endpoint
  status: [docs/product-ui-api-integration.md](docs/product-ui-api-integration.md).
  **Do not build a parallel/native runtime — evolve this app in place.**
- **Theming is system-aware** (light/dark via `prefers-color-scheme`). Use semantic
  tokens (`--surface-*`/`--content-*`/`--border-*`), never raw hex.
- **Verify on :4173 in both dark and light** (screenshot-diff against the reference)
  before calling a UX change done.
