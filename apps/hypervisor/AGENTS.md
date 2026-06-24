# Agent guide — Hypervisor App

**Before changing ANY UX, read [docs/design-system.md](docs/design-system.md).** It is the
canonical, ground-truth design system (tokens, typography, components, motion, a11y) for
this app, extracted from the running UI. Don't reinvent UI; match it.

Essential facts for UX work:

- **The product UI _is_ the live reference**, served by
  `scripts/serve-live-reference.mjs` (the reference bundle + an IOI `/api` adapter), not a
  hand-written React app. Run it and treat it as source of truth:
  `npm run serve:reference --workspace=@ioi/hypervisor-app` → http://localhost:4173
- **The reference bundle is a gitignored local mirror (read-only).** Product/UX/content
  changes go in the **committed serve layer** — response rewrites and the `/api` adapter
  (`scripts/ioi-api-adapter.mjs`) — never by editing the snapshot. Pattern + per-endpoint
  status: [docs/reference-api-integration.md](docs/reference-api-integration.md).
- **Theming is system-aware** (light/dark via `prefers-color-scheme`). Use semantic
  tokens (`--surface-*`/`--content-*`/`--border-*`), never raw hex.
- **Verify on :4173 in both dark and light** (screenshot-diff against the reference)
  before calling a UX change done.
