# Agent guide — Hypervisor App

**Before changing ANY UX, read [docs/design-system.md](docs/design-system.md).** It is the
canonical, ground-truth design system (tokens, typography, components, motion, a11y) for
this app, extracted from the running UI. Don't reinvent UI; match it.

Essential facts for UX work:

- **There is one canonical, IOI-owned app — source-owned React.** Surfaces live in
  `apps/hypervisor/src/surfaces/*` and the shell in `apps/hypervisor/src/shell/*`; data comes
  from the daemon's own contracts via the typed clients in `src/data/*` (`/v1/hypervisor/*`,
  `/v1/threads`, `/supervisor/*` env-ops). There is **no seed bundle and no `/api` adapter** —
  the seed was retired once every surface reached source parity.
- **Run it:** `npm run dev --workspace=@ioi/hypervisor-app` (vite, http://localhost:1420), or
  `npm run build && npm run serve:app` for the production serve (dist + daemon proxy). Source
  neutrality is enforced by `npm run check:source-neutral`; every surface has a behavioral
  contract test (`npm run test:contract`).
- **To change/extend a surface,** edit its React under `src/surfaces/<Name>/` and add the
  daemon call to its model; do not reintroduce an adapter or a parallel runtime.
- **Theming is system-aware** (light/dark via `prefers-color-scheme`). Use semantic
  tokens (`--surface-*`/`--content-*`/`--border-*`), never raw hex.
- **Verify on :4173 in both dark and light** (screenshot-diff against the reference)
  before calling a UX change done.
