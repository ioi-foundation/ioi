# IOI Design System — Portable Package Plan

> **Execution routing (2026-07-17): partially absorbed specialist source.**
> Track 1 is complete. Broader adoption and ESM-native work activate only
> through M6/M9 `WP-UX` in the
> [target-end-state master guide](./ioi-target-end-state-master-implementation-guide.md).

Status: planning · Untracked (internal-docs/implementation is gitignored) · 2026-06-27
Owner: `apps/hypervisor-web/src/design-system/` → `packages/design-system/` (`@ioi/design-system`)
Goal: turn the vendored design system into a shared workspace package any app can
depend on — CSS tokens, components, and assets included — with no copy-paste vendoring.

## 1. Current state (verified 2026-06-27)

- Lives **only** in `apps/hypervisor-web/src/design-system/` (6 files):
  `_ds_bundle.js` (generated, ~19.4k LOC), `styles.css`, `tokens/{colors,fonts,typography,spacing}.css`.
  Assets were just consolidated into `apps/hypervisor-web/public/assets/` (absolute `/assets/...` refs).
- `_ds_bundle.js` is a **generated artifact** (`@ds-bundle` header carries `sourceHashes` for
  `components/*.jsx`, `site/*.jsx`, `ui_kits/website/*.jsx`). **The component source and the generator
  are upstream — not in this repo.** We hold the dist, not the source.
- Consumption is **global-namespace, not ESM**:
  - `main.jsx`: `import "./design-system/styles.css"`; `window.React = React`; then
    `await import("./design-system/_ds_bundle.js")` (side effect populates `window.IoiDesignSystem`).
  - Surface in `hypervisor-web/src`: **25** files read `window.React`, **17** read
    `window.IoiDesignSystem`, **19** attach `window.Hv*` page/section globals.
- **No other app consumes it yet** (aiagent-xyz, benchmarks, developers-ioi-ai, hypervisor-app, sas-xyz
  have no design-system) — portability is forward-looking reuse.
- Monorepo: npm workspaces `apps/*` + `packages/*`; `packages/` already holds 6 packages, so a new
  `@ioi/design-system` slots in with zero workspace plumbing.

## 2. The two constraints that shape the whole plan

1. **Source-of-truth is upstream.** We own the generated bundle, not its generator/source. So we either
   (a) treat the generated bundle as the package's published **dist**, or (b) **in-source** the
   generator + component source and build it here. (b) requires upstream access — a hard dependency.
2. **The global contract is the opposite of an idiomatic package.** A real portable package exports ESM
   (`import { Button } from "@ioi/design-system"`). Getting there means migrating ~25 consumer files off
   `window.*`. That migration is **separable** from packaging and is the larger cost.

## 3. Recommended approach — two tracks

- **Track 1 — lift-and-shift workspace package (do first).** Ship a real, reusable `@ioi/design-system`
  fast, *keeping the proven global contract and the generated bundle as dist*. Delivers cross-app reuse +
  package-owned assets immediately, low risk.
- **Track 2 — ESM-native (optional, later).** The "real" portability: in-source the source, build to
  ESM + types, assets imported (bundler-hashed), drop the React/DS globals. Bigger; gated on upstream
  source access. Can be deferred indefinitely without blocking Track 1's benefits.

---

## Track 1 — workspace package (keeps the global contract)

### Phase 1 — Scaffold `packages/design-system/`
- `package.json`:
  ```jsonc
  {
    "name": "@ioi/design-system",
    "version": "0.1.0",
    "type": "module",
    "sideEffects": ["*.css", "./bundle/_ds_bundle.js"],
    "files": ["bundle", "tokens", "styles.css", "assets", "bin"],
    "exports": {
      ".": "./bundle/_ds_bundle.js",
      "./styles.css": "./styles.css",
      "./tokens/*": "./tokens/*",
      "./assets/*": "./assets/*"
    },
    "bin": { "ioi-ds-sync-assets": "./bin/sync-assets.mjs" },
    "peerDependencies": { "react": ">=18", "react-dom": ">=18" }
  }
  ```
- `peerDependencies` (not deps) so consumers own the single React copy — prevents a duplicate-React
  runtime. The bundle keeps using `window.React`; the consumer still sets it (see Phase 4).

### Phase 2 — Move files + decide asset ownership
- Move `_ds_bundle.js` → `bundle/`, plus `styles.css` + `tokens/*` verbatim.
- **Classify assets** (currently all in `hypervisor-web/public/assets/`):
  - **DS-owned** (move into `packages/design-system/assets/`): `brand/`, `fonts/`, `icons/`,
    `textures/`, generic partner `logos/`.
  - **App/marketing-owned** (stay in the app's `public/`): anything app-specific —
    re-evaluate `badges/`, `logos/models/*`, `logos/tools/*`, `Stripe.jpeg`. Split DS primitives from
    page content; when unsure, keep in the app.
- Net: the package becomes self-contained for DS-owned assets (fixes the "never truly self-contained"
  gap noted in the dedupe commit).

### Phase 3 — Asset delivery contract (the crux)
The bundle/CSS reference assets by **absolute `/assets/...`** (Vite-public). A package can't write to a
consumer's `public/`, so provide a sync, two supported options:
- **Default — `ioi-ds-sync-assets` bin:** copies `@ioi/design-system/assets/*` →
  `<consumer>/public/assets/`. Wire into consumer scripts: `"predev"` and `"prebuild"`.
- **Alternative — `vite-plugin-static-copy`:** document a snippet copying the package assets at build.
- Either keeps the absolute-`/assets/` refs working with **zero per-app duplication**. (Track 2 removes
  this contract by importing assets instead.)

### Phase 4 — Repoint hypervisor-web onto the package
- `main.jsx`: `import "@ioi/design-system/styles.css"` and `await import("@ioi/design-system")` (replaces
  the two `./design-system/...` paths). Keep `window.React = React` before the dynamic import.
- Add `"predev"/"prebuild": "ioi-ds-sync-assets"` to `apps/hypervisor-web/package.json`.
- `git rm -r apps/hypervisor-web/src/design-system/` and the DS-owned entries under `public/assets/`.
- Root `npm install` to link the new workspace.

### Phase 5 — Verify + guard
- `npm run build --workspace=@ioi/hypervisor-web` passes; `dist/assets/{fonts,textures,...}` present.
- Visual smoke: serve `dist/` (or `vite dev`), load `/`, confirm fonts render and the pistachio texture
  paints (the assets we just touched).
- Add a tiny conformance check (script) asserting: package `exports` resolve, `sync-assets` produces the
  expected files, and `hypervisor-web/src` has **0** `./design-system/` references.

**Track 1 done = a real `@ioi/design-system` workspace package, asset-complete, reusable by any app,
global contract intact.**

---

## Track 2 — ESM-native (optional; the "real" portability)

Gated on obtaining the **upstream component source + generator**. If unavailable, Track 1 is the ceiling
and Track 2 is N/A.

- **Phase A — In-source.** Bring `components/`, `ui_kits/`, and the bundle generator into
  `packages/design-system/src/`. Establish the source-of-truth here (or a documented mirror).
- **Phase B — Build pipeline.** `tsup` or Vite lib mode → ESM (+ optional CJS) + `.d.ts`. Assets become
  **imports** (`import logo from "./assets/brand/ioi-mark.svg"`) so the bundler hashes/inlines them —
  this **retires the Phase-3 public-asset sync** entirely. `react`/`react-dom` as peers; components
  `import React` instead of `window.React`.
- **Phase C — Named exports.** `export { Button, Card, Logo, ... }` + generated types. Tree-shakeable.
- **Phase D — Migrate consumers off globals (~25 files).** Codemod:
  `const NS = window.IoiDesignSystem` / `window.Hv*` → `import { ... } from "@ioi/design-system"`; remove
  `window.React = React`; convert `window.HvPage`/`window.HvHeader` page-globals to module exports +
  normal route imports. Do per-file, build-verifying as you go.
- **Phase E — Deprecate the global contract.** Remove the generated-bundle dist path and `window.*`
  shims once all consumers are ESM.

---

## 4. Risks & open decisions

- **Upstream source access** — hard gate for Track 2; confirm before committing to it.
- **Bundle update procedure (Track 1)** — since the bundle stays generated upstream, document the
  "drop a new `_ds_bundle.js`, bump version" refresh path so the vendored dist doesn't silently drift.
- **Asset classification** — DS-primitive vs app/marketing content; getting this wrong re-creates
  duplication or orphans. Default app-side when unsure.
- **React singleton** — peers + install dedupe; verify one React at runtime (the global pattern already
  assumes one `window.React`).
- **Page/section globals** (`window.Hv*`) are an app concern, not DS — Track 2's Phase D must untangle
  app page-modules from the DS migration so they don't get conflated.

## 5. Rollout

After Track 1: adopt `@ioi/design-system` in `developers-ioi-ai`, `sas-xyz`, `aiagent-xyz`, and the
`@ioi/hypervisor-app` workbench surfaces (each: add dep, `ioi-ds-sync-assets`, import `styles.css` +
the bundle). That second consumer is what proves the package is genuinely portable.

## 6. Effort (rough)

- Track 1: ~0.5–1.5 days (scaffold + move + sync bin + repoint + verify). Low risk.
- Track 2: multi-day, gated on upstream source; Phase D (consumer migration) is the bulk.
