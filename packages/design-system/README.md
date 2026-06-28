# @ioi/design-system

The IOI shared design system: CSS token layers, brand assets, and a prebuilt component bundle.

This package is the single source of truth for the design system so apps consume it instead of
vendoring a copy. It is a **prebuilt** package — it ships the generated component bundle and the token
CSS directly (no build step here). The component source and the bundle generator are upstream; the
upstream only ships compiled dist exports, so to refresh the design system you run the import pipeline
against a new export (see "Refreshing from an upstream export" below).

## What it ships

- `bundle/_ds_bundle.js` — the generated component bundle. On import it populates the global
  `window.IoiDesignSystem` namespace (Button, Card, Logo, Wordmark, Badge, Input, …). It reads
  `window.React`, so the consumer must assign `window.React` **before** importing the bundle.
- `styles.css` — the global stylesheet entry; it only `@import`s the token layers.
- `tokens/{colors,fonts,typography,spacing}.css` — the CSS variable layers.
- `assets/` — brand, fonts, icons, logos, textures. The bundle and tokens reference these by absolute
  `/assets/...` URLs at runtime.
- `bin/ioi-ds-sync-assets` — mirrors `assets/` into a consumer's `public/assets/`.

## Consuming it (Vite app)

1. Add the dependency (workspace): `"@ioi/design-system": "*"`.
2. Sync assets into your `public/` on dev/build:
   ```jsonc
   // package.json
   "scripts": {
     "predev":   "ioi-ds-sync-assets",
     "prebuild": "ioi-ds-sync-assets",
     "dev":   "vite",
     "build": "vite build"
   }
   ```
   (Alternatively, copy `node_modules/@ioi/design-system/assets` via `vite-plugin-static-copy`.)
3. Load it from your entry module:
   ```js
   import React from "react";
   import "@ioi/design-system/styles.css";

   window.React = React;                 // the bundle reads window.React
   await import("@ioi/design-system");    // side effect: populates window.IoiDesignSystem
   ```
4. Use components from the namespace: `const { Button, Card } = window.IoiDesignSystem;`.

## Refreshing from an upstream export

The upstream design system ships compiled dist exports (`_ds_bundle.js` + `styles.css` + `tokens/` +
`assets/`), and each export arrives un-neutralized: a per-export, hashed `window.<Brand>DesignSystem_<hash>`
namespace, brand strings in identifiers and comments, a UMD global-React assumption, and relative asset
paths. The import pipeline applies the deterministic adaptations so the result is always source-neutral
and Vite/ESM-consumable — no hand-massaging:

```bash
npm run import-export --workspace=@ioi/design-system -- "<path-to-export>/dist"
```

It performs, then asserts zero brand residue before writing:

1. **Brand neutralization** — `<Brand>DesignSystem_<hash>` → `IoiDesignSystem` (stable, so consumers'
   `window.IoiDesignSystem` keeps working across refreshes), `<Brand>Xxx` → `IoiXxx`, prose/domain
   `<Brand>`/`<brand>` → `IOI`/`ioi`.
2. **React prepend** — `const React = window.React;` so the bundle resolves React under ESM.
3. **Asset absolutization** — `url(../assets/…)` → `url(/assets/…)` in the bundle and token CSS.
4. **Additive asset merge** — refreshes the export's assets while preserving app-origin assets the
   export omits but the site components reference (`badges/`, `logos/models`, `logos/tools`,
   `brand/ioi-logo.svg`); it prints those so coverage is never silent.

The upstream export itself (the branded zip/folder) is an external input — keep it outside the tracked
tree and point the pipeline at it; it is never committed.

## Roadmap

A future track converts this to an ESM-native package (named exports + types, bundler-imported assets,
no `window.*` contract). That requires the upstream to ship component **source** + the generator (today
it ships compiled dist only) and migrating consumers off the globals; until then, the global contract
above is the supported interface and the import pipeline keeps refreshes neutral.
