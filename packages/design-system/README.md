# @ioi/design-system

The IOI shared design system: CSS token layers, brand assets, and a prebuilt component bundle.

This package is the single source of truth for the design system so apps consume it instead of
vendoring a copy. It is a **prebuilt** package — it ships the generated component bundle and the token
CSS directly (no build step here). The component source and the bundle generator are upstream; to refresh
the design system, drop a new `bundle/_ds_bundle.js` in and bump the version.

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

## Roadmap

A future track converts this to an ESM-native package (named exports + types, bundler-imported assets,
no `window.*` contract). That requires in-sourcing the component source + generator and migrating
consumers off the globals; until then, the global contract above is the supported interface.
