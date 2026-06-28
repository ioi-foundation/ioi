# Hypervisor Web

Browser-facing Hypervisor product and marketing surface scaffolded from the supplied design-system export.

The archive contents were promoted into a Vite workspace app instead of committing the raw zip:

- `src/design-system/` contains the bundled IOI design system, tokens, fonts, and source notes.
- `src/site/` contains the Hypervisor website React page sources from the archive.
- `public/assets/` contains the runtime assets referenced by the archived pages.

## Commands

```sh
npm run dev --workspace=@ioi/hypervisor-web
npm run build --workspace=@ioi/hypervisor-web
```

The local development server is pinned to `http://127.0.0.1:1421`.
