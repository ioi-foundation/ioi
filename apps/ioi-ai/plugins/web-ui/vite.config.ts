import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

const SERVER = process.env.WEB_UI_SERVER_URL ?? "http://localhost:8096";

const here = (rel: string): string => fileURLToPath(new URL(rel, import.meta.url));
export const KATEX_FONT_PATTERN = /^fonts\/(KaTeX_[^/]+\.(?:woff2?|ttf))$/;
export const KATEX_FONT_ALIAS = here("node_modules/katex/dist/fonts/$1");

export default defineConfig({
  base: process.env.WEB_UI_BASE ?? "/",
  resolve: {
    alias: [
      { find: KATEX_FONT_PATTERN, replacement: KATEX_FONT_ALIAS },
      { find: /^katex$/, replacement: here("src/lazy-katex.ts") },
      { find: "katex-real", replacement: here("node_modules/katex/dist/katex.mjs") },
      { find: /^highlight\.js\/lib\/core$/, replacement: here("src/lazy-hljs.ts") },
      { find: "hljs-real-javascript", replacement: here("node_modules/highlight.js/lib/languages/javascript.js") },
      { find: "hljs-real-typescript", replacement: here("node_modules/highlight.js/lib/languages/typescript.js") },
      { find: "hljs-real-python", replacement: here("node_modules/highlight.js/lib/languages/python.js") },
      { find: "hljs-real-xml", replacement: here("node_modules/highlight.js/lib/languages/xml.js") },
      { find: "hljs-real-css", replacement: here("node_modules/highlight.js/lib/languages/css.js") },
      { find: "hljs-real-json", replacement: here("node_modules/highlight.js/lib/languages/json.js") },
      { find: "hljs-real-bash", replacement: here("node_modules/highlight.js/lib/languages/bash.js") },
      { find: "hljs-real-sql", replacement: here("node_modules/highlight.js/lib/languages/sql.js") },
      { find: "hljs-real-markdown", replacement: here("node_modules/highlight.js/lib/languages/markdown.js") },
      { find: "hljs-real", replacement: here("node_modules/highlight.js/lib/core.js") },
      { find: /^highlight\.js\/lib\/languages\/.*$/, replacement: here("src/hljs-lang-stub.ts") },
    ],
  },
  build: {
    outDir: "dist-web",
    emptyOutDir: true,
  },
  server: {
    port: Number(process.env.VITE_PORT ?? 5173),
    fs: { allow: [fileURLToPath(new URL("..", import.meta.url))] },
    proxy: {
      "/signin": SERVER,
      "/signout": SERVER,
      "/me": SERVER,
      "/api": SERVER,
    },
  },
});
