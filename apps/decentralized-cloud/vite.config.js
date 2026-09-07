import { cpSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const HERE = path.dirname(fileURLToPath(import.meta.url));

// THE FONTS ARE COPIED FROM public/fonts AT BUILD TIME, not duplicated in the repo.
//
// Vite's `publicDir` would be the ordinary way to ship them, but this app's public/
// directory is the CURRENT vanilla surface — it holds index.html, face.css and
// face.js — and vite would copy that index.html over the built one. The obvious
// workaround was a second copy of the four font files under static/. I made that copy
// and then deleted it: a second copy of IOI.ttf is a second source that can drift from
// the first, which is the exact fault the wordmark's one-source gate exists to catch,
// one directory over. One copy on disk; the build reads it.
// The fonts follow the RESOLVED outDir, not a hard-coded dist/. The designer's builds
// go to a separate directory (`vite build --outDir .dist-designer`) so that a build by
// one session cannot rewrite the bytes under another session's gate run; a plugin that
// always wrote dist/fonts would have shipped that directory fontless and rendered the
// whole exhibit in fallback serif — a failure this programme has already paid for once.
const copyFonts = () => {
  let outDir = path.join(HERE, "dist");
  return {
    name: "dcloud-copy-fonts",
    configResolved(config) {
      outDir = path.isAbsolute(config.build.outDir)
        ? config.build.outDir
        : path.join(config.root, config.build.outDir);
    },
    closeBundle() {
      // public/brand travels the same way: the brand assets page and the SVGs it
      // serves are generated into public/brand by brand/mark/build-assets.mjs from
      // the same module the shell draws from, and are copied, never duplicated.
      for (const dir of ["fonts", "brand"]) {
        const from = path.join(HERE, "public", dir);
        const to = path.join(outDir, dir);
        mkdirSync(to, { recursive: true });
        cpSync(from, to, { recursive: true });
      }
    },
  };
};

export default defineConfig({
  root: HERE,
  publicDir: false,
  plugins: [react(), copyFonts()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // The served bytes are what every honesty gate reads, and a gate cannot scan what
    // it cannot see. Sourcemaps are off and the output is not minified beyond what is
    // needed: the surface's claims — the unwired labels, the allowlist, the drawn
    // glyph paths — must survive the build as READABLE bytes, because the gate asserts
    // against the artifact that ships rather than against the source it was built
    // from. A build step is exactly the kind of transform that can quietly drop one.
    minify: false,
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/face.js",
        chunkFileNames: "assets/[name].js",
        assetFileNames: "assets/[name][extname]",
      },
    },
  },
});
