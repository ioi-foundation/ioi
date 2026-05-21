import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: __dirname,
  plugins: [react()],
  build: {
    emptyOutDir: true,
    outDir: resolve(__dirname, "media/workflow-composer"),
    sourcemap: true,
    rollupOptions: {
      input: resolve(__dirname, "webview/workflow-composer/main.tsx"),
      output: {
        entryFileNames: "workflow-composer.js",
        chunkFileNames: "workflow-composer-[name].js",
        assetFileNames: "workflow-composer[extname]",
      },
    },
  },
});
