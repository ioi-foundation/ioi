// apps/autopilot/vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  // Force resolution to the root node_modules to avoid React duplication
  resolve: {
    alias: {
      react: path.resolve(__dirname, "../../node_modules/react"),
      "react-dom": path.resolve(__dirname, "../../node_modules/react-dom"),
      // Also force @xyflow/react to be a singleton to avoid context mismatch
      "@xyflow/react": path.resolve(__dirname, "../../node_modules/@xyflow/react"),
    },
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    // [FIX] Force binding to 127.0.0.1 (IPv4) to avoid localhost IPv6 resolution issues on Linux
    host: host || "127.0.0.1",
    hmr: host
      ? {
        protocol: "ws",
        host,
        port: 1421,
      }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
    fs: {
      // Allow serving shared workspace packages (e.g. @ioi/agent-ide built CSS).
      allow: [path.resolve(__dirname, "../..")],
    },
  },
}));
