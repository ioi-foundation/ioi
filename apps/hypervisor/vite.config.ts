// apps/hypervisor/vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

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

  // Keep the Hypervisor client server stable for local app shells and adapters.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    fs: {
      // Allow serving shared workspace packages (e.g. @ioi/agent-ide built CSS).
      allow: [path.resolve(__dirname, "../..")],
    },
    // T7 — the native surfaces are same-origin daemon projections. Proxy the daemon spine
    // (Session Execution Binding, env-files, terminals, environments, workruns, threads) to the
    // local hypervisor-daemon so the typed client's /v1/* calls resolve in dev.
    proxy: {
      "/v1": { target: process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765", changeOrigin: true },
      // The env-ops file/git plane lives at /supervisor/:env/supervisor.v1.EnvironmentOpsService/*
      // (the session workbench reads/writes the real scoped workspace through it).
      "/supervisor": { target: process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765", changeOrigin: true },
    },
  },
}));
