// apps/agent-studio/vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from "path";

// https://vitejs.dev/config/
export default defineConfig({
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
})