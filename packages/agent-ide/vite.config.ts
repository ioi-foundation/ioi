// packages/agent-ide/vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import dts from "vite-plugin-dts";
import { resolve } from "path";

export default defineConfig({
  plugins: [
    react(),
    dts({ 
      include: ["src"],
      insertTypesEntry: true,
    }),
  ],
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "AgentIDE",
      fileName: (format) => `index.${format}.js`,
    },
    rollupOptions: {
      // STRICTLY EXTERNALIZE REACT
      external: [
        "react", 
        "react-dom", 
        "react/jsx-runtime", // Important for new JSX transform
        "@xyflow/react", 
        "zustand"
      ],
      output: {
        globals: {
          react: "React",
          "react-dom": "ReactDOM",
          "@xyflow/react": "ReactFlow",
        },
      },
    },
  },
});